package ninjapanda

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/v9"

	"github.com/rs/zerolog/log"
)

const (
	Cluster_RegistrationsPrefix = "registrations_"
	Cluster_NodeKeysPrefix      = "nodekeys_"

	Channel_Name = "ninja_panda_ha"

	scan_count = 10000
)

type cacheType int64

const (
	redisCache cacheType = iota
	memoryCache
)

type CacheClient struct {
	cacheType     cacheType
	cacheConfig   *CacheConfig
	singleClient  *redis.Client
	redisAddr     string
	clusterClient *redis.ClusterClient
	useCluster    bool
	memoryCache   *cache.Cache
}

var (
	RegistrationsPrefix = "registrations_"
	StatesPrefix        = "states_"
)

func NewCacheClient(ctx context.Context, cfg *Config) (*CacheClient, error) {
	if cfg.Cache.CacheType == "redis" {
		return getRedisClient(ctx, cfg)
	} else {
		// In case the config type is not set, then just set it to In memory
		return &CacheClient{
			cacheType: memoryCache,
			memoryCache: cache.New(
				registerCacheExpiration,
				registerCacheCleanup,
			),
		}, nil
	}
}

func (z *CacheClient) StoreMachineRegistration(
	ctx context.Context,
	correlationId string,
	status MachineRegistrationStatus, expiration time.Duration,
) error {
	log.Info().
		Caller().
		Str(logtags.MakeTag("CorrelationId"), correlationId).
		Msg("Storing machine")

	var err error
	key := fmt.Sprintf("%s%s", RegistrationsPrefix, correlationId)
	if z.cacheType == redisCache {
		if z.useCluster {
			_, err = z.clusterClient.Set(
				ctx,
				key,
				status,
				expiration,
			).Result()
		} else {
			_, err = z.singleClient.Set(
				ctx,
				key,
				status,
				expiration,
			).Result()
		}
		if err != nil {
			redisCacheErrorCount.Inc()
		}
	} else {
		z.memoryCache.Set(key, status, expiration)
	}

	if err != nil {
		log.Warn().Caller().Err(err).Msg("Error: Unable to store machine registration")
		return err
	}
	cacheCorrelationIdsInsertedCount.Inc()
	return nil
}

func (z *CacheClient) GetMachineRegistrations(
	ctx context.Context,
) (map[string]MachineRegistrationStatus, error) {
	registrationStatuses := make(map[string]MachineRegistrationStatus)
	if z.cacheType == redisCache {

		var cursor uint64
		for {
			var keys []string
			var err error

			if z.useCluster {
				keys, cursor, err = z.clusterClient.Scan(ctx, cursor, RegistrationsPrefix+"*", scan_count).
					Result()
			} else {
				keys, cursor, err = z.singleClient.Scan(ctx, cursor, RegistrationsPrefix+"*", scan_count).Result()
			}
			if err != nil {
				redisCacheErrorCount.Inc()
				return registrationStatuses, err
			}

			registrationList, _ := z.getMachineRegistrationsNoPrefix(ctx, keys)
			for key, value := range registrationList {
				newKey := strings.Replace(key, RegistrationsPrefix, "", 1)
				registrationStatuses[newKey] = value
			}
			cacheCorrelationIdsCount.Set(float64(len(registrationList)))
			if cursor == 0 {
				break
			}
		}

		// sort.Slice(categories, func(i, j int) bool {
		// 	return categories[i].Id < categories[j].Id
		// })

		return registrationStatuses, nil
	} else if z.cacheType == memoryCache {
		for key, item := range z.memoryCache.Items() {
			registrationStatusIface := item.Object
			if registrationStatus, ok := registrationStatusIface.(MachineRegistrationStatus); ok {
				newKey := strings.Replace(key, RegistrationsPrefix, "", 1)
				registrationStatuses[newKey] = registrationStatus
			}
		}
		cacheCorrelationIdsCount.Set(float64(len(z.memoryCache.Items())))
	}
	return registrationStatuses, nil
}

func (z *CacheClient) SearchMachineRegistration(
	ctx context.Context,
	correlationId string,
) (MachineRegistrationStatus, bool) {
	var machineReg MachineRegistrationStatus
	key := fmt.Sprintf("%s%s", RegistrationsPrefix, correlationId)

	if z.cacheType == redisCache {
		log.Debug().Caller().
			Str(logtags.MakeTag("CorrelationId"), correlationId).
			Msg("Getting a specific machine registration")
		res, err := z.singleClient.Get(ctx, key).Result()
		if err != nil {
			log.Error().Caller().Err(err).Msg("Redis Search Machine registration error")
			redisCacheErrorCount.Inc()
			return MachineRegistrationStatus{}, false
		}
		err = json.Unmarshal([]byte(res), &machineReg)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Unable to marshall MachineRegistration from JSON")
			return MachineRegistrationStatus{}, false
		}
	} else if z.cacheType == memoryCache {
		registrationStatusIface, ok := z.memoryCache.Get(key)
		if !ok {
			return machineReg, false
		}
		if registrationStatus, ok := registrationStatusIface.(MachineRegistrationStatus); ok {
			return registrationStatus, true
		} else {
			return machineReg, false
		}

	}
	return machineReg, true
}

func (z *CacheClient) SearchState(ctx context.Context, state string) (any, bool) {
	key := fmt.Sprintf("%s%s", StatesPrefix, state)

	if z.cacheType == redisCache {
		res, err := z.singleClient.Get(ctx, key).Result()
		if err != nil {
			return "", false
		}
		return res, true

	} else if z.cacheType == memoryCache {
		nodeKeyIface, ok := z.memoryCache.Get(key)
		if !ok {
			return "", false
		}
		if nodeKey, ok := nodeKeyIface.(string); ok {
			return nodeKey, true
		} else {
			return "", false
		}

	}
	return "", false
}

func (z *CacheClient) StoreState(
	ctx context.Context,
	state string,
	nodeKey string,
	expiration time.Duration,
) bool {
	var err error
	key := fmt.Sprintf("%s%s", StatesPrefix, state)
	if z.cacheType == redisCache {
		if z.useCluster {
			_, err = z.clusterClient.Set(
				ctx,
				key,
				nodeKey,
				expiration,
			).Result()
		} else {
			_, err = z.singleClient.Set(
				ctx,
				key,
				nodeKey,
				expiration,
			).Result()
		}
	} else {
		z.memoryCache.Set(key, nodeKey, expiration)
	}

	if err != nil {
		log.Warn().Caller().Err(err).Msg("Error: Unable to store machine registration")
		return false
	}
	return true
}

func (z *CacheClient) getMachineRegistrationsNoPrefix(
	ctx context.Context,
	categoryIds []string,
) (map[string]MachineRegistrationStatus, error) {
	categories := make(map[string]MachineRegistrationStatus)

	for _, id := range categoryIds {
		b, err := z.GetValueNoPrefix(ctx, id)
		if err != nil {
			return nil, err
		}

		var category MachineRegistrationStatus
		json.Unmarshal([]byte(b), &category)
		categories[id] = category
	}
	return categories, nil
}

func (z *CacheClient) GetValueNoPrefix(
	ctx context.Context,
	key string,
) (string, error) {
	if z.useCluster {
		return z.clusterClient.Get(ctx, key).Result()
	} else {
		return z.singleClient.Get(ctx, key).Result()
	}
}

// end of storage.go
