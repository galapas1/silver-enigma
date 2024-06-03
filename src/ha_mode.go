package ninjapanda

import (
	"context"
	"strings"

	"github.com/gofrs/uuid"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

var (
	redisPrimaryClient *redis.Client
	redisReplicaClient *redis.Client
	redisClusterClient *redis.ClusterClient
	redisClusterExists int // 0 - have not tried; -1 - does not exist; 1 - exists
)

const (
	updatePolicyCmd     = "refetch policies"
	refreshRelaysCmd    = "refresh relays"
	queueStateUpdateCmd = "queue state update"
)

func getRedisClient(ctx context.Context, cfg *Config) (*CacheClient, error) {
	if redisPrimaryClient == nil {
		redisPrimaryClient = redis.NewClient(&redis.Options{
			Addr:            cfg.Cache.Addr,
			Password:        cfg.Cache.Password,
			MaxRetries:      cfg.Cache.MaxRetries,
			ConnMaxIdleTime: cfg.Cache.ConnMaxIdleTime,

			PoolSize:     cfg.Cache.PoolSize,
			MinIdleConns: cfg.Cache.MinIdleConns,
		})
	}

	redisClient := &CacheClient{
		singleClient: redisPrimaryClient,
		cacheConfig:  &cfg.Cache,
		cacheType:    redisCache,
		useCluster:   false,
	}

	_, err := redisPrimaryClient.Ping(ctx).Result()
	if err != nil {
		redisCacheErrorCount.Inc()
		return nil, err
	}

	return redisClient, nil
}

// This function configures Ninja Panda for HA Mode, by allowing it to subscribe to the
// HA-related update mechanisms.
func (np *Ninjapanda) initHA() {
	if np.cfg.Cache.CacheType == "redis" {
		subscriber := np.registrationCache.singleClient.Subscribe(
			context.Background(),
			Channel_Name,
		)
		np.redisSubscriber = subscriber
		go np.launchSubscriber()
	}
}

func (np *Ninjapanda) SubscribeToHAEvents() {
	uuid, _ := uuid.NewV4()
	me := uuid.String()

	log.Info().Caller().Msg("Initiating ha update subscriber")

	channel := np.redisSubscriber.Channel()
	for message := range channel {
		cmdComponents := strings.Split(message.Payload, ":")

		cmd, sender := cmdComponents[0], ""
		if len(cmdComponents) > 1 {
			sender = cmdComponents[1]
		}

		if sender == me {
			continue
		}

		log.Info().
			Interface(logtags.MakeTag("message"), message).
			Msg("Received ha update broadcast")

		switch string(cmd) {
		case updatePolicyCmd:
			np.LoadACLPolicyFromDB()
		case refreshRelaysCmd:
			np.RefreshRelayMap()
		case queueStateUpdateCmd:
			np.notifier.NotifyFromQueue()
		}
	}
	log.Error().Caller().Msg("[critical]: not expecting this loop to finish!")
}

// If a change arrives at the Ninja Panda that other Ninja Pandas need to know about,
// then the originating Ninja Panda (ONP) should publish a message on the channel
// instructing all NP's to refresh.
///
func (z *Ninjapanda) HAUpdatePolicies() {
	ctx := context.Background()
	if z.cfg.Cache.CacheType == "redis" {
		log.Info().
			Caller().
			Str(logtags.MakeTag("command"), updatePolicyCmd).
			Msg("publishing command")
		z.redisClient.Publish(ctx, Channel_Name, updatePolicyCmd)
	}
}

func (z *Ninjapanda) HARefreshRelays() {
	ctx := context.Background()
	if z.cfg.Cache.CacheType == "redis" {
		log.Info().
			Caller().
			Str(logtags.MakeTag("command"), refreshRelaysCmd).
			Msg("publishing command")
		z.redisClient.Publish(ctx, Channel_Name, refreshRelaysCmd)
	}
}

func (z *Ninjapanda) HAQueueUpdate(
	ctx context.Context,
	machineKey string,
	update StateUpdate,
) {
	// If we are not 'ha mode', the machine isn't online...
	// if/when it comes on line, this ninjapanda will see it
	// and update as needed
	if z.cfg.Cache.CacheType == "redis" {
		// TODO: queue specifics of the uppate and target
		// short-term, we'll use ~update all~
		log.Info().
			Caller().
			Str(logtags.MakeTag("command"), queueStateUpdateCmd).
			Msg("publishing command")
		z.redisClient.Publish(ctx, Channel_Name, queueStateUpdateCmd)
	}
}
