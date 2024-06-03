package ninjapanda

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"

	"github.com/stretchr/testify/assert"
)

func TestRedisMode(t *testing.T) {
	asserter := assert.New(t)
	pool, err := dockertest.NewPool("")
	asserter.NoError(err)
	asserter.NotNil(pool)
	redis, err := pool.RunWithOptions(&dockertest.RunOptions{
		Name:         "test-redis",
		Repository:   "redis",
		Tag:          "7-alpine",
		ExposedPorts: []string{"6379"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"6379": {
				{HostIP: "0.0.0.0", HostPort: "6379"},
			},
		},
	})
	time.Sleep(500 * time.Millisecond)
	defer redis.Close()
	asserter.NoError(err)
	asserter.NotNil(redis)

	cfg := &Config{
		Cache: CacheConfig{
			CacheType: "redis",
			Addr:      "localhost:6379",
		},
	}
	client, _ := NewCacheClient(context.Background(), cfg)

	testWithClient(asserter, context.Background(), client)
}

func TestInMemoryMode(t *testing.T) {
	asserter := assert.New(t)

	cfg := &Config{
		Cache: CacheConfig{
			CacheType: "memory",
		},
	}
	client, _ := NewCacheClient(context.Background(), cfg)

	testWithClient(asserter, context.Background(), client)
}

func TestRedisNoServerFails(t *testing.T) {
	asserter := assert.New(t)

	cfg := &Config{
		Cache: CacheConfig{
			CacheType: "redis",
			Addr:      "localhost:8000",
		},
	}
	_, err := NewCacheClient(context.Background(), cfg)
	asserter.Error(err, "Should not have been able to connect to Redis")
}

func testWithClient(
	asserter *assert.Assertions,
	ctx context.Context,
	client *CacheClient,
) {
	asserter.NotNil(client)

	var err error
	expiration := 100 * time.Second
	count := 200
	for i := 0; i < count; i++ {
		correlationId := fmt.Sprintf("abcd_%d", i)
		err = client.StoreMachineRegistration(ctx, correlationId,
			MachineRegistrationStatus{
				Status: "foo",
				Machine: Machine{
					ID: 1234,
				},
			}, expiration)
		asserter.NoError(err)
	}

	regMap, err := client.GetMachineRegistrations(ctx)
	asserter.NoError(err)
	asserter.Equal(count, len(regMap))
	for i := 0; i < count; i++ {
		key := fmt.Sprintf("abcd_%d", i)
		_, ok := regMap[key]
		asserter.True(ok)
	}

	for i := count; i < count+20; i++ {
		key := fmt.Sprintf("abcd_%d", i)
		_, ok := regMap[key]
		asserter.False(ok)
	}

	// Now search for machine registrations
	key := "abcd_150"
	reg, ok := client.SearchMachineRegistration(ctx, key)
	asserter.True(ok)
	asserter.Equal("foo", reg.Status)

	key = "abcd_201"
	reg, ok = client.SearchMachineRegistration(ctx, key)
	asserter.False(ok)
	asserter.Equal("", reg.Status)
}
