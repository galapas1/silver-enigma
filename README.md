<p align="center">
  <img src="logo/ninja_panda.png" width="150px" title="ninja-panda">
</p>

ZTMesh Control Plane

## ZTMesh Core Submodule

The "core" directory is a git submodule refering to ZTMesh Core. Use the following command to download the core submodule dependency.

```
git submodule update --init core
```

## Web Interactions

http://127.0.0.1:9090/metrics
http://0.0.0.0:8080/swagger

## Deps

Install the following dependencies using Brew and Go install.

```
brew install prettier
brew install clang-format
brew install grc
go install github.com/segmentio/golines@latest
go install mvdan.cc/gofumpt@latest
```

## Headscale Core

headscale last sync: bafb6791d3e61cc2fd9f283081885f29497150d2

## Kafka machine updates

Adding the following lines to the [config.yaml](config.yaml)

```yaml
#Change as appropriate
kafka:
  broker: localhost:9092
```

Or set the environment variable `NINJA_KAFKA_BOOTSTRAP_SERVER`; the
later takes precidence.

For local debugging add the folllowing to a `kafka.env` file:

```
KAFKA_ENABLE_KRAFT=yes
KAFKA_CFG_PROCESS_ROLES=broker,controller
KAFKA_CFG_CONTROLLER_LISTENER_NAMES=CONTROLLER
KAFKA_CFG_LISTENERS=PLAINTEXT://:9092,CONTROLLER://:9093
KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
KAFKA_CFG_ADVERTISED_LISTENERS=PLAINTEXT://127.0.0.1:9092
KAFKA_BROKER_ID=1
KAFKA_CFG_CONTROLLER_QUORUM_VOTERS=1@127.0.0.1:9093
ALLOW_PLAINTEXT_LISTENER=yes
```

And run:

```
docker run \
          -d \
          --name optmate-kafka \
          --env-file kafka.env \
          -p 9092:9092 \
          bitnami/kafka:latest
#Note: this takes a few minutes to start up on my arm64 macbook.
# it might be bacause the bitnami kafka image is only for x86 and
# docker desktop has to run it via QEMU.
```

Then create the topics (you will need to do `brew install kafka` to get
these tools):

```bash
for t in register update delete
do
   kafka-topics --bootstrap-server 127.0.0.1:9092 \
      --create --topic machine.$t
done
```

Then you can view the topics like so:

```
kafka-console-consumer --bootstrap-server 127.0.0.1:9092 --topic machine.register
kafka-console-consumer --bootstrap-server 127.0.0.1:9092 --topic machine.update
kafka-console-consumer --bootstrap-server 127.0.0.1:9092 --topic machine.delete
```

## Authorization Callback

When a client registers it's machine with ninja panda a `machine.register` Kafka message is send out with
the expectation that something will eventually POST back to `/api/v1/machine/register/callback/{corrId}`
with the authentication results. Note that, this authentication entity and it interaction with the client is
outside the purview of ninjapanda. The only thing ninjapanda has to do with it is to notify the client where
the authentication URL is. This is the role of this in the config:

```yaml
machine_auth_url: <URL OF OAUTH IDENTIFIER SERVICE>
```

This is overriden by the `NINJA_MACHINE_AUTH_URL` environment variable.

## In-Memory or Redis Cache

In the authorization flow above, ninjapanda either uses an in-memory cache (default) or Redis. To configure the Redis support use the following environment variables. For more details on the semantics of the Redis configurations see [this page.](https://github.com/redis/go-redis/blob/v9.0.3/options.go)

```
CACHE_TYPE=redis
CACHE_ADDRESS=your_redis_server.example.com:6379
CACHE_PASSWORD=top_secret
CACHE_MAX_RETRIES=10
CACHE_CONN_MAX_IDLE_TIME=1h
CACHE_POOL_SIZE=40
CACHE_MIN_IDLE_CONNS=3
```

## Alternate RELAY Servers

By default the RELAY servers used are the ones defined in the config file, in the relay.urls property.
This will not be viable for every environment. The list of URLs can be overriden with an environment variable.
`NINJA_RELAY_FILE_URLS` which should be a comma-separated list of URLs that contain a list of RELAY regions and servers.

```
NINJA_RELAY_FILE_URLS=https://resources.optm.com/relay-prod01.json,https://resources.optm.com/relay-prod02.json
```

## Clean cache

go clean -modcache

## Logging How-to

https://betterstack.com/community/guides/logging/zerolog/

## Testing

grpcurl -plaintext 0.0.0.0:50443 ninjapanda.v1.NinjapandaService/CheckHealth
