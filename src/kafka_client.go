package ninjapanda

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/iimos/saramaprom"
	"github.com/rs/zerolog/log"

	awsmsk "optm.com/ninja-panda/src/internal/awsmsk"
	sarama "optm.com/ninja-panda/src/internal/sarama"
)

type KafkaConfig struct {
	UpdateInterval  time.Duration
	BrokerAddress   string
	ProtocolVersion string
	EnableTLS       bool

	Authentication *awsmsk.Authentication
	Compression    string
}

type KafkaClient struct {
	UpdateInterval time.Duration
	Producer       sarama.SyncProducer
}

func NewKafkaClient(cfg KafkaConfig) (*KafkaClient, error) {
	k := &KafkaClient{}
	k.UpdateInterval = cfg.UpdateInterval

	if len(cfg.BrokerAddress) == 0 {
		return k, nil
	}

	sConfig := sarama.NewConfig()

	err := saramaprom.ExportMetrics(
		context.Background(),
		sConfig.MetricRegistry,
		saramaprom.Options{
			Namespace: "ninjapanda",
			Subsystem: "kafka",
		},
	)
	if err != nil {
		log.Warn().Err(err).Msg("Unable to register Kafka metrics with Prometheus")
	}

	sConfig.Producer.Return.Successes = true
	sConfig.Producer.Return.Errors = true
	sConfig.Producer.RequiredAcks = sarama.WaitForAll

	sConfig.Producer.Retry.Max = 5

	if cfg.ProtocolVersion != "" {
		version, err := sarama.ParseKafkaVersion(cfg.ProtocolVersion)
		if err != nil {
			return nil, err
		}
		sConfig.Version = version
	}

	// REVIEW: if auth is expanded beyond aws_iam,
	// this will check will need to reflect such
	if cfg.Authentication != nil {
		if err := awsmsk.ConfigureAuthentication(cfg.Authentication, sConfig); err != nil {
			return nil, err
		}

		sConfig.ClientID = "optm_msk_client"
		sConfig.Metadata.Full = true

		sConfig.Net.SASL.Enable = true
		sConfig.Net.SASL.Handshake = true
	}

	compression, err := saramaProducerCompressionCodec(cfg.Compression)
	if err != nil {
		return nil, err
	}

	sConfig.Producer.Compression = compression
	sConfig.Producer.Retry.Max = 3
	sConfig.Producer.RequiredAcks = sarama.WaitForAll
	sConfig.Producer.Return.Successes = true

	brokers := strings.Split(cfg.BrokerAddress, ",")

	conn, err := sarama.NewSyncProducer(brokers, sConfig)
	if err != nil {
		return k, fmt.Errorf("NewKafkaClient: %v", err)
	}

	k.Producer = conn

	return k, nil
}

func (k KafkaClient) PushToTopic(
	topic string,
	messageBody string,
	tenantId string,
) error {
	if !k.IsEnabled() || len(messageBody) == 0 {
		return nil
	}

	kmsg := &sarama.ProducerMessage{
		Topic: topic,
		Key:   nil,
		Value: sarama.StringEncoder(messageBody),
		Headers: []sarama.RecordHeader{
			{
				Key:   []byte("tenantId"),
				Value: []byte(tenantId),
			},
		},
		Metadata:  nil,
		Offset:    0,
		Partition: 0,
		Timestamp: time.Time{},
	}
	part, off, err := k.Producer.SendMessage(kmsg)
	if err == nil {
		log.Trace().
			Caller().
			Msgf("kafka producer wrote on part:%d and offset: %d", part, off)
	}

	return err
}

func (k KafkaClient) IsEnabled() bool {
	return k.Producer != nil
}

func saramaProducerCompressionCodec(
	compression string,
) (sarama.CompressionCodec, error) {
	switch compression {
	case "none":
		return sarama.CompressionNone, nil
	case "gzip":
		return sarama.CompressionGZIP, nil
	case "snappy":
		return sarama.CompressionSnappy, nil
	case "lz4":
		return sarama.CompressionLZ4, nil
	case "zstd":
		return sarama.CompressionZSTD, nil
	default:
		return sarama.CompressionNone, fmt.Errorf(
			"producer.compression should be one of 'none', 'gzip', 'snappy', 'lz4', or 'zstd'. configured value %v",
			compression,
		)
	}
}
