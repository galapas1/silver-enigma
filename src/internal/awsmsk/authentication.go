package awsmsk

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"fmt"

	sarama "optm.com/ninja-panda/src/internal/sarama"
)

// Authentication defines authentication.
type Authentication struct {
	PlainText *PlainTextConfig `mapstructure:"plain_text"`
	SASL      *SASLConfig      `mapstructure:"sasl"`
}

// PlainTextConfig defines plaintext authentication.
type PlainTextConfig struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

// SASLConfig defines the configuration for the SASL authentication.
type SASLConfig struct {
	// Username to be used on authentication
	Username string `mapstructure:"username"`
	// Password to be used on authentication
	Password string `mapstructure:"password"`
	// SASL Mechanism to be used, possible values are: (PLAIN, AWS_MSK_IAM, SCRAM-SHA-256 or SCRAM-SHA-512).
	Mechanism string `mapstructure:"mechanism"`

	AWSMSK AWSMSKConfig `mapstructure:"aws_msk"`
}

// AWSMSKConfig defines the additional SASL authentication
// measures needed to use AWS_MSK_IAM mechanism
type AWSMSKConfig struct {
	// Region is the AWS region the MSK cluster is based in
	Region string `mapstructure:"region"`
	// BrokerAddr is the client is connecting to in order to perform the auth required
	BrokerAddr string `mapstructure:"broker_addr"`
}

// ConfigureAuthentication configures authentication in sarama.Config.
func ConfigureAuthentication(
	config *Authentication,
	saramaConfig *sarama.Config,
) error {
	if config.PlainText != nil {
		configurePlaintext(*config.PlainText, saramaConfig)
	}

	if config.SASL != nil {
		if err := configureSASL(*config.SASL, saramaConfig); err != nil {
			return err
		}
	}

	return nil
}

func configurePlaintext(config PlainTextConfig, saramaConfig *sarama.Config) {
	saramaConfig.Net.SASL.Enable = true
	saramaConfig.Net.SASL.User = config.Username
	saramaConfig.Net.SASL.Password = config.Password
}

func configureSASL(config SASLConfig, saramaConfig *sarama.Config) error {
	//	if config.Username == "" {
	//		return fmt.Errorf("SASL username required")
	//	}

	//	if config.Password == "" {
	//		return fmt.Errorf("SASL password required")
	//	}

	saramaConfig.ClientID = "optm_scram_client"
	saramaConfig.Version = sarama.DefaultVersion // V0_10_0_0
	saramaConfig.Metadata.Full = true

	saramaConfig.Net.SASL.Enable = true
	saramaConfig.Net.SASL.User = config.Username
	saramaConfig.Net.SASL.Password = config.Password
	saramaConfig.Net.SASL.Handshake = true

	saramaConfig.Net.TLS.Enable = true
	saramaConfig.Net.TLS.Config = createTLSConfiguration()

	saramaConfig.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient { return &XDGSCRAMClient{HashGeneratorFcn: sha256.New} }
	saramaConfig.Net.SASL.Mechanism = sarama.SASLMechanism(sarama.SASLTypeSCRAMSHA256)

	switch config.Mechanism {
	case "SCRAM-SHA-512":
		saramaConfig.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient { return &XDGSCRAMClient{HashGeneratorFcn: sha512.New} }
		saramaConfig.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA512
	case "SCRAM-SHA-256":
		saramaConfig.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient { return &XDGSCRAMClient{HashGeneratorFcn: sha256.New} }
		saramaConfig.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA256
	case "PLAIN":
		saramaConfig.Net.SASL.Mechanism = sarama.SASLTypePlaintext
	case "AWS_MSK_IAM":
		saramaConfig.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
			return NewIAMSASLClient(
				config.AWSMSK.BrokerAddr,
				config.AWSMSK.Region,
				saramaConfig.ClientID,
			)
		}
		saramaConfig.Net.SASL.Mechanism = MechanismName
		saramaConfig.Net.SASL.AWSMSKIAM = sarama.AWSMSKIAMConfig{
			Region:          config.AWSMSK.Region,
			AccessKeyID:     config.Username,
			SecretAccessKey: config.Password,
		}
	default:
		return fmt.Errorf(
			`invalid SASL Mechanism %q: can be either "PLAIN", "AWS_MSK_IAM", "SCRAM-SHA-256" or "SCRAM-SHA-512"`,
			config.Mechanism,
		)
	}

	return nil
}

func createTLSConfiguration() (t *tls.Config) {
	t = &tls.Config{
		InsecureSkipVerify: false,
	}
	return t
}
