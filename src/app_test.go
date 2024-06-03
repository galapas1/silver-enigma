package ninjapanda

import (
	"fmt"
	"net/netip"
	"os"
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/suite"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

var _ = check.Suite(&Suite{})

type Suite struct {
	suite.Suite
	pool     dockertest.Pool
	network  dockertest.Network
	database dockertest.Resource
}

var (
	tmpDir string
	app    Ninjapanda
)

func (s *Suite) SetUpTest(c *check.C) {
	logtags = NewLogTags()

	if ppool, err := dockertest.NewPool(""); err == nil {
		s.pool = *ppool
	} else {
		s.FailNow(fmt.Sprintf("Could not connect to docker: %s", err), "")
	}

	network, err := GetFirstOrCreateNetwork(&s.pool, ninjapandaNetwork)
	if err != nil {
		s.FailNow(fmt.Sprintf("Failed to create or get network: %s", err), "")
	}
	s.network = network

	database, err := CreatePostgresDatabase(&s.pool, &network)
	if err != nil {
		s.FailNow(fmt.Sprintf("Failed to create postgres database: %s", err))
	}
	s.database = *database

	s.ResetDB(c)
}

func (s *Suite) TearDownTest(c *check.C) {
	if err := s.pool.Purge(&s.database); err != nil {
		s.Error(err, "Could not purge postgres database resource")
	}
}

func (s *Suite) ResetDB(c *check.C) {
	if len(tmpDir) != 0 {
		os.RemoveAll(tmpDir)
	}
	var err error
	tmpDir, err = os.MkdirTemp("", "autoygg-client-test")
	if err != nil {
		c.Fatal(err)
	}
	cfg := Config{
		IPPrefixes: []netip.Prefix{
			netip.MustParsePrefix("10.27.0.0/23"),
		},
		Kafka: KafkaConfig{},
	}

	app = Ninjapanda{
		cfg:         &cfg,
		dbType:      "sqlite3",
		dbString:    tmpDir + "/ninjapanda_test.db",
		kafkaClient: &KafkaClient{},
	}
	err = app.initDB()
	if err != nil {
		c.Fatal(err)
	}
	db, err := app.openDB()
	if err != nil {
		c.Fatal(err)
	}
	app.db = db
}
