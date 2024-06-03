package ninjapanda

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/qldbsession"
	"github.com/awslabs/amazon-qldb-driver-go/v3/qldbdriver"

	"github.com/rs/zerolog/log"
)

type NodeAudit struct {
	MachineId string `ion:"machineId"`
	NodeKey   string `ion:"nodeKey"`
}

type IvClient struct{}

func (np *Ninjapanda) initIV() (*qldbdriver.QLDBDriver, error) {
	if len(np.cfg.IVRegion) == 0 || len(np.cfg.IVLedgerName) == 0 {
		log.Warn().
			Caller().
			Msg("Not using IV to audit - missing required region + ledger name")
		return nil, nil // disabled
	}
	log.Info().Caller().
		Str(logtags.GetTag(logtags.config, "IVRegion"), np.cfg.IVRegion).
		Str(logtags.GetTag(logtags.config, "IVLedgerName"), np.cfg.IVLedgerName).
		Msg("IV driver starting")

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Could not init immutable ledger configuration")

		return nil, err
	}

	qldbSession := qldbsession.NewFromConfig(cfg, func(options *qldbsession.Options) {
		options.Region = np.cfg.IVRegion
	})
	driver, err := qldbdriver.New(
		np.cfg.IVLedgerName,
		qldbSession,
		func(options *qldbdriver.DriverOptions) {
			options.LoggerVerbosity = qldbdriver.LogInfo
		})
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Could not create immutable ledger driver")

		return nil, err
	}

	return driver, np.createIVTbls()
}

func (np *Ninjapanda) createIVTbls() error {
	if np.driver == nil {
		return nil
	}

	if np.tableExists("NodeAudit") {
		return nil
	}

	_, err := np.driver.Execute(
		context.Background(),
		func(txn qldbdriver.Transaction) (interface{}, error) {
			_, err := txn.Execute("CREATE TABLE NodeAudit")
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Msg("Could not create immutable ledger table")

				return nil, err
			}

			_, err = txn.Execute("CREATE INDEX ON NodeAudit (machineId)")
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Msg("Could not create immutable ledger index")

				return nil, err
			}

			return txn, nil
		},
	)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("immutable ledger transaction failed")
	}

	return err
}

func (np *Ninjapanda) insertIVPartial(
	machineId string,
	nodeKey string,
) {
	if np.driver == nil {
		return
	}
	_, err := np.driver.Execute(
		context.Background(),
		func(txn qldbdriver.Transaction) (interface{}, error) {
			return txn.Execute(
				"INSERT INTO NodeAudit {'machineId': '?', 'nodeKey': '?'}",
				machineId,
				nodeKey,
			)
		},
	)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Could not insert into immutable ledger")
	}
}

func (np *Ninjapanda) insertIV(
	nodeAudit NodeAudit,
) {
	if np.driver == nil {
		return
	}
	_, err := np.driver.Execute(
		context.Background(),
		func(txn qldbdriver.Transaction) (interface{}, error) {
			return txn.Execute(
				"INSERT INTO NodeAudit ?", nodeAudit,
			)
		},
	)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Could not insert into immutable ledger")
	}
}

func (np *Ninjapanda) updateIVPartial(
	machineId string,
	nodeKey string,
) {
	if np.driver == nil {
		return
	}
	_, err := np.driver.Execute(
		context.Background(),
		func(txn qldbdriver.Transaction) (interface{}, error) {
			return txn.Execute(
				"UPDATE NodeAudit SET nodeKey = ? WHERE machineId = ?",
				machineId,
				nodeKey,
			)
		},
	)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.machine, "MachineId"), machineId).
			Msg("Could not update immutable ledger")
	}
}

func (np *Ninjapanda) updateIV(
	nodeAudit NodeAudit,
) {
	if np.driver == nil {
		return
	}
	_, err := np.driver.Execute(
		context.Background(),
		func(txn qldbdriver.Transaction) (interface{}, error) {
			return txn.Execute(
				"UPDATE NodeAudit SET nodeKey = ? WHERE machineId = ?",
				nodeAudit.MachineId,
				nodeAudit.NodeKey,
			)
		},
	)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.machine, "MachineId"), nodeAudit.MachineId).
			Msg("Could not update immutable ledger")
	}
}

func (np *Ninjapanda) tableExists(tableName string) bool {
	_, err := np.driver.Execute(
		context.Background(),
		func(txn qldbdriver.Transaction) (interface{}, error) {
			result, err := txn.Execute(
				"SELECT tableId FROM information_schema.user_tables WHERE name = ?",
				tableName,
			)
			if err != nil {
				return nil, err
			}

			hasNext := result.Next(txn)
			if !hasNext && result.Err() != nil {
				return nil, result.Err()
			}
			return nil, nil
		},
	)
	if err != nil {
		return false
	}
	return true
}
