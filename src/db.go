package ninjapanda

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/glebarez/sqlite"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/Optm-Main/ztmesh-core/ztcfg"
)

const (
	dbVersion = "1"

	errValueNotFound     = Error("not found")
	ErrCannotParsePrefix = Error("cannot parse prefix")
)

// KV is a key-value store in a psql table. For future use...
type KV struct {
	Key   string
	Value string
}

func (np *Ninjapanda) initDB() error {
	db, err := np.openDB()
	if err != nil {
		return err
	}
	np.db = db

	if np.dbType == Postgres {
		db.Exec(`create extension if not exists "uuid-ossp";`)
	}

	err = db.AutoMigrate(&Route{})
	if err != nil {
		return err
	}

	err = db.AutoMigrate(&Machine{})
	if err != nil {
		return err
	}

	err = db.AutoMigrate(&KV{})
	if err != nil {
		return err
	}

	err = db.AutoMigrate(&Namespace{})
	if err != nil {
		return err
	}

	err = db.AutoMigrate(&PreAuthKey{})
	if err != nil {
		return err
	}

	err = db.AutoMigrate(&PreAuthKeyACLTag{})
	if err != nil {
		return err
	}

	err = db.AutoMigrate(&APIKey{})
	if err != nil {
		return err
	}

	err = db.AutoMigrate(&ACLPolicy{})
	if err != nil {
		return err
	}

	err = db.AutoMigrate(&DNSConfig{})
	if err != nil {
		return err
	}

	err = db.AutoMigrate(
		&UserProfile{},
		&UserMachine{},
	)
	if err != nil {
		return err
	}

	err = np.setValue("db_version", dbVersion)

	return err
}

func (np *Ninjapanda) openDB() (*gorm.DB, error) {
	var db *gorm.DB
	var err error

	var log logger.Interface
	if np.dbDebug {
		log = logger.Default
	} else {
		log = logger.Default.LogMode(logger.Silent)
	}

	switch np.dbType {
	case Sqlite:
		db, err = gorm.Open(
			sqlite.Open(np.dbString+"?_synchronous=1&_journal_mode=WAL"),
			&gorm.Config{
				DisableForeignKeyConstraintWhenMigrating: true,
				Logger:                                   log,
			},
		)

		db.Exec("PRAGMA foreign_keys=ON")

		// The pure Go SQLite library does not handle locking in
		// the same way as the C based one and we cant use the gorm
		// connection pool as of 2022/02/23.
		sqlDB, _ := db.DB()
		sqlDB.SetMaxIdleConns(1)
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetConnMaxIdleTime(time.Hour)

	case Postgres:
		db, err = gorm.Open(postgres.Open(np.dbString), &gorm.Config{
			DisableForeignKeyConstraintWhenMigrating: true,
			Logger:                                   log,
		})
	}

	if err != nil {
		return nil, err
	}

	return db, nil
}

// getValue returns the value for the given key in KV.
func (np *Ninjapanda) getValue(key string) (string, error) {
	var row KV
	if result := np.db.First(&row, "key = ?", key); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return "", errValueNotFound
	}

	return row.Value, nil
}

// setValue sets value for the given key in KV.
func (np *Ninjapanda) setValue(key string, value string) error {
	keyValue := KV{
		Key:   key,
		Value: value,
	}

	if _, err := np.getValue(key); err == nil {
		np.db.Model(&keyValue).Where("key = ?", key).Update("value", value)

		return nil
	}

	if err := np.db.Create(keyValue).Error; err != nil {
		return fmt.Errorf("failed to create key value pair in the database: %w", err)
	}

	return nil
}

func (np *Ninjapanda) deleteValue(key string) error {
	keyValue := KV{
		Key: key,
	}

	if err := np.db.Delete(keyValue).Error; err != nil {
		return fmt.Errorf("failed to delete key from KV table: %w", err)
	}

	return nil
}

func (np *Ninjapanda) pingDB(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	db, err := np.db.DB()
	if err != nil {
		return err
	}

	return db.PingContext(ctx)
}

// Hostinfo to allow us to add database "serialization"
// methods. This allows us to use a typed values throughout
// the code and not have to marshal/unmarshal and error
// check all over the code.
type HostInfo ztcfg.Hostinfo

func (hi *HostInfo) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case []byte:
		return json.Unmarshal(value, hi)

	case string:
		return json.Unmarshal([]byte(value), hi)

	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrMachineAddressesInvalid, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (hi HostInfo) Value() (driver.Value, error) {
	bytes, err := json.Marshal(hi)

	return string(bytes), err
}

type IPPrefix netip.Prefix

func (i *IPPrefix) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case string:
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return err
		}
		*i = IPPrefix(prefix)

		return nil
	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrCannotParsePrefix, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (i IPPrefix) Value() (driver.Value, error) {
	prefixStr := netip.Prefix(i).String()

	return prefixStr, nil
}

type IPPrefixes []netip.Prefix

func (i *IPPrefixes) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case []byte:
		return json.Unmarshal(value, i)

	case string:
		return json.Unmarshal([]byte(value), i)

	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrMachineAddressesInvalid, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (i IPPrefixes) Value() (driver.Value, error) {
	bytes, err := json.Marshal(i)

	return string(bytes), err
}

type StringList []string

func (i *StringList) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case []byte:
		return json.Unmarshal(value, i)

	case string:
		return json.Unmarshal([]byte(value), i)

	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrMachineAddressesInvalid, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (i StringList) Value() (driver.Value, error) {
	bytes, err := json.Marshal(i)

	return string(bytes), err
}
