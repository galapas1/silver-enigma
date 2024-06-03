package ninjapanda

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"golang.org/x/crypto/bcrypt"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

const (
	apiPrefixLength = 7
	apiKeyLength    = 32

	ErrAPIKeyFailedToParse = Error("Failed to parse ApiKey")
)

// APIKey describes the datamodel for API keys used to remotely authenticate with
// ninjapanda.
type APIKey struct {
	ID       uint64 `gorm:"primary_key"`
	ApiKeyId string `gorm:"type:varchar(64);unique" json:"apikey_id" yaml:"apikey_id"`
	Prefix   string `gorm:"uniqueIndex"`
	Hash     []byte

	CreatedAt  *time.Time
	Expiration *time.Time
	LastSeen   *time.Time
}

// CreateAPIKey creates a new ApiKey in a namespace, and returns it.
func (np *Ninjapanda) CreateAPIKey(
	expiration *time.Time,
) (string, *APIKey, error) {
	prefix, err := GenerateRandomStringURLSafe(apiPrefixLength)
	if err != nil {
		return "", nil, err
	}

	toBeHashed, err := GenerateRandomStringURLSafe(apiKeyLength)
	if err != nil {
		return "", nil, err
	}

	// Key to return to user, this will only be visible _once_
	keyStr := prefix + "." + toBeHashed

	hash, err := bcrypt.GenerateFromPassword([]byte(toBeHashed), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, err
	}

	keyId := uuid.New().String()
	key := APIKey{
		ApiKeyId:   keyId,
		Prefix:     prefix,
		Hash:       hash,
		Expiration: expiration,
	}

	if err := np.db.Save(&key).Error; err != nil {
		return "", nil, fmt.Errorf("failed to save API key to database: %w", err)
	}

	return keyStr, &key, nil
}

// ListAPIKeys returns the list of ApiKeys for a namespace.
func (np *Ninjapanda) ListAPIKeys() ([]APIKey, error) {
	keys := []APIKey{}
	if err := np.db.Find(&keys).Error; err != nil {
		return nil, err
	}

	return keys, nil
}

// GetAPIKey returns a ApiKey for a given key.
func (np *Ninjapanda) GetAPIKey(prefix string) (*APIKey, error) {
	key := APIKey{}
	if result := np.db.First(&key, "prefix = ?", prefix); result.Error != nil {
		return nil, result.Error
	}

	return &key, nil
}

// GetAPIKeyByID returns a ApiKey for a given id.
func (np *Ninjapanda) GetAPIKeyByID(id uint64) (*APIKey, error) {
	key := APIKey{}
	if result := np.db.Find(&APIKey{ID: id}).First(&key); result.Error != nil {
		return nil, result.Error
	}

	return &key, nil
}

// DestroyAPIKey destroys a ApiKey. Returns error if the ApiKey
// does not exist.
func (np *Ninjapanda) DestroyAPIKey(key APIKey) error {
	if result := np.db.Unscoped().Delete(key); result.Error != nil {
		return result.Error
	}

	return nil
}

// ExpireAPIKey marks a ApiKey as expired.
func (np *Ninjapanda) ExpireAPIKey(key *APIKey) error {
	if err := np.db.Model(&key).Update("Expiration", time.Now().UTC()).Error; err != nil {
		return err
	}

	return nil
}

func (np *Ninjapanda) ValidateAPIKey(
	keyStr string,
) (bool, error) {
	prefix, hash, found := strings.Cut(keyStr, ".")
	if !found {
		return false, ErrAPIKeyFailedToParse
	}

	key, err := np.GetAPIKey(prefix)
	if err != nil {
		return false, fmt.Errorf("failed to validate api key: %w", err)
	}

	if key.Expiration != nil && key.Expiration.Before(time.Now().UTC()) {
		return false, nil
	}

	if err := bcrypt.CompareHashAndPassword(key.Hash, []byte(hash)); err != nil {
		return false, err
	}

	return true, nil
}

func (key *APIKey) toProto() *v1.ApiKey {
	protoKey := v1.ApiKey{
		ApikeyId: key.ApiKeyId,
		Prefix:   key.Prefix,
	}

	if key.Expiration != nil {
		t := FormatTime(key.Expiration)
		protoKey.Expiration = &t
	}

	if key.CreatedAt != nil {
		protoKey.CreatedAt = FormatTime(key.CreatedAt)
	}

	if key.LastSeen != nil {
		t := FormatTime(key.LastSeen)
		protoKey.LastSeen = &t
	}

	return &protoKey
}
