package ninjapanda

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"

	"gorm.io/gorm"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

const (
	ErrPreAuthKeyNotFound        = Error("AuthKey not found")
	ErrPreAuthKeyExpired         = Error("AuthKey expired")
	ErrPreAuthKeyRevoked         = Error("AuthKey revoked")
	ErrPreAuthKeyHasBeenDepleted = Error("AuthKey has already been depleted")
	ErrNamespaceMismatch         = Error("namespace mismatch")
	ErrNamespaceMissing          = Error("namespace missing")
	ErrPreAuthKeyACLTagInvalid   = Error("AuthKey tag is invalid")
)

// PreAuthKey describes a pre-authorization key usable in a particular namespace.
type PreAuthKey struct {
	ID           uint64 `gorm:"primary_key"`
	PreAuthKeyId string `gorm:"type:varchar(64);unique" json:"preauthkey_id" yaml:"preauthkey_id"`
	Key          string

	NamespaceID uint
	Namespace   Namespace

	Prefix string `gorm:"type:varchar(24)"`

	ReuseCount uint64 `gorm:"default:0"`
	UsedCount  uint64 `gorm:"default:0"`

	Ephemeral bool `gorm:"default:false"`

	ACLTags []PreAuthKeyACLTag

	CreatedAt  *time.Time
	Expiration *time.Time
	RevokedAt  *time.Time
}

// PreAuthKeyACLTag describes an autmatic tag applied to a node when registered with the associated PreAuthKey.
type PreAuthKeyACLTag struct {
	ID           uint64 `gorm:"primary_key"`
	PreAuthKeyId string
	Tag          string
}

// CreatePreAuthKey creates a new PreAuthKey in a namespace, and returns it.
func (np *Ninjapanda) CreatePreAuthKey(
	namespaceName string,
	prefix string,
	reuseCount uint64,
	ephemeral bool,
	expiration *time.Time,
	aclTags []string,
) (*PreAuthKey, error) {
	namespace, err := np.GetNamespace(namespaceName)
	if err != nil {
		return nil, err
	}

	for _, tag := range aclTags {
		if !strings.HasPrefix(tag, "tag:") {
			return nil, fmt.Errorf(
				"%w: '%s' did not begin with 'tag:'",
				ErrPreAuthKeyACLTagInvalid,
				tag,
			)
		}
	}

	now := time.Now().UTC()
	kstr, err := np.generateKey(prefix)
	if err != nil {
		return nil, err
	}

	preAuthKeyId, err := uuid.NewV4()
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed not create UUID")
	}

	key := PreAuthKey{
		PreAuthKeyId: preAuthKeyId.String(),
		Key:          kstr,
		NamespaceID:  namespace.ID,
		Namespace:    *namespace,
		Prefix:       prefix,
		ReuseCount:   reuseCount,
		Ephemeral:    ephemeral,
		CreatedAt:    &now,
	}

	if expiration != nil {
		key.Expiration = expiration
	}

	err = np.db.Transaction(func(db *gorm.DB) error {
		if err := db.Save(&key).Error; err != nil {
			return fmt.Errorf("failed to create key in the database: %w", err)
		}

		if len(aclTags) > 0 {
			seenTags := map[string]bool{}

			for _, tag := range aclTags {
				if !seenTags[tag] {
					if err := db.Save(&PreAuthKeyACLTag{PreAuthKeyId: key.PreAuthKeyId, Tag: tag}).Error; err != nil {
						return fmt.Errorf(
							"failed to ceate key tag in the database: %w",
							err,
						)
					}
					seenTags[tag] = true
				}
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return &key, nil
}

// ListPreAuthKeys returns the list of PreAuthKeys for a namespace.
func (np *Ninjapanda) ListPreAuthKeys(
	namespaceName string,
) ([]PreAuthKey, error) {
	namespace, err := np.GetNamespace(namespaceName)
	if err != nil {
		return nil, err
	}

	keys := []PreAuthKey{}
	if err := np.db.Preload("Namespace").Preload("ACLTags").Where(&PreAuthKey{NamespaceID: namespace.ID}).Find(&keys).Error; err != nil {
		return nil, err
	}

	return keys, nil
}

// GetPreAuthKey returns a PreAuthKey for a given key.
func (np *Ninjapanda) GetPreAuthKey(
	namespace string,
	preAuthKeyId string,
) (*PreAuthKey, error) {
	pak, err := np.checkKeyValidityByKeyId(preAuthKeyId)
	if err != nil {
		return nil, err
	}

	if pak.Namespace.Name != namespace {
		return nil, ErrNamespaceMismatch
	}

	return pak, nil
}

// DestroyPreAuthKey destroys a preauthkey. Returns error if the PreAuthKey
// does not exist.
func (np *Ninjapanda) DestroyPreAuthKey(pak PreAuthKey) error {
	return np.db.Transaction(func(db *gorm.DB) error {
		if result := db.Unscoped().Where(PreAuthKeyACLTag{PreAuthKeyId: pak.PreAuthKeyId}).Delete(&PreAuthKeyACLTag{}); result.Error != nil {
			return result.Error
		}
		if result := db.Unscoped().Delete(pak); result.Error != nil {
			return result.Error
		}

		return nil
	})
}

// MarkExpirePreAuthKey marks a PreAuthKey as expired.
func (np *Ninjapanda) ExpirePreAuthKey(
	k *PreAuthKey,
) (*PreAuthKey, error) {
	if err := np.db.Model(&k).Update("Expiration", time.Now().UTC()).Error; err != nil {
		return nil, err
	}

	pak := PreAuthKey{}
	if result := np.db.Preload("Namespace").Preload("ACLTags").First(&pak, "pre_auth_key_id = ?", k.PreAuthKeyId); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return nil, ErrPreAuthKeyNotFound
	}

	return &pak, nil
}

// MarkRevokePreAuthKey marks a PreAuthKey as revoked.
func (np *Ninjapanda) RevokePreAuthKey(
	k *PreAuthKey,
) (*PreAuthKey, error) {
	if err := np.db.Model(&k).Update("RevokedAt", time.Now().UTC()).Error; err != nil {
		return nil, err
	}

	pak := PreAuthKey{}
	if result := np.db.Preload("Namespace").Preload("ACLTags").First(&pak, "pre_auth_key_id = ?", k.PreAuthKeyId); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return nil, ErrPreAuthKeyNotFound
	}

	return &pak, nil
}

// UsePreAuthKey marks a PreAuthKey as used.
func (np *Ninjapanda) UsePreAuthKey(k *PreAuthKey) error {
	k.UsedCount++
	if k.ReuseCount > 0 && k.UsedCount > k.ReuseCount {
		return ErrPreAuthKeyHasBeenDepleted
	}
	if err := np.db.Save(k).Error; err != nil {
		return fmt.Errorf("failed to update key used status in the database: %w", err)
	}

	return nil
}

// checkKeyValidity* does the heavy lifting for validation of the PreAuthKey coming from a node
// If returns no error and a PreAuthKey, it can be used.
func (np *Ninjapanda) checkKeyValidityByKeyId(
	preAuthKeyId string,
) (*PreAuthKey, error) {
	pak := PreAuthKey{}
	if result := np.db.Preload("Namespace").Preload("ACLTags").First(&pak, "pre_auth_key_id = ?", preAuthKeyId); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return nil, ErrPreAuthKeyNotFound
	}

	return np.checkKeyValidity(pak)
}

func (np *Ninjapanda) checkKeyValidityByAuthKey(key string) (*PreAuthKey, error) {
	pak := PreAuthKey{}
	if result := np.db.Preload("Namespace").Preload("ACLTags").First(&pak, "key = ?", key); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return nil, ErrPreAuthKeyNotFound
	}

	return np.checkKeyValidity(pak)
}

func (np *Ninjapanda) checkKeyValidity(pak PreAuthKey) (*PreAuthKey, error) {
	if pak.Namespace == (Namespace{}) || len(pak.Namespace.Name) == 0 {
		return nil, ErrNamespaceMissing
	}

	if pak.Expiration != nil && pak.Expiration.Before(time.Now().UTC()) {
		return nil, ErrPreAuthKeyExpired
	}

	if pak.RevokedAt != nil && pak.RevokedAt.Before(time.Now().UTC()) {
		return nil, ErrPreAuthKeyRevoked
	}

	if pak.ReuseCount < pak.UsedCount {
		return &pak, nil
	}

	machines := []Machine{}
	if err := np.db.Preload("AuthKey").Where(&Machine{AuthKeyID: uint(pak.ID)}).Find(&machines).Error; err != nil {
		return nil, err
	}

	// machine count should never be greater... but added for safty
	if pak.ReuseCount > 0 {
		// Keys can be depleted by either assigning to a Machine or by incrementing the UseCount.
		if pak.UsedCount >= pak.ReuseCount || uint64(len(machines)) >= pak.ReuseCount {
			return nil, ErrPreAuthKeyHasBeenDepleted
		}
	}

	return &pak, nil
}

func (np *Ninjapanda) generateKey(prefix string) (string, error) {
	size := 24
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return prefix + hex.EncodeToString(bytes), nil
}

func (key *PreAuthKey) toProto(showKey bool) *v1.PreAuthKey {
	status := "VALID"
	if key.ReuseCount > 0 && key.UsedCount >= key.ReuseCount {
		status = "DEPLETED"
	}

	protoKey := v1.PreAuthKey{
		PreAuthKeyId: key.PreAuthKeyId,
		Namespace:    key.Namespace.Name,
		Prefix:       key.Prefix,
		ReuseCount:   key.ReuseCount,
		UsedCount:    key.UsedCount,
		Ephemeral:    key.Ephemeral,
		AclTags:      make([]string, len(key.ACLTags)),
	}

	if showKey && len(key.Key) > 0 {
		protoKey.Key = &key.Key
	}

	if key.Expiration != nil {
		if key.Expiration.Before(time.Now().UTC()) {
			status = "EXPIRED"
		}
		t := FormatTime(key.Expiration)
		protoKey.Expiration = &t
	}

	if key.CreatedAt != nil {
		protoKey.CreatedAt = FormatTime(key.CreatedAt)
	}

	if key.RevokedAt != nil {
		status = "REVOKED"
		t := FormatTime(key.RevokedAt)
		protoKey.RevokedAt = &t
	}

	for idx := range key.ACLTags {
		protoKey.AclTags[idx] = key.ACLTags[idx].Tag
	}

	if value, ok := v1.PreAuthKeyStatus_value[status]; ok {
		protoKey.Status = *v1.PreAuthKeyStatus(value).Enum()
	}
	return &protoKey
}
