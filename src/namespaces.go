package ninjapanda

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"google.golang.org/protobuf/types/known/durationpb"

	"gorm.io/gorm"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

const (
	ErrNamespaceExists          = Error("Namespace already exists")
	ErrNamespaceNotFound        = Error("Namespace not found")
	ErrNamespaceNotEmptyOfNodes = Error("Namespace not empty: node(s) found")
	ErrInvalidNamespaceName     = Error("Invalid namespace name")
	ErrNamespaceMembersExceeded = Error("Namespace members exceeded")
)

const (
	// value related to RFC 1123 and 952.
	labelHostnameLength = 63
)

var invalidCharsInNamespaceRegex = regexp.MustCompile("[^a-z0-9-.]+")

// Namespace is the way Ninjapanda implements the concept of users
//
// At the end of the day, users are some kind of 'bubbles' or namespaces
// that contain our machines.
type Namespace struct {
	ID uint `gorm:"primary_key"`

	Name       string `gorm:"unique"`
	ExternalId string

	DefaultMachineKeyTtl time.Duration

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// CreateNamespace creates a new Namespace. Returns error if could not be created
// or another namespace already exists.
func (np *Ninjapanda) CreateNamespace(
	name string,
) (*Namespace, error) {
	err := CheckForFQDNRules(name)
	if err != nil {
		return nil, err
	}
	namespace := Namespace{}
	if err := np.db.Where("name = ?", name).First(&namespace).Error; err == nil {
		return nil, ErrNamespaceExists
	}
	namespace.Name = name
	if err := np.db.Create(&namespace).Error; err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Could not create row")

		return nil, err
	}

	return &namespace, nil
}

// DestroyNamespace destroys a Namespace. Returns error if the Namespace does
// not exist or if there are machines associated with it.
func (np *Ninjapanda) DestroyNamespace(name string) error {
	namespace, err := np.GetNamespace(name)
	if err != nil {
		return ErrNamespaceNotFound
	}

	machines, err := np.ListMachinesInNamespace(name)
	if err != nil {
		return err
	}
	if len(machines) > 0 {
		return ErrNamespaceNotEmptyOfNodes
	}

	keys, err := np.ListPreAuthKeys(name)
	if err != nil {
		return err
	}
	for _, key := range keys {
		err = np.DestroyPreAuthKey(key)
		if err != nil {
			return err
		}
	}

	if result := np.db.Unscoped().Delete(&namespace); result.Error != nil {
		return result.Error
	}

	return nil
}

// RenameNamespace renames a Namespace. Returns error if the Namespace does
// not exist or if another Namespace exists with the new name.
func (np *Ninjapanda) RenameNamespace(
	oldName, newName string,
) error {
	var err error
	oldNamespace, err := np.GetNamespace(oldName)
	if err != nil {
		return err
	}
	err = CheckForFQDNRules(newName)
	if err != nil {
		return err
	}
	_, err = np.GetNamespace(newName)
	if err == nil {
		return ErrNamespaceExists
	}
	if !errors.Is(err, ErrNamespaceNotFound) {
		return err
	}

	oldNamespace.Name = newName

	if result := np.db.Save(&oldNamespace); result.Error != nil {
		return result.Error
	}

	return nil
}

// RefreshNamespace updates the namespace entry in the DB
func (np *Ninjapanda) RefreshNamespace(
	namespace *Namespace,
) error {
	if err := np.db.Save(namespace).Error; err != nil {
		return fmt.Errorf(
			"failed to refresh namesspace in the database: %w",
			err,
		)
	}

	return nil
}

// GetNamespace fetches a namespace by name.
func (np *Ninjapanda) GetNamespace(
	name string,
) (*Namespace, error) {
	namespace := Namespace{}
	if result := np.db.First(&namespace, "name = ?", name); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return nil, ErrNamespaceNotFound
	}

	return &namespace, nil
}

// GetNamespaceByID fetches a namespace by ID.
func (np *Ninjapanda) GetNamespaceByID(
	id uint64,
) (*Namespace, error) {
	namespace := Namespace{}
	if result := np.db.First(&namespace, id); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return nil, ErrNamespaceNotFound
	}

	return &namespace, nil
}

// ListNamespaces gets all the existing namespaces.
func (np *Ninjapanda) ListNamespaces() ([]Namespace, error) {
	namespaces := []Namespace{}
	if err := np.db.Find(&namespaces).Error; err != nil {
		return nil, err
	}

	return namespaces, nil
}

// ListMachinesInNamespace gets all the nodes in a given namespace.
func (np *Ninjapanda) ListMachinesInNamespace(
	name string,
) ([]Machine, error) {
	err := CheckForFQDNRules(name)
	if err != nil {
		return nil, err
	}
	namespace, err := np.GetNamespace(name)
	if err != nil {
		return nil, err
	}

	machines := []Machine{}
	if err := np.db.Preload("AuthKey").
		Preload("AuthKey.Namespace").
		Preload("Namespace").Where(&Machine{NamespaceID: namespace.ID}).Find(&machines).Error; err != nil {
		return nil, err
	}

	return machines, nil
}

// SetMachineNamespace assigns a Machine to a namespace.
func (np *Ninjapanda) SetMachineNamespace(
	machine *Machine,
	namespaceName string,
) error {
	if len(machine.NodeKey) == 0 {
		return fmt.Errorf("Machine nodekey has length 0")
	}

	err := CheckForFQDNRules(namespaceName)
	if err != nil {
		return err
	}
	namespace, err := np.GetNamespace(namespaceName)
	if err != nil {
		return err
	}

	machine.Namespace = *namespace
	if result := np.db.Save(&machine); result.Error != nil {
		return result.Error
	}

	return nil
}

func (n *Namespace) toProto() *v1.Namespace {
	return &v1.Namespace{
		Name:                 n.Name,
		ExternalId:           n.ExternalId,
		CreatedAt:            FormatTime(&n.CreatedAt),
		DefaultMachineKeyTtl: durationpb.New(n.DefaultMachineKeyTtl),
	}
}

// NormalizeToFQDNRules will replace forbidden chars in namespace
// it can also return an error if the namespace doesn't respect RFC 952 and 1123.
func NormalizeToFQDNRules(name string, stripEmailDomain bool) (string, error) {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "'", "")
	atIdx := strings.Index(name, "@")
	if stripEmailDomain && atIdx > 0 {
		name = name[:atIdx]
	} else {
		name = strings.ReplaceAll(name, "@", ".")
	}
	name = invalidCharsInNamespaceRegex.ReplaceAllString(name, "-")

	for _, elt := range strings.Split(name, ".") {
		if len(elt) > labelHostnameLength {
			return "", fmt.Errorf(
				"label %v is more than 63 chars: %w",
				elt,
				ErrInvalidNamespaceName,
			)
		}
	}

	return name, nil
}

func CheckForFQDNRules(name string) error {
	if len(name) > labelHostnameLength {
		return fmt.Errorf(
			"DNS segment must not be over 63 chars. %v doesn't comply with this rule: %w",
			name,
			ErrInvalidNamespaceName,
		)
	}
	if strings.ToLower(name) != name {
		return fmt.Errorf(
			"DNS segment should be lowercase. %v doesn't comply with this rule: %w",
			name,
			ErrInvalidNamespaceName,
		)
	}
	if invalidCharsInNamespaceRegex.MatchString(name) {
		return fmt.Errorf(
			"DNS segment should only be composed of lowercase ASCII letters numbers, hyphen and dots. %v doesn't comply with theses rules: %w",
			name,
			ErrInvalidNamespaceName,
		)
	}

	return nil
}

func CheckForHostnameRules(name string) error {
	if len(name) > labelHostnameLength {
		return fmt.Errorf(
			"DNS segment must not be over 63 chars. %v doesn't comply with this rule: %w",
			name,
			ErrInvalidNamespaceName,
		)
	}
	return nil
}
