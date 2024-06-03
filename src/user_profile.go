package ninjapanda

import (
	"math"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/Optm-Main/ztmesh-core/ztcfg"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

const (
	TaggedDeviceID      = math.MaxUint32 - 1
	IncludeTaggedDevice = true
)

type UserMachine struct {
	ID uint64 `gorm:"primary_key"`

	MachineId string `gorm:"unique"`
	UserId    uint64 `gorm:"foreignKey:UserProfileID"`
}

type UserProfile struct {
	ID uint64 `gorm:"primary_key"`

	UserProfileId string `gorm:"unique"`

	FirstName string // "Alice"
	LastName  string // "Smith"

	LoginName   string // "alice@smith.com"; for display purposes only (provider is not listed)
	DisplayName string // "Alice Smith"

	UserMachines []UserMachine `gorm:"foreignKey:UserId"`

	CreatedAt time.Time
}

func (np *Ninjapanda) GetUserProfileByUserProfileId(
	userProfileId string,
) (*UserProfile, error) {
	userProfile := UserProfile{}
	if err := np.db.Preload("UserMachines").
		Where(&UserProfile{UserProfileId: userProfileId}).First(&userProfile).Error; err != nil {
		return nil, err
	}

	log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.userProfile, "UserProfileId"), userProfileId).
		Interface(logtags.GetTag(logtags.userProfile, ""), userProfile).
		Msg("returning user profile")

	return &userProfile, nil
}

func (np *Ninjapanda) GetUserProfileById(
	id uint64,
) (*UserProfile, error) {
	userProfile := UserProfile{}
	if err := np.db.Preload("UserMachines").
		Where(&UserProfile{ID: id}).First(&userProfile).Error; err != nil {
		return nil, err
	}

	log.Trace().
		Caller().
		Uint64(logtags.GetTag(logtags.userProfile, "ID"), id).
		Interface(logtags.GetTag(logtags.userProfile, ""), userProfile).
		Msg("returning user profile")

	return &userProfile, nil
}

func (np *Ninjapanda) DisassociateUserProfileByMachineId(
	machineId string,
) error {
	err := np.db.Unscoped().
		Where("machine_id = ?", machineId).
		Delete(UserMachine{}).Error
	return err
}

// Note: This does not return all machines for the user
func (np *Ninjapanda) GetUserProfileByMachineId(
	machineId string,
	showTaggedDevices bool,
) (*UserProfile, error) {
	var userProfile UserProfile
	result := np.db.
		Model(&userProfile).
		Select("user_profiles.*").
		Joins("join user_machines on user_machines.user_id = user_profiles.id").
		Where("user_machines.machine_id = ?", machineId)

	result.Statement.Scan(&userProfile)

	// If there was an error or the profile could not be found.
	err := result.Error
	if err != nil || userProfile.ID == 0 {
		if showTaggedDevices {
			log.Trace().
				Caller().
				Str(logtags.GetTag(logtags.machine, "MachineId"), machineId).
				Err(err).
				Msg("returning tagged-device profile")

			return &UserProfile{
				ID:          TaggedDeviceID,
				LoginName:   "tagged-devices",
				DisplayName: "Tagged Devices",
			}, nil
		}

		return nil, nil
	}

	log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.machine, "MachineId"), machineId).
		Interface(logtags.GetTag(logtags.userProfile, ""), userProfile).
		Msg("returning user profile")

	return &userProfile, nil
}

func (np *Ninjapanda) UpdateUserProfile(
	userProfile *UserProfile,
) (*UserProfile, error) {
	log.Debug().
		Caller().
		Interface(logtags.GetTag(logtags.userProfile, ""), userProfile).
		Msg("UpdateUserProfile called")

	if err := np.db.Save(&userProfile).Error; err != nil {
		log.Debug().
			Caller().
			Interface(logtags.GetTag(logtags.userProfile, ""), userProfile).
			Msg("machine already associated to user")
	}

	return userProfile, nil
}

func (userProfile *UserProfile) toProto() *v1.UserInfo {
	userInfoProto := &v1.UserInfo{
		UserInfoId:  userProfile.UserProfileId,
		Email:       userProfile.LoginName,
		DisplayName: userProfile.DisplayName,
		CreatedAt:   FormatTime(&userProfile.CreatedAt),
	}

	return userInfoProto
}

func (np *Ninjapanda) GetUserProfileMap(
	machines Machines,
) map[string]*UserProfile {
	userProfileMap := make(map[string]*UserProfile)
	for _, machine := range machines {
		if _, ok := userProfileMap[machine.MachineId]; !ok {
			userProfile := np.getUserProfileForMachine(machine.MachineId)
			if userProfile != nil {
				userProfileMap[machine.MachineId] = &UserProfile{
					ID:          uint64(userProfile.ID),
					LoginName:   userProfile.LoginName,
					DisplayName: userProfile.DisplayName,
					FirstName:   userProfile.FirstName,
					LastName:    userProfile.LastName,
				}
			}
		}
	}

	return userProfileMap
}

func (np *Ninjapanda) GetMapResponseUserProfiles(
	machine Machine,
	peers Machines,
) []ztcfg.UserProfile {
	profileMap := make(map[ztcfg.UserID]ztcfg.UserProfile)

	// self reference...
	userProfile := np.getUserProfileForMachine(machine.MachineId)
	if userProfile != nil {
		profileMap[userProfile.ID] = ztcfg.UserProfile{
			ID:          ztcfg.UserID(userProfile.ID),
			LoginName:   userProfile.LoginName,
			DisplayName: userProfile.DisplayName,
			FirstName:   userProfile.FirstName,
			LastName:    userProfile.LastName,
		}
	}

	for _, peer := range peers {
		userProfile := np.getUserProfileForMachine(peer.MachineId)
		if userProfile != nil {
			profileMap[userProfile.ID] = ztcfg.UserProfile{
				ID:          ztcfg.UserID(userProfile.ID),
				LoginName:   userProfile.LoginName,
				DisplayName: userProfile.DisplayName,
				FirstName:   userProfile.FirstName,
				LastName:    userProfile.LastName,
			}
		}
	}

	profiles := []ztcfg.UserProfile{}
	for _, profile := range profileMap {
		profiles = append(profiles, profile)
	}

	return profiles
}
