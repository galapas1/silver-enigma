package ninjapanda

import (
	"time"

	"github.com/Optm-Main/ztmesh-core/ztcfg"
)

type StateUpdateType int

const (
	SelfUpdateIdentifier                 = "self-update"
	StateFullUpdate      StateUpdateType = iota

	StatePeerChanged
	StatePeerChangedPatch
	StatePeerRemoved
	StateSelfUpdate
	StateRelayUpdated
)

type StateUpdate struct {
	Type StateUpdateType

	ChangedMachines Machines

	ChangePatches []*ztcfg.PeerChange

	Removed []ztcfg.NodeID

	RelayMap *ztcfg.RELAYMap

	Message string

	StartTime *time.Time
}

func (su *StateUpdate) Valid() bool {
	switch su.Type {
	case StatePeerChanged:
		if su.ChangedMachines == nil {
			panic(
				"Mandatory field ChangedMachines is not set on StatePeerChanged update",
			)
		}
	case StatePeerChangedPatch:
		if su.ChangePatches == nil {
			panic(
				"Mandatory field ChangePatches is not set on StatePeerChangedPatch update",
			)
		}
	case StatePeerRemoved:
		if su.Removed == nil {
			panic("Mandatory field Removed is not set on StatePeerRemove update")
		}
	case StateSelfUpdate:
		if su.ChangedMachines == nil || len(su.ChangedMachines) != 1 {
			panic(
				"Mandatory field ChangedMachines is not set for StateSelfUpdate or has more than one node",
			)
		}
	case StateRelayUpdated:
		if su.RelayMap == nil {
			panic("Mandatory field RelayMap is not set on StateRelayUpdated update")
		}
	}

	return true
}

func (su *StateUpdate) Empty() bool {
	switch su.Type {
	case StatePeerChanged:
		return len(su.ChangedMachines) == 0
	case StatePeerChangedPatch:
		return len(su.ChangePatches) == 0
	case StatePeerRemoved:
		return len(su.Removed) == 0
	}

	return false
}
