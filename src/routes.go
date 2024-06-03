package ninjapanda

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/rs/zerolog/log"

	"gorm.io/gorm"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

const (
	ErrRouteIsNotAvailable = Error("route is not available")
)

var (
	ExitRouteV4 = netip.MustParsePrefix("0.0.0.0/0")
	ExitRouteV6 = netip.MustParsePrefix("::/0")
)

type Route struct {
	ID uint64 `gorm:"primary_key"`

	RouteId   string `gorm:"unique" json:"route_id" yaml:"route_id"`
	MachineId string
	Prefix    IPPrefix

	Advertised bool
	Enabled    bool
	IsPrimary  bool

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time

	Machine *Machine `gorm:"-"`
}

type Routes []Route

func (r *Route) IsExitRoute() bool {
	return netip.Prefix(r.Prefix) == ExitRouteV4 ||
		netip.Prefix(r.Prefix) == ExitRouteV6
}

func (r Route) toPrefix() netip.Prefix {
	return netip.Prefix(r.Prefix)
}

func (rs Routes) toPrefixes() []netip.Prefix {
	prefixes := make([]netip.Prefix, len(rs))
	for i, r := range rs {
		prefixes[i] = netip.Prefix(r.Prefix)
	}

	return prefixes
}

func (np *Ninjapanda) GetRoutesByPrefix(prefix netip.Prefix) (Routes, error) {
	var routes Routes
	err := np.db.Where("prefix = ?", IPPrefix(prefix)).Find(&routes).Error
	if err != nil {
		return nil, err
	}

	return routes, nil
}

func (np *Ninjapanda) EnsureFailoverRouteIsAvailable(
	isConnected map[string]bool,
	machine *Machine,
) (*StateUpdate, error) {
	mRoutes, err := np.GetMachineRoutes(machine)
	if err != nil {
		return nil, err
	}

	var changedMachines Machines
	for _, mRoute := range mRoutes {
		routes, err := np.GetRoutesByPrefix(netip.Prefix(mRoute.Prefix))
		if err != nil {
			return nil, err
		}

		for _, route := range routes {
			route.Machine, err = np.GetMachineByMachineId(route.MachineId)
			if err != nil || route.Machine == nil {
				log.Error().
					Caller().
					Err(err).
					Str(logtags.GetTag(logtags.machine, "MachineId"), route.MachineId).
					Msg("failed to find machine for machineId")
				return nil, err
			}
			if route.IsPrimary {
				// if we have a primary route, and the machine is connected
				// our work is finished here...
				if isConnected[route.Machine.MachineKey] {
					continue
				}

				// if not, we need to failover the route
				update, err := np.failoverRouteReturnUpdate(isConnected, &route)
				if err != nil {
					return nil, err
				}

				if update != nil {
					changedMachines = append(changedMachines, update.ChangedMachines...)
				}
			}
		}
	}

	if len(changedMachines) != 0 {
		return &StateUpdate{
			Type:            StatePeerChanged,
			ChangedMachines: changedMachines,
			Message:         "EnsureFailoverRouteIsAvailable",
		}, nil
	}

	return nil, nil
}

func (np *Ninjapanda) failoverRouteReturnUpdate(
	isConnected map[string]bool,
	r *Route,
) (*StateUpdate, error) {
	changedKeys, err := np.failoverRoute(isConnected, r)
	if err != nil {
		return nil, err
	}

	log.Trace().
		Interface("isConnected", isConnected).
		Interface("changedKeys", changedKeys).
		Msg("building route failover")

	if len(changedKeys) == 0 {
		return nil, nil
	}

	var machines Machines
	for _, key := range changedKeys {
		machine, err := np.GetMachineByMachineKey(key)
		if err != nil {
			return nil, err
		}

		machines = append(machines, *machine)
	}

	return &StateUpdate{
		Type:            StatePeerChanged,
		ChangedMachines: machines,
		Message:         "failoverRouteReturnUpdate",
	}, nil
}

func (np *Ninjapanda) failoverRoute(
	isConnected map[string]bool,
	r *Route,
) ([]string, error) {
	if r == nil {
		return nil, nil
	}

	if !r.IsPrimary || r.IsExitRoute() {
		return nil, nil
	}

	routes, err := np.GetRoutesByPrefix(netip.Prefix(r.Prefix))
	if err != nil {
		return nil, err
	}

	var newPrimary *Route

	for indx, route := range routes {
		if r.ID == route.ID || !route.Enabled {
			continue
		}

		route.Machine, err = np.GetMachineByMachineId(route.MachineId)
		if err != nil {
			return nil, err
		}
		if isConnected[route.Machine.MachineKey] {
			newPrimary = &routes[indx]
			break
		}
	}

	if newPrimary == nil {
		return nil, nil
	}

	log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.machine, "Hostname"), newPrimary.Machine.Hostname).
		Msg("assigning new primary route")

	r.IsPrimary = false
	err = np.db.Save(&r).Error
	if err != nil {
		log.Error().Caller().Err(err).Msg("error disabling new primary route")

		return nil, err
	}

	newPrimary.IsPrimary = true
	err = np.db.Save(&newPrimary).Error
	if err != nil {
		log.Error().Err(err).Msg("error enabling new primary route")

		return nil, err
	}

	log.Trace().
		Str(logtags.GetTag(logtags.machine, "Hostname"), newPrimary.Machine.Hostname).
		Msg("set primary to new route")

	return []string{r.Machine.MachineKey, newPrimary.Machine.MachineKey}, nil
}

func (np *Ninjapanda) GetRoutes() (Routes, error) {
	var routes []Route
	err := np.db.Find(&routes).Error
	if err != nil {
		return nil, err
	}

	return routes, nil
}

func (np *Ninjapanda) GetRoutesByRouteId(
	routeIds []string,
) (Routes, error) {
	var routes Routes
	err := np.db.Where("route_id IN ?", routeIds).Find(&routes).Error
	if err != nil {
		log.Err(err).Caller().Msg("Unable to read routes")
		return nil, err
	}
	return routes, nil
}

func (np *Ninjapanda) GetMachineRoutes(
	m *Machine,
) (Routes, error) {
	var routes []Route
	err := np.db.
		Where("machine_id = ?", m.MachineId).
		Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	return routes, nil
}

func (np *Ninjapanda) GetMachineRouteByRouteId(
	routeId string,
) (*Route, error) {
	var route Route
	if err := np.db.First(&route, "route_id = ?", routeId).Error; err != nil {
		return nil, err
	}

	return &route, nil
}

func (np *Ninjapanda) UpdateMachineRoutes(routes Routes) error {
	for _, route := range routes {
		log.Trace().
			Caller().
			Interface(logtags.GetTag(logtags.route, ""), route).
			Msg("Calling update machine route")
		err := np.UpdateMachineRoute(&route)
		if err != nil {
			return err
		}
	}

	return nil
}

func (np *Ninjapanda) UpdateMachineRoute(route *Route) error {
	if route == nil || route.ID == 0 {
		return fmt.Errorf("failed to update machine route: malformed route")
	}

	if err := np.db.Save(route).Error; err != nil {
		return fmt.Errorf("failed to update machine route %v: %w", route, err)
	}

	return nil
}

func (np *Ninjapanda) DeleteMachineRoutes(machine *Machine) error {
	routes, err := np.GetMachineRoutes(machine)
	if err != nil {
		return err
	}

	for indx := range routes {
		route := &routes[indx]
		if err := np.db.Unscoped().Delete(route).Error; err != nil {
			return err
		}

		// REVIEW: What to do here??
		// np.handlePrimarySubnetFailover()
	}

	return nil
}

func (np *Ninjapanda) DeleteMachineRoute(route *Route) error {
	if err := np.db.Unscoped().Delete(&route).Error; err != nil {
		return err
	}

	return nil
}

func (np *Ninjapanda) EnableRoute(routeId string) (*StateUpdate, error) {
	route, err := np.GetMachineRouteByRouteId(routeId)
	if err != nil {
		return nil, err
	}

	machine, err := np.GetMachineByMachineId(route.MachineId)
	if err != nil {
		return nil, err
	}

	if route.IsExitRoute() {
		return np.EnableRoutes(machine, ExitRouteV4.String(), ExitRouteV6.String())
	}

	return np.EnableRoutes(machine, netip.Prefix(route.Prefix).String())
}

func (np *Ninjapanda) DisableRoute(routeId string) error {
	route, err := np.GetMachineRouteByRouteId(routeId)
	if err != nil {
		return err
	}

	route.Enabled = false
	route.IsPrimary = false
	if err = np.db.Save(route).Error; err != nil {
		return err
	}

	return np.handlePrimarySubnetFailover()
}

// isUniquePrefix returns if there is another machine providing the same route already.
func (np *Ninjapanda) isUniquePrefix(route Route) bool {
	var count int64
	np.db.
		Model(&Route{}).
		Where("prefix = ? AND machine_id != ? AND advertised = ? AND enabled = ?",
			route.Prefix,
			route.MachineId,
			true, true).Count(&count)

	return count == 0
}

// REVIEW: need machine_id?
func (np *Ninjapanda) getPrimaryRoute(prefix netip.Prefix) (*Route, error) {
	var route Route
	err := np.db.
		Where(
			"prefix = ? AND advertised = ? AND enabled = ? AND is_primary = ?",
			IPPrefix(prefix),
			true,
			true,
			true,
		).
		First(&route).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, gorm.ErrRecordNotFound
	}

	return &route, nil
}

// getMachinePrimaryRoutes returns the routes that are enabled and marked as primary
// (for subnet failover)
//
// Exit nodes are not considered for this, as they are never marked as Primary.
func (np *Ninjapanda) getMachinePrimaryRoutes(m *Machine) (Routes, error) {
	var routes []Route
	err := np.db.
		Where(
			"machine_id = ? AND advertised = ? AND enabled = ? AND is_primary = ?",
			m.MachineId,
			true,
			true,
			true,
		).
		Find(&routes).Error
	if err != nil {
		return nil, err
	}

	return routes, nil
}

func (np *Ninjapanda) CreateMachineRoutes(routes Routes) error {
	for _, route := range routes {
		if err := np.db.Save(&route).Error; err != nil {
			return err
		}
	}

	return nil
}

func (np *Ninjapanda) ProcessMachineRoutes(
	machine *Machine,
) (bool, error) {
	updated := false

	currentRoutes := []Route{}
	err := np.db.Where("machine_id = ?", machine.MachineId).Find(&currentRoutes).Error
	if err != nil {
		return updated, err
	}

	advertisedRoutes := map[netip.Prefix]bool{}
	for _, prefix := range machine.HostInfo.RoutableIPs {
		advertisedRoutes[prefix] = false
	}

	for indx, route := range currentRoutes {
		if _, ok := advertisedRoutes[netip.Prefix(route.Prefix)]; ok {
			if !route.Advertised {
				currentRoutes[indx].Advertised = true
				if err := np.db.Save(&currentRoutes[indx]).Error; err != nil {
					return updated, err
				}

				if route.Enabled {
					updated = true
				}
			}
			advertisedRoutes[netip.Prefix(route.Prefix)] = true
		} else if route.Advertised {
			currentRoutes[indx].Advertised = false
			currentRoutes[indx].Enabled = false
			if err := np.db.Save(&currentRoutes[indx]).Error; err != nil {
				return updated, err
			}
		}
	}

	for prefix, exists := range advertisedRoutes {
		if !exists {
			route := Route{
				MachineId:  machine.MachineId,
				Prefix:     IPPrefix(prefix),
				Advertised: true,
				Enabled:    false,
			}
			log.Debug().
				Caller().
				Interface(logtags.GetTag(logtags.route, ""), route).
				Str(logtags.GetTag(logtags.machine, "MachineId"), machine.MachineId).
				Msg("machine is advertising a route not mananged by ninjapanda")
		}
	}

	return updated, nil
}

func (np *Ninjapanda) handlePrimarySubnetFailover() error {
	// first, get all the enabled routes
	var routes []Route
	err := np.db.
		Where("advertised = ? AND enabled = ?", true, true).
		Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error().Caller().Err(err).Msg("error getting routes")
	}

	routesChanged := false
	for indx, route := range routes {
		if route.IsExitRoute() {
			continue
		}

		if !route.IsPrimary {
			_, err := np.getPrimaryRoute(netip.Prefix(route.Prefix))
			if np.isUniquePrefix(route) || errors.Is(err, gorm.ErrRecordNotFound) {
				log.Info().
					Str(logtags.GetTag(logtags.route, "Prefix"), netip.Prefix(route.Prefix).String()).
					Str(logtags.GetTag(logtags.route, "MachineId"), route.MachineId).
					Msg("Setting primary route")
				routes[indx].IsPrimary = true
				if err := np.db.Save(&routes[indx]).Error; err != nil {
					log.Error().Caller().Err(err).Msg("error marking route as primary")

					return err
				}

				routesChanged = true

				continue
			}
		}

		if route.IsPrimary {
			machine, err := np.GetMachineByMachineId(route.MachineId)
			if err != nil {
				log.Trace().
					Caller().
					Str(logtags.GetTag(logtags.route, "MachineId"), route.MachineId).
					Msg("failed to find machine")
				continue // REVIEW: when does this happen?
			}
			if machine.isOnline() {
				continue
			}

			// find a new primary route
			var newPrimaryRoutes []Route
			err = np.db.
				Where(
					"prefix = ? AND machine_id != ? AND advertised = ? AND enabled = ?",
					route.Prefix,
					route.MachineId,
					true,
					true,
				).
				Find(&newPrimaryRoutes).Error
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				log.Error().Err(err).Msg("error finding new primary route")

				return err
			}

			var newPrimaryRoute *Route
			for indx, r := range newPrimaryRoutes {
				m, err := np.GetMachineByMachineId(r.MachineId)
				if err != nil {
					return err
				}

				if m.isOnline() {
					newPrimaryRoute = &newPrimaryRoutes[indx]

					break
				}
			}

			if newPrimaryRoute == nil {
				continue
			}

			log.Info().
				Str("old_"+logtags.GetTag(logtags.machine, "MachineId"), machine.MachineId).
				Str(logtags.GetTag(logtags.route, "Prefix"), netip.Prefix(route.Prefix).String()).
				Str("new_"+logtags.GetTag(logtags.machine, "MachineId"), newPrimaryRoute.MachineId).
				Msgf("found new primary route")

			// disable the old primary route
			routes[indx].IsPrimary = false
			if err := np.db.Save(&routes[indx]).Error; err != nil {
				log.Error().Caller().Err(err).Msg("error disabling old primary route")

				return err
			}

			// enable the new primary route
			newPrimaryRoute.IsPrimary = true
			if err := np.db.Save(&newPrimaryRoute).Error; err != nil {
				log.Error().Caller().Err(err).Msg("error enabling new primary route")

				return err
			}

			routesChanged = true
		}
	}

	if routesChanged {
		// TODO: need StateUpdate
	}

	return nil
}

func (rs Routes) toProto() []*v1.Route {
	protoRoutes := []*v1.Route{}

	for _, route := range rs {
		protoRoute := v1.Route{
			RouteId:    route.RouteId,
			MachineId:  route.MachineId,
			Prefix:     netip.Prefix(route.Prefix).String(),
			Advertised: route.Advertised,
			Enabled:    route.Enabled,
			IsPrimary:  route.IsPrimary,
			CreatedAt:  FormatTime(&route.CreatedAt),
			UpdatedAt:  FormatTime(&route.UpdatedAt),
		}

		if route.DeletedAt != nil {
			d := FormatTime(route.DeletedAt)
			protoRoute.DeletedAt = &d
		}

		protoRoutes = append(protoRoutes, &protoRoute)
	}

	return protoRoutes
}
