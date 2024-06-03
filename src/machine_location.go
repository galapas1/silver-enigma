package ninjapanda

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/netip"
	"reflect"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/Optm-Main/ztmesh-core/ztcfg"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

// Stores the geographic location of a machine endpoint
type MachineLocation struct {
	City       string  `json:"city"`
	Region     string  `json:"region"`
	RegionCode string  `json:"region_code"`
	Country    string  `json:"country_name"`
	Lat        float64 `json:"latitude"`
	Lon        float64 `json:"longitude"`
}

// Alternative:
// see: https://ipapi.co/132.147.145.56/json
type IPAPI struct {
	IP                 string  `json:"ip"`
	Network            string  `json:"network"`
	Version            string  `json:"version"`
	City               string  `json:"city"`
	Region             string  `json:"region"`
	RegionCode         string  `json:"region_code"`
	Country            string  `json:"country"`
	CountryName        string  `json:"country_name"`
	CountryCode        string  `json:"country_code"`
	CountryCodeISO3    string  `json:"country_code_iso3"`
	CountryCapital     string  `json:"country_capital"`
	CountryTLD         string  `json:"country_tld"`
	ContinentCode      string  `json:"continent_code"`
	InEU               string  `json:"in_eu"`
	Postal             string  `json:"postal"`
	Latitude           float64 `json:"latitude"`
	Longitude          float64 `json:"longitude"`
	Timezone           string  `json:"timezone"`
	UTCOffset          string  `json:"utc_offset"`
	CountryCallingCode string  `json:"country_calling_code"`
	Currency           string  `json:"currency"`
	CurrencyName       string  `json:"currency_name"`
	Languages          string  `json:"languages"`
	CountryArea        string  `json:"country_area"`
	CountryPopulation  string  `json:"country_population"`
	ASN                string  `json:"asn"`
	ORG                string  `json:"org"`
}

// "ipinfo.io/66.229.222.168?token=fb45f6c1effd6e"
type IPInfo struct {
	IP         string `json:"ip"`
	Hostname   string `json:"hostname"`
	City       string `json:"city"`
	Region     string `json:"region"`
	RegionCode string
	Country    string `json:"country"`
	Loc        string `json:"loc"`
	ORG        string `json:"org"`
	Postal     string `json:"postal"`
	Timezone   string `json:"timezone"`
	Latitude   float64
	Longitude  float64
}

func (i *MachineLocation) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case []byte:
		return json.Unmarshal(value, i)

	case string:
		return json.Unmarshal([]byte(value), i)

	default:
		return fmt.Errorf("MachineLocation Scan: unexpected data type %T", destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (i MachineLocation) Value() (driver.Value, error) {
	bytes, err := json.Marshal(i)
	return string(bytes), err
}

// Returns the location corresponding to an ip address
// TODO: add cache
func (machine *Machine) GetLocation(
	stunIP string,
	geocodingEnabled bool,
) (bool, error) {
	updateApplied := false

	ipAddr, err := netip.ParseAddrPort(stunIP)
	if err != nil {
		return updateApplied, fmt.Errorf("Could not parse STUN IP: %s", stunIP)
	}

	// if location has already been resolved and the
	// STUN IP is unchanged, assume there has been no
	// location update
	if len(machine.MachineLocation.City) > 0 {
		for _, e := range machine.Endpoints {
			if e == stunIP {
				log.Debug().
					Caller().
					Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
					Msgf("STUN IP of machine unchanged, not updating location")

				return updateApplied, nil
			}
		}
	}

	loc := IPInfo{
		City:       "San Francisco",
		Region:     "California",
		RegionCode: "",
		Country:    "US",
		Latitude:   37.7509,
		Longitude:  -122.4153,
	}
	if geocodingEnabled {
		url := fmt.Sprintf(
			"https://ipinfo.io/%s?token=fb45f6c1effd6e",
			ipAddr.Addr().String(),
		)

		response, err := http.Get(url)
		if err != nil {
			return updateApplied, fmt.Errorf("Error accessing URL %s: %v", url, err)
		}

		responseData, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return updateApplied, fmt.Errorf("Error reading response body: %v", err)
		}
		defer response.Body.Close()

		log.Trace().
			Caller().
			Int(logtags.GetTag(logtags.httpResponse, "StatusCode"), response.StatusCode).
			Str(logtags.MakeTag("StatusText"), http.StatusText(response.StatusCode)).
			Str(logtags.GetTag(logtags.httpResponse, "Body"), string(responseData)).
			Str(logtags.GetTag(logtags.url, ""), url).
			Msg("GetLocation http.Get response status")

		err = json.Unmarshal(responseData, &loc)
		if err != nil {
			return updateApplied, fmt.Errorf("Error parsing JSON data: %v", err)
		}

		if len(loc.City) == 0 {
			return updateApplied, fmt.Errorf("Empty location returned")
		}

		if reflect.TypeOf(loc) == reflect.TypeOf(IPInfo{}) {
			if len(loc.Loc) > 0 {
				coords := strings.Split(loc.Loc, ",")
				if len(coords) > 1 {
					loc.Latitude, _ = strconv.ParseFloat(coords[0], BitSize64)
					loc.Longitude, _ = strconv.ParseFloat(coords[1], BitSize64)

					updateApplied = true
				}
			}
		}
	}
	log.Trace().
		Caller().
		Interface(logtags.GetTag(logtags.machineLocation, ""), loc).
		Msg("http.Get results")

	machine.MachineLocation = MachineLocation{
		City:       loc.City,
		Region:     loc.Region,
		RegionCode: loc.RegionCode,
		Country:    loc.Country,
		Lat:        loc.Latitude,
		Lon:        loc.Longitude,
	}

	return updateApplied, nil
}

func (np *Ninjapanda) UpdateLocation(
	mapRequest ztcfg.MapRequest,
	machine *Machine,
) {
	stunEndpointFound := false
	for indx, endPtType := range mapRequest.EndpointTypes {
		if !stunEndpointFound &&
			endPtType == ztcfg.EndpointSTUN {
			stunEndpointFound = true
			updateApplied, err := machine.GetLocation(
				mapRequest.Endpoints[indx],
				np.cfg.GeocodingEnabled,
			)
			if err != nil {
				log.Warn().
					Caller().
					Err(err).
					Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
					Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
					Msg("Get machine location response")
			} else if updateApplied {
				if err := np.db.Save(machine).Error; err != nil {
					log.Error().
						Caller().
						Err(err).
						Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
						Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
						Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
						Msg("failed to update machine location")
				}
			}
		}
	}
	if !stunEndpointFound {
		log.Warn().
			Caller().
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
			Msg("Machine has no STUN endpoint, location not resolved")
	}
}

func (loc *MachineLocation) toProto() *v1.MachineLocation {
	locProto := &v1.MachineLocation{
		City:       loc.City,
		Region:     loc.Region,
		RegionCode: loc.RegionCode,
		Country:    loc.Country,
		Latitude:   loc.Lat,
		Longitude:  loc.Lon,
	}

	return locProto
}
