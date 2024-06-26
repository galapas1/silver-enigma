package cli

import (
	"fmt"
	"log"
	"strconv"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

func init() {
	rootCmd.AddCommand(routesCmd)
	listRoutesCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	routesCmd.AddCommand(listRoutesCmd)

	enableRouteCmd.Flags().Uint64P("route", "r", 0, "Route identifier (ID)")
	err := enableRouteCmd.MarkFlagRequired("route")
	if err != nil {
		log.Fatalf(err.Error())
	}
	routesCmd.AddCommand(enableRouteCmd)

	disableRouteCmd.Flags().Uint64P("route", "r", 0, "Route identifier (ID)")
	err = disableRouteCmd.MarkFlagRequired("route")
	if err != nil {
		log.Fatalf(err.Error())
	}
	routesCmd.AddCommand(disableRouteCmd)
}

var routesCmd = &cobra.Command{
	Use:     "routes",
	Short:   "Manage the routes of Ninjapanda",
	Aliases: []string{"r", "route"},
}

var listRoutesCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all routes",
	Aliases: []string{"ls", "show"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		machineId, err := cmd.Flags().GetString("identifier")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting machine id from flag: %s", err),
				output,
			)

			return
		}

		ctx, client, conn, cancel := getNinjapandaCLIClient()
		defer cancel()
		defer conn.Close()

		var routes []*v1.Route

		if len(machineId) == 0 {
			response, err := client.GetRoutes(ctx, &v1.GetRoutesRequest{})
			if err != nil {
				ErrorOutput(
					err,
					fmt.Sprintf("Cannot get nodes: %s", status.Convert(err).Message()),
					output,
				)

				return
			}

			if output != "" {
				SuccessOutput(response.Routes, "", output)

				return
			}

			routes = response.Routes
		} else {
			response, err := client.GetMachineRoutes(ctx, &v1.GetMachineRoutesRequest{
				MachineId: machineId,
			})
			if err != nil {
				ErrorOutput(
					err,
					fmt.Sprintf("Cannot get routes for machine %s: %s", machineId, status.Convert(err).Message()),
					output,
				)

				return
			}

			if output != "" {
				SuccessOutput(response.Routes, "", output)

				return
			}

			routes = response.Routes
		}

		tableData := routesToPtables(routes)
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error converting to table: %s", err), output)

			return
		}

		err = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Failed to render pterm table: %s", err),
				output,
			)

			return
		}
	},
}

var enableRouteCmd = &cobra.Command{
	Use:   "enable",
	Short: "Set a route as enabled",
	Long:  `This command will make as enabled a given route.`,
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		routeID, err := cmd.Flags().GetString("route")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting machine id from flag: %s", err),
				output,
			)

			return
		}

		ctx, client, conn, cancel := getNinjapandaCLIClient()
		defer cancel()
		defer conn.Close()

		response, err := client.EnableRoute(ctx, &v1.EnableRouteRequest{
			RouteId: routeID,
		})
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf(
					"Cannot enable route %s: %s",
					routeID,
					status.Convert(err).Message(),
				),
				output,
			)

			return
		}

		if output != "" {
			SuccessOutput(response, "", output)

			return
		}
	},
}

var disableRouteCmd = &cobra.Command{
	Use:   "disable",
	Short: "Set as disabled a given route",
	Long:  `This command will make as disabled a given route.`,
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		routeID, err := cmd.Flags().GetString("route")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting machine id from flag: %s", err),
				output,
			)

			return
		}

		ctx, client, conn, cancel := getNinjapandaCLIClient()
		defer cancel()
		defer conn.Close()

		response, err := client.DisableRoute(ctx, &v1.DisableRouteRequest{
			RouteId: routeID,
		})
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf(
					"Cannot enable route %s: %s",
					routeID,
					status.Convert(err).Message(),
				),
				output,
			)

			return
		}

		if output != "" {
			SuccessOutput(response, "", output)

			return
		}
	},
}

// routesToPtables converts the list of routes to a nice table.
func routesToPtables(routes []*v1.Route) pterm.TableData {
	tableData := pterm.TableData{
		{"ID", "MachineId", "Prefix", "Advertised", "Enabled", "Primary"},
	}

	for _, route := range routes {
		tableData = append(tableData,
			[]string{
				route.RouteId,
				route.MachineId,
				route.Prefix,
				strconv.FormatBool(route.Advertised),
				strconv.FormatBool(route.Enabled),
				strconv.FormatBool(route.IsPrimary),
			})
	}

	return tableData
}
