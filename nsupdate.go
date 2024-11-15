// nsupdate.go
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

func generateNSUpdateScripts(discrepancies []Discrepancy, nsupdatePath string, zonesByName map[string]Zone, logger log.Logger) error {
	if len(discrepancies) == 0 {
		level.Info(logger).Log("msg", "No discrepancies found; nsupdate scripts not generated")
		return nil
	}

	// Create the output directory if it doesn't exist
	err := os.MkdirAll(nsupdatePath, 0755)
	if err != nil {
		return fmt.Errorf("failed to create nsupdate directory: %v", err)
	}

	// Group discrepancies by server and then by zone
	serverZoneMap := make(map[string]map[string][]Discrepancy)

	for _, d := range discrepancies {
		if _, exists := serverZoneMap[d.Server]; !exists {
			serverZoneMap[d.Server] = make(map[string][]Discrepancy)
		}
		serverZoneMap[d.Server][d.ZoneName] = append(serverZoneMap[d.Server][d.ZoneName], d)
	}

	for server, zones := range serverZoneMap {
		filename := filepath.Join(nsupdatePath, fmt.Sprintf("nsupdate_%s", server))
		file, err := os.Create(filename)
		if err != nil {
			level.Error(logger).Log("msg", "Failed to create nsupdate file", "file", filename, "err", err)
			continue
		}

		defer file.Close()

		fmt.Fprintf(file, "server %s\n", server)
		for zoneName, zoneDiscrepancies := range zones {
			// Write server and zone instructions once per zone
			fmt.Fprintf(file, "zone %s\n", zoneName)

			for _, d := range zoneDiscrepancies {
				switch d.RecordType {
				case "A", "AAAA", "CNAME", "PTR", "NS":
					expectedValues, ok := d.Expected.([]string)
					if !ok {
						continue
					}

					actualValues := []string{}
					if d.Actual != nil {
						actualValues, ok = d.Actual.([]string)
						if !ok {
							actualValues = []string{}
						}
					}

					// Determine if this is a TTL mismatch only
					if stringSlicesEqualUnordered(expectedValues, actualValues) && d.ExpectedTTL != d.ActualTTL {
						// TTL mismatch only, need to update TTL
						for _, val := range expectedValues {
							fmt.Fprintf(file, "update delete %s %s %s\n", d.FQDN, d.RecordType, val)
							fmt.Fprintf(file, "update add %s %d %s %s\n", d.FQDN, d.ExpectedTTL, d.RecordType, val)
						}
						continue
					}

					// Delete unexpected records
					for _, val := range actualValues {
						if !stringInSlice(val, expectedValues) {
							fmt.Fprintf(file, "update delete %s %s %s\n", d.FQDN, d.RecordType, val)
						}
					}

					// Add missing records
					for _, val := range expectedValues {
						if !stringInSlice(val, actualValues) {
							fmt.Fprintf(file, "update add %s %d %s %s\n", d.FQDN, d.ExpectedTTL, d.RecordType, val)
						}
					}
				default:
					// Write 'send' once per zone
					fmt.Fprintln(file, "send")
					// Handle other record types if necessary
					continue
				}
			}
			// Write 'send' once per zone
			fmt.Fprintln(file, "send")
		}

		level.Info(logger).Log("msg", "Generated nsupdate script", "file", filename)
	}

	return nil
}
