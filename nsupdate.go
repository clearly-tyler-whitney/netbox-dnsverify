// nsupdate.go
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

func generateNSUpdateScripts(discrepancies []Discrepancy, nsupdatePath string, logger log.Logger) error {
	if len(discrepancies) == 0 {
		level.Info(logger).Log("msg", "No discrepancies found; nsupdate scripts not generated")
		return nil
	}

	// Create the output directory if it doesn't exist
	err := os.MkdirAll(nsupdatePath, 0755)
	if err != nil {
		return fmt.Errorf("failed to create nsupdate directory: %v", err)
	}

	// Separate discrepancies into record mismatches and TTL mismatches
	recordDiscrepancies := []Discrepancy{}
	ttlDiscrepancies := []Discrepancy{}

	for _, d := range discrepancies {
		if recordsEqual(d.Expected, d.Actual) && d.ExpectedTTL != d.ActualTTL {
			ttlDiscrepancies = append(ttlDiscrepancies, d)
		} else {
			recordDiscrepancies = append(recordDiscrepancies, d)
		}
	}

	// Generate nsupdate scripts for record discrepancies
	err = generateNSUpdateScriptForDiscrepancies(recordDiscrepancies, nsupdatePath, "nsupdate_records", logger)
	if err != nil {
		return err
	}

	// Generate nsupdate scripts for TTL discrepancies
	err = generateNSUpdateScriptForDiscrepancies(ttlDiscrepancies, nsupdatePath, "nsupdate_ttls", logger)
	if err != nil {
		return err
	}

	return nil
}

func generateNSUpdateScriptForDiscrepancies(discrepancies []Discrepancy, nsupdatePath, filenamePrefix string, logger log.Logger) error {
	if len(discrepancies) == 0 {
		level.Info(logger).Log("msg", "No discrepancies found for", "type", filenamePrefix)
		return nil
	}

	serverDiscrepancies := make(map[string][]Discrepancy)

	for _, d := range discrepancies {
		serverDiscrepancies[d.Server] = append(serverDiscrepancies[d.Server], d)
	}

	for server, discrepancies := range serverDiscrepancies {
		filename := filepath.Join(nsupdatePath, fmt.Sprintf("%s_%s", filenamePrefix, server))
		file, err := os.Create(filename)
		if err != nil {
			level.Error(logger).Log("msg", "Failed to create nsupdate file", "file", filename, "err", err)
			continue
		}
		defer file.Close()

		// Write nsupdate commands for this server
		for _, d := range discrepancies {
			// Skip discrepancies without expected values
			if d.Expected == nil {
				continue
			}

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

			case "SOA":
				// For SOA records, handle accordingly
				expectedSOA, ok := d.Expected.(SOARecord)
				if !ok {
					continue
				}

				// Construct SOA record string
				soaValue := fmt.Sprintf("%s %s %d %d %d %d %d",
					expectedSOA.MName, expectedSOA.RName, expectedSOA.Serial, expectedSOA.Refresh, expectedSOA.Retry, expectedSOA.Expire, expectedSOA.Minimum)

				fmt.Fprintf(file, "update delete %s SOA\n", d.FQDN)
				fmt.Fprintf(file, "update add %s %d SOA %s\n", d.FQDN, d.ExpectedTTL, soaValue)

			default:
				// Handle other record types if necessary
				continue
			}
		}

		fmt.Fprintln(file, "send")
		level.Info(logger).Log("msg", "Generated nsupdate script", "file", filename)
	}

	return nil
}

func stringInSlice(str string, list []string) bool {
	for _, v := range list {
		if strings.EqualFold(strings.TrimSpace(v), strings.TrimSpace(str)) {
			return true
		}
	}
	return false
}

func recordsEqual(expected, actual interface{}) bool {
	switch expectedValues := expected.(type) {
	case []string:
		actualValues, ok := actual.([]string)
		if !ok {
			return false
		}
		return stringSlicesEqualUnordered(expectedValues, actualValues)
	case SOARecord:
		actualSOA, ok := actual.(SOARecord)
		if !ok {
			return false
		}
		return expectedValues == actualSOA
	default:
		return false
	}
}
