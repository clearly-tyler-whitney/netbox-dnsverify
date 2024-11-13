// nsupdate.go
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

func generateNSUpdateScript(discrepancies []Discrepancy, nsupdateFile string, logger log.Logger) error {
	if len(discrepancies) == 0 {
		level.Info(logger).Log("msg", "No discrepancies found; nsupdate script not generated")
		return nil
	}

	file, err := os.Create(nsupdateFile)
	if err != nil {
		return fmt.Errorf("failed to create nsupdate file: %v", err)
	}
	defer file.Close()

	for _, d := range discrepancies {
		// Skip discrepancies without actual values
		if d.Expected == nil || d.Actual == nil {
			continue
		}

		switch d.RecordType {
		case "A", "AAAA", "CNAME", "PTR", "NS":
			expectedValues, ok := d.Expected.([]string)
			if !ok {
				continue
			}
			actualValues, ok := d.Actual.([]string)
			if !ok {
				actualValues = []string{}
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
					fmt.Fprintf(file, "update add %s %d %s %s\n", d.FQDN, 3600, d.RecordType, val)
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
			fmt.Fprintf(file, "update add %s %d SOA %s\n", d.FQDN, 3600, soaValue)

		default:
			// Handle other record types if necessary
			continue
		}
	}

	fmt.Fprintln(file, "send")
	level.Info(logger).Log("msg", "Generated nsupdate script", "file", nsupdateFile)
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
