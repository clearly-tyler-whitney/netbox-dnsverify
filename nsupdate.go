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
		level.Info(logger).Log("msg", "No discrepancies to generate nsupdate script")
		return nil
	}

	file, err := os.Create(nsupdateFile)
	if err != nil {
		return fmt.Errorf("failed to create nsupdate file: %v", err)
	}
	defer file.Close()

	for _, d := range discrepancies {
		// Only process discrepancies where action is required
		switch strings.ToUpper(d.RecordType) {
		case "A", "CNAME", "PTR", "NS", "SOA":
			// Generate appropriate nsupdate commands based on discrepancy
			// Here, we assume that discrepancies only include failed validations
			level.Debug(logger).Log("msg", "Generating nsupdate command", "fqdn", d.FQDN, "type", d.RecordType, "server", d.Server, "message", d.Message)
			nsupdateCmds := []string{
				fmt.Sprintf("update delete %s %s", d.FQDN, d.RecordType),
				fmt.Sprintf("update add %s 3600 %s %s", d.FQDN, d.RecordType, d.Expected),
			}
			for _, cmd := range nsupdateCmds {
				_, err := file.WriteString(cmd + "\n")
				if err != nil {
					return fmt.Errorf("failed to write to nsupdate file: %v", err)
				}
			}
		default:
			level.Warn(logger).Log("msg", "Unsupported record type for nsupdate script", "type", d.RecordType)
		}
	}
	return nil
}
