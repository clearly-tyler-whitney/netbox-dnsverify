// nsupdate.go
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

// generateNSUpdateScript generates nsupdate commands based on discrepancies.
func generateNSUpdateScript(discrepancies []Discrepancy, nsupdateFile string, logger log.Logger) error {
	if len(discrepancies) == 0 {
		level.Info(logger).Log("msg", "No discrepancies to generate nsupdate script")
		return nil
	}

	file, err := os.Create(nsupdateFile)
	if err != nil {
		return fmt.Errorf("failed to create nsupdate script file: %v", err)
	}
	defer file.Close()

	for _, d := range discrepancies {
		// Handle missing records: need to add them
		for i, missing := range d.Missing {
			// Ensure FQDN ends with a dot
			fqdn := ensureTrailingDot(d.FQDN)
			ttl := d.ExpectedTTL[i]
			addCommand := fmt.Sprintf("update add %s %d %s %s\n",
				fqdn, ttl, d.RecordType, missing)
			_, err := file.WriteString(addCommand)
			if err != nil {
				return err
			}
		}

		// Handle extra records: need to delete them
		for _, extra := range d.Extra {
			// Ensure FQDN ends with a dot
			fqdn := ensureTrailingDot(d.FQDN)
			deleteCommand := fmt.Sprintf("update delete %s %s %s\n",
				fqdn, d.RecordType, extra)
			_, err := file.WriteString(deleteCommand)
			if err != nil {
				return err
			}
		}
	}

	// Add "send" command at the end
	_, err = file.WriteString("send\n")
	if err != nil {
		return err
	}

	level.Info(logger).Log("msg", "nsupdate script generated successfully", "file", nsupdateFile)
	return nil
}

// ensureTrailingDot ensures that a domain name ends with a trailing dot.
func ensureTrailingDot(domain string) string {
	if !strings.HasSuffix(domain, ".") {
		return domain + "."
	}
	return domain
}
