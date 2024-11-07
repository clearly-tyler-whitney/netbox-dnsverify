// report.go
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

// generateReport generates a discrepancy and success report in JSON format.
func generateReport(discrepancies []Discrepancy, successes []Success, reportFile string, reportFormat string, logger log.Logger) error {
	if reportFormat != "json" {
		level.Warn(logger).Log("msg", "Only JSON format is supported at the moment. Ignoring other formats.")
		reportFormat = "json"
	}

	if len(discrepancies) == 0 && len(successes) == 0 {
		level.Info(logger).Log("msg", "No discrepancies or successes to report")
		return nil
	}

	file, err := os.Create(reportFile)
	if err != nil {
		return fmt.Errorf("failed to create report file: %v", err)
	}
	defer file.Close()

	report := Report{
		Discrepancies: discrepancies,
		Successes:     successes,
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(report)
	if err != nil {
		return fmt.Errorf("failed to encode report to JSON: %v", err)
	}

	level.Info(logger).Log("msg", "JSON report generated successfully", "file", reportFile)
	return nil
}
