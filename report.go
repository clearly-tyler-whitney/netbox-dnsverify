// report.go
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

func generateReport(discrepancies []Discrepancy, reportFile string, reportFormat string, logger log.Logger) error {
	if len(discrepancies) == 0 {
		level.Info(logger).Log("msg", "No discrepancies found")
		return nil
	}

	file, err := os.Create(reportFile)
	if err != nil {
		return fmt.Errorf("failed to create report file: %v", err)
	}
	defer file.Close()

	switch reportFormat {
	case "json":
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		return encoder.Encode(discrepancies)
	case "csv":
		// Adjust CSV generation to handle interface{} types
		writer := csv.NewWriter(file)
		defer writer.Flush()

		header := []string{"FQDN", "Type", "Expected", "Actual", "Server", "Message"}
		err := writer.Write(header)
		if err != nil {
			return err
		}

		for _, d := range discrepancies {
			expectedStr := stringifyExpectedActual(d.Expected)
			actualStr := stringifyExpectedActual(d.Actual)
			record := []string{d.FQDN, d.RecordType, expectedStr, actualStr, d.Server, d.Message}
			err := writer.Write(record)
			if err != nil {
				return err
			}
		}
	default:
		// Default to table format
		for _, d := range discrepancies {
			fmt.Fprintf(file, "FQDN: %s\nType: %s\nExpected: %v\nActual: %v\nServer: %s\nMessage: %s\n\n",
				d.FQDN, d.RecordType, d.Expected, d.Actual, d.Server, d.Message)
		}
	}

	return nil
}

func stringifyExpectedActual(value interface{}) string {
	switch v := value.(type) {
	case []string:
		return strings.Join(v, ", ")
	case SOARecord:
		return fmt.Sprintf("%+v", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}
