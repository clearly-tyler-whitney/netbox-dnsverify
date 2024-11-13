// report.go
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"

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
		writer := csv.NewWriter(file)
		defer writer.Flush()

		header := []string{"FQDN", "Type", "Expected", "Actual", "Server", "Message"}
		err := writer.Write(header)
		if err != nil {
			return err
		}

		for _, d := range discrepancies {
			expected := fmt.Sprintf("%v", d.Expected)
			actual := fmt.Sprintf("%v", d.Actual)
			record := []string{d.FQDN, d.RecordType, expected, actual, d.Server, d.Message}
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

func generateSuccessfulReport(validations []ValidationRecord, reportFile string, reportFormat string, logger log.Logger) error {
	if len(validations) == 0 {
		level.Info(logger).Log("msg", "No successful validations to report")
		return nil
	}

	file, err := os.Create(reportFile)
	if err != nil {
		return fmt.Errorf("failed to create successful validations report file: %v", err)
	}
	defer file.Close()

	switch reportFormat {
	case "json":
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		return encoder.Encode(validations)
	case "csv":
		writer := csv.NewWriter(file)
		defer writer.Flush()

		header := []string{"FQDN", "Type", "Expected", "Actual", "Server", "Message"}
		err := writer.Write(header)
		if err != nil {
			return err
		}

		for _, v := range validations {
			expected := fmt.Sprintf("%v", v.Expected)
			actual := fmt.Sprintf("%v", v.Actual)
			record := []string{v.FQDN, v.RecordType, expected, actual, v.Server, v.Message}
			err := writer.Write(record)
			if err != nil {
				return err
			}
		}
	default:
		// Default to table format
		for _, v := range validations {
			fmt.Fprintf(file, "FQDN: %s\nType: %s\nExpected: %v\nActual: %v\nServer: %s\nMessage: %s\n\n",
				v.FQDN, v.RecordType, v.Expected, v.Actual, v.Server, v.Message)
		}
	}

	return nil
}
