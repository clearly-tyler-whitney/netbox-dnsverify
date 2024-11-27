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

		header := []string{"FQDN", "Zone Name", "Type", "Expected", "Actual", "Expected TTL", "Actual TTL", "Server", "Message"}
		err := writer.Write(header)
		if err != nil {
			return err
		}

		for _, d := range discrepancies {
			expected := fmt.Sprintf("%v", d.Expected)
			actual := fmt.Sprintf("%v", d.Actual)
			record := []string{
				d.FQDN,
				d.ZoneName,
				d.RecordType,
				expected,
				actual,
				fmt.Sprintf("%d", d.ExpectedTTL),
				fmt.Sprintf("%d", d.ActualTTL),
				d.Server,
				d.Message,
			}
			err := writer.Write(record)
			if err != nil {
				return err
			}
		}
	default:
		// Default to table format
		for _, d := range discrepancies {
			fmt.Fprintf(file, "FQDN: %s\nZone Name: %s\nType: %s\nExpected: %v\nActual: %v\nExpected TTL: %d\nActual TTL: %d\nServer: %s\nMessage: %s\n\n",
				d.FQDN, d.ZoneName, d.RecordType, d.Expected, d.Actual, d.ExpectedTTL, d.ActualTTL, d.Server, d.Message)
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

		header := []string{"FQDN", "Zone Name", "Type", "Expected", "Actual", "Expected TTL", "Actual TTL", "Server", "Message"}
		err := writer.Write(header)
		if err != nil {
			return err
		}

		for _, v := range validations {
			expected := fmt.Sprintf("%v", v.Expected)
			actual := fmt.Sprintf("%v", v.Actual)
			record := []string{
				v.FQDN,
				v.ZoneName,
				v.RecordType,
				expected,
				actual,
				fmt.Sprintf("%d", v.ExpectedTTL),
				fmt.Sprintf("%d", v.ActualTTL),
				v.Server,
				v.Message,
			}
			err := writer.Write(record)
			if err != nil {
				return err
			}
		}
	default:
		// Default to table format
		for _, v := range validations {
			fmt.Fprintf(file, "FQDN: %s\nZone Name: %s\nType: %s\nExpected: %v\nActual: %v\nExpected TTL: %d\nActual TTL: %d\nServer: %s\nMessage: %s\n\n",
				v.FQDN, v.ZoneName, v.RecordType, v.Expected, v.Actual, v.ExpectedTTL, v.ActualTTL, v.Server, v.Message)
		}
	}

	return nil
}

func generateMissingRecordsReport(missingRecords []MissingRecord, reportFile string, reportFormat string, logger log.Logger) error {
	if len(missingRecords) == 0 {
		level.Info(logger).Log("msg", "No missing records to report")
		return nil
	}

	file, err := os.Create(reportFile)
	if err != nil {
		return fmt.Errorf("failed to create missing records report file: %v", err)
	}
	defer file.Close()

	switch reportFormat {
	case "json":
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		return encoder.Encode(missingRecords)
	case "csv":
		writer := csv.NewWriter(file)
		defer writer.Flush()

		header := []string{"FQDN", "Zone Name", "Type", "Value", "TTL", "Server"}
		err := writer.Write(header)
		if err != nil {
			return err
		}

		for _, m := range missingRecords {
			record := []string{
				m.FQDN,
				m.ZoneName,
				m.RecordType,
				m.Value,
				fmt.Sprintf("%d", m.TTL),
				m.Server,
			}
			err := writer.Write(record)
			if err != nil {
				return err
			}
		}
	default:
		// Default to table format
		for _, m := range missingRecords {
			fmt.Fprintf(file, "FQDN: %s\nZone Name: %s\nType: %s\nValue: %s\nTTL: %d\nServer: %s\n\n",
				m.FQDN, m.ZoneName, m.RecordType, m.Value, m.TTL, m.Server)
		}
	}

	return nil
}
