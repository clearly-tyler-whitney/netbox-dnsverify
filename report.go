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

	switch strings.ToLower(reportFormat) {
	case "table":
		return writeTableReport(discrepancies, file)
	case "csv":
		return writeCSVReport(discrepancies, file)
	case "json":
		return writeJSONReport(discrepancies, file)
	default:
		return fmt.Errorf("unknown report format: %s", reportFormat)
	}
}

func writeTableReport(discrepancies []Discrepancy, file *os.File) error {
	header := fmt.Sprintf("%-40s %-8s %-30s %-30s %-30s %-30s\n", "FQDN", "Type", "Expected", "Actual", "Server", "Message")
	_, err := file.WriteString(header)
	if err != nil {
		return err
	}

	for _, d := range discrepancies {
		actual := strings.Join(d.Actual, ", ")
		line := fmt.Sprintf("%-40s %-8s %-30s %-30s %-30s %-30s\n",
			d.FQDN, d.RecordType, d.Expected, actual, d.Server, d.Message)
		_, err := file.WriteString(line)
		if err != nil {
			return err
		}
	}
	return nil
}

func writeCSVReport(discrepancies []Discrepancy, file *os.File) error {
	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{"FQDN", "Type", "Expected", "Actual", "Server", "Message"}
	err := writer.Write(header)
	if err != nil {
		return err
	}

	for _, d := range discrepancies {
		actual := strings.Join(d.Actual, "; ")
		record := []string{d.FQDN, d.RecordType, d.Expected, actual, d.Server, d.Message}
		err := writer.Write(record)
		if err != nil {
			return err
		}
	}
	return nil
}

func writeJSONReport(discrepancies []Discrepancy, file *os.File) error {
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(discrepancies)
}
