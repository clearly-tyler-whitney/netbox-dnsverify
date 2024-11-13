// validator.go
package main

import (
	"fmt"
	"strings"
	"sync"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/miekg/dns"
)

type Discrepancy struct {
	FQDN       string      `json:"FQDN"`
	RecordType string      `json:"RecordType"`
	Expected   interface{} `json:"Expected"`
	Actual     interface{} `json:"Actual"`
	Server     string      `json:"Server"`
	Message    string      `json:"Message,omitempty"`
}

type RecordKey struct {
	FQDN       string
	RecordType string
	ZoneName   string
	ViewName   string
}

func validateAllRecords(records []Record, servers []string, ignoreSerialNumbers bool, logger log.Logger, nameservers []Nameserver, zoneFilter, viewFilter string) []Discrepancy {
	var wg sync.WaitGroup
	discrepanciesChan := make(chan Discrepancy, len(records)*len(servers))

	validatedPTRs := make(map[string]bool) // Map to keep track of validated PTR record FQDNs

	// Group records by FQDN and Record Type
	expectedRecords := make(map[RecordKey][]Record)

	// Create mapping of (zone, view) to nameservers
	zoneViewToNameservers := make(map[string][]string)
	for _, ns := range nameservers {
		for _, zone := range ns.Zones {
			if zone.View != nil {
				key := fmt.Sprintf("%s|%s", zone.Name, zone.View.Name)
				zoneViewToNameservers[key] = append(zoneViewToNameservers[key], ns.Name)
			} else {
				level.Warn(logger).Log("msg", "Zone has no associated view", "zone", zone.Name)
			}
		}
	}

	for _, record := range records {
		// Skip SOA records (handled separately)
		if strings.ToUpper(record.Type) == "SOA" {
			continue
		}

		// Apply filters
		if zoneFilter != "" && record.ZoneName != zoneFilter {
			continue // Skip this record
		}
		if viewFilter != "" && record.ViewName != viewFilter {
			continue // Skip this record
		}

		key := RecordKey{
			FQDN:       record.FQDN,
			RecordType: strings.ToUpper(record.Type),
			ZoneName:   record.ZoneName,
			ViewName:   record.ViewName,
		}
		expectedRecords[key] = append(expectedRecords[key], record)

		// Collect PTR records to avoid double-handling
		if strings.ToUpper(record.Type) == "PTR" {
			ptrName := record.FQDN
			validatedPTRs[ptrName] = true
		}
	}

	for key, records := range expectedRecords {
		wg.Add(1)
		go func(key RecordKey, records []Record) {
			defer wg.Done()
			// Determine which nameservers are authoritative for this record's zone and view
			var recordServers []string
			if key.ZoneName != "" && key.ViewName != "" {
				zoneViewKey := fmt.Sprintf("%s|%s", key.ZoneName, key.ViewName)
				recordServers = zoneViewToNameservers[zoneViewKey]
				if len(recordServers) == 0 {
					// No nameservers found for this zone and view, skip validation
					level.Warn(logger).Log("msg", "No nameservers found for zone in view, skipping validation", "zone", key.ZoneName, "view", key.ViewName)
					return // Exits the goroutine
				}
			} else {
				// No zone or view information, cannot determine authoritative nameservers, skip validation
				level.Warn(logger).Log("msg", "No zone or view information for record, skipping validation", "fqdn", key.FQDN)
				return
			}

			discrepancy := validateRecordsForFQDN(key, records, recordServers, ignoreSerialNumbers, logger)
			if discrepancy != nil {
				discrepanciesChan <- *discrepancy
			}
		}(key, records)
	}

	wg.Wait()
	close(discrepanciesChan)

	var allDiscrepancies []Discrepancy
	for d := range discrepanciesChan {
		allDiscrepancies = append(allDiscrepancies, d)
	}

	return allDiscrepancies
}

func validateRecordsForFQDN(key RecordKey, records []Record, servers []string, ignoreSerialNumbers bool, logger log.Logger) *Discrepancy {
	expectedValues := []string{}

	// Prepare expected values
	for _, record := range records {
		value := record.Value

		// Handle unqualified CNAME targets
		if key.RecordType == "CNAME" && !strings.HasSuffix(value, ".") {
			zoneName := strings.TrimRight(record.ZoneName, ".")
			if zoneName != "" {
				value = value + "." + zoneName + "."
			} else {
				value = value + "."
			}
		}

		expectedValues = append(expectedValues, value)
	}

	qtype, ok := dns.StringToType[key.RecordType]
	if !ok {
		level.Error(logger).Log("msg", "Unknown record type", "type", key.RecordType)
		return &Discrepancy{
			FQDN:       key.FQDN,
			RecordType: key.RecordType,
			Expected:   expectedValues,
			Message:    "Unknown record type",
		}
	}

	for _, server := range servers {
		level.Debug(logger).Log("msg", "Validating records", "fqdn", key.FQDN, "type", key.RecordType, "expected_values", expectedValues, "server", server)
		resp, err := queryDNSWithRetry(key.FQDN, qtype, server, 3)
		if err != nil {
			level.Warn(logger).Log("msg", "DNS query error", "fqdn", key.FQDN, "server", server, "err", err)
			return &Discrepancy{
				FQDN:       key.FQDN,
				RecordType: key.RecordType,
				Expected:   expectedValues,
				Server:     server,
				Message:    fmt.Sprintf("DNS query error: %v", err),
			}
		}

		if len(resp.Answer) == 0 {
			level.Warn(logger).Log("msg", "No DNS answer", "fqdn", key.FQDN, "server", server)
			return &Discrepancy{
				FQDN:       key.FQDN,
				RecordType: key.RecordType,
				Expected:   expectedValues,
				Server:     server,
				Message:    "Record missing",
			}
		}

		actualValues := []string{}
		for _, ans := range resp.Answer {
			var val string
			switch rr := ans.(type) {
			case *dns.A:
				val = rr.A.String()
			case *dns.AAAA:
				val = rr.AAAA.String()
			case *dns.CNAME:
				val = rr.Target
			case *dns.NS:
				val = rr.Ns
			case *dns.PTR:
				val = rr.Ptr
			default:
				// Handle other record types if necessary
				continue
			}
			actualValues = append(actualValues, val)
		}

		// Compare expected and actual values (unordered)
		if !stringSlicesEqualUnordered(expectedValues, actualValues) {
			level.Warn(logger).Log("msg", "Record values mismatch", "fqdn", key.FQDN, "server", server)
			return &Discrepancy{
				FQDN:       key.FQDN,
				RecordType: key.RecordType,
				Expected:   expectedValues,
				Actual:     actualValues,
				Server:     server,
			}
		}

		level.Info(logger).Log("msg", "Records validated successfully", "fqdn", key.FQDN, "type", key.RecordType, "server", server)
	}

	return nil
}

func stringSlicesEqualUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	aMap := make(map[string]int)
	for _, val := range a {
		aMap[val]++
	}

	for _, val := range b {
		if count, exists := aMap[val]; !exists || count == 0 {
			return false
		} else {
			aMap[val]--
		}
	}

	for _, count := range aMap {
		if count != 0 {
			return false
		}
	}

	return true
}
