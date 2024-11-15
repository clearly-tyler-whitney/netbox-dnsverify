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

// validateAllRecords validates all DNS records except SOA records.
func validateAllRecords(
	records []Record,
	servers []string,
	ignoreSerialNumbers bool,
	logger log.Logger,
	nameservers []Nameserver,
	zoneFilter, viewFilter string,
	recordSuccessful bool,
	zonesByName map[string]Zone,
) ([]Discrepancy, []ValidationRecord) {
	var wg sync.WaitGroup
	discrepanciesChan := make(chan Discrepancy, len(records)*len(servers))
	successfulChan := make(chan ValidationRecord, len(records)*len(servers))

	// Group records by FQDN and Record Type using RecordKey
	expectedRecords := make(map[RecordKey][]Record)

	// Create a mapping of (zone, view) to nameservers
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

	// Populate expectedRecords map based on filters
	for _, record := range records {
		// Skip SOA records as they are handled separately
		if strings.ToUpper(record.Type) == "SOA" {
			continue
		}

		// Apply zone and view filters if specified
		if zoneFilter != "" && record.ZoneName != zoneFilter {
			continue
		}
		if viewFilter != "" && record.ViewName != viewFilter {
			continue
		}

		key := RecordKey{
			FQDN:       record.FQDN,
			RecordType: strings.ToUpper(record.Type),
			ZoneName:   record.ZoneName,
			ViewName:   record.ViewName,
		}
		expectedRecords[key] = append(expectedRecords[key], record)
	}

	// Iterate over each group and validate
	for key, records := range expectedRecords {
		wg.Add(1)
		go func(key RecordKey, records []Record) {
			defer wg.Done()

			// Determine authoritative nameservers for this record's zone and view
			var recordServers []string
			if key.ZoneName != "" && key.ViewName != "" {
				zoneViewKey := fmt.Sprintf("%s|%s", key.ZoneName, key.ViewName)
				recordServers = zoneViewToNameservers[zoneViewKey]
				if len(recordServers) == 0 {
					// No nameservers found for this zone and view, skip validation
					level.Warn(logger).Log("msg", "No nameservers found for zone in view, skipping validation", "zone", key.ZoneName, "view", key.ViewName)
					return
				}
			} else {
				// No zone or view information, cannot determine authoritative nameservers, skip validation
				level.Warn(logger).Log("msg", "No zone or view information for record, skipping validation", "fqdn", key.FQDN)
				return
			}

			// Validate records for this FQDN and RecordType
			discrepancies, successfulValidations := validateRecordsForFQDN(
				key,
				records,
				recordServers,
				ignoreSerialNumbers,
				logger,
				recordSuccessful,
				zonesByName,
			)

			// Send discrepancies and successful validations to channels
			for _, d := range discrepancies {
				discrepanciesChan <- d
			}
			for _, v := range successfulValidations {
				successfulChan <- v
			}
		}(key, records)
	}

	// Wait for all goroutines to finish
	wg.Wait()
	close(discrepanciesChan)
	close(successfulChan)

	// Collect all discrepancies and successful validations
	var allDiscrepancies []Discrepancy
	for d := range discrepanciesChan {
		allDiscrepancies = append(allDiscrepancies, d)
	}

	var successfulValidations []ValidationRecord
	for v := range successfulChan {
		successfulValidations = append(successfulValidations, v)
	}

	return allDiscrepancies, successfulValidations
}

// validateRecordsForFQDN validates DNS records for a specific FQDN and RecordType against the authoritative nameservers.
// It compares expected and actual DNS records, handles TTL inheritance, and returns any discrepancies found.
func validateRecordsForFQDN(
	key RecordKey,
	records []Record,
	servers []string,
	ignoreSerialNumbers bool,
	logger log.Logger,
	recordSuccessful bool,
	zonesByName map[string]Zone,
) ([]Discrepancy, []ValidationRecord) {
	expectedValues := []string{}
	expectedTTL := 0

	// Aggregate expected values and determine ExpectedTTL
	for _, record := range records {
		value := record.Value

		// Handle unqualified CNAME targets by appending the zone name
		if key.RecordType == "CNAME" && !strings.HasSuffix(value, ".") {
			zoneName := strings.TrimRight(record.ZoneName, ".")
			if zoneName != "" {
				value = value + "." + zoneName + "."
			} else {
				value = value + "."
			}
		}

		expectedValues = append(expectedValues, value)

		// Determine ExpectedTTL
		var recordTTL int
		if record.TTL != nil && *record.TTL > 0 {
			recordTTL = *record.TTL
		} else if key.RecordType == "NS" && record.Name == "@" {
			// For NS records at the zone apex, use zone's own SOA TTL
			if zone, ok := zonesByName[key.ZoneName]; ok {
				if zone.SoaTTL > 0 {
					recordTTL = zone.SoaTTL
				} else {
					recordTTL = record.ZoneDefaultTTL
				}
			} else {
				// Zone not found, fallback to zone's default TTL
				level.Warn(logger).Log("msg", "Zone not found for NS record", "zone", key.ZoneName)
				recordTTL = record.ZoneDefaultTTL
			}
		} else {
			// For other records, use zone's default TTL
			recordTTL = record.ZoneDefaultTTL
		}

		if expectedTTL == 0 {
			expectedTTL = recordTTL
		} else if expectedTTL != recordTTL {
			// Handle multiple TTLs within the same record group
			level.Warn(logger).Log("msg", "Multiple TTLs for records with same FQDN and type", "fqdn", key.FQDN)
		}
	}

	// Convert RecordType to DNS query type
	qtype, ok := dns.StringToType[key.RecordType]
	if !ok {
		level.Error(logger).Log("msg", "Unknown record type", "type", key.RecordType)
		discrepancy := Discrepancy{
			FQDN:       key.FQDN,
			RecordType: key.RecordType,
			ZoneName:   key.ZoneName,
			Expected:   expectedValues,
			Message:    "Unknown record type",
		}
		return []Discrepancy{discrepancy}, nil
	}

	var discrepancies []Discrepancy
	var successfulValidations []ValidationRecord

	// Query each authoritative nameserver
	for _, server := range servers {
		level.Debug(logger).Log(
			"msg", "Validating records",
			"fqdn", key.FQDN,
			"type", key.RecordType,
			"expected_values", expectedValues,
			"server", server,
		)
		resp, err := queryDNSWithRetry(key.FQDN, qtype, server, 3)
		if err != nil {
			if resp != nil && resp.Rcode == dns.RcodeNameError {
				// NXDOMAIN received, record is missing
				level.Warn(logger).Log("msg", "NXDOMAIN received", "fqdn", key.FQDN, "server", server)
				actualValues := []string{}
				discrepancy := Discrepancy{
					FQDN:        key.FQDN,
					RecordType:  key.RecordType,
					ZoneName:    key.ZoneName,
					Expected:    expectedValues,
					Actual:      actualValues,
					ExpectedTTL: expectedTTL,
					Server:      server,
					Message:     "Record missing (NXDOMAIN)",
				}
				discrepancies = append(discrepancies, discrepancy)
			} else {
				// Other DNS query errors
				level.Warn(logger).Log("msg", "DNS query error", "fqdn", key.FQDN, "server", server, "err", err)
				discrepancy := Discrepancy{
					FQDN:       key.FQDN,
					RecordType: key.RecordType,
					ZoneName:   key.ZoneName,
					Expected:   expectedValues,
					Server:     server,
					Message:    fmt.Sprintf("DNS query error: %v", err),
				}
				discrepancies = append(discrepancies, discrepancy)
			}
			continue
		}

		if len(resp.Answer) == 0 {
			// No answer section in DNS response
			level.Warn(logger).Log("msg", "No DNS answer", "fqdn", key.FQDN, "server", server)
			discrepancy := Discrepancy{
				FQDN:        key.FQDN,
				RecordType:  key.RecordType,
				ZoneName:    key.ZoneName,
				Expected:    expectedValues,
				Actual:      []string{},
				ExpectedTTL: expectedTTL,
				Server:      server,
				Message:     "Record missing",
			}
			discrepancies = append(discrepancies, discrepancy)
			continue
		}

		actualValues := []string{}
		actualTTL := 0
		for _, ans := range resp.Answer {
			var val string
			var ttl uint32
			ttl = ans.Header().Ttl

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

			if actualTTL == 0 {
				actualTTL = int(ttl)
			} else if actualTTL != int(ttl) {
				// Multiple TTLs found in DNS response
				level.Warn(logger).Log("msg", "Multiple TTLs in DNS response", "fqdn", key.FQDN)
			}
		}

		// Compare expected and actual values (unordered) and TTL
		ttlMismatch := expectedTTL != actualTTL
		if !stringSlicesEqualUnordered(expectedValues, actualValues) || ttlMismatch {
			level.Warn(logger).Log("msg", "Record values or TTL mismatch", "fqdn", key.FQDN, "server", server)
			discrepancy := Discrepancy{
				FQDN:        key.FQDN,
				RecordType:  key.RecordType,
				ZoneName:    key.ZoneName,
				Expected:    expectedValues,
				Actual:      actualValues,
				ExpectedTTL: expectedTTL,
				ActualTTL:   actualTTL,
				Server:      server,
			}
			discrepancies = append(discrepancies, discrepancy)
		} else {
			level.Debug(logger).Log("msg", "Records validated successfully", "fqdn", key.FQDN, "type", key.RecordType, "server", server)
			if recordSuccessful {
				validationRecord := ValidationRecord{
					FQDN:        key.FQDN,
					RecordType:  key.RecordType,
					ZoneName:    key.ZoneName,
					Expected:    expectedValues,
					Actual:      actualValues,
					ExpectedTTL: expectedTTL,
					ActualTTL:   actualTTL,
					Server:      server,
					Message:     "Record validated successfully",
				}
				successfulValidations = append(successfulValidations, validationRecord)
			}
		}
	}

	return discrepancies, successfulValidations
}
