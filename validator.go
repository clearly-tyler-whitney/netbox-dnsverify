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
	FQDN       string
	RecordType string
	Expected   string
	Actual     []string
	Server     string
	Message    string
}

func validateAllRecords(records []Record, servers []string, ignoreSerialNumbers bool, logger log.Logger, nameservers []Nameserver, zoneFilter, viewFilter string) []Discrepancy {
	var wg sync.WaitGroup
	discrepanciesChan := make(chan []Discrepancy, len(records)*len(servers)*2) // Adjusted buffer size

	validatedPTRs := make(map[string]bool) // Map to keep track of validated PTR record FQDNs

	// First, collect all PTR records to avoid double-handling
	for _, record := range records {
		if strings.ToUpper(record.Type) == "PTR" {
			ptrName := record.FQDN
			validatedPTRs[ptrName] = true
		}
	}

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
		// Apply filters
		if zoneFilter != "" && record.ZoneName != zoneFilter {
			continue // Skip this record
		}
		if viewFilter != "" && record.ViewName != viewFilter {
			continue // Skip this record
		}

		wg.Add(1)
		go func(rec Record) {
			defer wg.Done()
			// Determine which nameservers are authoritative for this record's zone and view
			var recordServers []string
			if rec.ZoneName != "" && rec.ViewName != "" {
				key := fmt.Sprintf("%s|%s", rec.ZoneName, rec.ViewName)
				recordServers = zoneViewToNameservers[key]
				if len(recordServers) == 0 {
					// If no specific nameservers found for the zone and view, use all servers
					recordServers = servers
					level.Warn(logger).Log("msg", "No nameservers found for zone in view", "zone", rec.ZoneName, "view", rec.ViewName, "using all servers")
				}
			} else {
				// If no zone or view information, use all servers
				recordServers = servers
				level.Warn(logger).Log("msg", "No zone or view information for record", "fqdn", rec.FQDN, "using all servers")
			}

			discrepancies := validateRecord(rec, recordServers, ignoreSerialNumbers, logger)
			if len(discrepancies) > 0 {
				discrepanciesChan <- discrepancies
			}
			// Validate PTR if applicable
			if strings.ToUpper(rec.Type) == "A" && !rec.DisablePTR {
				var expectedFQDN string
				if rec.PTRRecord != nil && rec.PTRRecord.Value != "" {
					expectedFQDN = rec.PTRRecord.Value
				} else {
					expectedFQDN = rec.FQDN
				}
				ptrName, err := dns.ReverseAddr(rec.Value)
				if err != nil {
					level.Error(logger).Log("msg", "Invalid IP address", "ip", rec.Value, "err", err)
				} else {
					if !validatedPTRs[ptrName] {
						validatedPTRs[ptrName] = true
						ptrDiscrepancies := validatePTRRecord(rec.Value, expectedFQDN, recordServers, logger)
						if len(ptrDiscrepancies) > 0 {
							discrepanciesChan <- ptrDiscrepancies
						}
					} else {
						level.Debug(logger).Log("msg", "Skipping PTR validation; already validated", "ptr_name", ptrName)
					}
				}
			}
		}(record)
	}

	wg.Wait()
	close(discrepanciesChan)

	var allDiscrepancies []Discrepancy
	for d := range discrepanciesChan {
		allDiscrepancies = append(allDiscrepancies, d...)
	}

	return allDiscrepancies
}

func validateRecord(record Record, servers []string, ignoreSerialNumbers bool, logger log.Logger) []Discrepancy {
	var discrepancies []Discrepancy
	expectedValue := record.Value

	qtype, ok := dns.StringToType[strings.ToUpper(record.Type)]
	if !ok {
		level.Error(logger).Log("msg", "Unknown record type", "type", record.Type)
		return discrepancies
	}

	// Handle CNAME targets that are not fully qualified
	if strings.ToUpper(record.Type) == "CNAME" && !strings.HasSuffix(expectedValue, ".") {
		// Trim any trailing dots
		expectedValue = strings.TrimRight(expectedValue, ".")
		zoneName := strings.TrimRight(record.ZoneName, ".")
		if zoneName != "" {
			// Append the zone suffix to the CNAME target
			expectedValue = expectedValue + "." + zoneName + "."
		} else {
			// If ZoneName is empty, log a warning and skip concatenation
			level.Warn(logger).Log("msg", "ZoneName is empty for CNAME record", "record_id", record.ID)
			// Assume root zone
			expectedValue = expectedValue + "."
		}
	}

	for _, server := range servers {
		level.Debug(logger).Log("msg", "Validating record", "fqdn", record.FQDN, "type", record.Type, "expected_value", expectedValue, "server", server)
		resp, err := queryDNSWithRetry(record.FQDN, qtype, server, 3)
		if err != nil {
			level.Warn(logger).Log("msg", "DNS query error", "fqdn", record.FQDN, "server", server, "err", err)
			discrepancies = append(discrepancies, Discrepancy{
				FQDN:       record.FQDN,
				RecordType: record.Type,
				Expected:   expectedValue,
				Server:     server,
				Message:    fmt.Sprintf("DNS query error: %v", err),
			})
			continue
		}
		if len(resp.Answer) == 0 {
			level.Warn(logger).Log("msg", "No DNS answer", "fqdn", record.FQDN, "server", server)
			discrepancies = append(discrepancies, Discrepancy{
				FQDN:       record.FQDN,
				RecordType: record.Type,
				Expected:   expectedValue,
				Server:     server,
				Message:    "Record missing",
			})
			continue
		}
		// Compare the response with expected value
		match := false
		var actualValues []string
		for _, ans := range resp.Answer {
			switch rr := ans.(type) {
			case *dns.A:
				actualValues = append(actualValues, rr.A.String())
				level.Debug(logger).Log("msg", "Comparing A record", "expected", expectedValue, "actual", rr.A.String())
				if rr.A.String() == expectedValue {
					match = true
					break
				}
			case *dns.CNAME:
				actualTarget := rr.Target
				actualValues = append(actualValues, actualTarget)
				level.Debug(logger).Log("msg", "Comparing CNAME record", "expected", dns.Fqdn(expectedValue), "actual", dns.Fqdn(actualTarget))
				if strings.EqualFold(dns.Fqdn(expectedValue), dns.Fqdn(actualTarget)) {
					match = true
					break
				}
			case *dns.NS:
				actualValues = append(actualValues, rr.Ns)
				level.Debug(logger).Log("msg", "Comparing NS record", "expected", dns.Fqdn(expectedValue), "actual", dns.Fqdn(rr.Ns))
				if strings.EqualFold(dns.Fqdn(expectedValue), dns.Fqdn(rr.Ns)) {
					match = true
					break
				}
			case *dns.PTR:
				actualValues = append(actualValues, rr.Ptr)
				level.Debug(logger).Log("msg", "Comparing PTR record", "expected", dns.Fqdn(expectedValue), "actual", dns.Fqdn(rr.Ptr))
				if strings.EqualFold(dns.Fqdn(expectedValue), dns.Fqdn(rr.Ptr)) {
					match = true
					break
				}
			case *dns.SOA:
				// Build the full SOA record string
				soaValue := fmt.Sprintf("%s %s %d %d %d %d %d",
					rr.Ns, rr.Mbox, rr.Serial, rr.Refresh, rr.Retry, rr.Expire, rr.Minttl)
				actualValues = append(actualValues, soaValue)
				level.Debug(logger).Log("msg", "Comparing SOA record", "expected", expectedValue, "actual", soaValue)

				if ignoreSerialNumbers {
					// Compare SOA records without serial number
					expectedParts := strings.SplitN(expectedValue, " ", 7)
					actualParts := strings.SplitN(soaValue, " ", 7)
					if len(expectedParts) == 7 && len(actualParts) == 7 {
						expectedWithoutSerial := strings.Join(append(expectedParts[:2], expectedParts[3:]...), " ")
						actualWithoutSerial := strings.Join(append(actualParts[:2], actualParts[3:]...), " ")
						if strings.EqualFold(expectedWithoutSerial, actualWithoutSerial) {
							match = true
							break
						}
					}
				} else {
					if strings.EqualFold(soaValue, expectedValue) {
						match = true
						break
					}
				}
			// Add other record types as needed
			default:
				// Handle other record types or log unhandled types
				actualValues = append(actualValues, rr.String())
				level.Debug(logger).Log("msg", "Unhandled record type", "type", dns.TypeToString[rr.Header().Rrtype], "record", rr.String())
			}
		}

		if !match {
			level.Warn(logger).Log("msg", "Record mismatch", "fqdn", record.FQDN, "server", server, "expected", expectedValue, "actual", actualValues)
			// Check if there are no actual values
			message := "Mismatch in DNS records"
			if len(actualValues) == 0 {
				message = "Record missing"
			}
			discrepancies = append(discrepancies, Discrepancy{
				FQDN:       record.FQDN,
				RecordType: record.Type,
				Expected:   expectedValue,
				Actual:     actualValues,
				Server:     server,
				Message:    message,
			})
		} else {
			level.Info(logger).Log("msg", "Record validated successfully", "fqdn", record.FQDN, "server", server)
		}
	}
	return discrepancies
}

func validatePTRRecord(ip string, expectedFQDN string, servers []string, logger log.Logger) []Discrepancy {
	var discrepancies []Discrepancy
	ptrName, err := dns.ReverseAddr(ip)
	if err != nil {
		level.Error(logger).Log("msg", "Invalid IP address", "ip", ip, "err", err)
		return discrepancies
	}
	level.Debug(logger).Log("msg", "Validating PTR record", "ip", ip, "ptr_name", ptrName, "expected_fqdn", expectedFQDN)
	for _, server := range servers {
		level.Debug(logger).Log("msg", "Querying DNS", "ptr_name", ptrName, "server", server)
		resp, err := queryDNSWithRetry(ptrName, dns.TypePTR, server, 3)
		if err != nil {
			level.Warn(logger).Log("msg", "DNS query error", "ptr_name", ptrName, "server", server, "err", err)
			discrepancies = append(discrepancies, Discrepancy{
				FQDN:       ptrName,
				RecordType: "PTR",
				Expected:   dns.Fqdn(expectedFQDN),
				Server:     server,
				Message:    fmt.Sprintf("DNS query error: %v", err),
			})
			continue
		}
		if len(resp.Answer) == 0 {
			level.Warn(logger).Log("msg", "No PTR record found", "ptr_name", ptrName, "server", server)
			discrepancies = append(discrepancies, Discrepancy{
				FQDN:       ptrName,
				RecordType: "PTR",
				Expected:   dns.Fqdn(expectedFQDN),
				Server:     server,
				Message:    "Record missing",
			})
			continue
		}
		match := false
		var actualValues []string
		for _, ans := range resp.Answer {
			switch rr := ans.(type) {
			case *dns.PTR:
				actualPtr := rr.Ptr
				actualValues = append(actualValues, actualPtr)
				level.Debug(logger).Log("msg", "Comparing PTR record", "expected", dns.Fqdn(expectedFQDN), "actual", dns.Fqdn(actualPtr))
				if strings.EqualFold(dns.Fqdn(expectedFQDN), dns.Fqdn(actualPtr)) {
					level.Info(logger).Log("msg", "PTR record validated successfully", "ptr_name", ptrName, "server", server)
					match = true
					break
				}
			default:
				// Handle unexpected record types gracefully
				actualValues = append(actualValues, rr.String())
				level.Debug(logger).Log("msg", "Unsupported record type in PTR response", "type", dns.TypeToString[rr.Header().Rrtype], "record", rr.String())
			}
		}
		if !match {
			level.Warn(logger).Log("msg", "PTR record mismatch", "ptr_name", ptrName, "server", server, "expected", dns.Fqdn(expectedFQDN), "actual", actualValues)
			discrepancies = append(discrepancies, Discrepancy{
				FQDN:       ptrName,
				RecordType: "PTR",
				Expected:   dns.Fqdn(expectedFQDN),
				Actual:     actualValues,
				Server:     server,
				Message:    "Mismatch in PTR records",
			})
		}
	}
	return discrepancies
}
