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

// validateRecordsGroup validates a group of records for a specific FQDN and type.
func validateRecordsGroup(fqdn string, recordType string, expectedRecords []Record, servers []string, ignoreSerialNumbers bool, zoneTTLMap map[string]int, logger log.Logger) ([]Discrepancy, []Success) {
	var discrepancies []Discrepancy
	var successes []Success

	expectedValues := make([]string, len(expectedRecords))
	expectedTTLs := make([]int, len(expectedRecords))
	for i, rec := range expectedRecords {
		expectedValues[i] = rec.Value
		if rec.TTL != nil {
			expectedTTLs[i] = *rec.TTL
		} else if rec.Zone != nil && rec.Zone.DefaultTTL != nil {
			expectedTTLs[i] = zoneTTLMap[rec.Zone.Name]
		} else {
			expectedTTLs[i] = 3600 // Fallback to a common default TTL if both are nil
			level.Warn(logger).Log("msg", "Both Record TTL and Zone DefaultTTL are nil. Using fallback TTL", "fqdn", fqdn, "recordType", recordType)
		}
	}

	for _, server := range servers {
		level.Debug(logger).Log("msg", "Validating records group", "fqdn", fqdn, "type", recordType, "expected_values", expectedValues, "server", server)
		qtype, ok := dns.StringToType[strings.ToUpper(recordType)]
		if !ok {
			level.Error(logger).Log("msg", "Unknown record type", "type", recordType)
			continue
		}

		// Call queryDNSWithRetry from dnsquery.go
		resp, err := queryDNSWithRetry(fqdn, qtype, server, 3, logger)
		if err != nil {
			level.Warn(logger).Log("msg", "DNS query error", "fqdn", fqdn, "server", server, "err", err)
			discrepancies = append(discrepancies, Discrepancy{
				FQDN:        fqdn,
				RecordType:  recordType,
				Expected:    expectedValues,
				Missing:     []string{},
				Extra:       []string{},
				Server:      server,
				Message:     fmt.Sprintf("DNS query error: %v", err),
				ExpectedTTL: expectedTTLs,
				ActualTTL:   []int{},
			})
			continue
		}

		if len(resp.Answer) == 0 {
			level.Warn(logger).Log("msg", "No DNS answers", "fqdn", fqdn, "server", server)
			discrepancies = append(discrepancies, Discrepancy{
				FQDN:        fqdn,
				RecordType:  recordType,
				Expected:    expectedValues,
				Missing:     expectedValues,
				Extra:       []string{},
				Server:      server,
				Message:     "All expected records missing",
				ExpectedTTL: expectedTTLs,
				ActualTTL:   []int{},
			})
			continue
		}

		// Extract actual values from DNS response
		var actualValues []string
		var actualTTLs []int
		for _, ans := range resp.Answer {
			switch rr := ans.(type) {
			case *dns.A:
				actualValues = append(actualValues, rr.A.String())
				actualTTLs = append(actualTTLs, int(rr.Header().Ttl))
			case *dns.CNAME:
				actualValues = append(actualValues, rr.Target)
				actualTTLs = append(actualTTLs, int(rr.Header().Ttl))
			case *dns.NS:
				actualValues = append(actualValues, rr.Ns)
				actualTTLs = append(actualTTLs, int(rr.Header().Ttl))
			case *dns.PTR:
				actualValues = append(actualValues, rr.Ptr)
				actualTTLs = append(actualTTLs, int(rr.Header().Ttl))
			case *dns.SOA:
				soaValue := fmt.Sprintf("%s %s %d %d %d %d %d",
					rr.Ns, rr.Mbox, rr.Serial, rr.Refresh, rr.Retry, rr.Expire, rr.Minttl)
				actualValues = append(actualValues, soaValue)
				actualTTLs = append(actualTTLs, int(rr.Header().Ttl))
			default:
				// Handle other record types or log unhandled types
				actualValues = append(actualValues, rr.String())
				actualTTLs = append(actualTTLs, int(rr.Header().Ttl))
			}
		}

		// Compare expected and actual values
		missing := difference(expectedValues, actualValues)
		extra := difference(actualValues, expectedValues)

		// Compare TTLs for matching records
		var mismatchedTTLs []int
		for i, expectedVal := range expectedValues {
			for j, actualVal := range actualValues {
				if strings.EqualFold(expectedVal, actualVal) {
					expectedTTL := expectedTTLs[i]
					actualTTL := actualTTLs[j]
					if expectedTTL != actualTTL {
						mismatchedTTLs = append(mismatchedTTLs, actualTTL)
						break
					}
				}
			}
		}

		message := ""
		if len(missing) > 0 {
			message += fmt.Sprintf("Missing records: %v. ", missing)
		}
		if len(extra) > 0 {
			message += fmt.Sprintf("Unexpected records: %v. ", extra)
		}
		if len(mismatchedTTLs) > 0 {
			message += fmt.Sprintf("TTL mismatch detected.")
		}

		if len(missing) > 0 || len(extra) > 0 || len(mismatchedTTLs) > 0 {
			discrepancies = append(discrepancies, Discrepancy{
				FQDN:        fqdn,
				RecordType:  recordType,
				Expected:    expectedValues,
				Missing:     missing,
				Extra:       extra,
				Server:      server,
				Message:     strings.TrimSpace(message),
				ExpectedTTL: expectedTTLs,
				ActualTTL:   mismatchedTTLs,
			})
		} else {
			// Collect success information
			successes = append(successes, Success{
				FQDN:        fqdn,
				RecordType:  recordType,
				Server:      server,
				Expected:    expectedValues,
				Actual:      actualValues,
				ExpectedTTL: expectedTTLs,
				ActualTTL:   actualTTLs,
				Message:     "All records match",
			})
			level.Info(logger).Log("msg", "Records validated successfully", "fqdn", fqdn, "type", recordType, "server", server)
		}
	}

	return discrepancies, successes
}

// validatePTRRecord validates PTR records.
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
		// Call queryDNSWithRetry from dnsquery.go
		resp, err := queryDNSWithRetry(ptrName, dns.TypePTR, server, 3, logger)
		if err != nil {
			level.Warn(logger).Log("msg", "DNS query error", "ptr_name", ptrName, "server", server, "err", err)
			discrepancies = append(discrepancies, Discrepancy{
				FQDN:        ptrName,
				RecordType:  "PTR",
				Expected:    []string{dns.Fqdn(expectedFQDN)},
				Missing:     []string{},
				Extra:       []string{},
				Server:      server,
				Message:     fmt.Sprintf("DNS query error: %v", err),
				ExpectedTTL: []int{},
				ActualTTL:   []int{},
			})
			continue
		}
		if len(resp.Answer) == 0 {
			level.Warn(logger).Log("msg", "No PTR record found", "ptr_name", ptrName, "server", server)
			discrepancies = append(discrepancies, Discrepancy{
				FQDN:        ptrName,
				RecordType:  "PTR",
				Expected:    []string{dns.Fqdn(expectedFQDN)},
				Missing:     []string{dns.Fqdn(expectedFQDN)},
				Extra:       []string{},
				Server:      server,
				Message:     "PTR record missing",
				ExpectedTTL: []int{},
				ActualTTL:   []int{},
			})
			continue
		}
		// Extract actual values from DNS response
		var actualValues []string
		var actualTTLs []int
		for _, ans := range resp.Answer {
			switch rr := ans.(type) {
			case *dns.PTR:
				actualPtr := rr.Ptr
				actualValues = append(actualValues, actualPtr)
				actualTTLs = append(actualTTLs, int(rr.Header().Ttl))
			default:
				// Handle unexpected record types gracefully
				actualValues = append(actualValues, rr.String())
				actualTTLs = append(actualTTLs, int(rr.Header().Ttl))
			}
		}

		// Compare expected and actual values
		missing := difference([]string{dns.Fqdn(expectedFQDN)}, actualValues)
		extra := difference(actualValues, []string{dns.Fqdn(expectedFQDN)})

		// Compare TTLs for matching records
		var mismatchedTTLs []int
		for _, expectedVal := range []string{dns.Fqdn(expectedFQDN)} {
			for j, actualVal := range actualValues {
				if strings.EqualFold(expectedVal, actualVal) {
					// Assuming expected TTL for PTR is not specified; adjust as needed
					// If you have expected TTLs for PTR records, include them here
					expectedTTL := 0 // Placeholder
					actualTTL := actualTTLs[j]
					if expectedTTL != 0 && expectedTTL != actualTTL {
						mismatchedTTLs = append(mismatchedTTLs, actualTTL)
					}
					break
				}
			}
		}

		message := ""
		if len(missing) > 0 {
			message += fmt.Sprintf("Missing records: %v. ", missing)
		}
		if len(extra) > 0 {
			message += fmt.Sprintf("Unexpected records: %v. ", extra)
		}
		if len(mismatchedTTLs) > 0 {
			message += fmt.Sprintf("TTL mismatch detected.")
		}

		if len(missing) > 0 || len(extra) > 0 || len(mismatchedTTLs) > 0 {
			discrepancies = append(discrepancies, Discrepancy{
				FQDN:        ptrName,
				RecordType:  "PTR",
				Expected:    []string{dns.Fqdn(expectedFQDN)},
				Missing:     missing,
				Extra:       extra,
				Server:      server,
				Message:     strings.TrimSpace(message),
				ExpectedTTL: []int{},
				ActualTTL:   mismatchedTTLs,
			})
		} else {
			// PTR records are typically single-valued; consider adding a Success entry if needed
			// For simplicity, we're not collecting successes for PTR here
			level.Info(logger).Log("msg", "PTR record validated successfully", "ptr_name", ptrName, "server", server)
		}
	}
	return discrepancies
}

// validateAllRecords validates all DNS records against actual DNS responses.
func validateAllRecords(records []Record, servers []string, ignoreSerialNumbers bool, logger log.Logger, nameservers []Nameserver, zoneTTLMap map[string]int) ([]Discrepancy, []Success) {
	var wg sync.WaitGroup
	discrepanciesChan := make(chan Discrepancy, len(records)*len(servers)*2) // Adjusted buffer size
	successesChan := make(chan Success, len(records)*len(servers))           // Channel for successes

	validatedPTRs := make(map[string]bool) // Map to keep track of validated PTR record FQDNs
	var mutex sync.Mutex                   // To protect validatedPTRs map

	// First, collect all PTR records to avoid double-handling
	for _, record := range records {
		if strings.ToUpper(record.Type) == "PTR" {
			ptrName := record.FQDN
			validatedPTRs[ptrName] = true
		}
	}

	// Group records by FQDN and Type
	groupedRecords := groupRecords(records)

	for key, group := range groupedRecords {
		wg.Add(1)
		go func(k string, group []Record) {
			defer wg.Done()
			// Split the key back into FQDN and Type
			parts := strings.Split(k, "|")
			if len(parts) != 2 {
				level.Error(logger).Log("msg", "Invalid group key", "key", k)
				return
			}
			fqdn := parts[0]
			recordType := parts[1]

			// Determine which nameservers are authoritative for this record's zone
			var recordServers []string
			// Assuming all records in the group share the same zone
			zoneName := group[0].ZoneName
			if zoneName != "" {
				recordServers = nameserversForZone(zoneName, nameservers)
				if len(recordServers) == 0 {
					// If no specific nameservers found for the zone, use all servers
					recordServers = servers
					level.Warn(logger).Log("msg", "No nameservers found for zone", "zone", zoneName, "using all servers")
				}
			} else {
				// If no zone information, use all servers
				recordServers = servers
				level.Warn(logger).Log("msg", "No zone information for record", "fqdn", fqdn, "using all servers")
			}

			// Validate the group
			groupDiscrepancies, groupSuccesses := validateRecordsGroup(fqdn, recordType, group, recordServers, ignoreSerialNumbers, zoneTTLMap, logger)
			if len(groupDiscrepancies) > 0 {
				for _, d := range groupDiscrepancies {
					discrepanciesChan <- d
				}
			}
			if len(groupSuccesses) > 0 {
				for _, s := range groupSuccesses {
					successesChan <- s
				}
			}

			// Validate PTR if applicable
			if strings.ToUpper(recordType) == "A" && !group[0].DisablePTR {
				var expectedFQDN string
				if group[0].PTRRecord != nil && group[0].PTRRecord.Value != "" {
					expectedFQDN = group[0].PTRRecord.Value
				} else {
					expectedFQDN = group[0].FQDN
				}
				ip := group[0].Value
				ptrName, err := dns.ReverseAddr(ip)
				if err != nil {
					level.Error(logger).Log("msg", "Invalid IP address", "ip", ip, "err", err)
				} else {
					mutex.Lock()
					alreadyValidated := validatedPTRs[ptrName]
					if !alreadyValidated {
						validatedPTRs[ptrName] = true
						mutex.Unlock()
						ptrDiscrepancies := validatePTRRecord(ip, expectedFQDN, recordServers, logger)
						if len(ptrDiscrepancies) > 0 {
							for _, d := range ptrDiscrepancies {
								discrepanciesChan <- d
							}
						} else {
							// If no discrepancies, consider it a success
							successesChan <- Success{
								FQDN:        ptrName,
								RecordType:  "PTR",
								Server:      "", // Can be modified if PTR is associated with a specific server
								Expected:    []string{dns.Fqdn(expectedFQDN)},
								Actual:      []string{dns.Fqdn(expectedFQDN)},
								ExpectedTTL: []int{},
								ActualTTL:   []int{},
								Message:     "PTR record matches expected value",
							}
						}
					} else {
						mutex.Unlock()
						level.Debug(logger).Log("msg", "Skipping PTR validation; already validated", "ptr_name", ptrName)
					}
				}
			}
		}(key, group)
	}

	wg.Wait()
	close(discrepanciesChan)
	close(successesChan)

	var allDiscrepancies []Discrepancy
	for d := range discrepanciesChan {
		allDiscrepancies = append(allDiscrepancies, d)
	}

	var allSuccesses []Success
	for s := range successesChan {
		allSuccesses = append(allSuccesses, s)
	}

	return allDiscrepancies, allSuccesses
}

// nameserversForZone retrieves nameservers responsible for a given zone.
func nameserversForZone(zoneName string, nameservers []Nameserver) []string {
	var servers []string
	for _, ns := range nameservers {
		for _, zone := range ns.Zones {
			if strings.EqualFold(zone.Name, zoneName) {
				servers = append(servers, ns.Name)
				break
			}
		}
	}
	return servers
}
