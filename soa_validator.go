// soa_validator.go
package main

import (
	"fmt"
	"strings"
	"sync"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/miekg/dns"
)

func validateSOARecords(records []Record, servers []string, ignoreSerialNumbers bool, logger log.Logger, nameservers []Nameserver, recordSuccessful bool) ([]Discrepancy, []ValidationRecord) {
	var wg sync.WaitGroup
	discrepanciesChan := make(chan Discrepancy, len(records)*len(servers))
	successfulChan := make(chan ValidationRecord, len(records)*len(servers))

	// Filter SOA records
	var soaRecords []Record
	for _, record := range records {
		if strings.ToUpper(record.Type) == "SOA" {
			soaRecords = append(soaRecords, record)
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

	for _, record := range soaRecords {
		wg.Add(1)
		go func(record Record) {
			defer wg.Done()
			key := RecordKey{
				FQDN:       record.FQDN,
				RecordType: "SOA",
				ZoneName:   record.ZoneName,
				ViewName:   record.ViewName,
			}
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
				level.Warn(logger).Log("msg", "No zone or view information for SOA record, skipping validation", "fqdn", record.FQDN)
				return
			}

			discrepancies, successfulValidations := validateSOARecord(record, recordServers, ignoreSerialNumbers, logger, recordSuccessful)
			for _, d := range discrepancies {
				discrepanciesChan <- d
			}
			for _, v := range successfulValidations {
				successfulChan <- v
			}
		}(record)
	}

	wg.Wait()
	close(discrepanciesChan)
	close(successfulChan)

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

func validateSOARecord(record Record, servers []string, ignoreSerialNumbers bool, logger log.Logger, recordSuccessful bool) ([]Discrepancy, []ValidationRecord) {
	expectedSOA := parseSOARecord(record)
	if expectedSOA == nil {
		level.Warn(logger).Log("msg", "Invalid SOA record format", "fqdn", record.FQDN)
		discrepancy := Discrepancy{
			FQDN:       record.FQDN,
			RecordType: "SOA",
			Message:    "Invalid SOA record format",
		}
		return []Discrepancy{discrepancy}, nil
	}

	expectedTTL := 0
	if record.TTL != nil && *record.TTL > 0 {
		expectedTTL = *record.TTL
	} else {
		expectedTTL = record.ZoneDefaultTTL
	}

	var discrepancies []Discrepancy
	var successfulValidations []ValidationRecord

	for _, server := range servers {
		level.Debug(logger).Log("msg", "Validating SOA record", "fqdn", record.FQDN, "server", server)
		resp, err := queryDNSWithRetry(record.FQDN, dns.TypeSOA, server, 3)
		if err != nil {
			if resp != nil && resp.Rcode == dns.RcodeNameError {
				// NXDOMAIN
				level.Warn(logger).Log("msg", "NXDOMAIN received", "fqdn", record.FQDN, "server", server)
				discrepancy := Discrepancy{
					FQDN:       record.FQDN,
					RecordType: "SOA",
					Expected:   *expectedSOA,
					Server:     server,
					Message:    "SOA record missing (NXDOMAIN)",
				}
				discrepancies = append(discrepancies, discrepancy)
			} else {
				// Other errors
				level.Warn(logger).Log("msg", "DNS query error", "fqdn", record.FQDN, "server", server, "err", err)
				discrepancy := Discrepancy{
					FQDN:       record.FQDN,
					RecordType: "SOA",
					Expected:   *expectedSOA,
					Server:     server,
					Message:    fmt.Sprintf("DNS query error: %v", err),
				}
				discrepancies = append(discrepancies, discrepancy)
			}
			continue
		}

		if len(resp.Answer) == 0 {
			level.Warn(logger).Log("msg", "No DNS answer for SOA record", "fqdn", record.FQDN, "server", server)
			discrepancy := Discrepancy{
				FQDN:       record.FQDN,
				RecordType: "SOA",
				Expected:   *expectedSOA,
				Server:     server,
				Message:    "SOA record missing",
			}
			discrepancies = append(discrepancies, discrepancy)
			continue
		}

		for _, ans := range resp.Answer {
			if rr, ok := ans.(*dns.SOA); ok {
				actualSOA := SOARecord{
					MName:   rr.Ns,
					RName:   rr.Mbox,
					Serial:  rr.Serial,
					Refresh: rr.Refresh,
					Retry:   rr.Retry,
					Expire:  rr.Expire,
					Minimum: rr.Minttl,
				}

				actualTTL := int(ans.Header().Ttl)

				if !soaRecordsEqual(*expectedSOA, actualSOA, ignoreSerialNumbers) || expectedTTL != actualTTL {
					level.Warn(logger).Log("msg", "SOA record mismatch", "fqdn", record.FQDN, "server", server)
					discrepancy := Discrepancy{
						FQDN:        record.FQDN,
						RecordType:  "SOA",
						Expected:    *expectedSOA,
						Actual:      actualSOA,
						ExpectedTTL: expectedTTL,
						ActualTTL:   actualTTL,
						Server:      server,
					}
					discrepancies = append(discrepancies, discrepancy)
				} else {
					level.Info(logger).Log("msg", "SOA record validated successfully", "fqdn", record.FQDN, "server", server)
					if recordSuccessful {
						validationRecord := ValidationRecord{
							FQDN:        record.FQDN,
							RecordType:  "SOA",
							Expected:    *expectedSOA,
							Actual:      actualSOA,
							ExpectedTTL: expectedTTL,
							ActualTTL:   actualTTL,
							Server:      server,
							Message:     "SOA record validated successfully",
						}
						successfulValidations = append(successfulValidations, validationRecord)
					}
				}
				break // Since we found the SOA record, we can break out of the loop
			}
		}
	}

	return discrepancies, successfulValidations
}

func parseSOARecord(record Record) *SOARecord {
	parts := strings.Fields(record.Value)
	if len(parts) != 7 {
		return nil
	}
	return &SOARecord{
		MName:   parts[0],
		RName:   parts[1],
		Serial:  parseUint32(parts[2]),
		Refresh: parseUint32(parts[3]),
		Retry:   parseUint32(parts[4]),
		Expire:  parseUint32(parts[5]),
		Minimum: parseUint32(parts[6]),
	}
}

func parseUint32(s string) uint32 {
	var val uint32
	fmt.Sscanf(s, "%d", &val)
	return val
}

func soaRecordsEqual(a, b SOARecord, ignoreSerial bool) bool {
	if a.MName != b.MName || a.RName != b.RName || a.Refresh != b.Refresh || a.Retry != b.Retry || a.Expire != b.Expire || a.Minimum != b.Minimum {
		return false
	}
	if ignoreSerial {
		return true
	}
	return a.Serial == b.Serial
}
