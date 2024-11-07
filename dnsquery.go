// dnsquery.go
package main

import (
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/miekg/dns"
)

// queryDNSWithRetry performs a DNS query with a specified number of retries.
// It returns the DNS message on success or an error if all retries fail.
func queryDNSWithRetry(fqdn string, qtype uint16, server string, retries int, logger log.Logger) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), qtype)
	m.RecursionDesired = false

	client := new(dns.Client)
	client.Timeout = 5 * time.Second

	var resp *dns.Msg
	var err error

	for attempt := 1; attempt <= retries; attempt++ {
		level.Debug(logger).Log("msg", "Performing DNS query", "fqdn", fqdn, "type", dns.TypeToString[qtype], "server", server, "attempt", attempt)
		resp, _, err = client.Exchange(m, server+":53")
		if err == nil {
			level.Debug(logger).Log("msg", "DNS query successful", "fqdn", fqdn, "server", server)
			return resp, nil
		}
		level.Warn(logger).Log("msg", "DNS query failed", "fqdn", fqdn, "server", server, "attempt", attempt, "err", err)
		time.Sleep(time.Duration(attempt) * time.Second) // Exponential backoff
	}

	level.Error(logger).Log("msg", "All DNS query attempts failed", "fqdn", fqdn, "server", server, "retries", retries, "err", err)
	return nil, err
}
