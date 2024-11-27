// dnsutils.go
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/miekg/dns"
)

// queryDNSWithRetry performs a DNS query with a specified number of retries.
// It returns the DNS message response or an error if all retries fail.
func queryDNSWithRetry(fqdn string, qtype uint16, server string, retries int) (*dns.Msg, error) {
	client := new(dns.Client)
	var resp *dns.Msg
	var err error

	for i := 0; i < retries; i++ {
		resp, _, err = client.Exchange(&dns.Msg{
			MsgHdr: dns.MsgHdr{
				RecursionDesired: true,
			},
			Question: []dns.Question{
				{
					Name:   fqdn,
					Qtype:  qtype,
					Qclass: dns.ClassINET,
				},
			},
		}, server+":53")

		if err == nil {
			return resp, nil
		}
	}

	return resp, fmt.Errorf("failed to query DNS after %d retries: %v", retries, err)
}

// performAXFR performs a DNS zone transfer (AXFR) for the specified zone and server.
// If tsigKey is provided, it uses TSIG authentication.
func performAXFR(zoneName string, server string, tsigKey *TSIGKey, logger log.Logger) ([]dns.RR, error) {
	client := new(dns.Client)
	client.Net = "tcp"

	if tsigKey != nil {
		client.TsigSecret = map[string]string{dns.Fqdn(tsigKey.Name): tsigKey.Secret}
	}

	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(zoneName))

	if tsigKey != nil {
		m.SetTsig(dns.Fqdn(tsigKey.Name), tsigKey.Algorithm, 300, time.Now().Unix())
	}

	t := new(dns.Transfer)
	t.TsigSecret = client.TsigSecret

	// Start the transfer
	envChan, err := t.In(m, server+":53")
	if err != nil {
		return nil, fmt.Errorf("AXFR failed: %v", err)
	}

	var records []dns.RR
	for env := range envChan {
		if env.Error != nil {
			return nil, fmt.Errorf("AXFR failed: %v", env.Error)
		}
		records = append(records, env.RR...)
	}

	return records, nil
}

// TSIGKey represents the TSIG key configuration.
type TSIGKey struct {
	Name      string
	Secret    string
	Algorithm string
}

// parseTSIGKeyFile parses a BIND-style TSIG keyfile and returns a TSIGKey.
func parseTSIGKeyFile(filePath string) (*TSIGKey, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open TSIG keyfile: %v", err)
	}
	defer file.Close()

	var name, secret, algorithm string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") {
			continue
		}

		if strings.HasPrefix(line, "key") && strings.HasSuffix(line, "{") {
			// Extract key name
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				name = strings.Trim(parts[1], "\"")
			}
		} else if strings.Contains(line, "algorithm") {
			parts := strings.Split(line, "algorithm")
			if len(parts) >= 2 {
				algorithm = strings.TrimSpace(strings.Trim(parts[1], " ;\""))
			}
		} else if strings.Contains(line, "secret") {
			parts := strings.Split(line, "secret")
			if len(parts) >= 2 {
				secret = strings.TrimSpace(strings.Trim(parts[1], " ;\""))
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read TSIG keyfile: %v", err)
	}

	if name == "" || secret == "" {
		return nil, fmt.Errorf("TSIG keyfile is missing name or secret")
	}

	// Map algorithm string to dns package constant
	switch strings.ToUpper(algorithm) {
	case "HMAC-MD5.SIG-ALG.REG.INT":
		algorithm = dns.HmacMD5
	case "HMAC-SHA1":
		algorithm = dns.HmacSHA1
	case "HMAC-SHA256":
		algorithm = dns.HmacSHA256
	case "HMAC-SHA512":
		algorithm = dns.HmacSHA512
	default:
		return nil, fmt.Errorf("unsupported TSIG algorithm: %s", algorithm)
	}

	return &TSIGKey{
		Name:      name,
		Secret:    secret,
		Algorithm: algorithm,
	}, nil
}
