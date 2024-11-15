// dnsutils.go
package main

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

func queryDNS(name string, qtype uint16, server string) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	c := new(dns.Client)
	c.Timeout = 5 * time.Second
	r, _, err := c.Exchange(m, server+":53")
	if err != nil {
		return nil, err
	}
	// Return the response even if Rcode is not RcodeSuccess
	if r.Rcode != dns.RcodeSuccess {
		return r, fmt.Errorf("DNS query failed with Rcode %d", r.Rcode)
	}
	return r, nil
}

func queryDNSWithRetry(name string, qtype uint16, server string, retries int) (*dns.Msg, error) {
	var err error
	var resp *dns.Msg
	for i := 0; i < retries; i++ {
		resp, err = queryDNS(name, qtype, server)
		if err == nil {
			return resp, nil
		}
		time.Sleep(time.Second * time.Duration(i+1))
	}
	return resp, err
}
