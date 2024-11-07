// main.go
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

func main() {
	var (
		apiURL              string
		apiToken            string
		dnsServers          string
		reportFile          string
		reportFormat        string
		nsupdateFile        string
		ignoreSerialNumbers bool
		logLevel            string
	)

	flag.StringVar(&apiURL, "api-url", "", "NetBox API URL")
	flag.StringVar(&apiToken, "api-token", "", "NetBox API token")
	flag.StringVar(&dnsServers, "dns-servers", "", "Comma-separated list of DNS servers")
	flag.StringVar(&reportFile, "report-file", "discrepancies.txt", "File to write the report")
	flag.StringVar(&reportFormat, "report-format", "table", "Format of the report (table, csv, json)")
	flag.StringVar(&nsupdateFile, "nsupdate-file", "nsupdate.txt", "File to write nsupdate commands")
	flag.BoolVar(&ignoreSerialNumbers, "ignore-serial-numbers", false, "Ignore serial numbers when comparing SOA records")
	flag.StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	flag.Parse()

	if apiURL == "" || apiToken == "" || dnsServers == "" {
		fmt.Println("api-url, api-token, and dns-servers are required")
		flag.Usage()
		os.Exit(1)
	}

	logger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
	logger = level.NewFilter(logger, parseLogLevel(logLevel))
	logger = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)

	level.Info(logger).Log("msg", "Starting DNS validation")

	servers := strings.Split(dnsServers, ",")

	records, err := getAllDNSRecords(apiURL, apiToken, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to get DNS records from NetBox", "err", err)
		os.Exit(1)
	}

	discrepancies := validateAllRecords(records, servers, ignoreSerialNumbers, logger)

	err = generateReport(discrepancies, reportFile, reportFormat, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to generate report", "err", err)
		os.Exit(1)
	}

	err = generateNSUpdateScript(discrepancies, nsupdateFile, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to generate nsupdate script", "err", err)
		os.Exit(1)
	}

	level.Info(logger).Log("msg", "DNS validation completed")
}

func parseLogLevel(levelStr string) level.Option {
	switch strings.ToLower(levelStr) {
	case "debug":
		return level.AllowDebug()
	case "info":
		return level.AllowInfo()
	case "warn":
		return level.AllowWarn()
	case "error":
		return level.AllowError()
	default:
		return level.AllowInfo()
	}
}
