// main.go
package main

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func main() {
	var (
		configFile          string
		apiURL              string
		apiToken            string
		apiTokenFile        string
		dnsServers          string
		reportFile          string
		reportFormat        string
		nsupdateFile        string
		ignoreSerialNumbers bool
		logLevel            string
		nameserversAPIPath  string
		recordsAPIPath      string
	)

	// Define command-line flags
	pflag.StringVar(&configFile, "config", "", "Path to the configuration file")
	pflag.StringVar(&apiURL, "api-url", "", "NetBox API root URL (e.g., https://netbox.example.com/)")
	pflag.StringVar(&apiToken, "api-token", "", "NetBox API token")
	pflag.StringVar(&apiTokenFile, "api-token-file", "", "Path to the NetBox API token file")
	pflag.StringVar(&dnsServers, "dns-servers", "", "Comma-separated list of DNS servers")
	pflag.StringVar(&reportFile, "report-file", "discrepancies.json", "File to write the JSON report")
	pflag.StringVar(&reportFormat, "report-format", "json", "Format of the report (json)")
	pflag.StringVar(&nsupdateFile, "nsupdate-file", "nsupdate.txt", "File to write nsupdate commands")
	pflag.BoolVar(&ignoreSerialNumbers, "ignore-serial-numbers", false, "Ignore serial numbers when comparing SOA records")
	pflag.StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	pflag.StringVar(&nameserversAPIPath, "nameservers-api-path", "/api/plugins/netbox-dns/nameservers/", "NetBox Nameservers API path")
	pflag.StringVar(&recordsAPIPath, "records-api-path", "/api/plugins/netbox-dns/records/", "NetBox DNS Records API path")
	pflag.Parse()

	// Initialize Viper
	viper.SetConfigType("yaml")
	viper.SetConfigName("config") // Default config file name is 'config.yaml'
	viper.AddConfigPath(".")      // Search in current directory
	viper.AddConfigPath("/etc/netbox-dnsverify/")

	// If a config file is specified, use it
	if configFile != "" {
		viper.SetConfigFile(configFile)
	}

	// Read the config file if available
	if err := viper.ReadInConfig(); err != nil {
		level.Warn(log.NewNopLogger()).Log("msg", "No config file found, using defaults and other sources", "err", err)
	} else {
		level.Info(log.NewNopLogger()).Log("msg", "Using config file", "file", viper.ConfigFileUsed())
	}

	// Bind environment variables
	viper.SetEnvPrefix("DNSVERIFY")
	viper.AutomaticEnv()

	// Bind specific environment variables
	viper.BindEnv("api_url")
	viper.BindEnv("api_token")
	viper.BindEnv("api_token_file")
	viper.BindEnv("dns_servers")
	viper.BindEnv("report_file")
	viper.BindEnv("report_format")
	viper.BindEnv("nsupdate_file")
	viper.BindEnv("ignore_serial_numbers")
	viper.BindEnv("log_level")
	viper.BindEnv("nameservers_api_path")
	viper.BindEnv("records_api_path")

	// Set default values from flags
	viper.SetDefault("api_url", apiURL)
	viper.SetDefault("api_token", apiToken)
	viper.SetDefault("api_token_file", apiTokenFile)
	viper.SetDefault("dns_servers", dnsServers)
	viper.SetDefault("report_file", reportFile)
	viper.SetDefault("report_format", reportFormat)
	viper.SetDefault("nsupdate_file", nsupdateFile)
	viper.SetDefault("ignore_serial_numbers", ignoreSerialNumbers)
	viper.SetDefault("log_level", logLevel)
	viper.SetDefault("nameservers_api_path", nameserversAPIPath)
	viper.SetDefault("records_api_path", recordsAPIPath)

	// Override flags with environment variables if they are set
	// Environment variables have higher priority
	apiURL = viper.GetString("api_url")
	apiToken = viper.GetString("api_token")
	apiTokenFile = viper.GetString("api_token_file")
	dnsServers = viper.GetString("dns_servers")
	reportFile = viper.GetString("report_file")
	reportFormat = viper.GetString("report_format")
	nsupdateFile = viper.GetString("nsupdate_file")
	ignoreSerialNumbers = viper.GetBool("ignore_serial_numbers")
	logLevel = viper.GetString("log_level")
	nameserversAPIPath = viper.GetString("nameservers_api_path")
	recordsAPIPath = viper.GetString("records_api_path")

	// Load NetBox API token from file if specified
	if apiTokenFile != "" {
		tokenBytes, err := os.ReadFile(apiTokenFile)
		if err != nil {
			fmt.Printf("Failed to read API token file: %v\n", err)
			os.Exit(1)
		}
		apiToken = strings.TrimSpace(string(tokenBytes))
	}

	if apiURL == "" || apiToken == "" {
		fmt.Println("api-url and api-token are required")
		pflag.Usage()
		os.Exit(1)
	}

	// Ensure apiURL ends with a slash for proper URL parsing
	if !strings.HasSuffix(apiURL, "/") {
		apiURL += "/"
	}

	parsedBaseURL, err := url.Parse(apiURL)
	if err != nil {
		fmt.Printf("Invalid api-url: %v\n", err)
		os.Exit(1)
	}

	logger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
	logger = level.NewFilter(logger, parseLogLevel(logLevel))
	logger = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)

	level.Info(logger).Log("msg", "Starting DNS validation")

	var servers []string
	var nameservers []Nameserver

	if dnsServers != "" {
		// DNS servers are explicitly configured via flags/env/config
		servers = splitAndTrim(dnsServers, ",") // Using comma as delimiter
		level.Info(logger).Log("msg", "Using configured DNS servers", "servers", servers)
	} else {
		// Fetch nameservers from NetBox API
		level.Info(logger).Log("msg", "No DNS servers configured, fetching from NetBox Nameservers API")
		nameserversEndpoint := resolveURL(parsedBaseURL, nameserversAPIPath)

		fetchedNameservers, err := getAllNameservers(nameserversEndpoint, apiToken, logger)
		if err != nil {
			level.Error(logger).Log("msg", "Failed to fetch nameservers from NetBox", "err", err)
			os.Exit(1)
		}

		if len(fetchedNameservers) == 0 {
			level.Error(logger).Log("msg", "No nameservers found from NetBox API")
			os.Exit(1)
		}

		nameservers = fetchedNameservers
		level.Info(logger).Log("msg", "Fetched nameservers from NetBox", "count", len(nameservers))

		// Extract unique DNS servers
		serverSet := make(map[string]bool)
		for _, ns := range nameservers {
			serverSet[ns.Name] = true
		}
		for server := range serverSet {
			servers = append(servers, server)
		}

		level.Info(logger).Log("msg", "Authoritative DNS servers extracted", "servers", servers)
	}

	// Fetch all Zones to build a map of zone_name -> default_ttl
	zonesEndpoint := resolveURL(parsedBaseURL, "/api/plugins/netbox-dns/zones/")
	zones, err := getZones(zonesEndpoint, apiToken, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to fetch zones from NetBox", "err", err)
		os.Exit(1)
	}

	if len(zones) == 0 {
		level.Error(logger).Log("msg", "No zones found in NetBox")
		os.Exit(1)
	}

	zoneTTLMap := make(map[string]int)
	for _, zone := range zones {
		if zone.DefaultTTL != nil {
			zoneTTLMap[zone.Name] = *zone.DefaultTTL
		} else {
			zoneTTLMap[zone.Name] = 3600 // Fallback to a common default TTL if DefaultTTL is nil
			level.Warn(logger).Log("msg", "Zone DefaultTTL is not set, using fallback", "zone", zone.Name)
		}
	}

	// Construct the Records API endpoint
	recordsEndpoint := resolveURL(parsedBaseURL, recordsAPIPath)

	// Fetch DNS Records
	records, err := getAllDNSRecords(recordsEndpoint, apiToken, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to get DNS records from NetBox", "err", err)
		os.Exit(1)
	}

	level.Info(logger).Log("msg", "Fetched DNS records from NetBox", "count", len(records))

	// Validate Records
	discrepancies, successes := validateAllRecords(records, servers, ignoreSerialNumbers, logger, nameservers, zoneTTLMap)

	// Generate Report
	err = generateReport(discrepancies, successes, reportFile, reportFormat, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to generate report", "err", err)
		os.Exit(1)
	}

	// Generate NSUpdate Script
	err = generateNSUpdateScript(discrepancies, nsupdateFile, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to generate nsupdate script", "err", err)
		os.Exit(1)
	}

	level.Info(logger).Log("msg", "DNS validation completed")
}

// parseLogLevel parses the log level string into a log.Option.
func parseLogLevel(levelStr string) level.Option {
	switch strings.ToLower(levelStr) {
	case "debug":
		return level.AllowDebug()
	case "info":
		return level.AllowInfo()
	case "warn", "warning":
		return level.AllowWarn()
	case "error":
		return level.AllowError()
	default:
		return level.AllowInfo()
	}
}

// resolveURL appends the given path to the base URL properly.
func resolveURL(base *url.URL, relativePath string) string {
	u := *base // copy
	u.Path = path.Join(u.Path, relativePath)
	return u.String()
}
