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
		configFile           string
		apiURL               string
		apiToken             string
		apiTokenFile         string
		reportFile           string
		reportFormat         string
		nsupdatePath         string
		ignoreSerialNumbers  bool
		validateSOA          string
		logLevel             string
		logFormat            string
		zoneFilter           string
		viewFilter           string
		nameserverFilter     string
		recordSuccessful     bool
		successfulReportFile string
		missingReportFile    string
		useAXFR              bool
		tsigKeyFile          string
		showHelp             bool
	)

	// Define command-line flags with short versions
	pflag.StringVarP(&configFile, "config", "c", "", "Path to the configuration file (default: ./config.yaml)")
	pflag.StringVarP(&apiURL, "api-url", "u", "", "NetBox API root URL (e.g., https://netbox.example.com/)")
	pflag.StringVarP(&apiToken, "api-token", "t", "", "NetBox API token")
	pflag.StringVarP(&apiTokenFile, "api-token-file", "T", "", "Path to the NetBox API token file")
	pflag.StringVarP(&reportFile, "report-file", "r", "bad.report", "File to write the discrepancy report")
	pflag.StringVarP(&reportFormat, "report-format", "f", "table", "Format of the report (table, csv, json)")
	pflag.StringVarP(&nsupdatePath, "nsupdate-path", "p", "out", "Directory to write nsupdate commands")
	pflag.BoolVarP(&ignoreSerialNumbers, "ignore-serial-numbers", "i", true, "Ignore serial numbers when comparing SOA records")
	pflag.StringVarP(&validateSOA, "validate-soa", "s", "false", "SOA record validation ('false', 'true', or 'only')")
	pflag.StringVarP(&logLevel, "log-level", "l", "info", "Log level (debug, info, warn, error)")
	pflag.StringVarP(&logFormat, "log-format", "L", "logfmt", "Log format (logfmt or json)")
	pflag.StringVarP(&zoneFilter, "zone", "z", "", "Filter by zone name")
	pflag.StringVarP(&viewFilter, "view", "v", "", "Filter by view name")
	pflag.StringVarP(&nameserverFilter, "nameserver", "N", "", "Filter by nameserver")
	pflag.BoolVarP(&recordSuccessful, "record-successful", "R", false, "Record successful validations")
	pflag.StringVarP(&successfulReportFile, "successful-report-file", "S", "good.report", "File to write successful validations report")
	pflag.StringVarP(&missingReportFile, "missing-report-file", "M", "missing.report", "File to write records found in DNS but missing from NetBox")
	pflag.BoolVarP(&useAXFR, "use-axfr", "a", false, "Use AXFR zone transfer for validation")
	pflag.StringVarP(&tsigKeyFile, "tsig-keyfile", "k", "", "Path to the TSIG keyfile for AXFR")
	pflag.BoolVarP(&showHelp, "help", "h", false, "Display help message")
	pflag.Parse()

	// Show help message if requested
	if showHelp {
		fmt.Println("Usage of netbox-dnsverify:")
		pflag.PrintDefaults()
		os.Exit(0)
	}

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

	// Bind environment variables (standardized names)
	viper.SetEnvPrefix("DNSVERIFY")
	viper.AutomaticEnv()

	// Bind specific environment variables
	viper.BindEnv("config")
	viper.BindEnv("api_url")
	viper.BindEnv("api_token")
	viper.BindEnv("api_token_file")
	viper.BindEnv("dns_servers")
	viper.BindEnv("report_file")
	viper.BindEnv("report_format")
	viper.BindEnv("nsupdate_path")
	viper.BindEnv("ignore_serial_numbers")
	viper.BindEnv("validate_soa")
	viper.BindEnv("log_level")
	viper.BindEnv("log_format")
	viper.BindEnv("zone")
	viper.BindEnv("view")
	viper.BindEnv("nameserver")
	viper.BindEnv("record_successful")
	viper.BindEnv("successful_report_file")
	viper.BindEnv("missing_report_file")
	viper.BindEnv("use_axfr")
	viper.BindEnv("tsig_keyfile")

	// Set default values from flags (lowest precedence)
	viper.SetDefault("config", configFile)
	viper.SetDefault("api_url", apiURL)
	viper.SetDefault("api_token", apiToken)
	viper.SetDefault("api_token_file", apiTokenFile)
	viper.SetDefault("report_file", reportFile)
	viper.SetDefault("report_format", reportFormat)
	viper.SetDefault("nsupdate_path", nsupdatePath)
	viper.SetDefault("ignore_serial_numbers", ignoreSerialNumbers)
	viper.SetDefault("validate_soa", validateSOA)
	viper.SetDefault("log_level", logLevel)
	viper.SetDefault("log_format", logFormat)
	viper.SetDefault("zone", zoneFilter)
	viper.SetDefault("view", viewFilter)
	viper.SetDefault("nameserver", nameserverFilter)
	viper.SetDefault("record_successful", recordSuccessful)
	viper.SetDefault("successful_report_file", successfulReportFile)
	viper.SetDefault("missing_report_file", missingReportFile)
	viper.SetDefault("use_axfr", useAXFR)
	viper.SetDefault("tsig_keyfile", tsigKeyFile)

	// Override environment variables with command-line flags (highest precedence)
	viper.BindPFlags(pflag.CommandLine)

	// Extract final configuration values
	configFile = viper.GetString("config")
	apiURL = viper.GetString("api_url")
	apiToken = viper.GetString("api_token")
	apiTokenFile = viper.GetString("api_token_file")
	reportFile = viper.GetString("report_file")
	reportFormat = viper.GetString("report_format")
	nsupdatePath = viper.GetString("nsupdate_path")
	ignoreSerialNumbers = viper.GetBool("ignore_serial_numbers")
	validateSOA = viper.GetString("validate_soa")
	logLevel = viper.GetString("log_level")
	logFormat = viper.GetString("log_format")
	zoneFilter = viper.GetString("zone")
	viewFilter = viper.GetString("view")
	nameserverFilter = viper.GetString("nameserver")
	recordSuccessful = viper.GetBool("record_successful")
	successfulReportFile = viper.GetString("successful_report_file")
	missingReportFile = viper.GetString("missing_report_file")
	useAXFR = viper.GetBool("use_axfr")
	tsigKeyFile = viper.GetString("tsig_keyfile")

	// Load NetBox API token from file if specified
	if apiTokenFile != "" && apiToken == "" {
		tokenBytes, err := os.ReadFile(apiTokenFile)
		if err != nil {
			fmt.Printf("Failed to read API token file: %v\n", err)
			os.Exit(1)
		}
		apiToken = strings.TrimSpace(string(tokenBytes))
	}

	if apiURL == "" || apiToken == "" {
		fmt.Println("Error: --api-url and --api-token are required.")
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

	// Set up logger with configurable format
	var logger log.Logger
	switch strings.ToLower(logFormat) {
	case "json":
		logger = log.NewJSONLogger(log.NewSyncWriter(os.Stderr))
	default:
		logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	}
	logger = level.NewFilter(logger, parseLogLevel(logLevel))
	logger = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)

	level.Info(logger).Log("msg", "Starting DNS validation")

	var servers []string
	var nameserversList []Nameserver

	{
		// Fetch nameservers from NetBox API
		level.Info(logger).Log("msg", "Fetching nameservers from NetBox Nameservers API")
		nameserversEndpoint := resolveURL(parsedBaseURL, "/api/plugins/netbox-dns/nameservers/")

		fetchedNameservers, err := getAllNameservers(nameserversEndpoint, apiToken, logger, nameserverFilter)
		if err != nil {
			level.Error(logger).Log("msg", "Failed to fetch nameservers from NetBox", "err", err)
			os.Exit(1)
		}

		if len(fetchedNameservers) == 0 {
			level.Error(logger).Log("msg", "No nameservers found from NetBox API")
			os.Exit(1)
		}

		nameserversList = fetchedNameservers
		level.Info(logger).Log("msg", "Fetched nameservers from NetBox", "count", len(nameserversList))

		// Extract unique DNS servers
		serverSet := make(map[string]bool)
		for _, ns := range nameserversList {
			serverSet[ns.Name] = true
		}
		for server := range serverSet {
			servers = append(servers, server)
		}

		level.Info(logger).Log("msg", "Authoritative DNS servers extracted", "servers", strings.Join(servers, ", "))
	}

	// Determine zones to validate based on nameservers if nameserverFilter is used
	var zonesToValidate []string
	if nameserverFilter != "" {
		zonesSet := make(map[string]bool)
		for _, ns := range nameserversList {
			for _, zone := range ns.Zones {
				zonesSet[zone.Name] = true
			}
		}
		for zone := range zonesSet {
			zonesToValidate = append(zonesToValidate, zone)
		}
		level.Info(logger).Log("msg", "Zones to validate derived from nameservers", "zones", strings.Join(zonesToValidate, ", "))
	}

	// Construct the Records API endpoint
	recordsEndpoint := resolveURL(parsedBaseURL, "/api/plugins/netbox-dns/records/")

	// Fetch DNS Records
	records, err := getAllDNSRecords(recordsEndpoint, apiToken, logger, zoneFilter, viewFilter, zonesToValidate)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to get DNS records from NetBox", "err", err)
		os.Exit(1)
	}

	level.Info(logger).Log("msg", "Fetched DNS records from NetBox", "count", len(records))

	// Fetch Zones
	zonesEndpoint := resolveURL(parsedBaseURL, "/api/plugins/netbox-dns/zones/")
	zonesMap, err := getAllZones(zonesEndpoint, apiToken, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to get DNS zones from NetBox", "err", err)
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Fetched DNS zones from NetBox", "count", len(zonesMap))

	// Build a map from zone name to Zone
	zonesByName := make(map[string]Zone)
	for _, zone := range zonesMap {
		zonesByName[zone.Name] = zone
	}

	// Assign ZoneDefaultTTL and SoaTTL to each record
	for i := range records {
		record := &records[i]
		if record.Zone != nil {
			if zone, ok := zonesMap[record.Zone.ID]; ok {
				record.ZoneDefaultTTL = zone.DefaultTTL
				// Update the Zone struct in the record to include SoaTTL
				record.Zone.SoaTTL = zone.SoaTTL
			} else {
				level.Warn(logger).Log("msg", "Zone not found in zones map", "zone_id", record.Zone.ID)
			}
		}
	}

	// Determine SOA validation mode
	soaValidationMode := parseSOAValidationMode(validateSOA)

	// Parse TSIG keyfile if provided
	if tsigKeyFile != "" && useAXFR {
		// Ensure the TSIG keyfile exists and is readable
		if _, err := os.Stat(tsigKeyFile); os.IsNotExist(err) {
			level.Error(logger).Log("msg", "TSIG keyfile does not exist", "file", tsigKeyFile)
			os.Exit(1)
		}
	}

	// Validate Records
	var discrepancies []Discrepancy
	var successfulValidations []ValidationRecord
	var missingRecords []MissingRecord

	if useAXFR {
		// Perform validation using AXFR
		discrepancies, successfulValidations, missingRecords = validateAllRecordsAXFR(records, servers, ignoreSerialNumbers, logger, nameserversList, zoneFilter, viewFilter, recordSuccessful, zonesByName, tsigKeyFile)
	} else {
		// Validate Records using individual queries
		if soaValidationMode != "only" {
			// Validate all records except SOA
			discrepancies, successfulValidations = validateAllRecords(records, servers, ignoreSerialNumbers, logger, nameserversList, zoneFilter, viewFilter, recordSuccessful, zonesByName)
		}

		if soaValidationMode != "false" {
			// Validate SOA records separately
			soaDiscrepancies, soaSuccessfulValidations := validateSOARecords(records, servers, ignoreSerialNumbers, logger, nameserversList, recordSuccessful)
			discrepancies = append(discrepancies, soaDiscrepancies...)
			successfulValidations = append(successfulValidations, soaSuccessfulValidations...)
		}
	}

	// Generate Discrepancy Report
	err = generateReport(discrepancies, reportFile, reportFormat, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to generate discrepancy report", "err", err)
		os.Exit(1)
	}

	// Generate Successful Validations Report if enabled
	if recordSuccessful {
		err = generateSuccessfulReport(successfulValidations, successfulReportFile, reportFormat, logger)
		if err != nil {
			level.Error(logger).Log("msg", "Failed to generate successful validations report", "err", err)
			os.Exit(1)
		}
	}

	// Generate Missing Records Report if enabled and missing records are found
	if missingReportFile != "" && len(missingRecords) > 0 {
		err = generateMissingRecordsReport(missingRecords, missingReportFile, reportFormat, logger)
		if err != nil {
			level.Error(logger).Log("msg", "Failed to generate missing records report", "err", err)
			os.Exit(1)
		}
	}

	// Generate NSUpdate Scripts per server and zone
	err = generateNSUpdateScripts(discrepancies, nsupdatePath, zonesByName, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to generate nsupdate scripts", "err", err)
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

func parseSOAValidationMode(mode string) string {
	switch strings.ToLower(mode) {
	case "true":
		return "true"
	case "only":
		return "only"
	default:
		return "false"
	}
}

// resolveURL appends the given path to the base URL properly
func resolveURL(base *url.URL, relativePath string) string {
	u := *base // copy
	u.Path = path.Join(u.Path, relativePath)
	return u.String()
}
