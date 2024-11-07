// main.go
package main

import (
	"fmt"
	"os"
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
	)

	// Define command-line flags
	pflag.StringVar(&configFile, "config", "", "Path to the configuration file")
	pflag.StringVar(&apiURL, "api-url", "", "NetBox API URL")
	pflag.StringVar(&apiToken, "api-token", "", "NetBox API token")
	pflag.StringVar(&apiTokenFile, "api-token-file", "", "Path to the NetBox API token file")
	pflag.StringVar(&dnsServers, "dns-servers", "", "Comma-separated list of DNS servers")
	pflag.StringVar(&reportFile, "report-file", "discrepancies.txt", "File to write the report")
	pflag.StringVar(&reportFormat, "report-format", "table", "Format of the report (table, csv, json)")
	pflag.StringVar(&nsupdateFile, "nsupdate-file", "nsupdate.txt", "File to write nsupdate commands")
	pflag.BoolVar(&ignoreSerialNumbers, "ignore-serial-numbers", false, "Ignore serial numbers when comparing SOA records")
	pflag.StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
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

	// Override command-line flags with environment variables
	// (Environment variables have higher priority than flags)
	viper.BindEnv("api_url")
	viper.BindEnv("api_token")
	viper.BindEnv("api_token_file")
	viper.BindEnv("dns_servers")
	viper.BindEnv("report_file")
	viper.BindEnv("report_format")
	viper.BindEnv("nsupdate_file")
	viper.BindEnv("ignore_serial_numbers")
	viper.BindEnv("log_level")

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

	// Now, override flags with environment variables if they are set
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

	// Load NetBox API token from file if specified
	if apiTokenFile != "" {
		tokenBytes, err := os.ReadFile(apiTokenFile)
		if err != nil {
			fmt.Printf("Failed to read API token file: %v\n", err)
			os.Exit(1)
		}
		apiToken = strings.TrimSpace(string(tokenBytes))
	}

	if apiURL == "" || apiToken == "" || dnsServers == "" {
		fmt.Println("api-url, api-token, and dns-servers are required")
		pflag.Usage()
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
