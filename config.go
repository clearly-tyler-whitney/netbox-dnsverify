// config.go
package main

import (
	"encoding/json"
	"os"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

type Config struct {
	NetBoxURL   string   `json:"netbox_url"`
	NetBoxToken string   `json:"netbox_token"`
	NameServers []string `json:"name_servers"`
}

func LoadConfig(logger log.Logger) *Config {
	config := &Config{
		NetBoxURL:   os.Getenv("NETBOX_URL"),
		NetBoxToken: os.Getenv("NETBOX_TOKEN"),
	}

	nameServers := os.Getenv("NAME_SERVERS")
	if nameServers != "" {
		config.NameServers = splitAndTrim(nameServers, ",")
	}

	// Optionally load from a config file
	configFile := os.Getenv("CONFIG_FILE")
	if configFile != "" {
		fileConfig := &Config{}
		data, err := os.ReadFile(configFile)
		if err != nil {
			level.Error(logger).Log("msg", "Failed to read config file", "err", err)
			os.Exit(1)
		}
		err = json.Unmarshal(data, fileConfig)
		if err != nil {
			level.Error(logger).Log("msg", "Failed to parse config file", "err", err)
			os.Exit(1)
		}
		mergeConfigs(config, fileConfig)
	}

	if config.NetBoxURL == "" || config.NetBoxToken == "" || len(config.NameServers) == 0 {
		level.Error(logger).Log("msg", "Configuration incomplete: ensure NETBOX_URL, NETBOX_TOKEN, and NAME_SERVERS are set")
		os.Exit(1)
	}

	return config
}

func mergeConfigs(base, override *Config) {
	if override.NetBoxURL != "" {
		base.NetBoxURL = override.NetBoxURL
	}
	if override.NetBoxToken != "" {
		base.NetBoxToken = override.NetBoxToken
	}
	if len(override.NameServers) > 0 {
		base.NameServers = override.NameServers
	}
}
