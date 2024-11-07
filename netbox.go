// netbox.go
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

// getDNSRecords fetches DNS records from the provided NetBox API URL.
func getDNSRecords(apiURL, token string, logger log.Logger) ([]Record, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to create HTTP request for DNS records", "err", err)
		return nil, err
	}

	req.Header.Set("Authorization", "Token "+token)

	// Log the outgoing request
	level.Debug(logger).Log("msg", "Sending request to NetBox for DNS records", "method", req.Method, "url", req.URL.String())

	resp, err := client.Do(req)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to execute HTTP request for DNS records", "err", err)
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to read DNS records response body", "err", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		level.Error(logger).Log("msg", "Non-OK HTTP response from NetBox DNS Records API", "status_code", resp.StatusCode, "body", string(bodyBytes))
		return nil, fmt.Errorf("NetBox DNS Records API returned status code %d", resp.StatusCode)
	}

	// Log the response body at debug level
	level.Debug(logger).Log("msg", "Received response from NetBox DNS Records API")

	var apiResponse ApiResponse
	err = json.Unmarshal(bodyBytes, &apiResponse)
	if err != nil {
		// Log the error and the response body for debugging
		level.Error(logger).Log("msg", "Failed to parse JSON response from NetBox DNS Records API", "err", err)
		return nil, err
	}

	// Populate ZoneName and handle TTLs
	for i := range apiResponse.Results {
		record := &apiResponse.Results[i]
		if record.Zone != nil {
			record.ZoneName = record.Zone.Name
			if record.Zone.DefaultTTL != nil {
				// Log the DefaultTTL at debug level
				level.Debug(logger).Log("msg", "Zone has DefaultTTL", "zone", record.ZoneName, "DefaultTTL", *record.Zone.DefaultTTL)
			} else {
				// Warn if DefaultTTL is not set
				level.Warn(logger).Log("msg", "Zone DefaultTTL is not set", "zone", record.ZoneName)
			}
			if record.ZoneName == "" {
				level.Warn(logger).Log("msg", "Zone name is empty", "record_id", record.ID)
			}
		} else {
			record.ZoneName = ""
			level.Warn(logger).Log("msg", "Zone is nil for record", "record_id", record.ID)
		}
	}

	return apiResponse.Results, nil
}

// getNameservers fetches Nameservers from the provided NetBox API URL.
func getNameservers(apiURL, token string, logger log.Logger) ([]Nameserver, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to create HTTP request for Nameservers", "err", err)
		return nil, err
	}

	req.Header.Set("Authorization", "Token "+token)

	// Log the outgoing request
	level.Debug(logger).Log("msg", "Sending request to NetBox for Nameservers", "method", req.Method, "url", req.URL.String())

	resp, err := client.Do(req)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to execute HTTP request for Nameservers", "err", err)
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to read Nameservers response body", "err", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		level.Error(logger).Log("msg", "Non-OK HTTP response from NetBox Nameservers API", "status_code", resp.StatusCode, "body", string(bodyBytes))
		return nil, fmt.Errorf("NetBox Nameservers API returned status code %d", resp.StatusCode)
	}

	// Log the response body at debug level
	level.Debug(logger).Log("msg", "Received response from NetBox Nameservers API")

	var nsResponse NameserversResponse
	err = json.Unmarshal(bodyBytes, &nsResponse)
	if err != nil {
		// Log the error and the response body for debugging
		level.Error(logger).Log("msg", "Failed to parse JSON response from NetBox Nameservers API", "err", err)
		return nil, err
	}

	// Populate DefaultTTL for each zone within nameservers
	for i := range nsResponse.Results {
		for j := range nsResponse.Results[i].Zones {
			zone := &nsResponse.Results[i].Zones[j]
			if zone.DefaultTTL != nil {
				level.Debug(logger).Log("msg", "Zone has DefaultTTL", "zone", zone.Name, "DefaultTTL", *zone.DefaultTTL)
			} else {
				level.Warn(logger).Log("msg", "Zone DefaultTTL is not set", "zone", zone.Name)
			}
		}
	}

	return nsResponse.Results, nil
}

// getZones fetches Zones from the provided NetBox API URL.
func getZones(apiURL, token string, logger log.Logger) ([]Zone, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to create HTTP request for Zones", "err", err)
		return nil, err
	}

	req.Header.Set("Authorization", "Token "+token)

	// Log the outgoing request
	level.Debug(logger).Log("msg", "Sending request to NetBox for Zones", "method", req.Method, "url", req.URL.String())

	resp, err := client.Do(req)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to execute HTTP request for Zones", "err", err)
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to read Zones response body", "err", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		level.Error(logger).Log("msg", "Non-OK HTTP response from NetBox Zones API", "status_code", resp.StatusCode, "body", string(bodyBytes))
		return nil, fmt.Errorf("NetBox Zones API returned status code %d", resp.StatusCode)
	}

	// Log the response body at debug level
	level.Debug(logger).Log("msg", "Received response from NetBox Zones API")

	var zoneResponse ZoneResponse
	err = json.Unmarshal(bodyBytes, &zoneResponse)
	if err != nil {
		// Log the error and the response body for debugging
		level.Error(logger).Log("msg", "Failed to parse JSON response from NetBox Zones API", "err", err)
		return nil, err
	}

	return zoneResponse.Results, nil
}

// getAllDNSRecords fetches all DNS records with pagination.
func getAllDNSRecords(baseURL, token string, logger log.Logger) ([]Record, error) {
	var allRecords []Record
	offset := 0
	limit := 50

	parsedBaseURL, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %v", err)
	}

	for {
		// Clone the parsed URL to avoid modifying the original
		parsedURL := *parsedBaseURL

		// Set query parameters
		query := parsedURL.Query()
		query.Set("limit", fmt.Sprintf("%d", limit))
		query.Set("offset", fmt.Sprintf("%d", offset))
		parsedURL.RawQuery = query.Encode()

		apiURLPage := parsedURL.String()

		// Log the current page being fetched
		level.Debug(logger).Log("msg", "Requesting DNS Records page", "url", apiURLPage)

		records, err := getDNSRecords(apiURLPage, token, logger)
		if err != nil {
			return nil, err
		}
		allRecords = append(allRecords, records...)
		if len(records) < limit {
			break
		}
		offset += limit
	}

	return allRecords, nil
}

// getAllNameservers fetches all Nameservers with pagination.
func getAllNameservers(baseURL, token string, logger log.Logger) ([]Nameserver, error) {
	var allNameservers []Nameserver
	offset := 0
	limit := 50

	parsedBaseURL, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %v", err)
	}

	for {
		// Clone the parsed URL to avoid modifying the original
		parsedURL := *parsedBaseURL

		// Set query parameters
		query := parsedURL.Query()
		query.Set("limit", fmt.Sprintf("%d", limit))
		query.Set("offset", fmt.Sprintf("%d", offset))
		parsedURL.RawQuery = query.Encode()

		apiURLPage := parsedURL.String()

		// Log the current page being fetched
		level.Debug(logger).Log("msg", "Requesting Nameservers page", "url", apiURLPage)

		nameservers, err := getNameservers(apiURLPage, token, logger)
		if err != nil {
			return nil, err
		}
		allNameservers = append(allNameservers, nameservers...)
		if len(nameservers) < limit {
			break
		}
		offset += limit
	}

	return allNameservers, nil
}

// getAllZones fetches all Zones with pagination.
func getAllZones(apiURL, token string, logger log.Logger) ([]Zone, error) {
	var allZones []Zone
	offset := 0
	limit := 50

	parsedBaseURL, err := url.Parse(strings.TrimRight(apiURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %v", err)
	}

	for {
		// Clone the parsed URL to avoid modifying the original
		parsedURL := *parsedBaseURL

		// Set query parameters
		query := parsedURL.Query()
		query.Set("limit", fmt.Sprintf("%d", limit))
		query.Set("offset", fmt.Sprintf("%d", offset))
		parsedURL.RawQuery = query.Encode()

		apiURLPage := parsedURL.String()

		// Log the current page being fetched
		level.Debug(logger).Log("msg", "Requesting Zones page", "url", apiURLPage)

		zones, err := getZones(apiURLPage, token, logger)
		if err != nil {
			return nil, err
		}
		allZones = append(allZones, zones...)
		if len(zones) < limit {
			break
		}
		offset += limit
	}

	return allZones, nil
}
