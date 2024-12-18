// netbox.go
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

// Fetch DNS Records from NetBox with filters
func getAllDNSRecords(baseURL, token string, logger log.Logger, zoneFilter, viewFilter string, zonesToValidate []string) ([]Record, error) {
	var allRecords []Record
	offset := 0
	limit := 50

	// Parse the base URL
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
		// Apply filters
		if zoneFilter != "" {
			query.Set("zone__name", zoneFilter)
		}
		if viewFilter != "" {
			query.Set("zone__view__name", viewFilter)
		}
		if len(zonesToValidate) > 0 {
			// Filter by zones from nameserver's zones
			query.Set("zone__name__in", strings.Join(zonesToValidate, ","))
		}
		parsedURL.RawQuery = query.Encode()

		apiURL := parsedURL.String()

		// Add debug log for the outgoing request URL
		level.Debug(logger).Log("msg", "Requesting NetBox API", "url", apiURL)

		records, err := getDNSRecords(apiURL, token, logger)
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

// Fetch Nameservers and their Zones from NetBox with filter
func getAllNameservers(baseURL, token string, logger log.Logger, nameserverFilter string) ([]Nameserver, error) {
	var allNameservers []Nameserver
	offset := 0
	limit := 50

	// Parse the base URL
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
		// Apply nameserver filter
		if nameserverFilter != "" {
			query.Set("name", nameserverFilter)
		}
		parsedURL.RawQuery = query.Encode()

		apiURL := parsedURL.String()

		// Add debug log for the outgoing request URL
		level.Debug(logger).Log("msg", "Requesting NetBox Nameservers API", "url", apiURL)

		nameservers, err := getNameservers(apiURL, token, logger)
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

// Fetch DNS Records from NetBox
func getDNSRecords(apiURL, token string, logger log.Logger) ([]Record, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Token "+token)

	// Log the outgoing request
	level.Debug(logger).Log("msg", "Sending request to NetBox", "method", req.Method, "url", req.URL.String())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		level.Error(logger).Log("msg", "Non-OK HTTP response from NetBox", "status_code", resp.StatusCode, "body", string(bodyBytes))
		return nil, fmt.Errorf("NetBox API returned status code %d", resp.StatusCode)
	}

	// Log the response body at debug level
	level.Debug(logger).Log("msg", "Received response from NetBox")

	var apiResponse ApiResponse
	err = json.Unmarshal(bodyBytes, &apiResponse)
	if err != nil {
		// Log the error and the response body for debugging
		level.Error(logger).Log("msg", "Failed to parse JSON response from NetBox", "err", err)
		return nil, err
	}

	// Populate ZoneName and ViewName for each record
	for i := range apiResponse.Results {
		record := &apiResponse.Results[i]
		if record.Zone != nil {
			record.ZoneName = record.Zone.Name
			record.ZoneDefaultTTL = record.Zone.DefaultTTL
			if record.Zone.View != nil {
				record.ViewName = record.Zone.View.Name
			}
		} else {
			record.ZoneName = ""
			level.Warn(logger).Log("msg", "Zone is nil", "record_id", record.ID)
		}
	}

	return apiResponse.Results, nil
}

// Fetch Nameservers from NetBox
func getNameservers(apiURL, token string, logger log.Logger) ([]Nameserver, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Token "+token)

	// Log the outgoing request
	level.Debug(logger).Log("msg", "Sending request to NetBox for Nameservers", "method", req.Method, "url", req.URL.String())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		level.Error(logger).Log("msg", "Non-OK HTTP response from NetBox Nameservers API", "status_code", resp.StatusCode, "body", string(bodyBytes))
		return nil, fmt.Errorf("NetBox Nameservers API returned status code %d", resp.StatusCode)
	}

	// Log the response body at debug level
	level.Debug(logger).Log("msg", "Received Nameservers response from NetBox")

	var nsResponse NameserversResponse
	err = json.Unmarshal(bodyBytes, &nsResponse)
	if err != nil {
		// Log the error and the response body for debugging
		level.Error(logger).Log("msg", "Failed to parse JSON Nameservers response from NetBox", "err", err)
		return nil, err
	}

	return nsResponse.Results, nil
}

func getAllZones(baseURL, token string, logger log.Logger) (map[int]Zone, error) {
	zonesMap := make(map[int]Zone)
	offset := 0
	limit := 50

	parsedBaseURL, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %v", err)
	}

	for {
		parsedURL := *parsedBaseURL

		query := parsedURL.Query()
		query.Set("limit", fmt.Sprintf("%d", limit))
		query.Set("offset", fmt.Sprintf("%d", offset))
		parsedURL.RawQuery = query.Encode()

		apiURL := parsedURL.String()

		level.Debug(logger).Log("msg", "Requesting NetBox Zones API", "url", apiURL)

		zones, err := getZones(apiURL, token, logger)
		if err != nil {
			return nil, err
		}

		for _, zone := range zones {
			zonesMap[zone.ID] = zone
		}

		if len(zones) < limit {
			break
		}
		offset += limit
	}
	return zonesMap, nil
}

// Fetch Zones from NetBox
func getZones(apiURL, token string, logger log.Logger) ([]Zone, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Token "+token)

	level.Debug(logger).Log("msg", "Sending request to NetBox for Zones", "method", req.Method, "url", req.URL.String())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		level.Error(logger).Log("msg", "Non-OK HTTP response from NetBox Zones API", "status_code", resp.StatusCode, "body", string(bodyBytes))
		return nil, fmt.Errorf("NetBox Zones API returned status code %d", resp.StatusCode)
	}

	level.Debug(logger).Log("msg", "Received Zones response from NetBox")

	var zonesResponse ZonesResponse
	err = json.Unmarshal(bodyBytes, &zonesResponse)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to parse JSON Zones response from NetBox", "err", err)
		return nil, err
	}

	return zonesResponse.Results, nil
}
