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
	bodyBytes, err := ioutil.ReadAll(resp.Body)
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

	// Populate ZoneName for each record
	for i := range apiResponse.Results {
		record := &apiResponse.Results[i]
		if record.Zone != nil {
			record.ZoneName = record.Zone.Name
			if record.ZoneName == "" {
				level.Warn(logger).Log("msg", "Zone name is empty", "record_id", record.ID)
			}
		} else {
			record.ZoneName = ""
			level.Warn(logger).Log("msg", "Zone is nil", "record_id", record.ID)
		}
	}

	return apiResponse.Results, nil
}

func getAllDNSRecords(baseURL, token string, logger log.Logger) ([]Record, error) {
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
