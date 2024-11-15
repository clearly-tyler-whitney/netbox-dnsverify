// common.go
package main

import (
	"strings"
)

// Discrepancy represents a mismatch between expected and actual DNS records.
type Discrepancy struct {
	FQDN        string      `json:"FQDN"`
	RecordType  string      `json:"RecordType"`
	ZoneName    string      `json:"ZoneName"`
	Expected    interface{} `json:"Expected"`
	Actual      interface{} `json:"Actual"`
	ExpectedTTL int         `json:"ExpectedTTL"`
	ActualTTL   int         `json:"ActualTTL"`
	Server      string      `json:"Server"`
	Message     string      `json:"Message,omitempty"`
}

// ValidationRecord represents a successful validation of DNS records.
type ValidationRecord struct {
	FQDN        string      `json:"FQDN"`
	RecordType  string      `json:"RecordType"`
	ZoneName    string      `json:"ZoneName"`
	Expected    interface{} `json:"Expected"`
	Actual      interface{} `json:"Actual"`
	ExpectedTTL int         `json:"ExpectedTTL"`
	ActualTTL   int         `json:"ActualTTL"`
	Server      string      `json:"Server"`
	Message     string      `json:"Message,omitempty"`
}

// RecordKey is used to group records by FQDN and RecordType.
type RecordKey struct {
	FQDN       string
	RecordType string
	ZoneName   string
	ViewName   string
}

// Helper function to determine if two string slices are equal, regardless of order.
func stringSlicesEqualUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	aMap := make(map[string]int)
	for _, val := range a {
		aMap[val]++
	}

	for _, val := range b {
		if count, exists := aMap[val]; !exists || count == 0 {
			return false
		} else {
			aMap[val]--
		}
	}

	for _, count := range aMap {
		if count != 0 {
			return false
		}
	}

	return true
}

// Helper function to check if a string exists in a slice.
func stringInSlice(str string, list []string) bool {
	for _, v := range list {
		if strings.EqualFold(strings.TrimSpace(v), strings.TrimSpace(str)) {
			return true
		}
	}
	return false
}

// Helper function to extract the parent zone name.
func getParentZoneName(zoneName string) string {
	// Remove the first label from the zone name
	parts := strings.SplitN(zoneName, ".", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}
