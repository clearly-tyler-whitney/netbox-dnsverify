// utils.go
package main

import (
	"fmt"
	"strings"
)

// splitAndTrim splits a string by a delimiter and trims whitespace from each element.
func splitAndTrim(input string, delimiter string) []string {
	parts := strings.Split(input, delimiter)
	var result []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// difference returns the elements in a that are not in b, case-insensitive.
func difference(a, b []string) []string {
	set := make(map[string]struct{})
	for _, item := range b {
		set[strings.ToLower(item)] = struct{}{}
	}
	var diff []string
	for _, item := range a {
		if _, found := set[strings.ToLower(item)]; !found {
			diff = append(diff, item)
		}
	}
	return diff
}

// groupRecords groups records by FQDN and Type.
func groupRecords(records []Record) map[string][]Record {
	grouped := make(map[string][]Record)
	for _, record := range records {
		key := fmt.Sprintf("%s|%s", record.FQDN, record.Type)
		grouped[key] = append(grouped[key], record)
	}
	return grouped
}
