// utils.go
package main

import (
	"strings"
)

func splitAndTrim(s string, delimiter ...string) []string {
	delim := ","
	if len(delimiter) > 0 && delimiter[0] != "" {
		delim = delimiter[0]
	}
	parts := strings.Split(s, delim)
	var trimmed []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			trimmed = append(trimmed, p)
		}
	}
	return trimmed
}
