// types.go
package main

type ApiResponse struct {
	Count   int      `json:"count"`
	Results []Record `json:"results"`
}

type NameserversResponse struct {
	Count   int          `json:"count"`
	Results []Nameserver `json:"results"`
}

type ZoneResponse struct {
	Count   int    `json:"count"`
	Results []Zone `json:"results"`
}

type Record struct {
	ID          int        `json:"id"`
	Type        string     `json:"type"`
	Name        string     `json:"name"`
	FQDN        string     `json:"fqdn"`
	Value       string     `json:"value"`
	Zone        *Zone      `json:"zone"`
	ZoneName    string     `json:"-"`
	PTRRecord   *PTRRecord `json:"ptr_record"`
	DisablePTR  bool       `json:"disable_ptr"`
	Managed     bool       `json:"managed"`
	Status      string     `json:"status"`
	Description string     `json:"description"`
	TTL         *int       `json:"ttl"` // Pointer to handle null values
}

type Zone struct {
	ID            int     `json:"id"`
	URL           string  `json:"url"`
	Display       string  `json:"display"`
	Name          string  `json:"name"`
	View          *View   `json:"view"`
	Status        string  `json:"status"`
	Active        bool    `json:"active"`
	RFC2317Prefix *string `json:"rfc2317_prefix"`
	DefaultTTL    *int    `json:"default_ttl"` // Added DefaultTTL field
	SOATTL        *int    `json:"soa_ttl"`     // Assuming tracking SOA TTL
	SOAMName      string  `json:"soa_mname"`
	SOARName      string  `json:"soa_rname"`
	SOASerial     int     `json:"soa_serial"`
	SOARefresh    int     `json:"soa_refresh"`
	SOARetry      int     `json:"soa_retry"`
	SOAExpire     int     `json:"soa_expire"`
	SOAMinimum    int     `json:"soa_minimum"`
	// Add other fields as needed
}

type View struct {
	ID          int    `json:"id"`
	URL         string `json:"url"`
	Display     string `json:"display"`
	Name        string `json:"name"`
	DefaultView bool   `json:"default_view"`
	Description string `json:"description"`
	// Add other fields as needed
}

type PTRRecord struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Value string `json:"value"`
	// Add other fields as needed
}

type Nameserver struct {
	ID          int    `json:"id"`
	URL         string `json:"url"`
	Display     string `json:"display"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Zones       []Zone `json:"zones"`
	// Add other fields as needed
}

type Success struct {
	FQDN        string   `json:"fqdn"`
	RecordType  string   `json:"record_type"`
	Server      string   `json:"server"`
	Expected    []string `json:"expected"`
	Actual      []string `json:"actual"`
	ExpectedTTL []int    `json:"expected_ttl"`
	ActualTTL   []int    `json:"actual_ttl"`
	Message     string   `json:"message"`
}

type Discrepancy struct {
	FQDN        string   `json:"fqdn"`
	RecordType  string   `json:"record_type"`
	Expected    []string `json:"expected"`
	Missing     []string `json:"missing"`
	Extra       []string `json:"extra"`
	Server      string   `json:"server"`
	Message     string   `json:"message"`
	ExpectedTTL []int    `json:"expected_ttl"`
	ActualTTL   []int    `json:"actual_ttl"`
}

type Report struct {
	Discrepancies []Discrepancy `json:"discrepancies"`
	Successes     []Success     `json:"successes"`
}
