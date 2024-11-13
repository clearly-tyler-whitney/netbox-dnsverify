// types.go
package main

type ApiResponse struct {
	Count   int      `json:"count"`
	Results []Record `json:"results"`
}

type Record struct {
	ID          int        `json:"id"`
	Type        string     `json:"type"`
	Name        string     `json:"name"`
	FQDN        string     `json:"fqdn"`
	Value       string     `json:"value"`
	TTL         int        `json:"ttl"`
	Zone        *Zone      `json:"zone"`
	ZoneName    string     // Extracted from Zone.Name
	ViewName    string     // Extracted from Zone.View.Name
	PTRRecord   *PTRRecord `json:"ptr_record"`
	DisablePTR  bool       `json:"disable_ptr"`
	Managed     bool       `json:"managed"`
	Status      string     `json:"status"`
	Description string     `json:"description"`
	// Add other fields as needed
}

type SOARecord struct {
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
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

type NameserversResponse struct {
	Count    int          `json:"count"`
	Next     *string      `json:"next"`
	Previous *string      `json:"previous"`
	Results  []Nameserver `json:"results"`
}

type Nameserver struct {
	ID           int                    `json:"id"`
	URL          string                 `json:"url"`
	Display      string                 `json:"display"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Tags         []string               `json:"tags"`
	Zones        []Zone                 `json:"zones"`
	Created      string                 `json:"created"`
	LastUpdated  string                 `json:"last_updated"`
	CustomFields map[string]interface{} `json:"custom_fields"`
	Tenant       *string                `json:"tenant"`
}
