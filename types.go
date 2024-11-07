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
	Zone        *Zone      `json:"zone"` // Changed to a pointer
	ZoneName    string     // Will extract ZoneName from Zone.Name
	PTRRecord   *PTRRecord `json:"ptr_record"`
	DisablePTR  bool       `json:"disable_ptr"`
	Managed     bool       `json:"managed"`
	Status      string     `json:"status"`
	Description string     `json:"description"`
	// Add other fields as needed
}

type Zone struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	// Add other fields as needed
}

type PTRRecord struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Value string `json:"value"`
	// Add other fields as needed
}
