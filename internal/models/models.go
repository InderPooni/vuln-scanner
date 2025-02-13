package models

// ScanRequest is the request body for the scan request
type ScanRequest struct {
	Repo  string   `json:"repo"`
	Files []string `json:"files"`
}

// QueryRequest represents the request body for the query request
type QueryRequest struct {
	Filters map[string]string `json:"filters"`
}

// Vulnerability represents the simplified vulnerability structure
type Vulnerability struct {
	ID             string   `json:"id"`
	Severity       string   `json:"severity"`
	Cvss           float64  `json:"cvss"`
	Status         string   `json:"status"`
	PackageName    string   `json:"package_name"`
	CurrentVersion string   `json:"current_version"`
	FixedVersion   string   `json:"fixed_version"`
	Description    string   `json:"description"`
	PublishedDate  string   `json:"published_date"`
	Link           string   `json:"link"`
	RiskFactors    []string `json:"risk_factors"`
}

// Scan mirrors the structure of the downloaded JSON
type Scan struct {
	ScanResults struct {
		ScanID          string `json:"scan_id"`
		Timestamp       string `json:"timestamp"`
		ScanStatus      string `json:"scan_status"`
		ResourceType    string `json:"resource_type"`
		ResourceName    string `json:"resource_name"`
		Vulnerabilities []struct {
			ID             string   `json:"id"`
			Severity       string   `json:"severity"`
			Cvss           float64  `json:"cvss"`
			Status         string   `json:"status"`
			PackageName    string   `json:"package_name"`
			CurrentVersion string   `json:"current_version"`
			FixedVersion   string   `json:"fixed_version"`
			Description    string   `json:"description"`
			PublishedDate  string   `json:"published_date"`
			Link           string   `json:"link"`
			RiskFactors    []string `json:"risk_factors"`
		} `json:"vulnerabilities"`
		// summary and scan_metadata are omitted since they're not needed here
	} `json:"scanResults"`
}
