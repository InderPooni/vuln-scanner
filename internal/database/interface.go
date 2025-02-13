package database

import "vuln-scanner/internal/models"

// DataStore defines the operations required for storing and retrieving vulnerabilities.
type DataStore interface {
	Init()
	InsertVulnerability(v models.Vulnerability) error
	QueryVulnerabilities(filters map[string]string) ([]models.Vulnerability, error)
}
