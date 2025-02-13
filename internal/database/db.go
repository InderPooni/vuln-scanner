package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"vuln-scanner/internal/models"
)

type Database struct {
	db *sql.DB
}

var _ DataStore = &Database{}

func NewDatabase() (*Database, error) {
	db, err := sql.Open("sqlite3", "data.db")
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &Database{db: db}, nil
}

func (d *Database) Init() {
	createStmt := `
	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id TEXT PRIMARY KEY,
		severity TEXT,
		cvss REAL,
		status TEXT,
		package_name TEXT,
		current_version TEXT,
		fixed_version TEXT,
		description TEXT,
		published_date TEXT,
		link TEXT,
		risk_factors TEXT,
		file_name TEXT,
		scan_time TEXT
	);
	`
	d.db.Exec(createStmt)
}

// InsertVulnerability inserts a vulnerability record into the database
// The "risk_factors" field is stored as a JSON encoded string
func (d *Database) InsertVulnerability(v models.Vulnerability) error {
	riskFactors, err := json.Marshal(v.RiskFactors)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`
	INSERT OR REPLACE INTO vulnerabilities (
		id, severity, cvss, status, package_name, current_version, fixed_version, description, published_date, link, risk_factors) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		v.ID, v.Severity, v.Cvss, v.Status, v.PackageName,
		v.CurrentVersion, v.FixedVersion, v.Description,
		v.PublishedDate, v.Link, string(riskFactors))
	return err
}

// QueryVulnerabilities will validate the provided filters and generate a query dynamically
func (d *Database) QueryVulnerabilities(filters map[string]string) ([]models.Vulnerability, error) {
	allowedFilters := map[string]struct{}{
		"id":              {},
		"severity":        {},
		"status":          {},
		"package_name":    {},
		"current_version": {},
		"fixed_version":   {},
		"description":     {},
		"published_date":  {},
		"link":            {},
		"cvss":            {},
	}

	var conditions []string
	var params []interface{}

	// Build a condition for each allowed filter.
	for key, value := range filters {
		if _, ok := allowedFilters[key]; !ok {
			continue // skip disallowed keys
		}

		// Special handling for numeric field "cvss"
		if key == "cvss" {
			// validatate the cvss score is a valid float
			cvssVal, err := strconv.ParseFloat(value, 64)
			if err != nil {
				continue
			}
			conditions = append(conditions, fmt.Sprintf("%s = ?", key))
			params = append(params, cvssVal)
		} else {
			conditions = append(conditions, fmt.Sprintf("%s = ?", key))
			params = append(params, value)
		}
	}

	// If no valid filters were provided, return an error
	if len(conditions) == 0 {
		return nil, fmt.Errorf("no valid filters provided")
	}

	query := `
		SELECT id, severity, cvss, status, package_name, current_version, fixed_version, description, published_date, link, risk_factors
		FROM vulnerabilities
		WHERE ` + strings.Join(conditions, " OR ")

	rows, err := d.db.Query(query, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.Vulnerability
	for rows.Next() {
		var vuln models.Vulnerability
		var riskFactorsJSON string
		if err := rows.Scan(
			&vuln.ID,
			&vuln.Severity,
			&vuln.Cvss,
			&vuln.Status,
			&vuln.PackageName,
			&vuln.CurrentVersion,
			&vuln.FixedVersion,
			&vuln.Description,
			&vuln.PublishedDate,
			&vuln.Link,
			&riskFactorsJSON,
		); err != nil {
			return nil, err
		}

		// Unmarshal json encoding string risk_factors back to a slice
		if err := json.Unmarshal([]byte(riskFactorsJSON), &vuln.RiskFactors); err != nil {
			vuln.RiskFactors = []string{}
		}
		results = append(results, vuln)
	}
	return results, nil
}

func (d *Database) Close() error {
	return d.db.Close()
}
