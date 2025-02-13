package database

import (
	"database/sql"
	"testing"

	"vuln-scanner/internal/models"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestDatabase(t *testing.T) *Database {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	return &Database{db: db}
}

func TestInit_Insert_Query(t *testing.T) {
	db := newTestDatabase(t)
	defer db.Close()

	db.Init()

	vuln := models.Vulnerability{
		ID:             "CVE-TEST-001",
		Severity:       "HIGH",
		Cvss:           9.8,
		Status:         "active",
		PackageName:    "openssl",
		CurrentVersion: "1.1.1",
		FixedVersion:   "1.1.2",
		Description:    "Buffer overflow in openssl",
		PublishedDate:  "2025-01-01T00:00:00Z",
		Link:           "https://example.com/cve/CVE-TEST-001",
		RiskFactors:    []string{"Exploit available", "Remote attack"},
	}

	err := db.InsertVulnerability(vuln)
	require.NoError(t, err)

	filters := map[string]string{"id": "CVE-TEST-001"}
	results, err := db.QueryVulnerabilities(filters)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, vuln.ID, results[0].ID)
	assert.Equal(t, vuln.RiskFactors, results[0].RiskFactors)

	filters = map[string]string{"cvss": "9.8"}
	results, err = db.QueryVulnerabilities(filters)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, vuln.ID, results[0].ID)

	filters = map[string]string{"severity": "HIGH", "package_name": "openssl"}
	results, err = db.QueryVulnerabilities(filters)
	require.NoError(t, err)
	require.Len(t, results, 1)
}

func TestQueryVulnerabilities_NoValidFilters(t *testing.T) {
	db := newTestDatabase(t)
	defer db.Close()
	db.Init()

	vuln := models.Vulnerability{
		ID:          "CVE-TEST-002",
		Severity:    "LOW",
		Cvss:        3.5,
		Status:      "fixed",
		PackageName: "tomcat",
	}
	err := db.InsertVulnerability(vuln)
	require.NoError(t, err)

	filters := map[string]string{"foo": "bar"}
	results, err := db.QueryVulnerabilities(filters)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid filters provided")
	assert.Len(t, results, 0)
}

func TestQueryVulnerabilities_InvalidCvss(t *testing.T) {
	db := newTestDatabase(t)
	defer db.Close()
	db.Init()

	vuln := models.Vulnerability{
		ID:          "CVE-TEST-003",
		Severity:    "MEDIUM",
		Cvss:        5.5,
		Status:      "active",
		PackageName: "nginx",
	}
	err := db.InsertVulnerability(vuln)
	require.NoError(t, err)

	filters := map[string]string{"cvss": "notafloat"}
	results, err := db.QueryVulnerabilities(filters)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid filters provided")
	assert.Len(t, results, 0)
}

func TestQueryRiskFactorsUnmarshalError(t *testing.T) {
	db := newTestDatabase(t)
	defer db.Close()
	db.Init()

	vuln := models.Vulnerability{
		ID:          "CVE-TEST-004",
		Severity:    "MEDIUM",
		Cvss:        6.0,
		Status:      "active",
		PackageName: "apache",
		RiskFactors: []string{"Factor A", "Factor B"},
	}
	err := db.InsertVulnerability(vuln)
	require.NoError(t, err)

	_, err = db.db.Exec(`UPDATE vulnerabilities SET risk_factors = ? WHERE id = ?`, "invalid_json", vuln.ID)
	require.NoError(t, err)

	filters := map[string]string{"id": vuln.ID}
	results, err := db.QueryVulnerabilities(filters)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, []string{}, results[0].RiskFactors)
}

func TestClose(t *testing.T) {
	db := newTestDatabase(t)
	err := db.Close()
	assert.NoError(t, err)
}
