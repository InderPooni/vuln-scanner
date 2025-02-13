package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"vuln-scanner/internal/database"
	"vuln-scanner/internal/models"
	"vuln-scanner/internal/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockDatabase struct {
	mu              sync.Mutex
	vulnerabilities []models.Vulnerability
}

var _ database.DataStore = (*MockDatabase)(nil)

func (m *MockDatabase) Init() {}

func (m *MockDatabase) Close() {}

func (m *MockDatabase) InsertVulnerability(v models.Vulnerability) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vulnerabilities = append(m.vulnerabilities, v)
	return nil
}

func (m *MockDatabase) QueryVulnerabilities(filters map[string]string) ([]models.Vulnerability, error) {
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
	for key, value := range filters {
		if _, ok := allowedFilters[key]; ok {
			if key == "cvss" {
				if _, err := strconv.ParseFloat(value, 64); err != nil {
					continue
				}
			}
			conditions = append(conditions, fmt.Sprintf("%s = ?", key))
		}
	}
	if len(conditions) == 0 {
		return nil, fmt.Errorf("no valid filters provided")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var results []models.Vulnerability
	//  Filter by severity
	if sev, ok := filters["severity"]; ok {
		for _, v := range m.vulnerabilities {
			if v.Severity == sev {
				results = append(results, v)
			}
		}
	} else {
		results = append(results, m.vulnerabilities...)
	}
	return results, nil
}

// Additional mock that always returns an error for QueryVulnerabilities
type ErrorMockDatabase struct{}

var _ database.DataStore = (*ErrorMockDatabase)(nil)

func (e *ErrorMockDatabase) Init()                                            {}
func (e *ErrorMockDatabase) Close()                                           {}
func (e *ErrorMockDatabase) InsertVulnerability(v models.Vulnerability) error { return nil }
func (e *ErrorMockDatabase) QueryVulnerabilities(filters map[string]string) ([]models.Vulnerability, error) {
	return nil, fmt.Errorf("query error")
}

var sampleScanJSON = []byte(`[
  {
    "scanResults": {
      "scan_id": "TEST_SCAN",
      "timestamp": "2025-01-29T09:15:00Z",
      "scan_status": "completed",
      "resource_type": "container",
      "resource_name": "test-service:1.0.0",
      "vulnerabilities": [
        {
          "id": "CVE-TEST-0001",
          "severity": "HIGH",
          "cvss": 9.0,
          "status": "fixed",
          "package_name": "testpkg",
          "current_version": "1.0.0",
          "fixed_version": "1.0.1",
          "description": "Test vulnerability",
          "published_date": "2025-01-28T00:00:00Z",
          "link": "https://example.com",
          "risk_factors": ["Test Factor"]
        }
      ]
    }
  }
]`)

// Override utils.FetchWithExponentialBackoff for testing
var originalFetch = utils.FetchWithExponentialBackoff

func restoreFetch() {
	utils.FetchWithExponentialBackoff = originalFetch
}

func testFetchAlwaysSucceeds(url string, attempts int) ([]byte, error) {
	return sampleScanJSON, nil
}

func TestScanHandler_Success(t *testing.T) {
	utils.FetchWithExponentialBackoff = testFetchAlwaysSucceeds
	defer restoreFetch()

	mockDB := &MockDatabase{}

	srv := &Server{
		DB:      mockDB,
		Router:  http.NewServeMux(),
		Address: ":8080",
	}
	srv.registerHandlers()

	scanReq := models.ScanRequest{
		Repo:  "velancio/vulnerability_scans",
		Files: []string{"vulnscan1011.json"},
	}
	reqBody, err := json.Marshal(scanReq)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(reqBody))
	rr := httptest.NewRecorder()

	srv.scanHandler(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	mockDB.mu.Lock()
	defer mockDB.mu.Unlock()
	require.Len(t, mockDB.vulnerabilities, 1)
	v := mockDB.vulnerabilities[0]
	assert.Equal(t, "CVE-TEST-0001", v.ID)
	assert.Equal(t, "HIGH", v.Severity)
}

func TestScanHandler_InvalidJSON(t *testing.T) {
	srv := &Server{
		DB:      &MockDatabase{},
		Router:  http.NewServeMux(),
		Address: ":8080",
	}
	srv.registerHandlers()

	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader([]byte("invalid json")))
	rr := httptest.NewRecorder()

	srv.scanHandler(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestScanHandler_MissingRepoOrFiles(t *testing.T) {
	scanReq := models.ScanRequest{
		Files: []string{"file.json"},
	}
	reqBody, err := json.Marshal(scanReq)
	require.NoError(t, err)

	srv := &Server{
		DB:      &MockDatabase{},
		Router:  http.NewServeMux(),
		Address: ":8080",
	}
	srv.registerHandlers()

	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(reqBody))
	rr := httptest.NewRecorder()

	srv.scanHandler(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestScanHandler_InvalidRepo(t *testing.T) {
	scanReq := models.ScanRequest{
		Repo:  "invalid",
		Files: []string{"file.json"},
	}
	reqBody, err := json.Marshal(scanReq)
	require.NoError(t, err)

	srv := &Server{
		DB:      &MockDatabase{},
		Router:  http.NewServeMux(),
		Address: ":8080",
	}
	srv.registerHandlers()

	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(reqBody))
	rr := httptest.NewRecorder()

	srv.scanHandler(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestScanHandler_FetchError(t *testing.T) {
	utils.FetchWithExponentialBackoff = func(url string, attempts int) ([]byte, error) {
		return nil, fmt.Errorf("fetch error")
	}
	defer restoreFetch()

	scanReq := models.ScanRequest{
		Repo:  "velancio/vulnerability_scans",
		Files: []string{"file.json"},
	}
	reqBody, err := json.Marshal(scanReq)
	require.NoError(t, err)

	srv := &Server{
		DB:      &MockDatabase{},
		Router:  http.NewServeMux(),
		Address: ":8080",
	}
	srv.registerHandlers()

	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(reqBody))
	rr := httptest.NewRecorder()

	srv.scanHandler(rr, req)
	assert.NotEqual(t, http.StatusCreated, rr.Code)
}

func TestQueryHandler_Success(t *testing.T) {
	mockDB := &MockDatabase{}
	vuln1 := models.Vulnerability{
		ID:       "CVE-TEST-0001",
		Severity: "HIGH",
		Cvss:     9.0,
		Status:   "fixed",
	}
	vuln2 := models.Vulnerability{
		ID:       "CVE-TEST-0002",
		Severity: "LOW",
		Cvss:     3.0,
		Status:   "active",
	}
	require.NoError(t, mockDB.InsertVulnerability(vuln1))
	require.NoError(t, mockDB.InsertVulnerability(vuln2))

	srv := &Server{
		DB:      mockDB,
		Router:  http.NewServeMux(),
		Address: ":8080",
	}
	srv.registerHandlers()

	queryReq := models.QueryRequest{
		Filters: map[string]string{"severity": "HIGH"},
	}
	reqBody, err := json.Marshal(queryReq)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/query", bytes.NewReader(reqBody))
	rr := httptest.NewRecorder()

	srv.queryHandler(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	body, err := io.ReadAll(rr.Body)
	require.NoError(t, err)

	var returnedVulns []models.Vulnerability
	err = json.Unmarshal(body, &returnedVulns)
	require.NoError(t, err)

	require.Len(t, returnedVulns, 1)
	assert.Equal(t, "CVE-TEST-0001", returnedVulns[0].ID)
}

func TestQueryHandler_InvalidJSON(t *testing.T) {
	srv := &Server{
		DB:      &MockDatabase{},
		Router:  http.NewServeMux(),
		Address: ":8080",
	}
	srv.registerHandlers()

	req := httptest.NewRequest(http.MethodPost, "/query", bytes.NewReader([]byte("invalid json")))
	rr := httptest.NewRecorder()

	srv.queryHandler(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestQueryHandler_DBError(t *testing.T) {
	srv := &Server{
		DB:      &ErrorMockDatabase{},
		Router:  http.NewServeMux(),
		Address: ":8080",
	}
	srv.registerHandlers()

	queryReq := models.QueryRequest{
		Filters: map[string]string{"severity": "HIGH"},
	}
	reqBody, err := json.Marshal(queryReq)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/query", bytes.NewReader(reqBody))
	rr := httptest.NewRecorder()

	srv.queryHandler(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestQueryHandler_NoValidFilters(t *testing.T) {
	srv := &Server{
		DB:      &MockDatabase{},
		Router:  http.NewServeMux(),
		Address: ":8080",
	}
	srv.registerHandlers()

	queryReq := models.QueryRequest{
		Filters: map[string]string{"not_allowed": "value"},
	}
	reqBody, err := json.Marshal(queryReq)
	require.NoError(t, err)

	require.NotNil(t, reqBody)

	// Directly call the DB's QueryVulnerabilities to simulate error behavior
	_, err = srv.DB.QueryVulnerabilities(queryReq.Filters)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid filters provided")
}
