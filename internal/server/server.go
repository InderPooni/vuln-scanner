package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"vuln-scanner/internal/database"
	"vuln-scanner/internal/models"
	"vuln-scanner/internal/utils"
)

const (
	// Process at least 3 files concurrently
	concurrency = 3
	// Number of retry attempts for fetching a file
	retryAttempts = 2
)

// Server represents the HTTP server
// Server will handle request routing and maintains a db connection
type Server struct {
	DB      *database.Database
	Router  *http.ServeMux
	Address string
}

func NewServer(address string) (*Server, error) {
	db, err := database.NewDatabase()
	if err != nil {
		return nil, err
	}
	s := &Server{
		DB:      db,
		Router:  http.NewServeMux(),
		Address: address,
	}
	// register configured route handlers once server is initialized
	s.registerHandlers()
	return s, nil
}

func (s *Server) Start() error {
	s.DB.Init()
	return http.ListenAndServe(s.Address, s.Router)
}

func (s *Server) registerHandlers() {
	s.Router.HandleFunc("POST /scan", s.scanHandler)
	s.Router.HandleFunc("POST /query", s.queryHandler)
}

func (s *Server) scanHandler(w http.ResponseWriter, r *http.Request) {
	var scanReq models.ScanRequest

	if err := json.NewDecoder(r.Body).Decode(&scanReq); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if scanReq.Repo == "" || len(scanReq.Files) == 0 {
		http.Error(w, "missing repo or files in request", http.StatusBadRequest)
		return
	}

	url, err := utils.GenerateBaseURL(scanReq.Repo)

	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid repository URL: %v", err), http.StatusBadRequest)
		return
	}

	// Use a semaphore channel to limit concurrency
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, fileName := range scanReq.Files {
		wg.Add(1)
		sem <- struct{}{}
		go func(f string) {
			defer wg.Done()
			defer func() { <-sem }()
			fileURL := fmt.Sprintf("%s/%s", url, f)

			err := func() error {
				data, err := utils.FetchWithExponentialBackoff(fileURL, retryAttempts)
				if err != nil {
					return fmt.Errorf("error fetching file %s: %v", fileURL, err)
				}

				// Unmarshal the JSON into a slice of DownloadedScan.
				var scans []models.Scan
				if err := json.Unmarshal(data, &scans); err != nil {
					log.Fatalf("Error unmarshaling JSON: %v", err)
					return err
				}

				// Transform the scan result into a vulnerability and insert it into the database
				for _, scan := range scans {
					for _, v := range scan.ScanResults.Vulnerabilities {
						vuln := models.Vulnerability{
							ID:             v.ID,
							Severity:       v.Severity,
							Cvss:           v.Cvss,
							Status:         v.Status,
							PackageName:    v.PackageName,
							CurrentVersion: v.CurrentVersion,
							FixedVersion:   v.FixedVersion,
							Description:    v.Description,
							PublishedDate:  v.PublishedDate,
							Link:           v.Link,
							RiskFactors:    v.RiskFactors,
						}
						if err := s.DB.InsertVulnerability(vuln); err != nil {
							return fmt.Errorf("error inserting vulnerability %s. err: %v", v.ID, err)
						}
					}
				}
				return nil
			}()
			if err != nil {
				http.Error(w, fmt.Sprintf("Error processing file %s: %v", fileURL, err), http.StatusInternalServerError)
				return
			}
		}(fileName)
	}

	wg.Wait()
	w.Header().Add("Content-Type", "application/json")
	// return back a 201 Created status code since we are not returning any data
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) queryHandler(w http.ResponseWriter, r *http.Request) {
	var req models.QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Error parsing JSON: %v", err), http.StatusBadRequest)
		return
	}

	// Build the query dynamically from the provided filters
	vulns, err := s.DB.QueryVulnerabilities(req.Filters)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error querying vulnerabilities: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(vulns); err != nil {
		http.Error(w, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
	}
}
