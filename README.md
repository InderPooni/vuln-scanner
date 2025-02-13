# vuln-scanner

A Go-based service for scanning a GitHub repository for vulnerability JSON files and querying the stored vulnerability payloads using key-value filters.

This service fetches vulnerability data from a GitHub repository, processes JSON files containing vulnerability arrays, stores each payload (with metadata) in an SQLite database, and exposes RESTful APIs to query the data.

## Features

- **Scan API:**  
  Fetch and process JSON files from a given GitHub repository path.  
  **Endpoint:** `POST /scan`

- **Query API:**  
  Query stored vulnerability payloads using key-value filters (e.g., filtering by severity).  
  **Endpoint:** `POST /query`

## Prerequisites

- [Go 1.23+](https://golang.org/dl/) installed on your machine
- Git
- (Optional) Docker (with Buildx enabled) if you want to build and run using containers

## Local Development

### 1. Clone the Repository

```bash
git clone https://github.com/InderPooni/vuln-scanner.git
cd vuln-scanner
go mod download
go run ./cmd/...
```

## Run with Docker without persistant volume

```bash
docker build -t vuln-scanner .
docker run -p 8080:8080 vuln-scanner
```


## Run with Docker with persistant volume

```bash
mkdir -p data
docker run -p 8080:8080 -v $(pwd)/data:/app/data vuln-scanner
```