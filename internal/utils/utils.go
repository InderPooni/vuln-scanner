package utils

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GenerateBaseURL converts a GitHub repository URL or an "owner/repo" string
// to the raw URL prefix
// Example:
//
// "https://github.com/velancio/vulnerability_scans" ->
// "https://raw.githubusercontent.com/velancio/vulnerability_scans/main"
// "velancio/vulnerability_scans" becomes the same
func GenerateBaseURL(input string) (string, error) {
	var owner, repo string

	// Check if the input starts with "http(s)://" to determine if it's a URL
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		parsed, err := url.Parse(input)
		if err != nil {
			return "", err
		}
		parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		if len(parts) < 2 {
			return "", errors.New("repository URL must include owner and repo")
		}
		owner = parts[0]
		repo = parts[1]
	} else {
		// Assume the input is in the "owner/repo" format
		parts := strings.Split(strings.TrimSpace(input), "/")
		if len(parts) != 2 {
			return "", errors.New("input must be a valid GitHub URL or in the format owner/repo")
		}
		owner = parts[0]
		repo = parts[1]
	}

	// Assume branch "main". Adjust if needed.
	rawPrefix := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/main", owner, repo)
	return rawPrefix, nil
}

const requestTimeout = 10 * time.Second

// FetchWithRetry performs an HTTP GET on the URL with retry logic
func FetchWithExponentialBackoff(url string, attempts int) ([]byte, error) {
	var lastErr error
	client := &http.Client{Timeout: requestTimeout}
	delay := 2 * time.Second

	for i := 0; i < attempts; i++ {
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
		} else if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
			resp.Body.Close()
		} else {
			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				lastErr = err
			} else {
				return data, nil // Success: return the data.
			}
		}

		// Sleep for the current delay duration before retrying.
		time.Sleep(delay)
		// Exponentially increase the delay (e.g., double it)
		delay *= 2
	}

	return nil, lastErr
}
