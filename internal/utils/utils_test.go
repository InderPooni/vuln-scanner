package utils

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateBaseURL(t *testing.T) {
	tests := []struct {
		input          string
		expectedPrefix string
		expectError    bool
	}{
		{
			input:          "https://github.com/velancio/vulnerability_scans",
			expectedPrefix: "https://raw.githubusercontent.com/velancio/vulnerability_scans/main",
			expectError:    false,
		},
		{
			input:          "velancio/vulnerability_scans",
			expectedPrefix: "https://raw.githubusercontent.com/velancio/vulnerability_scans/main",
			expectError:    false,
		},
		{
			input:       "invalidinput",
			expectError: true,
		},
	}

	for _, tc := range tests {
		prefix, err := GenerateBaseURL(tc.input)
		if tc.expectError {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			assert.Equal(t, tc.expectedPrefix, prefix)
		}
	}
}

func TestFetchWithRetry(t *testing.T) {
	const output string = "Hello, world!"
	// Create a test HTTP server that returns a known response
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(output))
	}))
	defer ts.Close()

	data, err := FetchWithExponentialBackoff(ts.URL, 3)
	require.NoError(t, err)
	assert.Equal(t, output, string(data))
}
