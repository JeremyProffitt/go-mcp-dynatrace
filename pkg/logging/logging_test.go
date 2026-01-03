package logging

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty string", "", ""},
		{"short token (4 chars)", "abcd", "xxxabcd"},
		{"short token (3 chars)", "abc", "xxxabc"},
		{"normal token", "mysecrettoken123", "xxxn123"},
		{"long token", "dt0c01.ABCDEFGHIJKLMNOPQRSTUVWXYZ.1234567890abcdefghij", "xxxghij"},
		{"bearer token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0", "xxxwIn0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskSecret(tt.input)
			if result != tt.expected {
				t.Errorf("MaskSecret(%q) = %q, want %q", tt.input, result, tt.expected)
			}
			// Verify last 4 chars are preserved (if input is long enough)
			if len(tt.input) >= 4 && !strings.HasSuffix(result, tt.input[len(tt.input)-4:]) {
				t.Errorf("MaskSecret(%q) should end with last 4 chars of input", tt.input)
			}
		})
	}
}

func TestSanitizePII(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"SSN with dashes", "My SSN is 123-45-6789", "My SSN is [SSN-REDACTED]"},
		{"SSN without dashes", "SSN: 123456789", "SSN: [SSN-REDACTED]"},
		{"credit card with spaces", "Card: 4111 1111 1111 1111", "Card: [PAN-REDACTED]"},
		{"credit card with dashes", "Card: 4111-1111-1111-1111", "Card: [PAN-REDACTED]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizePII(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizePII(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizePII_JSONTokens(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{
			"access_token in JSON",
			`{"access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.xyz", "token_type": "Bearer"}`,
			`"access_token": "xxx.xyz"`,
		},
		{
			"token in JSON",
			`{"token": "secret123456"}`,
			`"token": "xxx3456"`,
		},
		{
			"api_key in JSON",
			`{"api_key": "dt0c01.ABCDEFGH.12345678"}`,
			`"api_key": "xxx5678"`,
		},
		{
			"password in JSON",
			`{"username": "admin", "password": "supersecret123"}`,
			`"password": "xxxt123"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizePII(tt.input)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("SanitizePII(%q) should contain %q, got %q", tt.input, tt.contains, result)
			}
		})
	}
}

func TestSanitizeAndMaskSecrets(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		secrets []string
		check   func(result string) bool
	}{
		{
			"mask client ID",
			"client_id=myclientid12345&client_secret=mysecret",
			[]string{"myclientid12345"},
			func(result string) bool {
				return strings.Contains(result, "xxx2345") && !strings.Contains(result, "myclientid12345")
			},
		},
		{
			"mask multiple secrets",
			"id=abc123 secret=xyz789",
			[]string{"abc123", "xyz789"},
			func(result string) bool {
				return strings.Contains(result, "xxxc123") && strings.Contains(result, "xxxz789")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeAndMaskSecrets(tt.input, tt.secrets...)
			if !tt.check(result) {
				t.Errorf("SanitizeAndMaskSecrets unexpected result: %q", result)
			}
		})
	}
}

func TestSanitizeHeaders(t *testing.T) {
	headers := map[string]string{
		"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test1234",
		"Content-Type":  "application/json",
		"X-Api-Key":     "dt0c01.ABCDEFGH.12345678",
	}

	result := sanitizeHeaders(headers)

	// Authorization should be masked
	if !strings.HasPrefix(result["Authorization"], "xxx") {
		t.Errorf("Authorization header should be masked, got: %s", result["Authorization"])
	}
	if !strings.HasSuffix(result["Authorization"], "1234") {
		t.Errorf("Authorization header should show last 4 chars, got: %s", result["Authorization"])
	}

	// Content-Type should not be masked
	if result["Content-Type"] != "application/json" {
		t.Errorf("Content-Type should not be masked, got: %s", result["Content-Type"])
	}

	// X-Api-Key should be masked
	if !strings.HasPrefix(result["X-Api-Key"], "xxx") {
		t.Errorf("X-Api-Key should be masked, got: %s", result["X-Api-Key"])
	}
}

func TestLogHTTPRequest(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		level:  LevelDebug,
		logger: log.New(&buf, "", 0),
	}

	req := &HTTPRequestInfo{
		Method: "POST",
		URL:    "https://sso.dynatrace.com/sso/oauth2/token",
		Headers: map[string]string{
			"Authorization": "Bearer eyJtoken123456789",
			"Content-Type":  "application/json",
		},
		Body: `{"client_id": "myclientid", "client_secret": "mysupersecret123"}`,
	}

	logger.LogHTTPRequest("test_request", req, "mysupersecret123")

	output := buf.String()

	// Token in Authorization should be masked
	if strings.Contains(output, "eyJtoken123456789") {
		t.Errorf("Full token should not appear in log output")
	}

	// Secret in body should be masked
	if strings.Contains(output, "mysupersecret123") {
		t.Errorf("Secret should not appear in log output")
	}

	// Last 4 chars should appear (Authorization ends in 6789, secret ends in t123)
	if !strings.Contains(output, "xxx6789") && !strings.Contains(output, "xxxt123") {
		t.Logf("Output: %s", output)
		t.Errorf("Masked value with last 4 chars should appear in log")
	}
}

func TestLogHTTPResponse(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		level:  LevelDebug,
		logger: log.New(&buf, "", 0),
	}

	resp := &HTTPResponseInfo{
		StatusCode: 200,
		Headers: map[string]string{
			"X-Token": "responsetoken12345",
		},
		Body: `{"access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.abcd1234", "expires_in": 3600}`,
	}

	logger.LogHTTPResponse("test_response", resp, 100*time.Millisecond)

	output := buf.String()

	// access_token in body should be masked (JSON pattern)
	if strings.Contains(output, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.abcd1234") {
		t.Errorf("Full access_token should not appear in log output: %s", output)
	}

	// Should contain masked version with last 4 chars
	if !strings.Contains(output, "access_token") {
		t.Errorf("access_token key should still appear in log")
	}
}

func TestLoggerLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		level:  LevelInfo, // Only INFO and above, not DEBUG
		logger: log.New(&buf, "", 0),
	}

	req := &HTTPRequestInfo{
		Method: "GET",
		URL:    "https://example.com/api",
	}

	// This should NOT log because level is INFO, not DEBUG
	logger.LogHTTPRequest("test", req)

	output := buf.String()
	if output != "" {
		t.Errorf("LogHTTPRequest should not log at INFO level, got: %s", output)
	}

	// Set to DEBUG level
	logger.level = LevelDebug
	logger.LogHTTPRequest("test", req)

	output = buf.String()
	if output == "" {
		t.Errorf("LogHTTPRequest should log at DEBUG level")
	}
}
