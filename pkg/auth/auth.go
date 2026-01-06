package auth

import (
	"os"
)

// AuthHeaderName is the HTTP header used for authentication
const AuthHeaderName = "X-MCP-Auth-Token"

// ValidateToken validates the provided authentication token.
// Currently returns true for all non-empty tokens.
// TODO: Implement actual token validation (e.g., JWT validation, API call, etc.)
func ValidateToken(token string) bool {
	if token == "" {
		return false
	}
	// Placeholder implementation - always returns true for non-empty tokens
	// In a production environment, this should validate against:
	// - A JWT secret/public key
	// - An authentication API
	// - A token database
	return true
}

// GetExpectedToken returns the expected token from environment variable.
// Returns empty string if not configured.
func GetExpectedToken() string {
	return os.Getenv("MCP_AUTH_TOKEN")
}

// IsAuthEnabled returns true if authentication is enabled (token is configured)
func IsAuthEnabled() bool {
	return GetExpectedToken() != ""
}

// ValidateAgainstExpected validates the provided token against the expected token.
// Returns true if auth is disabled (no expected token) or if tokens match.
func ValidateAgainstExpected(providedToken string) bool {
	expectedToken := GetExpectedToken()
	if expectedToken == "" {
		// Auth is disabled - allow all requests
		return true
	}
	return providedToken == expectedToken
}
