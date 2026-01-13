package auth

import (
	"context"
	"net/http"
)

// Authorizer defines the interface for request authorization
type Authorizer interface {
	Authorize(ctx context.Context, token string) (bool, error)
}

// MockAuthorizer is a mock implementation that always authorizes
type MockAuthorizer struct{}

// Authorize always returns true for MockAuthorizer
func (m *MockAuthorizer) Authorize(ctx context.Context, token string) (bool, error) {
	return true, nil
}

// DefaultAuthorizer is the authorizer used by the HTTP middleware
var DefaultAuthorizer Authorizer = &MockAuthorizer{}

// SetAuthorizer sets the default authorizer for the middleware
func SetAuthorizer(a Authorizer) {
	DefaultAuthorizer = a
}

// AuthMiddleware wraps an http.Handler with authorization checking
// It skips authorization for the /health endpoint
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health endpoint
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		// Get authorization header
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, `{"error":"missing Authorization header"}`, http.StatusUnauthorized)
			return
		}

		// Call authorizer
		authorized, err := DefaultAuthorizer.Authorize(r.Context(), token)
		if err != nil {
			http.Error(w, `{"error":"authorization failed"}`, http.StatusInternalServerError)
			return
		}

		if !authorized {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
