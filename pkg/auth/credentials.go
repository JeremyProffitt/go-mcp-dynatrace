package auth

import (
	"context"
	"net/http"
)

// Header names for Dynatrace credentials
const (
	HeaderOAuthClientID     = "X-DT-OAuth-Client-Id"
	HeaderOAuthClientSecret = "X-DT-OAuth-Client-Secret"
	HeaderAccountURN        = "X-DT-Account-URN"
)

// DTCredentials holds Dynatrace OAuth credentials from request headers
type DTCredentials struct {
	OAuthClientID     string
	OAuthClientSecret string
	AccountURN        string
}

// contextKey is a type for context keys to avoid collisions
type contextKey string

const dtCredentialsKey contextKey = "dt_credentials"

// CredentialsFromContext retrieves DTCredentials from the context
// Returns nil if no credentials are present
func CredentialsFromContext(ctx context.Context) *DTCredentials {
	if creds, ok := ctx.Value(dtCredentialsKey).(*DTCredentials); ok {
		return creds
	}
	return nil
}

// ContextWithCredentials adds DTCredentials to the context
func ContextWithCredentials(ctx context.Context, creds *DTCredentials) context.Context {
	return context.WithValue(ctx, dtCredentialsKey, creds)
}

// CredentialsMiddleware extracts Dynatrace credentials from request headers
// and adds them to the request context. If headers are present, they take
// precedence over environment variables.
func CredentialsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID := r.Header.Get(HeaderOAuthClientID)
		clientSecret := r.Header.Get(HeaderOAuthClientSecret)
		accountURN := r.Header.Get(HeaderAccountURN)

		// Only add credentials to context if at least one header is present
		if clientID != "" || clientSecret != "" || accountURN != "" {
			creds := &DTCredentials{
				OAuthClientID:     clientID,
				OAuthClientSecret: clientSecret,
				AccountURN:        accountURN,
			}
			r = r.WithContext(ContextWithCredentials(r.Context(), creds))
		}

		next.ServeHTTP(w, r)
	})
}
