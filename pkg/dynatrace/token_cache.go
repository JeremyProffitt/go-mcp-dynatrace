package dynatrace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dynatrace-oss/go-mcp-dynatrace/pkg/logging"
)

const (
	tokenCacheFilename = ".dynatrace_token_cache.json"
)

// CachedToken represents a cached OAuth token
type CachedToken struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
	Environment string    `json:"environment"` // Used to validate cache matches current env
	ClientID    string    `json:"client_id"`   // Used to validate cache matches current client
}

// TokenCache handles persistent storage of OAuth tokens
type TokenCache struct {
	mu       sync.RWMutex
	filePath string
}

// NewTokenCache creates a new token cache
// The cache file is stored in the same directory as the executable
func NewTokenCache() *TokenCache {
	// Get the executable directory
	exePath, err := os.Executable()
	if err != nil {
		logging.Debug("TOKEN_CACHE failed to get executable path: %v, using current directory", err)
		exePath = "."
	}
	exeDir := filepath.Dir(exePath)

	return &TokenCache{
		filePath: filepath.Join(exeDir, tokenCacheFilename),
	}
}

// NewTokenCacheWithPath creates a token cache with a specific file path
func NewTokenCacheWithPath(filePath string) *TokenCache {
	return &TokenCache{
		filePath: filePath,
	}
}

// Load attempts to load a cached token from disk
// Returns nil if no valid cache exists or if the token has expired
func (tc *TokenCache) Load(environment, clientID string) *CachedToken {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	data, err := os.ReadFile(tc.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			logging.Debug("TOKEN_CACHE failed to read cache file: %v", err)
		}
		return nil
	}

	var cached CachedToken
	if err := json.Unmarshal(data, &cached); err != nil {
		logging.Debug("TOKEN_CACHE failed to parse cache file: %v", err)
		return nil
	}

	// Validate cache matches current configuration
	if cached.Environment != environment || cached.ClientID != clientID {
		logging.Debug("TOKEN_CACHE cache mismatch (env or client_id changed)")
		return nil
	}

	// Check if token is still valid (with 30 second buffer)
	if time.Now().Add(30 * time.Second).After(cached.ExpiresAt) {
		logging.Debug("TOKEN_CACHE cached token expired at %s", cached.ExpiresAt.Format(time.RFC3339))
		return nil
	}

	remainingTime := time.Until(cached.ExpiresAt)
	logging.Debug("TOKEN_CACHE loaded valid token (expires in %s)", remainingTime.Round(time.Second))
	return &cached
}

// Save persists a token to disk
func (tc *TokenCache) Save(token, environment, clientID string, expiresAt time.Time) error {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	cached := CachedToken{
		AccessToken: token,
		ExpiresAt:   expiresAt,
		Environment: environment,
		ClientID:    clientID,
	}

	data, err := json.MarshalIndent(cached, "", "  ")
	if err != nil {
		return err
	}

	// Write with restricted permissions (owner read/write only)
	if err := os.WriteFile(tc.filePath, data, 0600); err != nil {
		logging.Debug("TOKEN_CACHE failed to write cache file: %v", err)
		return err
	}

	logging.Debug("TOKEN_CACHE saved token (expires at %s)", expiresAt.Format(time.RFC3339))
	return nil
}

// Clear removes the cached token file
func (tc *TokenCache) Clear() error {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if err := os.Remove(tc.filePath); err != nil && !os.IsNotExist(err) {
		return err
	}

	logging.Debug("TOKEN_CACHE cleared")
	return nil
}

// FilePath returns the path to the cache file
func (tc *TokenCache) FilePath() string {
	return tc.filePath
}
