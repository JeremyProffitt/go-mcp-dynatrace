package dynatrace

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestTokenCache_SaveAndLoad(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir, err := os.MkdirTemp("", "token_cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cachePath := filepath.Join(tmpDir, ".dynatrace_token_cache.json")
	cache := NewTokenCacheWithPath(cachePath)

	environment := "https://abc12345.apps.dynatrace.com"
	clientID := "dt0c01.TESTCLIENT"
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"
	expiresAt := time.Now().Add(1 * time.Hour)

	// Save token
	err = cache.Save(token, environment, clientID, expiresAt)
	if err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	// Verify file exists with correct permissions
	info, err := os.Stat(cachePath)
	if err != nil {
		t.Fatalf("Cache file not created: %v", err)
	}
	// On Windows, file permissions work differently, so skip this check
	if runtime.GOOS != "windows" {
		if info.Mode().Perm()&0077 != 0 {
			t.Errorf("Cache file has insecure permissions: %v", info.Mode().Perm())
		}
	}

	// Load token
	cached := cache.Load(environment, clientID)
	if cached == nil {
		t.Fatal("Failed to load cached token")
	}

	if cached.AccessToken != token {
		t.Errorf("Token mismatch: got %q, want %q", cached.AccessToken, token)
	}
	if cached.Environment != environment {
		t.Errorf("Environment mismatch: got %q, want %q", cached.Environment, environment)
	}
	if cached.ClientID != clientID {
		t.Errorf("ClientID mismatch: got %q, want %q", cached.ClientID, clientID)
	}
}

func TestTokenCache_ExpiredToken(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "token_cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cachePath := filepath.Join(tmpDir, ".dynatrace_token_cache.json")
	cache := NewTokenCacheWithPath(cachePath)

	environment := "https://abc12345.apps.dynatrace.com"
	clientID := "dt0c01.TESTCLIENT"
	token := "expired_token"
	expiresAt := time.Now().Add(-1 * time.Hour) // Expired 1 hour ago

	// Save expired token
	err = cache.Save(token, environment, clientID, expiresAt)
	if err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	// Load should return nil for expired token
	cached := cache.Load(environment, clientID)
	if cached != nil {
		t.Error("Expected nil for expired token, got cached token")
	}
}

func TestTokenCache_MismatchedEnvironment(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "token_cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cachePath := filepath.Join(tmpDir, ".dynatrace_token_cache.json")
	cache := NewTokenCacheWithPath(cachePath)

	environment := "https://abc12345.apps.dynatrace.com"
	clientID := "dt0c01.TESTCLIENT"
	token := "test_token"
	expiresAt := time.Now().Add(1 * time.Hour)

	// Save token
	err = cache.Save(token, environment, clientID, expiresAt)
	if err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	// Load with different environment should return nil
	cached := cache.Load("https://different.apps.dynatrace.com", clientID)
	if cached != nil {
		t.Error("Expected nil for mismatched environment, got cached token")
	}

	// Load with different clientID should return nil
	cached = cache.Load(environment, "different_client_id")
	if cached != nil {
		t.Error("Expected nil for mismatched clientID, got cached token")
	}
}

func TestTokenCache_Clear(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "token_cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cachePath := filepath.Join(tmpDir, ".dynatrace_token_cache.json")
	cache := NewTokenCacheWithPath(cachePath)

	environment := "https://abc12345.apps.dynatrace.com"
	clientID := "dt0c01.TESTCLIENT"
	token := "test_token"
	expiresAt := time.Now().Add(1 * time.Hour)

	// Save token
	err = cache.Save(token, environment, clientID, expiresAt)
	if err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	// Clear cache
	err = cache.Clear()
	if err != nil {
		t.Fatalf("Failed to clear cache: %v", err)
	}

	// Load should return nil
	cached := cache.Load(environment, clientID)
	if cached != nil {
		t.Error("Expected nil after clear, got cached token")
	}

	// File should not exist
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Error("Cache file still exists after clear")
	}
}

func TestTokenCache_NonExistentFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "token_cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cachePath := filepath.Join(tmpDir, "nonexistent", ".dynatrace_token_cache.json")
	cache := NewTokenCacheWithPath(cachePath)

	// Load from non-existent file should return nil without error
	cached := cache.Load("https://test.apps.dynatrace.com", "client_id")
	if cached != nil {
		t.Error("Expected nil for non-existent file, got cached token")
	}
}

func TestTokenCache_30SecondBuffer(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "token_cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cachePath := filepath.Join(tmpDir, ".dynatrace_token_cache.json")
	cache := NewTokenCacheWithPath(cachePath)

	environment := "https://abc12345.apps.dynatrace.com"
	clientID := "dt0c01.TESTCLIENT"
	token := "almost_expired_token"
	// Token expires in 20 seconds, which is within the 30 second buffer
	expiresAt := time.Now().Add(20 * time.Second)

	// Save token
	err = cache.Save(token, environment, clientID, expiresAt)
	if err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	// Load should return nil because token is within 30 second expiry buffer
	cached := cache.Load(environment, clientID)
	if cached != nil {
		t.Error("Expected nil for token expiring within 30 seconds, got cached token")
	}
}
