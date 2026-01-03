package dql

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedReference(t *testing.T) {
	if embeddedReference == "" {
		t.Error("Embedded reference should not be empty")
	}

	// Verify it contains key DQL documentation sections
	requiredSections := []string{
		"Dynatrace Query Language",
		"fetch",
		"filter",
		"summarize",
		"Data Types",
		"Operators",
	}

	for _, section := range requiredSections {
		if !strings.Contains(embeddedReference, section) {
			t.Errorf("Embedded reference should contain section: %s", section)
		}
	}
}

func TestEmbeddedRule(t *testing.T) {
	if embeddedRule == "" {
		t.Error("Embedded rule should not be empty")
	}

	// Verify it contains key rule content
	if !strings.Contains(embeddedRule, "DQL") {
		t.Error("Embedded rule should mention DQL")
	}
}

func TestReferenceProvider_GetReference(t *testing.T) {
	provider := NewReferenceProvider()
	ref := provider.GetReference()

	if ref == "" {
		t.Error("GetReference should return non-empty content")
	}

	// Verify embedded content is included
	if !strings.Contains(ref, "Dynatrace Query Language") {
		t.Error("Reference should contain DQL documentation")
	}
}

func TestReferenceProvider_GetRule(t *testing.T) {
	provider := NewReferenceProvider()
	rule := provider.GetRule()

	if rule == "" {
		t.Error("GetRule should return non-empty content")
	}
}

func TestReferenceProvider_ListResources(t *testing.T) {
	provider := NewReferenceProvider()
	resources := provider.ListResources()

	if len(resources) != 2 {
		t.Errorf("Expected 2 resources, got %d", len(resources))
	}

	// Check for expected URIs
	uris := make(map[string]bool)
	for _, r := range resources {
		uris[r.URI] = true
	}

	if !uris["dql://reference"] {
		t.Error("Should have dql://reference resource")
	}
	if !uris["dql://rule"] {
		t.Error("Should have dql://rule resource")
	}
}

func TestReferenceProvider_ReadResource(t *testing.T) {
	provider := NewReferenceProvider()

	// Test reading reference
	content, mimeType, err := provider.ReadResource("dql://reference")
	if err != nil {
		t.Errorf("Failed to read reference: %v", err)
	}
	if mimeType != "text/markdown" {
		t.Errorf("Expected text/markdown, got %s", mimeType)
	}
	if content == "" {
		t.Error("Reference content should not be empty")
	}

	// Test reading rule
	content, mimeType, err = provider.ReadResource("dql://rule")
	if err != nil {
		t.Errorf("Failed to read rule: %v", err)
	}
	if mimeType != "text/markdown" {
		t.Errorf("Expected text/markdown, got %s", mimeType)
	}
	if content == "" {
		t.Error("Rule content should not be empty")
	}

	// Test invalid URI
	_, _, err = provider.ReadResource("dql://invalid")
	if err == nil {
		t.Error("Should return error for invalid URI")
	}
	if _, ok := err.(*ResourceNotFoundError); !ok {
		t.Error("Should return ResourceNotFoundError")
	}
}

func TestReferenceProvider_CustomExtensions(t *testing.T) {
	// Create a temp directory to simulate executable directory
	tmpDir, err := os.MkdirTemp("", "dql_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a custom extensions file
	customContent := "# My Custom DQL Patterns\n\n" +
		"## Custom Query: Error Rate by Service\n\n" +
		"```dql\n" +
		"fetch logs\n" +
		"| filter loglevel == \"ERROR\"\n" +
		"| summarize count(), by: {service.name}\n" +
		"```\n"
	customPath := filepath.Join(tmpDir, CustomReferenceFilename)
	if err := os.WriteFile(customPath, []byte(customContent), 0644); err != nil {
		t.Fatalf("Failed to write custom file: %v", err)
	}

	// Create provider with custom directory
	provider := &ReferenceProvider{
		executableDir: tmpDir,
	}

	// Verify custom extensions are detected
	if !provider.HasCustomExtensions() {
		t.Error("Should detect custom extensions file")
	}

	// Verify custom content is appended
	ref := provider.GetReference()
	if !strings.Contains(ref, "My Custom DQL Patterns") {
		t.Error("Reference should include custom extensions content")
	}
	if !strings.Contains(ref, "Custom DQL Reference Extensions") {
		t.Error("Reference should include custom extensions header")
	}

	// Verify embedded content is still present
	if !strings.Contains(ref, "Dynatrace Query Language") {
		t.Error("Reference should still include embedded content")
	}
}

func TestReferenceProvider_FullOverride(t *testing.T) {
	// Create a temp directory
	tmpDir, err := os.MkdirTemp("", "dql_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a full override file
	overrideContent := `# Custom DQL Reference

This completely replaces the default reference.

## Custom Section
Custom content only.
`
	overridePath := filepath.Join(tmpDir, ReferenceFilename)
	if err := os.WriteFile(overridePath, []byte(overrideContent), 0644); err != nil {
		t.Fatalf("Failed to write override file: %v", err)
	}

	// Create provider with custom directory
	provider := &ReferenceProvider{
		executableDir: tmpDir,
	}

	// Verify override is detected
	if !provider.HasOverride() {
		t.Error("Should detect override file")
	}

	// Verify override content is used
	ref := provider.GetReference()
	if !strings.Contains(ref, "Custom DQL Reference") {
		t.Error("Reference should use override content")
	}
	if !strings.Contains(ref, "This completely replaces") {
		t.Error("Reference should include override content")
	}

	// Verify embedded content is NOT present (overridden)
	if strings.Contains(ref, "Query Structure and Syntax") {
		t.Error("Reference should NOT include embedded content when override exists")
	}
}

func TestReferenceProvider_Reload(t *testing.T) {
	provider := NewReferenceProvider()

	// First load
	ref1 := provider.GetReference()
	if ref1 == "" {
		t.Error("First load should return content")
	}

	// Reload should clear cache
	provider.Reload()

	// Check that initialized is reset
	provider.mu.RLock()
	initialized := provider.initialized
	cached := provider.cachedRef
	provider.mu.RUnlock()

	if initialized {
		t.Error("Reload should reset initialized flag")
	}
	if cached != "" {
		t.Error("Reload should clear cached content")
	}

	// Second load should work
	ref2 := provider.GetReference()
	if ref2 == "" {
		t.Error("Second load should return content")
	}
}

func TestMCPResourceAdapter(t *testing.T) {
	provider := NewReferenceProvider()
	adapter := NewMCPResourceAdapter(provider)

	// Test ListResources
	resources := adapter.ListResources()
	if len(resources) != 2 {
		t.Errorf("Expected 2 resources, got %d", len(resources))
	}

	// Verify resource fields are properly mapped
	for _, r := range resources {
		if r.URI == "" {
			t.Error("Resource URI should not be empty")
		}
		if r.Name == "" {
			t.Error("Resource Name should not be empty")
		}
		if r.MimeType != "text/markdown" {
			t.Errorf("Expected text/markdown, got %s", r.MimeType)
		}
	}

	// Test ReadResource
	content, mimeType, err := adapter.ReadResource("dql://reference")
	if err != nil {
		t.Errorf("ReadResource failed: %v", err)
	}
	if content == "" {
		t.Error("Content should not be empty")
	}
	if mimeType != "text/markdown" {
		t.Errorf("Expected text/markdown, got %s", mimeType)
	}
}
