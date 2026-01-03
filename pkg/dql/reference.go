// Package dql provides Dynatrace Query Language reference documentation
// that can be exposed through MCP resources.
package dql

import (
	_ "embed"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/dynatrace-oss/go-mcp-dynatrace/pkg/logging"
)

const (
	// CustomReferenceFilename is the name of the optional custom reference file
	// that extends the built-in reference. Place this file in the same directory
	// as the executable to add custom DQL patterns, queries, and documentation.
	CustomReferenceFilename = "dynatrace-language-custom.md"

	// ReferenceFilename is the name of the optional full reference override file.
	// If this file exists, it completely replaces the built-in reference.
	ReferenceFilename = "dynatrace-language-reference.md"
)

//go:embed reference.md
var embeddedReference string

//go:embed rule.md
var embeddedRule string

// ReferenceProvider manages access to DQL reference documentation
type ReferenceProvider struct {
	mu            sync.RWMutex
	cachedRef     string
	cachedRule    string
	executableDir string
	initialized   bool
}

// NewReferenceProvider creates a new reference provider
func NewReferenceProvider() *ReferenceProvider {
	exePath, err := os.Executable()
	if err != nil {
		logging.Debug("DQL_REFERENCE failed to get executable path: %v", err)
		exePath = "."
	}

	return &ReferenceProvider{
		executableDir: filepath.Dir(exePath),
	}
}

// GetReference returns the complete DQL language reference.
// It combines the embedded default with any custom extensions found
// in the executable directory.
//
// Loading order:
// 1. Check for full override file (dynatrace-language-reference.md)
//    - If exists, use it entirely and skip embedded
// 2. Use embedded default reference
// 3. Append custom extensions (dynatrace-language-custom.md) if exists
func (p *ReferenceProvider) GetReference() string {
	p.mu.RLock()
	if p.initialized && p.cachedRef != "" {
		defer p.mu.RUnlock()
		return p.cachedRef
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if p.initialized && p.cachedRef != "" {
		return p.cachedRef
	}

	var result strings.Builder

	// Check for full override
	overridePath := filepath.Join(p.executableDir, ReferenceFilename)
	if content, err := os.ReadFile(overridePath); err == nil {
		logging.Info("DQL_REFERENCE loaded override from %s (%d bytes)", overridePath, len(content))
		result.Write(content)
	} else {
		// Use embedded default
		result.WriteString(embeddedReference)
		logging.Debug("DQL_REFERENCE using embedded default (%d bytes)", len(embeddedReference))

		// Check for custom extensions
		customPath := filepath.Join(p.executableDir, CustomReferenceFilename)
		if content, err := os.ReadFile(customPath); err == nil {
			logging.Info("DQL_REFERENCE loaded custom extensions from %s (%d bytes)", customPath, len(content))
			result.WriteString("\n\n---\n\n")
			result.WriteString("# Custom DQL Reference Extensions\n\n")
			result.WriteString("*The following content is loaded from custom extensions.*\n\n")
			result.Write(content)
		}
	}

	p.cachedRef = result.String()
	p.initialized = true
	return p.cachedRef
}

// GetRule returns the DQL rule for AI assistants (continue.dev format)
func (p *ReferenceProvider) GetRule() string {
	p.mu.RLock()
	if p.cachedRule != "" {
		defer p.mu.RUnlock()
		return p.cachedRule
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if p.cachedRule != "" {
		return p.cachedRule
	}

	// Check for override
	overridePath := filepath.Join(p.executableDir, "dynatrace-language-rule.md")
	if content, err := os.ReadFile(overridePath); err == nil {
		logging.Info("DQL_RULE loaded override from %s (%d bytes)", overridePath, len(content))
		p.cachedRule = string(content)
	} else {
		p.cachedRule = embeddedRule
		logging.Debug("DQL_RULE using embedded default (%d bytes)", len(embeddedRule))
	}

	return p.cachedRule
}

// Reload clears the cache and forces a reload from files
func (p *ReferenceProvider) Reload() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cachedRef = ""
	p.cachedRule = ""
	p.initialized = false
	logging.Debug("DQL_REFERENCE cache cleared, will reload on next access")
}

// GetCustomFilePath returns the path where custom extensions should be placed
func (p *ReferenceProvider) GetCustomFilePath() string {
	return filepath.Join(p.executableDir, CustomReferenceFilename)
}

// GetOverrideFilePath returns the path where the full override should be placed
func (p *ReferenceProvider) GetOverrideFilePath() string {
	return filepath.Join(p.executableDir, ReferenceFilename)
}

// HasCustomExtensions returns true if a custom extensions file exists
func (p *ReferenceProvider) HasCustomExtensions() bool {
	customPath := filepath.Join(p.executableDir, CustomReferenceFilename)
	_, err := os.Stat(customPath)
	return err == nil
}

// HasOverride returns true if a full override file exists
func (p *ReferenceProvider) HasOverride() bool {
	overridePath := filepath.Join(p.executableDir, ReferenceFilename)
	_, err := os.Stat(overridePath)
	return err == nil
}

// ResourceInfo contains information about available DQL resources
type ResourceInfo struct {
	URI         string
	Name        string
	Description string
	MimeType    string
}

// ListResources returns the available DQL reference resources
func (p *ReferenceProvider) ListResources() []ResourceInfo {
	resources := []ResourceInfo{
		{
			URI:         "dql://reference",
			Name:        "DQL Language Reference",
			Description: "Comprehensive Dynatrace Query Language (DQL) reference documentation",
			MimeType:    "text/markdown",
		},
		{
			URI:         "dql://rule",
			Name:        "DQL Assistant Rule",
			Description: "DQL rule for AI assistants (continue.dev format)",
			MimeType:    "text/markdown",
		},
	}

	// Add info about customization
	if p.HasOverride() {
		resources[0].Description += " (using custom override)"
	} else if p.HasCustomExtensions() {
		resources[0].Description += " (with custom extensions)"
	}

	return resources
}

// ReadResource reads a DQL resource by URI
func (p *ReferenceProvider) ReadResource(uri string) (string, string, error) {
	switch uri {
	case "dql://reference":
		return p.GetReference(), "text/markdown", nil
	case "dql://rule":
		return p.GetRule(), "text/markdown", nil
	default:
		return "", "", &ResourceNotFoundError{URI: uri}
	}
}

// ResourceNotFoundError is returned when a requested resource doesn't exist
type ResourceNotFoundError struct {
	URI string
}

func (e *ResourceNotFoundError) Error() string {
	return "resource not found: " + e.URI
}

// MCPResource is an MCP-compatible resource representation
type MCPResource struct {
	URI         string
	Name        string
	Description string
	MimeType    string
}

// ListMCPResources returns resources in MCP format
func (p *ReferenceProvider) ListMCPResources() []MCPResource {
	resources := p.ListResources()
	mcpResources := make([]MCPResource, len(resources))
	for i, r := range resources {
		mcpResources[i] = MCPResource{
			URI:         r.URI,
			Name:        r.Name,
			Description: r.Description,
			MimeType:    r.MimeType,
		}
	}
	return mcpResources
}
