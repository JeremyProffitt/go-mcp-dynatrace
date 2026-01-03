package dql

import (
	"github.com/dynatrace-oss/go-mcp-dynatrace/pkg/mcp"
)

// MCPResourceAdapter adapts ReferenceProvider to the mcp.ResourceProvider interface
type MCPResourceAdapter struct {
	provider *ReferenceProvider
}

// NewMCPResourceAdapter creates a new adapter for use with MCP server
func NewMCPResourceAdapter(provider *ReferenceProvider) *MCPResourceAdapter {
	return &MCPResourceAdapter{provider: provider}
}

// ListResources implements mcp.ResourceProvider
func (a *MCPResourceAdapter) ListResources() []mcp.Resource {
	resources := a.provider.ListResources()
	mcpResources := make([]mcp.Resource, len(resources))
	for i, r := range resources {
		mcpResources[i] = mcp.Resource{
			URI:         r.URI,
			Name:        r.Name,
			Description: r.Description,
			MimeType:    r.MimeType,
		}
	}
	return mcpResources
}

// ReadResource implements mcp.ResourceProvider
func (a *MCPResourceAdapter) ReadResource(uri string) (string, string, error) {
	return a.provider.ReadResource(uri)
}
