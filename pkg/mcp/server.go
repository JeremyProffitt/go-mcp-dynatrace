package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// ToolHandler is a function that handles a tool call
type ToolHandler func(arguments map[string]interface{}) (*CallToolResult, error)

// ResourceProvider is an interface for providing MCP resources
type ResourceProvider interface {
	// ListResources returns the available resources
	ListResources() []Resource
	// ReadResource reads a resource by URI, returns content and mimeType
	ReadResource(uri string) (content string, mimeType string, err error)
}

// Server represents an MCP server
type Server struct {
	name     string
	version  string
	tools    []Tool
	handlers map[string]ToolHandler
	mu       sync.RWMutex
	stdin    io.Reader
	stdout   io.Writer
	stderr   io.Writer

	// Resources
	resourceProviders []ResourceProvider

	// Rate limiting
	toolCallTimestamps []time.Time
	rateLimitMu        sync.Mutex

	// Callbacks
	onToolCall func(name string, args map[string]interface{}, duration time.Duration, success bool)
	onError    func(err error, context string)
}

// NewServer creates a new MCP server
func NewServer(name, version string) *Server {
	return &Server{
		name:               name,
		version:            version,
		tools:              make([]Tool, 0),
		handlers:           make(map[string]ToolHandler),
		resourceProviders:  make([]ResourceProvider, 0),
		stdin:              os.Stdin,
		stdout:             os.Stdout,
		stderr:             os.Stderr,
		toolCallTimestamps: make([]time.Time, 0),
	}
}

// SetToolCallCallback sets a callback for tool calls (for telemetry)
func (s *Server) SetToolCallCallback(cb func(name string, args map[string]interface{}, duration time.Duration, success bool)) {
	s.onToolCall = cb
}

// SetErrorCallback sets a callback for errors
func (s *Server) SetErrorCallback(cb func(err error, context string)) {
	s.onError = cb
}

// RegisterTool registers a tool with its handler
func (s *Server) RegisterTool(tool Tool, handler ToolHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tools = append(s.tools, tool)
	s.handlers[tool.Name] = handler
}

// RegisterResourceProvider registers a resource provider
func (s *Server) RegisterResourceProvider(provider ResourceProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resourceProviders = append(s.resourceProviders, provider)
}

// checkRateLimit returns true if the request should be rate limited
func (s *Server) checkRateLimit() bool {
	s.rateLimitMu.Lock()
	defer s.rateLimitMu.Unlock()

	now := time.Now()
	twentySecondsAgo := now.Add(-20 * time.Second)

	// Remove old timestamps
	newTimestamps := make([]time.Time, 0)
	for _, ts := range s.toolCallTimestamps {
		if ts.After(twentySecondsAgo) {
			newTimestamps = append(newTimestamps, ts)
		}
	}
	s.toolCallTimestamps = newTimestamps

	// Check if we have 5 or more calls in the past 20s
	if len(s.toolCallTimestamps) >= 5 {
		return true
	}

	// Record this call
	s.toolCallTimestamps = append(s.toolCallTimestamps, now)
	return false
}

// Run starts the server in stdio mode
func (s *Server) Run() error {
	lines := make(chan string)
	errors := make(chan error)

	go func() {
		reader := bufio.NewReader(s.stdin)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					if line != "" {
						lines <- line
					}
					errors <- io.EOF
					return
				}
				errors <- err
				return
			}
			lines <- line
		}
	}()

	receivedData := false
	initialTimeout := time.After(30 * time.Second)

	for {
		select {
		case line := <-lines:
			receivedData = true
			line = trimLine(line)
			if line == "" {
				continue
			}

			response := s.handleMessage([]byte(line))
			if response != nil {
				s.sendResponse(response)
			}

		case err := <-errors:
			if err == io.EOF {
				if receivedData {
					return nil
				}
				return fmt.Errorf("stdin closed before receiving any data")
			}
			return fmt.Errorf("read error: %w", err)

		case <-initialTimeout:
			if !receivedData {
				initialTimeout = time.After(24 * time.Hour)
			}
		}
	}
}

// RunHTTP starts the server in HTTP mode
func (s *Server) RunHTTP(addr string) error {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      nil,
				"error":   map[string]interface{}{"code": -32700, "message": "Parse error"},
			})
			return
		}

		response := s.handleMessage(body)
		if response != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}
	})

	fmt.Fprintf(s.stderr, "Dynatrace MCP Server running on HTTP at %s\n", addr)
	return http.ListenAndServe(addr, nil)
}

func trimLine(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

func (s *Server) handleMessage(data []byte) *JSONRPCResponse {
	var request JSONRPCRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &JSONRPCError{
				Code:    ParseError,
				Message: "Parse error",
				Data:    err.Error(),
			},
		}
	}

	// Handle notifications (no ID)
	if request.ID == nil {
		s.handleNotification(&request)
		return nil
	}

	return s.handleRequest(&request)
}

func (s *Server) handleNotification(request *JSONRPCRequest) {
	switch request.Method {
	case "notifications/initialized":
		fmt.Fprintln(s.stderr, "Client initialized")
	case "notifications/cancelled":
		// Request cancellation
	}
}

func (s *Server) handleRequest(request *JSONRPCRequest) *JSONRPCResponse {
	response := &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      request.ID,
	}

	switch request.Method {
	case "initialize":
		response.Result = s.handleInitialize(request.Params)
	case "tools/list":
		response.Result = s.handleListTools()
	case "tools/call":
		result, err := s.handleCallTool(request.Params)
		if err != nil {
			response.Error = &JSONRPCError{
				Code:    InternalError,
				Message: err.Error(),
			}
		} else {
			response.Result = result
		}
	case "resources/list":
		response.Result = s.handleListResources()
	case "resources/read":
		result, err := s.handleReadResource(request.Params)
		if err != nil {
			response.Error = &JSONRPCError{
				Code:    InternalError,
				Message: err.Error(),
			}
		} else {
			response.Result = result
		}
	case "ping":
		response.Result = map[string]interface{}{}
	default:
		response.Error = &JSONRPCError{
			Code:    MethodNotFound,
			Message: fmt.Sprintf("Method not found: %s", request.Method),
		}
	}

	return response
}

func (s *Server) handleInitialize(params interface{}) *InitializeResult {
	capabilities := ServerCapabilities{
		Tools: &ToolsCapability{
			ListChanged: false,
		},
	}

	// Add resources capability if we have any resource providers
	s.mu.RLock()
	hasResources := len(s.resourceProviders) > 0
	s.mu.RUnlock()

	if hasResources {
		capabilities.Resources = &ResourcesCapability{
			Subscribe:   false,
			ListChanged: false,
		}
	}

	return &InitializeResult{
		ProtocolVersion: "2024-11-05",
		Capabilities:    capabilities,
		ServerInfo: ServerInfo{
			Name:    s.name,
			Version: s.version,
		},
	}
}

func (s *Server) handleListTools() *ListToolsResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return &ListToolsResult{
		Tools: s.tools,
	}
}

func (s *Server) handleListResources() *ListResourcesResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	resources := make([]Resource, 0)
	for _, provider := range s.resourceProviders {
		resources = append(resources, provider.ListResources()...)
	}

	return &ListResourcesResult{
		Resources: resources,
	}
}

func (s *Server) handleReadResource(params interface{}) (*ReadResourceResult, error) {
	paramsMap, ok := params.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid params type")
	}

	uri, ok := paramsMap["uri"].(string)
	if !ok {
		return nil, fmt.Errorf("missing resource URI")
	}

	s.mu.RLock()
	providers := s.resourceProviders
	s.mu.RUnlock()

	// Try each provider until we find one that can handle the URI
	for _, provider := range providers {
		content, mimeType, err := provider.ReadResource(uri)
		if err == nil {
			return &ReadResourceResult{
				Contents: []ResourceContent{
					{
						URI:      uri,
						MimeType: mimeType,
						Text:     content,
					},
				},
			}, nil
		}
	}

	return nil, fmt.Errorf("resource not found: %s", uri)
}

func (s *Server) handleCallTool(params interface{}) (*CallToolResult, error) {
	paramsMap, ok := params.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid params type")
	}

	name, ok := paramsMap["name"].(string)
	if !ok {
		return nil, fmt.Errorf("missing tool name")
	}

	arguments, _ := paramsMap["arguments"].(map[string]interface{})

	// Check rate limit
	if s.checkRateLimit() {
		return &CallToolResult{
			Content: []ContentItem{{Type: "text", Text: "Rate limit exceeded: Maximum 5 tool calls per 20 seconds. Please try again later."}},
			IsError: true,
		}, nil
	}

	s.mu.RLock()
	handler, exists := s.handlers[name]
	s.mu.RUnlock()

	if !exists {
		return &CallToolResult{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("Unknown tool: %s", name)}},
			IsError: true,
		}, nil
	}

	startTime := time.Now()
	result, err := handler(arguments)
	duration := time.Since(startTime)

	success := err == nil && (result == nil || !result.IsError)

	// Call telemetry callback
	if s.onToolCall != nil {
		s.onToolCall(name, arguments, duration, success)
	}

	if err != nil {
		if s.onError != nil {
			s.onError(err, fmt.Sprintf("tool_%s", name))
		}
		return &CallToolResult{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("Error: %s", err.Error())}},
			IsError: true,
		}, nil
	}

	return result, nil
}

func (s *Server) sendResponse(response *JSONRPCResponse) {
	data, err := json.Marshal(response)
	if err != nil {
		fmt.Fprintf(s.stderr, "Error marshaling response: %v\n", err)
		return
	}
	fmt.Fprintln(s.stdout, string(data))
}

// Log writes a message to stderr for debugging
func (s *Server) Log(format string, args ...interface{}) {
	fmt.Fprintf(s.stderr, format+"\n", args...)
}
