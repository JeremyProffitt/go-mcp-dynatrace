package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dynatrace-oss/go-mcp-dynatrace/pkg/auth"
)

// createTestServer creates an MCP server wrapped with auth middleware for testing
func createTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()

	// Create MCP server
	server := NewServer("Test MCP Server", "1.0.0-test")

	// Register a simple test tool
	server.RegisterTool(Tool{
		Name:        "test_tool",
		Description: "A test tool for integration testing",
		InputSchema: JSONSchema{
			Type: "object",
			Properties: map[string]Property{
				"message": {
					Type:        "string",
					Description: "A test message",
				},
			},
		},
	}, func(arguments map[string]interface{}) (*CallToolResult, error) {
		msg, _ := arguments["message"].(string)
		if msg == "" {
			msg = "default message"
		}
		return &CallToolResult{
			Content: []ContentItem{{Type: "text", Text: "Echo: " + msg}},
		}, nil
	})

	// Set up HTTP handlers
	mux := http.NewServeMux()

	// Health check endpoint (no auth required)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"version": server.version,
		})
	})

	// MCP endpoint
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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

		response := server.handleMessage(body)
		if response != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}
	})

	// Wrap with auth middleware
	handler := auth.AuthMiddleware(mux)

	// Create test server
	testServer := httptest.NewServer(handler)

	return server, testServer
}

func TestHTTPHealthEndpoint(t *testing.T) {
	_, testServer := createTestServer(t)
	defer testServer.Close()

	// Send GET request to /health
	resp, err := http.Get(testServer.URL + "/health")
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}

	// Parse response body
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("Failed to parse response body: %v", err)
	}

	// Check response fields
	if status, ok := body["status"].(string); !ok || status != "ok" {
		t.Errorf("Expected status 'ok', got '%v'", body["status"])
	}

	if _, ok := body["version"].(string); !ok {
		t.Errorf("Expected version to be a string, got '%v'", body["version"])
	}
}

func TestHTTPAuthMiddleware_MissingHeader(t *testing.T) {
	_, testServer := createTestServer(t)
	defer testServer.Close()

	// Create JSON-RPC request
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}
	reqBody, _ := json.Marshal(request)

	// Send POST request without Authorization header
	resp, err := http.Post(testServer.URL+"/", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check status code - should be 401 Unauthorized
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}

	// Read response body
	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	// Check that response contains error message about missing Authorization
	if bodyStr == "" {
		t.Error("Expected non-empty error response body")
	}
}

func TestHTTPAuthMiddleware_WithHeader(t *testing.T) {
	_, testServer := createTestServer(t)
	defer testServer.Close()

	// Ensure MockAuthorizer is used (it always authorizes)
	auth.SetAuthorizer(&auth.MockAuthorizer{})

	// Create JSON-RPC request
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "ping",
	}
	reqBody, _ := json.Marshal(request)

	// Create request with Authorization header
	req, err := http.NewRequest(http.MethodPost, testServer.URL+"/", bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check status code - should be 200 OK (auth passed)
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Errorf("Expected status 200, got %d. Body: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	var response JSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Check that we got a valid JSON-RPC response (not an error)
	if response.Error != nil {
		t.Errorf("Expected no error, got: %v", response.Error)
	}
}

func TestHTTPMCPInitialize(t *testing.T) {
	_, testServer := createTestServer(t)
	defer testServer.Close()

	// Ensure MockAuthorizer is used
	auth.SetAuthorizer(&auth.MockAuthorizer{})

	// Create initialize request
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "test-client",
				"version": "1.0.0",
			},
		},
	}
	reqBody, _ := json.Marshal(request)

	// Create request with Authorization header
	req, err := http.NewRequest(http.MethodPost, testServer.URL+"/", bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d. Body: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	var response JSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Check for errors
	if response.Error != nil {
		t.Fatalf("Expected no error, got: code=%d, message=%s", response.Error.Code, response.Error.Message)
	}

	// Check response structure
	if response.JSONRPC != "2.0" {
		t.Errorf("Expected JSONRPC '2.0', got '%s'", response.JSONRPC)
	}

	if response.ID == nil {
		t.Error("Expected ID to be set")
	}

	// Check result structure
	result, ok := response.Result.(*InitializeResult)
	if !ok {
		// Result might be a map from JSON unmarshaling
		resultMap, ok := response.Result.(map[string]interface{})
		if !ok {
			t.Fatalf("Expected result to be InitializeResult or map, got %T", response.Result)
		}

		// Check required fields in map
		if protocolVersion, ok := resultMap["protocolVersion"].(string); !ok || protocolVersion == "" {
			t.Error("Expected protocolVersion in result")
		}

		if serverInfo, ok := resultMap["serverInfo"].(map[string]interface{}); ok {
			if name, ok := serverInfo["name"].(string); !ok || name == "" {
				t.Error("Expected serverInfo.name in result")
			}
			if version, ok := serverInfo["version"].(string); !ok || version == "" {
				t.Error("Expected serverInfo.version in result")
			}
		} else {
			t.Error("Expected serverInfo in result")
		}

		if _, ok := resultMap["capabilities"].(map[string]interface{}); !ok {
			t.Error("Expected capabilities in result")
		}
	} else {
		// Direct type assertion worked
		if result.ProtocolVersion == "" {
			t.Error("Expected protocolVersion to be set")
		}
		if result.ServerInfo.Name == "" {
			t.Error("Expected serverInfo.name to be set")
		}
	}
}

func TestHTTPMCPToolsList(t *testing.T) {
	_, testServer := createTestServer(t)
	defer testServer.Close()

	// Ensure MockAuthorizer is used
	auth.SetAuthorizer(&auth.MockAuthorizer{})

	// Create tools/list request
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}
	reqBody, _ := json.Marshal(request)

	// Create request with Authorization header
	req, err := http.NewRequest(http.MethodPost, testServer.URL+"/", bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d. Body: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	var response JSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Check for errors
	if response.Error != nil {
		t.Fatalf("Expected no error, got: code=%d, message=%s", response.Error.Code, response.Error.Message)
	}

	// Check result structure
	resultMap, ok := response.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected result to be a map, got %T", response.Result)
	}

	// Check for tools array
	tools, ok := resultMap["tools"].([]interface{})
	if !ok {
		t.Fatalf("Expected tools to be an array, got %T", resultMap["tools"])
	}

	// We registered one test tool, so we should have at least 1 tool
	if len(tools) < 1 {
		t.Errorf("Expected at least 1 tool, got %d", len(tools))
	}

	// Check first tool structure
	if len(tools) > 0 {
		tool, ok := tools[0].(map[string]interface{})
		if !ok {
			t.Fatalf("Expected tool to be a map, got %T", tools[0])
		}

		if name, ok := tool["name"].(string); !ok || name == "" {
			t.Error("Expected tool to have a name")
		}

		if _, ok := tool["inputSchema"].(map[string]interface{}); !ok {
			t.Error("Expected tool to have an inputSchema")
		}
	}
}

func TestHTTPMCPToolsCall(t *testing.T) {
	_, testServer := createTestServer(t)
	defer testServer.Close()

	// Ensure MockAuthorizer is used
	auth.SetAuthorizer(&auth.MockAuthorizer{})

	// Create tools/call request
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": "test_tool",
			"arguments": map[string]interface{}{
				"message": "Hello, World!",
			},
		},
	}
	reqBody, _ := json.Marshal(request)

	// Create request with Authorization header
	req, err := http.NewRequest(http.MethodPost, testServer.URL+"/", bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d. Body: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	var response JSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Check for errors
	if response.Error != nil {
		t.Fatalf("Expected no error, got: code=%d, message=%s", response.Error.Code, response.Error.Message)
	}

	// Check result structure
	resultMap, ok := response.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected result to be a map, got %T", response.Result)
	}

	// Check for content array
	content, ok := resultMap["content"].([]interface{})
	if !ok {
		t.Fatalf("Expected content to be an array, got %T", resultMap["content"])
	}

	if len(content) < 1 {
		t.Fatal("Expected at least 1 content item")
	}

	// Check content item
	contentItem, ok := content[0].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected content item to be a map, got %T", content[0])
	}

	if text, ok := contentItem["text"].(string); !ok || text != "Echo: Hello, World!" {
		t.Errorf("Expected text 'Echo: Hello, World!', got '%v'", contentItem["text"])
	}
}

func TestHTTPMethodNotAllowed(t *testing.T) {
	_, testServer := createTestServer(t)
	defer testServer.Close()

	// Ensure MockAuthorizer is used
	auth.SetAuthorizer(&auth.MockAuthorizer{})

	// Create GET request with Authorization header (should fail because only POST is allowed on /)
	req, err := http.NewRequest(http.MethodGet, testServer.URL+"/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-token")

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check status code - should be 405 Method Not Allowed
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", resp.StatusCode)
	}
}

func TestHTTPInvalidJSON(t *testing.T) {
	_, testServer := createTestServer(t)
	defer testServer.Close()

	// Ensure MockAuthorizer is used
	auth.SetAuthorizer(&auth.MockAuthorizer{})

	// Send invalid JSON
	req, err := http.NewRequest(http.MethodPost, testServer.URL+"/", bytes.NewBufferString("not valid json"))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Should still return 200 but with JSON-RPC error
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 (JSON-RPC handles errors in body), got %d", resp.StatusCode)
	}

	// Parse response
	var response JSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Check for parse error
	if response.Error == nil {
		t.Fatal("Expected error in response")
	}

	if response.Error.Code != ParseError {
		t.Errorf("Expected error code %d (ParseError), got %d", ParseError, response.Error.Code)
	}
}

func TestHTTPUnknownMethod(t *testing.T) {
	_, testServer := createTestServer(t)
	defer testServer.Close()

	// Ensure MockAuthorizer is used
	auth.SetAuthorizer(&auth.MockAuthorizer{})

	// Create request with unknown method
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "unknown/method",
	}
	reqBody, _ := json.Marshal(request)

	req, err := http.NewRequest(http.MethodPost, testServer.URL+"/", bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Parse response
	var response JSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Check for method not found error
	if response.Error == nil {
		t.Fatal("Expected error in response")
	}

	if response.Error.Code != MethodNotFound {
		t.Errorf("Expected error code %d (MethodNotFound), got %d", MethodNotFound, response.Error.Code)
	}
}
