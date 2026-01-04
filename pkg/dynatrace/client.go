package dynatrace

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dynatrace-oss/go-mcp-dynatrace/pkg/logging"
)

const (
	DefaultSSOURL      = "https://sso.dynatrace.com/sso/oauth2/token"
	DefaultTimeout     = 30 * time.Second
	DefaultGrailBudget = 1000 // GB
)

// Client is the Dynatrace API client
type Client struct {
	httpClient        *http.Client
	baseURL           string
	ssoURL            string
	oauthClientID     string
	oauthClientSecret string
	platformToken     string
	accountURN        string
	scopes            []string

	// Token management
	accessToken string
	tokenExpiry time.Time
	tokenMu     sync.RWMutex
	tokenCache  *TokenCache

	// Budget tracking
	budgetTracker *GrailBudgetTracker
	budgetMu      sync.Mutex

	// Logger
	logger *logging.Logger
}

// Config holds client configuration
type Config struct {
	Environment       string
	OAuthClientID     string
	OAuthClientSecret string
	PlatformToken     string
	SSOURL            string
	AccountURN        string
	GrailBudgetGB     int
	Logger            *logging.Logger
}

// NewClient creates a new Dynatrace client
func NewClient(cfg Config) (*Client, error) {
	if cfg.Environment == "" {
		return nil, fmt.Errorf("DT_ENVIRONMENT is required")
	}

	// Normalize base URL
	baseURL := strings.TrimSuffix(cfg.Environment, "/")

	ssoURL := cfg.SSOURL
	if ssoURL == "" {
		ssoURL = DefaultSSOURL
	}

	budgetGB := cfg.GrailBudgetGB
	if budgetGB <= 0 {
		budgetGB = DefaultGrailBudget
	}

	client := &Client{
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		baseURL:           baseURL,
		ssoURL:            ssoURL,
		oauthClientID:     cfg.OAuthClientID,
		oauthClientSecret: cfg.OAuthClientSecret,
		platformToken:     cfg.PlatformToken,
		accountURN:        cfg.AccountURN,
		budgetTracker:     NewGrailBudgetTracker(budgetGB),
		logger:            cfg.Logger,
		scopes:            getRequiredScopes(),
		tokenCache:        NewTokenCache(),
	}

	// Try to load cached token
	if cfg.OAuthClientID != "" && cfg.PlatformToken == "" {
		if cached := client.tokenCache.Load(baseURL, cfg.OAuthClientID); cached != nil {
			client.accessToken = cached.AccessToken
			client.tokenExpiry = cached.ExpiresAt
			logging.Info("Loaded cached OAuth token (expires in %s)", time.Until(cached.ExpiresAt).Round(time.Second))
		}
	}

	return client, nil
}

func getRequiredScopes() []string {
	return []string{
		"app-engine:apps:run",
		"storage:events:read",
		"storage:user.events:read",
		"storage:buckets:read",
		"storage:security.events:read",
		"storage:entities:read",
		"storage:smartscape:read",
		"storage:logs:read",
		"storage:metrics:read",
		"storage:bizevents:read",
		"storage:spans:read",
		"storage:system:read",
		"app-settings:objects:read",
		"davis-copilot:nl2dql:execute",
		"davis-copilot:dql2nl:execute",
		"davis-copilot:conversations:execute",
		"davis:analyzers:read",
		"davis:analyzers:execute",
		"automation:workflows:write",
		"automation:workflows:read",
		"automation:workflows:run",
		"email:emails:send",
	}
}

// TestConnection tests the connection to Dynatrace
func (c *Client) TestConnection(ctx context.Context) error {
	// First, test basic connectivity without auth
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to Dynatrace: %w", err)
	}
	defer resp.Body.Close()

	// Then test with authentication
	return c.refreshToken(ctx)
}

// refreshToken obtains a new access token
func (c *Client) refreshToken(ctx context.Context) error {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	// Check if token is still valid
	if c.accessToken != "" && time.Now().Add(30*time.Second).Before(c.tokenExpiry) {
		return nil
	}

	// If we have a platform token, use it directly
	if c.platformToken != "" {
		c.accessToken = c.platformToken
		c.tokenExpiry = time.Now().Add(24 * time.Hour) // Platform tokens don't expire quickly
		return nil
	}

	// OAuth client credentials flow
	if c.oauthClientID == "" || c.oauthClientSecret == "" {
		err := fmt.Errorf("OAuth credentials required: set OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET")
		logging.LogTokenError("oauth", c.ssoURL, c.oauthClientID, c.oauthClientSecret, 0, "", err)
		return err
	}

	if c.accountURN == "" {
		err := fmt.Errorf("DT_ACCOUNT_URN is required for OAuth authentication (format: urn:dtaccount:<account-uuid>)")
		logging.LogTokenError("oauth", c.ssoURL, c.oauthClientID, c.oauthClientSecret, 0, "", err)
		return err
	}

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.oauthClientID)
	data.Set("client_secret", c.oauthClientSecret)
	data.Set("resource", c.accountURN)
	// Note: scope is omitted as it can conflict with resource parameter
	// Scopes should be configured on the OAuth client in Dynatrace

	req, err := http.NewRequestWithContext(ctx, "POST", c.ssoURL, strings.NewReader(data.Encode()))
	if err != nil {
		logging.LogTokenError("oauth", c.ssoURL, c.oauthClientID, c.oauthClientSecret, 0, "", err)
		return fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Log OAuth request at DEBUG level (credentials will be masked to show only last 4 chars)
	logging.LogHTTPRequest("oauth_token", &logging.HTTPRequestInfo{
		Method: "POST",
		URL:    c.ssoURL,
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		Body: data.Encode(),
	}, c.oauthClientID, c.oauthClientSecret)

	startTime := time.Now()
	resp, err := c.httpClient.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		logging.LogTokenError("oauth", c.ssoURL, c.oauthClientID, c.oauthClientSecret, 0, "", err)
		logging.AuthToken("oauth", 0, err)
		return fmt.Errorf("failed to get token: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Log OAuth response at DEBUG level
	logging.LogHTTPResponse("oauth_token", &logging.HTTPResponseInfo{
		StatusCode: resp.StatusCode,
		Body:       string(body),
	}, duration, c.oauthClientID, c.oauthClientSecret)

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("token request failed with status %d", resp.StatusCode)
		logging.LogTokenError("oauth", c.ssoURL, c.oauthClientID, c.oauthClientSecret, resp.StatusCode, string(body), err)
		logging.AuthToken("oauth", 0, err)
		return fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, logging.SanitizeAndMaskSecrets(string(body), c.oauthClientID, c.oauthClientSecret))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		logging.LogTokenError("oauth", c.ssoURL, c.oauthClientID, c.oauthClientSecret, resp.StatusCode, string(body), err)
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	c.accessToken = tokenResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	// Cache the token for future use
	if c.tokenCache != nil {
		if err := c.tokenCache.Save(c.accessToken, c.baseURL, c.oauthClientID, c.tokenExpiry); err != nil {
			logging.Debug("Failed to cache token: %v", err)
		}
	}

	logging.AuthToken("oauth", time.Duration(tokenResp.ExpiresIn)*time.Second, nil)
	logging.Debug("Token obtained successfully in %s", duration)

	return nil
}

// doRequest performs an authenticated HTTP request
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	// Refresh token if needed
	if err := c.refreshToken(ctx); err != nil {
		return nil, err
	}

	var reqBody io.Reader
	var reqBodyStr string
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBodyStr = string(jsonBody)
		reqBody = bytes.NewReader(jsonBody)
	}

	fullURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, reqBody)
	if err != nil {
		logging.LogHTTPError("create_request", &logging.HTTPRequestInfo{
			Method: method,
			URL:    fullURL,
			Body:   reqBodyStr,
		}, nil, err, c.accessToken)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.tokenMu.RLock()
	token := c.accessToken
	c.tokenMu.RUnlock()

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Log request at DEBUG level (token will be masked to show only last 4 chars)
	logging.LogHTTPRequest("api_request", &logging.HTTPRequestInfo{
		Method: method,
		URL:    fullURL,
		Headers: map[string]string{
			"Authorization": "Bearer " + token,
			"Content-Type":  "application/json",
			"Accept":        "application/json",
		},
		Body: reqBodyStr,
	}, token)

	startTime := time.Now()
	resp, err := c.httpClient.Do(req)
	duration := time.Since(startTime)

	statusCode := 0
	if resp != nil {
		statusCode = resp.StatusCode
	}

	// Log detailed error information on network errors
	if err != nil {
		logging.LogHTTPError("http_request", &logging.HTTPRequestInfo{
			Method: method,
			URL:    fullURL,
			Headers: map[string]string{
				"Authorization": "Bearer " + token,
				"Content-Type":  "application/json",
			},
			Body: reqBodyStr,
		}, nil, err, token)
	} else {
		// Log successful response at DEBUG level
		// Note: Response body is read later by the caller, so we log headers only here
		respHeaders := make(map[string]string)
		for k, v := range resp.Header {
			if len(v) > 0 {
				respHeaders[k] = v[0]
			}
		}
		logging.LogHTTPResponse("api_response", &logging.HTTPResponseInfo{
			StatusCode: statusCode,
			Headers:    respHeaders,
		}, duration, token)
	}

	logging.APIRequest(method, path, statusCode, duration, err)

	return resp, err
}

// logAPIError logs API errors with request/response details
func (c *Client) logAPIError(context, method, path string, statusCode int, responseBody string, err error) {
	c.tokenMu.RLock()
	token := c.accessToken
	c.tokenMu.RUnlock()

	logging.LogHTTPError(context, &logging.HTTPRequestInfo{
		Method: method,
		URL:    c.baseURL + path,
		Headers: map[string]string{
			"Authorization": "Bearer " + token,
			"Content-Type":  "application/json",
		},
	}, &logging.HTTPResponseInfo{
		StatusCode: statusCode,
		Body:       responseBody,
	}, err, token)
}

// logResponseBody logs the response body at DEBUG level with redaction.
// This should be called after reading the response body to log its contents.
func (c *Client) logResponseBody(context string, statusCode int, body []byte) {
	c.tokenMu.RLock()
	token := c.accessToken
	c.tokenMu.RUnlock()

	logging.LogHTTPResponseBody(context, &logging.HTTPResponseInfo{
		StatusCode: statusCode,
		Body:       string(body),
	}, token)
}

// readAndLogBody reads the response body, logs it at DEBUG level, and returns the bytes.
// It returns the body bytes and any error from reading.
func (c *Client) readAndLogBody(resp *http.Response, context string) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	c.logResponseBody(context, resp.StatusCode, body)
	return body, nil
}

// GetEnvironmentInfo retrieves environment information
func (c *Client) GetEnvironmentInfo(ctx context.Context) (*EnvironmentInfo, error) {
	path := "/platform/management/v1/environment"
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := c.readAndLogBody(resp, "get_environment_info")
	if err != nil {
		c.logAPIError("get_environment_info_read", "GET", path, 0, "", fmt.Errorf("failed to read response: %w", err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("API request failed with status %d", resp.StatusCode)
		c.logAPIError("get_environment_info", "GET", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, logging.SanitizePII(string(body)))
	}

	var info EnvironmentInfo
	if err := json.Unmarshal(body, &info); err != nil {
		c.logAPIError("get_environment_info_decode", "GET", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &info, nil
}

// ExecuteDQL executes a DQL query
func (c *Client) ExecuteDQL(ctx context.Context, query string, maxRecords, maxBytes int) (*DQLQueryResponse, error) {
	// Check budget
	c.budgetMu.Lock()
	if c.budgetTracker.GetState().IsBudgetExceeded {
		c.budgetMu.Unlock()
		return nil, fmt.Errorf("Grail query budget exceeded. Use 'reset_grail_budget' tool to continue")
	}
	c.budgetMu.Unlock()

	path := "/platform/storage/query/v1/query:execute"
	reqBody := DQLQueryRequest{
		Query:            query,
		MaxResultRecords: maxRecords,
		MaxResultBytes:   maxBytes,
		RequestTimeoutMs: 60000,
	}

	resp, err := c.doRequest(ctx, "POST", path, reqBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := c.readAndLogBody(resp, "execute_dql")
	if err != nil {
		c.logAPIError("execute_dql_read", "POST", path, 0, "", fmt.Errorf("failed to read response: %w", err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("DQL query failed with status %d", resp.StatusCode)
		c.logAPIError("execute_dql", "POST", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("DQL query failed with status %d: %s", resp.StatusCode, logging.SanitizePII(string(body)))
	}

	var queryResp DQLQueryResponse
	if err := json.Unmarshal(body, &queryResp); err != nil {
		c.logAPIError("execute_dql_decode", "POST", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Handle async query
	if queryResp.State == "RUNNING" && queryResp.RequestToken != "" {
		return c.pollDQLResult(ctx, queryResp.RequestToken)
	}

	// Track bytes scanned
	if queryResp.Result != nil && queryResp.Result.Metadata != nil && queryResp.Result.Metadata.GrailMetrics != nil {
		c.budgetMu.Lock()
		c.budgetTracker.AddBytesScanned(queryResp.Result.Metadata.GrailMetrics.ScannedBytes)
		c.budgetMu.Unlock()

		recordCount := len(queryResp.Result.Records)
		bytesScanned := queryResp.Result.Metadata.GrailMetrics.ScannedBytes
		logging.DQLQuery(query, recordCount, bytesScanned, 0, nil)
	}

	return &queryResp, nil
}

func (c *Client) pollDQLResult(ctx context.Context, token string) (*DQLQueryResponse, error) {
	path := "/platform/storage/query/v1/query:poll?request-token=" + url.QueryEscape(token)
	for i := 0; i < 60; i++ { // Max 60 attempts (60 seconds)
		time.Sleep(time.Second)

		resp, err := c.doRequest(ctx, "GET", path, nil)
		if err != nil {
			return nil, err
		}

		body, err := c.readAndLogBody(resp, "poll_dql")
		resp.Body.Close()
		if err != nil {
			c.logAPIError("poll_dql_read", "GET", path, 0, "", fmt.Errorf("failed to read poll response: %w", err))
			return nil, fmt.Errorf("failed to read poll response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			err := fmt.Errorf("DQL poll failed with status %d", resp.StatusCode)
			c.logAPIError("poll_dql", "GET", path, resp.StatusCode, string(body), err)
			return nil, fmt.Errorf("DQL poll failed with status %d: %s", resp.StatusCode, logging.SanitizePII(string(body)))
		}

		var queryResp DQLQueryResponse
		if err := json.Unmarshal(body, &queryResp); err != nil {
			c.logAPIError("poll_dql_decode", "GET", path, resp.StatusCode, string(body), err)
			return nil, fmt.Errorf("failed to decode poll response: %w", err)
		}

		if queryResp.State == "SUCCEEDED" || queryResp.State == "FAILED" {
			// Track bytes scanned
			if queryResp.Result != nil && queryResp.Result.Metadata != nil && queryResp.Result.Metadata.GrailMetrics != nil {
				c.budgetMu.Lock()
				c.budgetTracker.AddBytesScanned(queryResp.Result.Metadata.GrailMetrics.ScannedBytes)
				c.budgetMu.Unlock()
			}
			return &queryResp, nil
		}
	}

	return nil, fmt.Errorf("DQL query timed out")
}

// VerifyDQL verifies a DQL statement
func (c *Client) VerifyDQL(ctx context.Context, query string) (*DQLVerifyResponse, error) {
	path := "/platform/storage/query/v1/query:verify"
	reqBody := DQLVerifyRequest{Query: query}

	resp, err := c.doRequest(ctx, "POST", path, reqBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := c.readAndLogBody(resp, "verify_dql")
	if err != nil {
		c.logAPIError("verify_dql_read", "POST", path, 0, "", fmt.Errorf("failed to read response: %w", err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("DQL verify failed with status %d", resp.StatusCode)
		c.logAPIError("verify_dql", "POST", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("DQL verify failed with status %d: %s", resp.StatusCode, logging.SanitizePII(string(body)))
	}

	var verifyResp DQLVerifyResponse
	if err := json.Unmarshal(body, &verifyResp); err != nil {
		c.logAPIError("verify_dql_decode", "POST", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &verifyResp, nil
}

// ChatWithDavisCopilot sends a message to Davis CoPilot
func (c *Client) ChatWithDavisCopilot(ctx context.Context, text string, contexts []DavisCopilotContext) (*DavisCopilotResponse, error) {
	path := "/platform/davis/v1/copilot/conversation"
	reqBody := map[string]interface{}{
		"text": text,
	}
	if len(contexts) > 0 {
		reqBody["context"] = contexts
	}

	resp, err := c.doRequest(ctx, "POST", path, reqBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := c.readAndLogBody(resp, "davis_copilot")
	if err != nil {
		c.logAPIError("davis_copilot_read", "POST", path, 0, "", fmt.Errorf("failed to read response: %w", err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("Davis CoPilot request failed with status %d", resp.StatusCode)
		c.logAPIError("davis_copilot", "POST", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("Davis CoPilot request failed with status %d: %s", resp.StatusCode, logging.SanitizePII(string(body)))
	}

	var copilotResp DavisCopilotResponse
	if err := json.Unmarshal(body, &copilotResp); err != nil {
		c.logAPIError("davis_copilot_decode", "POST", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &copilotResp, nil
}

// GenerateDQLFromNL converts natural language to DQL
func (c *Client) GenerateDQLFromNL(ctx context.Context, text string) (*NL2DQLResponse, error) {
	path := "/platform/davis/v1/copilot/nl2dql"
	reqBody := NL2DQLRequest{Text: text}

	resp, err := c.doRequest(ctx, "POST", path, reqBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := c.readAndLogBody(resp, "nl2dql")
	if err != nil {
		c.logAPIError("nl2dql_read", "POST", path, 0, "", fmt.Errorf("failed to read response: %w", err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("NL2DQL request failed with status %d", resp.StatusCode)
		c.logAPIError("nl2dql", "POST", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("NL2DQL request failed with status %d: %s", resp.StatusCode, logging.SanitizePII(string(body)))
	}

	var nl2dqlResp NL2DQLResponse
	if err := json.Unmarshal(body, &nl2dqlResp); err != nil {
		c.logAPIError("nl2dql_decode", "POST", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &nl2dqlResp, nil
}

// ExplainDQLInNL explains DQL in natural language
func (c *Client) ExplainDQLInNL(ctx context.Context, dql string) (*DQL2NLResponse, error) {
	path := "/platform/davis/v1/copilot/dql2nl"
	reqBody := DQL2NLRequest{DQL: dql}

	resp, err := c.doRequest(ctx, "POST", path, reqBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := c.readAndLogBody(resp, "dql2nl")
	if err != nil {
		c.logAPIError("dql2nl_read", "POST", path, 0, "", fmt.Errorf("failed to read response: %w", err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("DQL2NL request failed with status %d", resp.StatusCode)
		c.logAPIError("dql2nl", "POST", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("DQL2NL request failed with status %d: %s", resp.StatusCode, logging.SanitizePII(string(body)))
	}

	var dql2nlResp DQL2NLResponse
	if err := json.Unmarshal(body, &dql2nlResp); err != nil {
		c.logAPIError("dql2nl_decode", "POST", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &dql2nlResp, nil
}

// ListDavisAnalyzers lists available Davis Analyzers
func (c *Client) ListDavisAnalyzers(ctx context.Context) ([]DavisAnalyzer, error) {
	path := "/platform/davis/v1/analyzers"
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := c.readAndLogBody(resp, "list_analyzers")
	if err != nil {
		c.logAPIError("list_analyzers_read", "GET", path, 0, "", fmt.Errorf("failed to read response: %w", err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("list analyzers request failed with status %d", resp.StatusCode)
		c.logAPIError("list_analyzers", "GET", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("list analyzers request failed with status %d: %s", resp.StatusCode, logging.SanitizePII(string(body)))
	}

	var response struct {
		Analyzers []DavisAnalyzer `json:"analyzers"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		c.logAPIError("list_analyzers_decode", "GET", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Analyzers, nil
}

// ExecuteDavisAnalyzer executes a Davis Analyzer
func (c *Client) ExecuteDavisAnalyzer(ctx context.Context, analyzerName string, input map[string]interface{}) (*DavisAnalyzerResult, error) {
	reqBody := DavisAnalyzerExecuteRequest{Input: input}

	path := fmt.Sprintf("/platform/davis/v1/analyzers/%s:execute", url.PathEscape(analyzerName))
	resp, err := c.doRequest(ctx, "POST", path, reqBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := c.readAndLogBody(resp, "execute_analyzer")
	if err != nil {
		c.logAPIError("execute_analyzer_read", "POST", path, 0, "", fmt.Errorf("failed to read response: %w", err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("execute analyzer request failed with status %d", resp.StatusCode)
		c.logAPIError("execute_analyzer", "POST", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("execute analyzer request failed with status %d: %s", resp.StatusCode, logging.SanitizePII(string(body)))
	}

	var result DavisAnalyzerResult
	if err := json.Unmarshal(body, &result); err != nil {
		c.logAPIError("execute_analyzer_decode", "POST", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// CreateWorkflow creates a new workflow
func (c *Client) CreateWorkflow(ctx context.Context, workflow *WorkflowCreateRequest) (*Workflow, error) {
	path := "/platform/automation/v1/workflows"
	resp, err := c.doRequest(ctx, "POST", path, workflow)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := c.readAndLogBody(resp, "create_workflow")
	if err != nil {
		c.logAPIError("create_workflow_read", "POST", path, 0, "", fmt.Errorf("failed to read response: %w", err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("create workflow request failed with status %d", resp.StatusCode)
		c.logAPIError("create_workflow", "POST", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("create workflow request failed with status %d: %s", resp.StatusCode, logging.SanitizePII(string(body)))
	}

	var result Workflow
	if err := json.Unmarshal(body, &result); err != nil {
		c.logAPIError("create_workflow_decode", "POST", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// UpdateWorkflow updates an existing workflow
func (c *Client) UpdateWorkflow(ctx context.Context, workflowID string, updates map[string]interface{}) (*Workflow, error) {
	path := fmt.Sprintf("/platform/automation/v1/workflows/%s", url.PathEscape(workflowID))
	resp, err := c.doRequest(ctx, "PATCH", path, updates)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := c.readAndLogBody(resp, "update_workflow")
	if err != nil {
		c.logAPIError("update_workflow_read", "PATCH", path, 0, "", fmt.Errorf("failed to read response: %w", err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("update workflow request failed with status %d", resp.StatusCode)
		c.logAPIError("update_workflow", "PATCH", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("update workflow request failed with status %d: %s", resp.StatusCode, logging.SanitizePII(string(body)))
	}

	var result Workflow
	if err := json.Unmarshal(body, &result); err != nil {
		c.logAPIError("update_workflow_decode", "PATCH", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// SendEmail sends an email
func (c *Client) SendEmail(ctx context.Context, email *EmailRequest) (*EmailResponse, error) {
	path := "/platform/notification/v1/email"
	resp, err := c.doRequest(ctx, "POST", path, email)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := c.readAndLogBody(resp, "send_email")
	if err != nil {
		c.logAPIError("send_email_read", "POST", path, 0, "", fmt.Errorf("failed to read response: %w", err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		err := fmt.Errorf("send email request failed with status %d", resp.StatusCode)
		c.logAPIError("send_email", "POST", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("send email request failed with status %d: %s", resp.StatusCode, logging.SanitizePII(string(body)))
	}

	var result EmailResponse
	if err := json.Unmarshal(body, &result); err != nil {
		c.logAPIError("send_email_decode", "POST", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// SendSlackMessage sends a Slack message
func (c *Client) SendSlackMessage(ctx context.Context, connectionID, channel, message string) (map[string]interface{}, error) {
	path := "/platform/app-engine/slack-connector/send-message"
	reqBody := map[string]interface{}{
		"connectionId": connectionID,
		"channel":      channel,
		"message":      message,
	}

	resp, err := c.doRequest(ctx, "POST", path, reqBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := c.readAndLogBody(resp, "send_slack")
	if err != nil {
		c.logAPIError("send_slack_read", "POST", path, 0, "", fmt.Errorf("failed to read response: %w", err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("send Slack message request failed with status %d", resp.StatusCode)
		c.logAPIError("send_slack", "POST", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("send Slack message request failed with status %d: %s", resp.StatusCode, logging.SanitizePII(string(body)))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		c.logAPIError("send_slack_decode", "POST", path, resp.StatusCode, string(body), err)
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result, nil
}

// GetBudgetTracker returns the budget tracker
func (c *Client) GetBudgetTracker() *GrailBudgetTracker {
	return c.budgetTracker
}

// ResetBudget resets the budget tracker
func (c *Client) ResetBudget() {
	c.budgetMu.Lock()
	defer c.budgetMu.Unlock()
	c.budgetTracker.Reset()
}

// GetBaseURL returns the base URL
func (c *Client) GetBaseURL() string {
	return c.baseURL
}
