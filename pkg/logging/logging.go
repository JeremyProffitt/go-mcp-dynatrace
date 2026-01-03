package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// LogLevel represents the severity of a log message
type LogLevel int

// ConfigSource indicates where a configuration value came from
type ConfigSource string

const (
	SourceDefault     ConfigSource = "default"
	SourceEnvironment ConfigSource = "environment"
	SourceFlag        ConfigSource = "flag"
)

const (
	LevelOff LogLevel = iota
	LevelError
	LevelWarn
	LevelInfo
	LevelAccess
	LevelDebug
)

func (l LogLevel) String() string {
	switch l {
	case LevelOff:
		return "OFF"
	case LevelError:
		return "ERROR"
	case LevelWarn:
		return "WARN"
	case LevelInfo:
		return "INFO"
	case LevelAccess:
		return "ACCESS"
	case LevelDebug:
		return "DEBUG"
	default:
		return "UNKNOWN"
	}
}

func ParseLogLevel(s string) LogLevel {
	switch s {
	case "off", "OFF":
		return LevelOff
	case "error", "ERROR":
		return LevelError
	case "warn", "WARN", "warning", "WARNING":
		return LevelWarn
	case "info", "INFO":
		return LevelInfo
	case "access", "ACCESS":
		return LevelAccess
	case "debug", "DEBUG":
		return LevelDebug
	default:
		return LevelInfo
	}
}

type Logger struct {
	mu             sync.Mutex
	level          LogLevel
	logger         *log.Logger
	file           *os.File
	logDir         string
	appName        string
	startTime      time.Time
	logDQLQueries  bool
}

type Config struct {
	LogDir        string
	AppName       string
	Level         LogLevel
	LogDQLQueries bool
}

var (
	defaultLogger *Logger
	once          sync.Once
)

func DefaultLogDir(appName string) string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", appName, "logs")
	}
	return filepath.Join(homeDir, appName, "logs")
}

func Init(cfg Config) error {
	var initErr error
	once.Do(func() {
		defaultLogger, initErr = NewLogger(cfg)
	})
	return initErr
}

func NewLogger(cfg Config) (*Logger, error) {
	if cfg.AppName == "" {
		cfg.AppName = "go-mcp-dynatrace"
	}

	logDir := cfg.LogDir
	if logDir == "" {
		logDir = DefaultLogDir(cfg.AppName)
	}

	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory %s: %w", logDir, err)
	}

	timestamp := time.Now().Format("2006-01-02")
	logFileName := fmt.Sprintf("%s-%s.log", cfg.AppName, timestamp)
	logPath := filepath.Join(logDir, logFileName)

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file %s: %w", logPath, err)
	}

	l := &Logger{
		level:         cfg.Level,
		logger:        log.New(file, "", 0),
		file:          file,
		logDir:        logDir,
		appName:       cfg.AppName,
		startTime:     time.Now(),
		logDQLQueries: cfg.LogDQLQueries,
	}

	return l, nil
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if l == nil || level > l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().Format("2006-01-02T15:04:05.000Z07:00")
	message := fmt.Sprintf(format, args...)
	l.logger.Printf("[%s] [%s] %s", timestamp, level.String(), message)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.log(LevelError, format, args...)
}

func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(LevelWarn, format, args...)
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.log(LevelInfo, format, args...)
}

func (l *Logger) Access(format string, args ...interface{}) {
	l.log(LevelAccess, format, args...)
}

func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(LevelDebug, format, args...)
}

// API operations logging (no sensitive data)
func (l *Logger) APIRequest(method, endpoint string, statusCode int, duration time.Duration, err error) {
	if err != nil {
		l.Access("API_REQUEST method=%s endpoint=%q status=%d duration=%s error=%q", method, endpoint, statusCode, duration, err.Error())
	} else {
		l.Access("API_REQUEST method=%s endpoint=%q status=%d duration=%s", method, endpoint, statusCode, duration)
	}
}

func (l *Logger) DQLQuery(query string, recordCount int, bytesScanned int64, duration time.Duration, err error) {
	// Log query structure but not actual data
	if err != nil {
		l.Access("DQL_QUERY records=%d bytes_scanned=%d duration=%s error=%q", recordCount, bytesScanned, duration, err.Error())
	} else {
		l.Access("DQL_QUERY records=%d bytes_scanned=%d duration=%s", recordCount, bytesScanned, duration)
	}
}

// SaveDQLQueryToFile saves a DQL query to a file if DQL query logging is enabled.
// Files are saved to {logDir}/DQL/YYYYMMDD/{descriptiveName}.YYYYMMDD.HHmmss.dql
func (l *Logger) SaveDQLQueryToFile(query string, descriptiveName string) error {
	if l == nil || !l.logDQLQueries {
		return nil
	}

	now := time.Now()
	dateDir := now.Format("20060102")
	timestamp := now.Format("20060102.150405")

	// Create DQL subdirectory: {logDir}/DQL/YYYYMMDD
	dqlDir := filepath.Join(l.logDir, "DQL", dateDir)
	if err := os.MkdirAll(dqlDir, 0755); err != nil {
		l.Error("Failed to create DQL log directory %s: %v", dqlDir, err)
		return fmt.Errorf("failed to create DQL log directory: %w", err)
	}

	// Sanitize descriptive name for use in filename
	safeName := sanitizeFilename(descriptiveName)
	if safeName == "" {
		safeName = "query"
	}

	// Create filename: {descriptiveName}.YYYYMMDD.HHmmss.dql
	filename := fmt.Sprintf("%s.%s.dql", safeName, timestamp)
	filePath := filepath.Join(dqlDir, filename)

	// Write query to file
	if err := os.WriteFile(filePath, []byte(query), 0644); err != nil {
		l.Error("Failed to write DQL query to file %s: %v", filePath, err)
		return fmt.Errorf("failed to write DQL query to file: %w", err)
	}

	l.Debug("DQL query saved to %s", filePath)
	return nil
}

// sanitizeFilename removes or replaces characters that are invalid in filenames
func sanitizeFilename(name string) string {
	// Replace common invalid characters with underscores
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		"\n", "_",
		"\r", "_",
		"\t", "_",
	)
	sanitized := replacer.Replace(name)

	// Remove leading/trailing spaces and dots
	sanitized = strings.Trim(sanitized, " .")

	// Truncate if too long (max 100 chars for the descriptive part)
	if len(sanitized) > 100 {
		sanitized = sanitized[:100]
	}

	return sanitized
}

// IsDQLQueryLoggingEnabled returns whether DQL query logging is enabled
func (l *Logger) IsDQLQueryLoggingEnabled() bool {
	if l == nil {
		return false
	}
	return l.logDQLQueries
}

func (l *Logger) ToolCall(toolName string, args map[string]interface{}, duration time.Duration, success bool) {
	argKeys := make([]string, 0, len(args))
	for k := range args {
		argKeys = append(argKeys, k)
	}
	l.Info("TOOL_CALL tool=%q args=%v duration=%s success=%v", toolName, argKeys, duration, success)
}

func (l *Logger) AuthToken(tokenType string, expiresIn time.Duration, err error) {
	if err != nil {
		l.Debug("AUTH_TOKEN type=%s error=%q", tokenType, err.Error())
	} else {
		l.Debug("AUTH_TOKEN type=%s expires_in=%s", tokenType, expiresIn)
	}
}

// ConfigValue holds a configuration value and its source
type ConfigValue struct {
	Value  string
	Source ConfigSource
}

type StartupInfo struct {
	Version        string
	GoVersion      string
	OS             string
	Arch           string
	NumCPU         int
	LogDir         ConfigValue
	LogLevel       ConfigValue
	DynatraceEnv   ConfigValue
	GrailBudgetGB  int
	LogDQLQueries  bool
	PID            int
	StartTime      time.Time
}

func (l *Logger) LogStartup(info StartupInfo) {
	l.Info("========================================")
	l.Info("SERVER STARTUP")
	l.Info("========================================")
	l.Info("Application: %s", l.appName)
	l.Info("Version: %s", info.Version)
	l.Info("Go Version: %s", info.GoVersion)
	l.Info("OS: %s", info.OS)
	l.Info("Architecture: %s", info.Arch)
	l.Info("Number of CPUs: %d", info.NumCPU)
	l.Info("Process ID: %d", info.PID)
	l.Info("Start Time: %s", info.StartTime.Format(time.RFC3339))
	l.Info("----------------------------------------")
	l.Info("CONFIGURATION (value [source])")
	l.Info("----------------------------------------")
	l.Info("Log Directory: %s [%s]", info.LogDir.Value, info.LogDir.Source)
	l.Info("Log Level: %s [%s]", info.LogLevel.Value, info.LogLevel.Source)
	l.Info("Dynatrace Environment: %s [%s]", info.DynatraceEnv.Value, info.DynatraceEnv.Source)
	l.Info("Grail Budget: %d GB [default]", info.GrailBudgetGB)
	l.Info("Log DQL Queries: %v", info.LogDQLQueries)
	l.Info("========================================")
}

func (l *Logger) LogShutdown(reason string) {
	uptime := time.Since(l.startTime)
	l.Info("========================================")
	l.Info("SERVER SHUTDOWN")
	l.Info("========================================")
	l.Info("Reason: %s", reason)
	l.Info("Uptime: %s", uptime)
	l.Info("========================================")
}

func GetLogger() *Logger {
	return defaultLogger
}

func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logger.SetOutput(w)
}

func GetStartupInfo(version string, logDir ConfigValue, logLevel ConfigValue, dtEnv ConfigValue, grailBudgetGB int, logDQLQueries bool) StartupInfo {
	return StartupInfo{
		Version:       version,
		GoVersion:     runtime.Version(),
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		NumCPU:        runtime.NumCPU(),
		LogDir:        logDir,
		LogLevel:      logLevel,
		DynatraceEnv:  dtEnv,
		GrailBudgetGB: grailBudgetGB,
		LogDQLQueries: logDQLQueries,
		PID:           os.Getpid(),
		StartTime:     time.Now(),
	}
}

// Global convenience functions

func Error(format string, args ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Error(format, args...)
	}
}

func Warn(format string, args ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Warn(format, args...)
	}
}

func Info(format string, args ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Info(format, args...)
	}
}

func Access(format string, args ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Access(format, args...)
	}
}

func Debug(format string, args ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Debug(format, args...)
	}
}

func APIRequest(method, endpoint string, statusCode int, duration time.Duration, err error) {
	if defaultLogger != nil {
		defaultLogger.APIRequest(method, endpoint, statusCode, duration, err)
	}
}

func DQLQuery(query string, recordCount int, bytesScanned int64, duration time.Duration, err error) {
	if defaultLogger != nil {
		defaultLogger.DQLQuery(query, recordCount, bytesScanned, duration, err)
	}
}

func ToolCall(toolName string, args map[string]interface{}, duration time.Duration, success bool) {
	if defaultLogger != nil {
		defaultLogger.ToolCall(toolName, args, duration, success)
	}
}

func AuthToken(tokenType string, expiresIn time.Duration, err error) {
	if defaultLogger != nil {
		defaultLogger.AuthToken(tokenType, expiresIn, err)
	}
}

// PII filtering patterns
var (
	// SSN patterns: xxx-xx-xxxx or xxxxxxxxx (9 digits)
	ssnPattern = regexp.MustCompile(`\b(\d{3}[-\s]?\d{2}[-\s]?\d{4})\b`)
	// PAN (credit card) patterns: 13-19 digit sequences, optionally with spaces/dashes
	panPattern = regexp.MustCompile(`\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,7})\b`)
	// Additional PAN pattern for continuous digits
	panContinuousPattern = regexp.MustCompile(`\b(\d{13,19})\b`)
	// JSON token patterns - mask access_token, token, api_key, secret values in JSON
	jsonTokenPattern = regexp.MustCompile(`("(?:access_token|token|api_key|apikey|secret|password|credential|bearer)":\s*")([^"]+)(")`)
)

// MaskSecret masks a secret value showing only the last 4 characters
// e.g., "mysecrettoken123" becomes "xxx3123"
func MaskSecret(secret string) string {
	if secret == "" {
		return ""
	}
	if len(secret) <= 4 {
		return "xxx" + secret
	}
	return "xxx" + secret[len(secret)-4:]
}

// SanitizePII removes or masks PII data from log messages
// - SSNs are replaced with [SSN-REDACTED]
// - PANs (credit card numbers) are replaced with [PAN-REDACTED]
// - JSON token values are masked to show only last 4 characters
func SanitizePII(message string) string {
	// Mask SSNs
	message = ssnPattern.ReplaceAllString(message, "[SSN-REDACTED]")
	// Mask PANs with separators
	message = panPattern.ReplaceAllString(message, "[PAN-REDACTED]")
	// Mask continuous digit PANs
	message = panContinuousPattern.ReplaceAllString(message, "[PAN-REDACTED]")
	// Mask JSON token values (show only last 4 chars)
	message = jsonTokenPattern.ReplaceAllStringFunc(message, func(match string) string {
		parts := jsonTokenPattern.FindStringSubmatch(match)
		if len(parts) == 4 {
			// parts[1] = key and opening quote, parts[2] = value, parts[3] = closing quote
			return parts[1] + MaskSecret(parts[2]) + parts[3]
		}
		return match
	})
	return message
}

// SanitizeAndMaskSecrets sanitizes PII and masks known secret field values
func SanitizeAndMaskSecrets(message string, secretFields ...string) string {
	sanitized := SanitizePII(message)
	for _, field := range secretFields {
		if field != "" {
			masked := MaskSecret(field)
			sanitized = strings.ReplaceAll(sanitized, field, masked)
		}
	}
	return sanitized
}

// HTTPRequestInfo contains HTTP request details for logging
type HTTPRequestInfo struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// HTTPResponseInfo contains HTTP response details for logging
type HTTPResponseInfo struct {
	StatusCode int
	Headers    map[string]string
	Body       string
}

// sanitizeHeaders removes sensitive header values
func sanitizeHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	sanitized := make(map[string]string)
	sensitiveHeaders := []string{"authorization", "x-api-key", "api-key", "token", "secret", "password", "credential"}
	for k, v := range headers {
		lowerKey := strings.ToLower(k)
		isSensitive := false
		for _, sensitive := range sensitiveHeaders {
			if strings.Contains(lowerKey, sensitive) {
				isSensitive = true
				break
			}
		}
		if isSensitive {
			sanitized[k] = MaskSecret(v)
		} else {
			sanitized[k] = SanitizePII(v)
		}
	}
	return sanitized
}

// formatHeaders formats headers for logging
func formatHeaders(headers map[string]string) string {
	if len(headers) == 0 {
		return "{}"
	}
	parts := make([]string, 0, len(headers))
	for k, v := range headers {
		parts = append(parts, fmt.Sprintf("%s=%q", k, v))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// LogHTTPError logs detailed HTTP error information with PII filtering
func (l *Logger) LogHTTPError(context string, req *HTTPRequestInfo, resp *HTTPResponseInfo, err error, secrets ...string) {
	if l == nil {
		return
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP_ERROR context=%q", context))

	if req != nil {
		sb.WriteString(fmt.Sprintf(" request.method=%s request.url=%q", req.Method, req.URL))
		if len(req.Headers) > 0 {
			sanitizedHeaders := sanitizeHeaders(req.Headers)
			sb.WriteString(fmt.Sprintf(" request.headers=%s", formatHeaders(sanitizedHeaders)))
		}
		if req.Body != "" {
			sanitizedBody := SanitizeAndMaskSecrets(req.Body, secrets...)
			// Truncate long bodies
			if len(sanitizedBody) > 500 {
				sanitizedBody = sanitizedBody[:500] + "...[truncated]"
			}
			sb.WriteString(fmt.Sprintf(" request.body=%q", sanitizedBody))
		}
	}

	if resp != nil {
		sb.WriteString(fmt.Sprintf(" response.status=%d", resp.StatusCode))
		if len(resp.Headers) > 0 {
			sanitizedHeaders := sanitizeHeaders(resp.Headers)
			sb.WriteString(fmt.Sprintf(" response.headers=%s", formatHeaders(sanitizedHeaders)))
		}
		if resp.Body != "" {
			sanitizedBody := SanitizeAndMaskSecrets(resp.Body, secrets...)
			// Truncate long bodies
			if len(sanitizedBody) > 1000 {
				sanitizedBody = sanitizedBody[:1000] + "...[truncated]"
			}
			sb.WriteString(fmt.Sprintf(" response.body=%q", sanitizedBody))
		}
	}

	if err != nil {
		sanitizedErr := SanitizeAndMaskSecrets(err.Error(), secrets...)
		sb.WriteString(fmt.Sprintf(" error=%q", sanitizedErr))
	}

	l.Error(sb.String())
}

// LogTokenError logs token retrieval errors with masked credentials
func (l *Logger) LogTokenError(tokenType, ssoURL, clientID, clientSecret string, statusCode int, responseBody string, err error) {
	if l == nil {
		return
	}

	maskedClientID := MaskSecret(clientID)
	maskedClientSecret := MaskSecret(clientSecret)
	sanitizedBody := SanitizeAndMaskSecrets(responseBody, clientID, clientSecret)

	// Truncate long bodies
	if len(sanitizedBody) > 500 {
		sanitizedBody = sanitizedBody[:500] + "...[truncated]"
	}

	var errStr string
	if err != nil {
		errStr = SanitizeAndMaskSecrets(err.Error(), clientID, clientSecret)
	}

	l.Error("TOKEN_ERROR type=%s sso_url=%q client_id=%s client_secret=%s status=%d response=%q error=%q",
		tokenType, ssoURL, maskedClientID, maskedClientSecret, statusCode, sanitizedBody, errStr)
}

// LogHTTPRequest logs HTTP request details at DEBUG level with PII filtering
func (l *Logger) LogHTTPRequest(context string, req *HTTPRequestInfo, secrets ...string) {
	if l == nil || LevelDebug > l.level {
		return
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP_REQUEST context=%q", context))

	if req != nil {
		sb.WriteString(fmt.Sprintf(" method=%s url=%q", req.Method, req.URL))
		if len(req.Headers) > 0 {
			sanitizedHeaders := sanitizeHeaders(req.Headers)
			sb.WriteString(fmt.Sprintf(" headers=%s", formatHeaders(sanitizedHeaders)))
		}
		if req.Body != "" {
			sanitizedBody := SanitizeAndMaskSecrets(req.Body, secrets...)
			// Truncate long bodies
			if len(sanitizedBody) > 500 {
				sanitizedBody = sanitizedBody[:500] + "...[truncated]"
			}
			sb.WriteString(fmt.Sprintf(" body=%q", sanitizedBody))
		}
	}

	l.Debug(sb.String())
}

// LogHTTPResponse logs HTTP response details at DEBUG level with PII filtering
func (l *Logger) LogHTTPResponse(context string, resp *HTTPResponseInfo, duration time.Duration, secrets ...string) {
	if l == nil || LevelDebug > l.level {
		return
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP_RESPONSE context=%q", context))

	if resp != nil {
		sb.WriteString(fmt.Sprintf(" status=%d", resp.StatusCode))
		if len(resp.Headers) > 0 {
			sanitizedHeaders := sanitizeHeaders(resp.Headers)
			sb.WriteString(fmt.Sprintf(" headers=%s", formatHeaders(sanitizedHeaders)))
		}
		if resp.Body != "" {
			sanitizedBody := SanitizeAndMaskSecrets(resp.Body, secrets...)
			// Truncate long bodies
			if len(sanitizedBody) > 1000 {
				sanitizedBody = sanitizedBody[:1000] + "...[truncated]"
			}
			sb.WriteString(fmt.Sprintf(" body=%q", sanitizedBody))
		}
	}

	sb.WriteString(fmt.Sprintf(" duration=%s", duration))
	l.Debug(sb.String())
}

// Global convenience functions for HTTP error logging

func LogHTTPError(context string, req *HTTPRequestInfo, resp *HTTPResponseInfo, err error, secrets ...string) {
	if defaultLogger != nil {
		defaultLogger.LogHTTPError(context, req, resp, err, secrets...)
	}
}

// LogHTTPRequest is the global convenience function for HTTP request logging
func LogHTTPRequest(context string, req *HTTPRequestInfo, secrets ...string) {
	if defaultLogger != nil {
		defaultLogger.LogHTTPRequest(context, req, secrets...)
	}
}

// LogHTTPResponse is the global convenience function for HTTP response logging
func LogHTTPResponse(context string, resp *HTTPResponseInfo, duration time.Duration, secrets ...string) {
	if defaultLogger != nil {
		defaultLogger.LogHTTPResponse(context, resp, duration, secrets...)
	}
}

func LogTokenError(tokenType, ssoURL, clientID, clientSecret string, statusCode int, responseBody string, err error) {
	if defaultLogger != nil {
		defaultLogger.LogTokenError(tokenType, ssoURL, clientID, clientSecret, statusCode, responseBody, err)
	}
}
