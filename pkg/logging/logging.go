package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
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
	mu        sync.Mutex
	level     LogLevel
	logger    *log.Logger
	file      *os.File
	logDir    string
	appName   string
	startTime time.Time
}

type Config struct {
	LogDir  string
	AppName string
	Level   LogLevel
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
		level:     cfg.Level,
		logger:    log.New(file, "", 0),
		file:      file,
		logDir:    logDir,
		appName:   cfg.AppName,
		startTime: time.Now(),
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
	Version         string
	GoVersion       string
	OS              string
	Arch            string
	NumCPU          int
	LogDir          ConfigValue
	LogLevel        ConfigValue
	DynatraceEnv    ConfigValue
	GrailBudgetGB   int
	PID             int
	StartTime       time.Time
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

func GetStartupInfo(version string, logDir ConfigValue, logLevel ConfigValue, dtEnv ConfigValue, grailBudgetGB int) StartupInfo {
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
