package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dynatrace-oss/go-mcp-dynatrace/pkg/dql"
	"github.com/dynatrace-oss/go-mcp-dynatrace/pkg/dynatrace"
	"github.com/dynatrace-oss/go-mcp-dynatrace/pkg/logging"
	"github.com/dynatrace-oss/go-mcp-dynatrace/pkg/mcp"
	"github.com/dynatrace-oss/go-mcp-dynatrace/pkg/prompts"
	"github.com/dynatrace-oss/go-mcp-dynatrace/pkg/tools"
)

const (
	AppName = "go-mcp-dynatrace"
	Version = "1.0.0"
)

// Environment variable names
const (
	EnvLogDir              = "MCP_LOG_DIR"
	EnvLogLevel            = "MCP_LOG_LEVEL"
	EnvLogDQLQueries       = "DT_LOG_DQL_QUERIES"
	EnvDTEnvironment       = "DT_ENVIRONMENT"
	EnvDTPlatformToken     = "DT_PLATFORM_TOKEN"
	EnvOAuthClientID       = "OAUTH_CLIENT_ID"
	EnvOAuthClientSecret   = "OAUTH_CLIENT_SECRET"
	EnvDTSSOURL            = "DT_SSO_URL"
	EnvDTAccountURN        = "DT_ACCOUNT_URN"
	EnvGrailBudgetGB       = "DT_GRAIL_QUERY_BUDGET_GB"
	EnvSlackConnID         = "SLACK_CONNECTION_ID"
	EnvEnableDavisCopilot  = "DT_ENABLE_DAVIS_COPILOT"
)

func main() {
	// Load environment variables from ~/.mcp_env if it exists
	// This must happen before flag parsing so env vars are available for defaults
	logging.LoadEnvFile()

	// Parse command line flags
	logDir := flag.String("log-dir", "", "Directory for log files (default: ~/go-mcp-dynatrace/logs)")
	logLevel := flag.String("log-level", "info", "Log level: off, error, warn, info, access, debug")
	httpMode := flag.Bool("http", false, "Run in HTTP mode instead of stdio")
	httpPort := flag.Int("port", 3000, "Port for HTTP server")
	httpHost := flag.String("host", "127.0.0.1", "Host for HTTP server")
	showVersion := flag.Bool("version", false, "Show version information")
	showHelp := flag.Bool("help", false, "Show help information")
	flag.Parse()

	if *showHelp {
		printHelp()
		os.Exit(0)
	}

	if *showVersion {
		fmt.Printf("%s version %s\n", AppName, Version)
		os.Exit(0)
	}

	// Resolve log directory
	var resolvedLogDir string
	var logDirSource logging.ConfigSource
	if *logDir != "" {
		resolvedLogDir = *logDir
		logDirSource = logging.SourceFlag
	} else if envVal := os.Getenv(EnvLogDir); envVal != "" {
		resolvedLogDir = envVal
		logDirSource = logging.SourceEnvironment
	} else {
		resolvedLogDir = logging.DefaultLogDir(AppName)
		logDirSource = logging.SourceDefault
	}

	// Resolve log level
	var resolvedLogLevel string
	var logLevelSource logging.ConfigSource
	if *logLevel != "info" {
		resolvedLogLevel = *logLevel
		logLevelSource = logging.SourceFlag
	} else if envVal := os.Getenv(EnvLogLevel); envVal != "" {
		resolvedLogLevel = envVal
		logLevelSource = logging.SourceEnvironment
	} else {
		resolvedLogLevel = "info"
		logLevelSource = logging.SourceDefault
	}
	parsedLogLevel := logging.ParseLogLevel(resolvedLogLevel)

	// Resolve DQL query logging (off by default)
	logDQLQueries := false
	if envVal := os.Getenv(EnvLogDQLQueries); envVal != "" {
		logDQLQueries = envVal == "true" || envVal == "1" || envVal == "yes"
	}

	// Initialize logger
	logger, err := logging.NewLogger(logging.Config{
		LogDir:        resolvedLogDir,
		AppName:       AppName,
		Level:         parsedLogLevel,
		LogDQLQueries: logDQLQueries,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()

	// Get Dynatrace configuration
	dtEnvironment := os.Getenv(EnvDTEnvironment)
	if dtEnvironment == "" {
		fmt.Fprintf(os.Stderr, "Error: %s environment variable is required\n", EnvDTEnvironment)
		os.Exit(1)
	}

	dtPlatformToken := os.Getenv(EnvDTPlatformToken)
	oauthClientID := os.Getenv(EnvOAuthClientID)
	oauthClientSecret := os.Getenv(EnvOAuthClientSecret)
	ssoURL := os.Getenv(EnvDTSSOURL)
	accountURN := os.Getenv(EnvDTAccountURN)
	slackConnID := os.Getenv(EnvSlackConnID)

	// Davis Copilot is disabled by default
	davisCopilotEnabled := false
	if envVal := os.Getenv(EnvEnableDavisCopilot); envVal != "" {
		davisCopilotEnabled = envVal == "true" || envVal == "1" || envVal == "yes"
	}

	grailBudgetGB := 1000 // Default
	if envVal := os.Getenv(EnvGrailBudgetGB); envVal != "" {
		fmt.Sscanf(envVal, "%d", &grailBudgetGB)
	}

	// Determine Dynatrace env source
	var dtEnvSource logging.ConfigSource = logging.SourceEnvironment

	// Log startup information
	startupInfo := logging.GetStartupInfo(
		Version,
		logging.ConfigValue{Value: resolvedLogDir, Source: logDirSource},
		logging.ConfigValue{Value: resolvedLogLevel, Source: logLevelSource},
		logging.ConfigValue{Value: dtEnvironment, Source: dtEnvSource},
		grailBudgetGB,
		logDQLQueries,
	)
	logger.LogStartup(startupInfo)

	fmt.Fprintf(os.Stderr, "Initializing Dynatrace MCP Server v%s...\n", Version)

	// Create Dynatrace client
	dtClient, err := dynatrace.NewClient(dynatrace.Config{
		Environment:       dtEnvironment,
		OAuthClientID:     oauthClientID,
		OAuthClientSecret: oauthClientSecret,
		PlatformToken:     dtPlatformToken,
		SSOURL:            ssoURL,
		AccountURN:        accountURN,
		GrailBudgetGB:     grailBudgetGB,
		Logger:            logger,
	})
	if err != nil {
		logger.Error("Failed to create Dynatrace client: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to create Dynatrace client: %v\n", err)
		os.Exit(1)
	}

	// Test connection
	fmt.Fprintf(os.Stderr, "Testing connection to Dynatrace environment: %s...\n", dtEnvironment)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = dtClient.TestConnection(ctx)
	cancel()

	if err != nil {
		logger.Error("Failed to connect to Dynatrace: %v", err)
		fmt.Fprintf(os.Stderr, "❌ Failed to connect to Dynatrace environment: %v\n", err)
		os.Exit(2)
	}

	fmt.Fprintf(os.Stderr, "✅ Successfully connected to Dynatrace environment at %s\n", dtEnvironment)
	logger.Info("Successfully connected to Dynatrace environment: %s", dtEnvironment)

	// Create MCP server
	server := mcp.NewServer("Dynatrace MCP Server", Version)

	// Set up telemetry callback
	server.SetToolCallCallback(func(name string, args map[string]interface{}, duration time.Duration, success bool) {
		logger.ToolCall(name, args, duration, success)
	})

	// Register all tools
	registry := tools.NewRegistry(tools.Config{
		Client:              dtClient,
		Logger:              logger,
		SlackConnID:         slackConnID,
		DavisCopilotEnabled: davisCopilotEnabled,
	})
	registry.RegisterAll(server)

	// Register DQL reference as a resource
	dqlProvider := dql.NewReferenceProvider()
	dqlAdapter := dql.NewMCPResourceAdapter(dqlProvider)
	server.RegisterResourceProvider(dqlAdapter)

	// Register prompts
	promptRegistry := prompts.NewRegistry()
	server.RegisterPromptProvider(promptRegistry)

	if dqlProvider.HasOverride() {
		logger.Info("DQL reference: using custom override file")
	} else if dqlProvider.HasCustomExtensions() {
		logger.Info("DQL reference: loaded custom extensions")
	} else {
		logger.Info("DQL reference: using embedded default")
	}

	logger.Info("Registered all tools and resources")
	fmt.Fprintf(os.Stderr, "Starting Dynatrace MCP Server v%s...\n", Version)

	// Set up graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logger.LogShutdown(fmt.Sprintf("received signal: %v", sig))
		fmt.Fprintf(os.Stderr, "\nShutting down MCP server...\n")
		os.Exit(0)
	}()

	// Run server
	if *httpMode {
		addr := fmt.Sprintf("%s:%d", *httpHost, *httpPort)
		logger.Info("Starting HTTP server on %s", addr)
		if err := server.RunHTTP(addr); err != nil {
			logger.Error("HTTP server error: %v", err)
			logger.LogShutdown(fmt.Sprintf("error: %v", err))
			fmt.Fprintf(os.Stderr, "HTTP server error: %v\n", err)
			os.Exit(1)
		}
	} else {
		logger.Info("Starting stdio server")
		fmt.Fprintf(os.Stderr, "Dynatrace MCP Server running on stdio\n")
		if err := server.Run(); err != nil {
			logger.Error("Server error: %v", err)
			logger.LogShutdown(fmt.Sprintf("error: %v", err))
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			os.Exit(1)
		}
	}

	logger.LogShutdown("normal exit")
}

func printHelp() {
	fmt.Printf(`%s - Dynatrace MCP Server

A Model Context Protocol (MCP) server that provides Dynatrace capabilities to LLMs.

USAGE:
    %s [OPTIONS]

OPTIONS:
    --http              Run in HTTP mode instead of stdio
    -p, --port <port>   Port for HTTP server (default: 3000)
    -H, --host <host>   Host for HTTP server (default: 127.0.0.1)

    -log-dir <path>     Directory for log files
                        Default: ~/go-mcp-dynatrace/logs
                        Env: MCP_LOG_DIR

    -log-level <level>  Log level: off, error, warn, info, access, debug
                        Default: info
                        Env: MCP_LOG_LEVEL

    -version            Show version information
    -help               Show this help message

ENVIRONMENT VARIABLES (Required):
    DT_ENVIRONMENT          URL to your Dynatrace Platform (required)
                            Example: https://abc12345.apps.dynatrace.com

ENVIRONMENT VARIABLES (Authentication - one method required):
    DT_PLATFORM_TOKEN       Platform authentication token

    OR

    OAUTH_CLIENT_ID         OAuth client ID
    OAUTH_CLIENT_SECRET     OAuth client secret
    DT_ACCOUNT_URN          Account URN for OAuth (required for OAuth)
                            Format: urn:dtaccount:<account-uuid>
    DT_SSO_URL              SSO URL (default: https://sso.dynatrace.com/sso/oauth2/token)

ENVIRONMENT VARIABLES (Optional):
    DT_GRAIL_QUERY_BUDGET_GB   Grail query budget in GB (default: 1000)
    DT_LOG_DQL_QUERIES         Log DQL queries to files (default: false)
                               When enabled, queries are saved to:
                               {log_dir}/DQL/YYYYMMDD/{name}.YYYYMMDD.HHmmss.dql
    DT_ENABLE_DAVIS_COPILOT    Enable Davis Copilot AI tools (default: false)
                               When enabled, adds tools for:
                               - Natural language to DQL conversion
                               - DQL explanation in natural language
                               - Davis Copilot chat
                               - Davis Analyzers
    SLACK_CONNECTION_ID        Slack connector ID for sending Slack messages
    MCP_LOG_DIR                Override default log directory
    MCP_LOG_LEVEL              Override default log level

EXAMPLES:
    # Run with OAuth credentials (stdio mode)
    export DT_ENVIRONMENT="https://abc12345.apps.dynatrace.com"
    export OAUTH_CLIENT_ID="dt0s02.XXXXXXXX"
    export OAUTH_CLIENT_SECRET="dt0s02.XXXXXXXX.XXXXXXXXXXXXXXXX"
    export DT_ACCOUNT_URN="urn:dtaccount:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    %s

    # Run in HTTP mode
    %s --http --port 8080

    # Run with platform token
    export DT_PLATFORM_TOKEN="dt0c01.XXXXXXXX.XXXXXXXXXXXXXXXX"
    %s

    # Run with debug logging
    %s -log-level debug

AVAILABLE TOOLS:
    get_environment_info            Get Dynatrace environment information
    list_problems                   List problems from Dynatrace
    list_vulnerabilities            List security vulnerabilities
    find_entity_by_name             Find monitored entities by name
    execute_dql                     Execute DQL queries
    verify_dql                      Verify DQL syntax
    get_kubernetes_events           Get Kubernetes events
    list_exceptions                 List application exceptions
    create_workflow_for_notification    Create notification workflow
    make_workflow_public            Make workflow public
    send_email                      Send email via Dynatrace
    send_slack_message              Send Slack message
    reset_grail_budget              Reset Grail query budget

  Davis Copilot Tools (requires DT_ENABLE_DAVIS_COPILOT=true):
    generate_dql_from_natural_language   Convert natural language to DQL
    explain_dql_in_natural_language      Explain DQL in natural language
    chat_with_davis_copilot         Chat with Davis CoPilot
    list_davis_analyzers            List available Davis Analyzers
    execute_davis_analyzer          Execute a Davis Analyzer

AVAILABLE PROMPTS:
    entity-deep-dive                Deep analysis of a monitored entity
    daily-summary                   Daily operations summary report

`, AppName, AppName, AppName, AppName, AppName, AppName)
}
