# go-mcp-dynatrace

A Go implementation of the [Dynatrace MCP Server](https://github.com/dynatrace-oss/dynatrace-mcp) - a Model Context Protocol (MCP) server that enables LLMs to interact with Dynatrace for observability, security, and automation tasks.

## Features

- **Full MCP Protocol Support**: Implements the Model Context Protocol for seamless LLM integration
- **Dynatrace Integration**: Query problems, vulnerabilities, entities, logs, metrics, and more
- **Davis CoPilot**: Natural language to DQL conversion, DQL explanation, and conversational AI
- **Davis Analyzers**: Execute forecast, anomaly detection, and correlation analyzers
- **Automation**: Create and manage workflows, send notifications via email and Slack
- **Budget Tracking**: Built-in Grail query budget management
- **Comprehensive Logging**: File-based logging with configurable levels

## Quick Start

### Prerequisites

- Go 1.21 or later
- A Dynatrace Platform environment
- OAuth credentials or Platform token

### Installation

```bash
# Clone the repository
git clone https://github.com/dynatrace-oss/go-mcp-dynatrace.git
cd go-mcp-dynatrace

# Build
go build -o go-mcp-dynatrace .

# Or install directly
go install github.com/dynatrace-oss/go-mcp-dynatrace@latest
```

### Configuration

Set the required environment variables:

```bash
# Required: Dynatrace environment URL
export DT_ENVIRONMENT="https://abc12345.apps.dynatrace.com"

# Authentication Option 1: OAuth credentials (recommended)
export OAUTH_CLIENT_ID="dt0s02.XXXXXXXX"
export OAUTH_CLIENT_SECRET="dt0s02.XXXXXXXX.XXXXXXXXXXXXXXXX"

# Authentication Option 2: Platform token
export DT_PLATFORM_TOKEN="dt0c01.XXXXXXXX.XXXXXXXXXXXXXXXX"

# Optional: Slack integration
export SLACK_CONNECTION_ID="your-slack-connection-id"

# Optional: Query budget (default: 1000 GB)
export DT_GRAIL_QUERY_BUDGET_GB="500"
```

### Running

```bash
# Run in stdio mode (for MCP clients)
./go-mcp-dynatrace

# Run in HTTP mode
./go-mcp-dynatrace --http --port 3000

# Run with debug logging
./go-mcp-dynatrace -log-level debug
```

## Usage with Claude Desktop

Add to your Claude Desktop configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "dynatrace": {
      "command": "/path/to/go-mcp-dynatrace",
      "env": {
        "DT_ENVIRONMENT": "https://abc12345.apps.dynatrace.com",
        "OAUTH_CLIENT_ID": "dt0s02.XXXXXXXX",
        "OAUTH_CLIENT_SECRET": "dt0s02.XXXXXXXX.XXXXXXXXXXXXXXXX"
      }
    }
  }
}
```

## Available Tools

### Data Query & Retrieval

| Tool | Description |
|------|-------------|
| `get_environment_info` | Get information about the connected Dynatrace environment |
| `execute_dql` | Execute DQL queries to retrieve logs, metrics, spans, events, and entity data |
| `verify_dql` | Verify DQL syntax before execution |
| `find_entity_by_name` | Find monitored entities by name |

### Problems & Security

| Tool | Description |
|------|-------------|
| `list_problems` | List all problems known on Dynatrace |
| `list_vulnerabilities` | List active security vulnerabilities |
| `list_exceptions` | List application exceptions |
| `get_kubernetes_events` | Get events from Kubernetes clusters |

### Davis AI

| Tool | Description |
|------|-------------|
| `generate_dql_from_natural_language` | Convert natural language to DQL using Davis CoPilot |
| `explain_dql_in_natural_language` | Explain DQL statements in natural language |
| `chat_with_davis_copilot` | Ask any Dynatrace-related question |
| `list_davis_analyzers` | List available Davis Analyzers |
| `execute_davis_analyzer` | Execute a Davis Analyzer |

### Automation & Notifications

| Tool | Description |
|------|-------------|
| `create_workflow_for_notification` | Create notification workflows |
| `make_workflow_public` | Make a workflow publicly available |
| `send_email` | Send email via Dynatrace |
| `send_slack_message` | Send Slack messages |

### Utilities

| Tool | Description |
|------|-------------|
| `reset_grail_budget` | Reset the Grail query budget |

## Command Line Options

```
Options:
    --http              Run in HTTP mode instead of stdio
    -p, --port <port>   Port for HTTP server (default: 3000)
    -H, --host <host>   Host for HTTP server (default: 127.0.0.1)
    -log-dir <path>     Directory for log files
    -log-level <level>  Log level: off, error, warn, info, access, debug
    -version            Show version information
    -help               Show help information
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DT_ENVIRONMENT` | Yes | URL to your Dynatrace Platform |
| `OAUTH_CLIENT_ID` | * | OAuth client ID |
| `OAUTH_CLIENT_SECRET` | * | OAuth client secret |
| `DT_PLATFORM_TOKEN` | * | Platform authentication token |
| `DT_SSO_URL` | No | SSO URL (default: sso.dynatrace.com) |
| `DT_GRAIL_QUERY_BUDGET_GB` | No | Grail query budget in GB (default: 1000) |
| `SLACK_CONNECTION_ID` | No | Slack connector ID |
| `MCP_LOG_DIR` | No | Log directory |
| `MCP_LOG_LEVEL` | No | Log level |

\* Either OAuth credentials or Platform token required

## Logging

Logs are written to `~/go-mcp-dynatrace/logs/` by default, with daily rotation.

Log levels:
- `off` - Disable logging
- `error` - Errors only
- `warn` - Warnings and errors
- `info` - General information (default)
- `access` - API access operations
- `debug` - Detailed debugging

**Security Note**: Logging never captures sensitive data like query results, tokens, or response content. Only operation metadata (endpoints, durations, record counts) is logged.

## OAuth Scopes Required

The server requests the following scopes:

- `app-engine:apps:run` - Environment information
- `storage:*:read` - Read logs, metrics, events, entities, spans
- `davis-copilot:*:execute` - Davis CoPilot features
- `davis:analyzers:read/execute` - Davis Analyzers
- `automation:workflows:*` - Workflow management
- `email:emails:send` - Email sending
- `app-settings:objects:read` - App settings

## Building from Source

```bash
# Build for current platform
go build -o go-mcp-dynatrace .

# Build for all platforms
./build.sh        # Linux/macOS
./build.ps1       # Windows

# Run tests
go test ./...
```

## Architecture

```
go-mcp-dynatrace/
├── main.go                 # Entry point
├── pkg/
│   ├── mcp/               # MCP protocol implementation
│   │   ├── server.go      # JSON-RPC server
│   │   └── types.go       # Protocol types
│   ├── dynatrace/         # Dynatrace API client
│   │   ├── client.go      # HTTP client with OAuth
│   │   └── types.go       # API types
│   ├── tools/             # MCP tool implementations
│   │   └── tools.go       # All tool handlers
│   └── logging/           # Logging infrastructure
│       └── logging.go     # Logger implementation
└── go.mod
```

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting PRs.

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- Based on the [Dynatrace MCP Server](https://github.com/dynatrace-oss/dynatrace-mcp) (TypeScript)
- MCP architecture inspired by [go-mcp-file-context-server](https://github.com/JeremyProffitt/go-mcp-file-context-server)
