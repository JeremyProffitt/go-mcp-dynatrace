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
- **DQL Query Logging**: Optional file-based logging of all DQL queries for debugging and auditing
- **MCP Resources**: DQL language reference available as an MCP resource

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
export DT_ACCOUNT_URN="urn:dtaccount:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Authentication Option 2: Platform token
export DT_PLATFORM_TOKEN="dt0c01.XXXXXXXX.XXXXXXXXXXXXXXXX"

# Optional: Custom SSO URL (default: https://sso.dynatrace.com/sso/oauth2/token)
export DT_SSO_URL="https://sso.dynatrace.com/sso/oauth2/token"

# Optional: Slack integration
export SLACK_CONNECTION_ID="your-slack-connection-id"

# Optional: Query budget (default: 1000 GB)
export DT_GRAIL_QUERY_BUDGET_GB="500"
```

> **Note**: When using OAuth authentication, the `DT_ACCOUNT_URN` is required. You can find your account UUID in the Dynatrace Account Management portal under Account Settings.

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
        "OAUTH_CLIENT_SECRET": "dt0s02.XXXXXXXX.XXXXXXXXXXXXXXXX",
        "DT_ACCOUNT_URN": "urn:dtaccount:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
      }
    }
  }
}
```

## Usage with Continue.dev

### JSON Configuration

Add to your Continue configuration (`config.json`):

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "transport": {
          "type": "stdio",
          "command": "/path/to/go-mcp-dynatrace",
          "args": [],
          "env": {
            "DT_ENVIRONMENT": "https://abc12345.apps.dynatrace.com",
            "OAUTH_CLIENT_ID": "dt0s02.XXXXXXXX",
            "OAUTH_CLIENT_SECRET": "dt0s02.XXXXXXXX.XXXXXXXXXXXXXXXX",
            "DT_ACCOUNT_URN": "urn:dtaccount:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
          }
        }
      }
    ]
  }
}
```

### YAML Configuration

Add to your Continue configuration (`config.yaml`):

```yaml
experimental:
  modelContextProtocolServers:
    - transport:
        type: stdio
        command: /path/to/go-mcp-dynatrace
        args: []
        env:
          DT_ENVIRONMENT: https://abc12345.apps.dynatrace.com
          OAUTH_CLIENT_ID: dt0s02.XXXXXXXX
          OAUTH_CLIENT_SECRET: dt0s02.XXXXXXXX.XXXXXXXXXXXXXXXX
          DT_ACCOUNT_URN: urn:dtaccount:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### Using Environment Variables

You can reference environment variables in your configuration to avoid hardcoding sensitive values.

**JSON with environment variables:**

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "transport": {
          "type": "stdio",
          "command": "/path/to/go-mcp-dynatrace",
          "args": [],
          "env": {
            "DT_ENVIRONMENT": "${DT_ENVIRONMENT}",
            "OAUTH_CLIENT_ID": "${OAUTH_CLIENT_ID}",
            "OAUTH_CLIENT_SECRET": "${OAUTH_CLIENT_SECRET}",
            "DT_ACCOUNT_URN": "${DT_ACCOUNT_URN}"
          }
        }
      }
    ]
  }
}
```

**YAML with environment variables:**

```yaml
experimental:
  modelContextProtocolServers:
    - transport:
        type: stdio
        command: /path/to/go-mcp-dynatrace
        args: []
        env:
          DT_ENVIRONMENT: ${DT_ENVIRONMENT}
          OAUTH_CLIENT_ID: ${OAUTH_CLIENT_ID}
          OAUTH_CLIENT_SECRET: ${OAUTH_CLIENT_SECRET}
          DT_ACCOUNT_URN: ${DT_ACCOUNT_URN}
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
| `DT_ACCOUNT_URN` | * | Account URN for OAuth (format: `urn:dtaccount:<uuid>`) |
| `DT_PLATFORM_TOKEN` | ** | Platform authentication token |
| `DT_SSO_URL` | No | SSO URL (default: sso.dynatrace.com) |
| `DT_GRAIL_QUERY_BUDGET_GB` | No | Grail query budget in GB (default: 1000) |
| `DT_LOG_DQL_QUERIES` | No | Log DQL queries to files (default: false) |
| `SLACK_CONNECTION_ID` | No | Slack connector ID |
| `MCP_LOG_DIR` | No | Log directory |
| `MCP_LOG_LEVEL` | No | Log level |

\* Required for OAuth authentication
\*\* Alternative to OAuth - use Platform token instead

## Global Environment File

All go-mcp servers support loading environment variables from `~/.mcp_env`. This provides a central location to configure credentials and settings, especially useful on macOS where GUI applications don't inherit shell environment variables from `.zshrc` or `.bashrc`.

### File Format

Create `~/.mcp_env` with KEY=VALUE pairs:

```bash
# ~/.mcp_env - MCP Server Environment Variables

# Dynatrace Configuration
DT_ENVIRONMENT=https://abc12345.apps.dynatrace.com
OAUTH_CLIENT_ID=dt0s02.XXXXXXXX
OAUTH_CLIENT_SECRET=dt0s02.XXXXXXXX.XXXXXXXXXXXXXXXX
DT_ACCOUNT_URN=urn:dtaccount:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Logging
MCP_LOG_DIR=~/mcp-logs
MCP_LOG_LEVEL=info
```

### Features

- Lines starting with `#` are treated as comments
- Empty lines are ignored
- Values can be quoted with single or double quotes
- **Existing environment variables are NOT overwritten** (env vars take precedence)
- Paths with `~` are automatically expanded to your home directory

### Path Expansion

All path-related settings support `~` expansion:

```bash
MCP_LOG_DIR=~/logs/dynatrace
```

This works in the `~/.mcp_env` file, environment variables, and command-line flags.

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

### DQL Query Logging

Enable DQL query file logging for debugging and auditing by setting:

```bash
export DT_LOG_DQL_QUERIES=true
```

When enabled, all DQL queries are saved to individual files:

```
~/go-mcp-dynatrace/logs/DQL/YYYYMMDD/{name}.YYYYMMDD.HHmmss.dql
```

Example:
```
~/go-mcp-dynatrace/logs/DQL/20260103/fetch_logs.20260103.142530.dql
~/go-mcp-dynatrace/logs/DQL/20260103/list_problems.20260103.143215.dql
```

This is useful for:
- Debugging query issues
- Auditing what queries were executed
- Reproducing queries in the Dynatrace UI
- Building a library of working DQL queries

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
│   │   ├── server.go      # JSON-RPC server with resource support
│   │   └── types.go       # Protocol types
│   ├── dynatrace/         # Dynatrace API client
│   │   ├── client.go      # HTTP client with OAuth
│   │   ├── types.go       # API types
│   │   └── token_cache.go # OAuth token caching
│   ├── dql/               # DQL language reference
│   │   ├── reference.go   # Reference provider
│   │   └── mcp_adapter.go # MCP resource adapter
│   ├── tools/             # MCP tool implementations
│   │   └── tools.go       # All tool handlers
│   └── logging/           # Logging infrastructure
│       └── logging.go     # Logger with DQL query file logging
└── go.mod
```

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting PRs.

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- Based on the [Dynatrace MCP Server](https://github.com/dynatrace-oss/dynatrace-mcp) (TypeScript)
- MCP architecture inspired by [go-mcp-file-context-server](https://github.com/JeremyProffitt/go-mcp-file-context-server)
