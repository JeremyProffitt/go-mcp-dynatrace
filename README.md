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

## Tool Reference

This MCP server provides 19 tools organized into 6 categories for comprehensive Dynatrace observability operations.

### Discovery Tools (Read-Only)

Use these tools first to understand your environment and find entities.

| Tool | Description | When to Use |
|------|-------------|-------------|
| `get_environment_info` | Get Dynatrace environment details (name, ID, capabilities) | First call to verify connection and understand environment |
| `find_entity_by_name` | Search monitored entities by name pattern | Finding hosts, services, or applications by name |

### Query Tools (Read-Only)

Execute and validate DQL queries against Grail data lakehouse.

| Tool | Description | When to Use |
|------|-------------|-------------|
| `execute_dql` | Run DQL queries for logs, metrics, spans, events, entities | Primary data retrieval - use for all observability queries |
| `verify_dql` | Validate DQL syntax without execution | Check query syntax before running expensive queries |

### Security Tools (Read-Only)

Monitor security posture and vulnerabilities.

| Tool | Description | When to Use |
|------|-------------|-------------|
| `list_vulnerabilities` | Get active security vulnerabilities with severity | Security audits, vulnerability assessments |
| `list_problems` | List active Davis-detected problems | Incident response, problem investigation |
| `list_exceptions` | Get application exceptions and stack traces | Debugging application errors |
| `get_kubernetes_events` | Retrieve K8s cluster events | Kubernetes troubleshooting |

### AI Tools (Davis CoPilot)

Leverage Davis AI for natural language interactions and analysis.

| Tool | Description | When to Use |
|------|-------------|-------------|
| `generate_dql_from_natural_language` | Convert plain English to DQL queries | When unsure how to write a DQL query |
| `explain_dql_in_natural_language` | Get human-readable explanation of DQL | Understanding complex existing queries |
| `chat_with_davis_copilot` | Ask any Dynatrace question | General questions, best practices, guidance |
| `list_davis_analyzers` | List available AI analyzers | Discover available analysis capabilities |
| `execute_davis_analyzer` | Run forecast, anomaly, or correlation analysis | Predictive analysis, root cause analysis |

### Write Tools (Modifying)

Create and manage automation workflows.

| Tool | Description | When to Use |
|------|-------------|-------------|
| `create_workflow_for_notification` | Create alert notification workflows | Setting up automated alerting |
| `make_workflow_public` | Share workflow with other users | Enabling workflow collaboration |

### Admin Tools

System administration and notifications.

| Tool | Description | When to Use |
|------|-------------|-------------|
| `send_email` | Send email via Dynatrace email service | Sending reports, notifications |
| `send_slack_message` | Post to Slack channels | Team notifications, incident alerts |
| `reset_grail_budget` | Reset query budget counter | When budget is exhausted mid-session |

---

## Common Workflows

### Workflow 1: Incident Investigation

When investigating a production issue, follow this sequence:

```
1. get_environment_info          # Verify connection
2. list_problems                 # See active Davis-detected problems
3. execute_dql                   # Query logs around problem timeframe
   Query: fetch logs, from: now() - 1h | filter loglevel == "ERROR" | limit 100
4. find_entity_by_name           # Find affected services/hosts
5. execute_dql                   # Get related spans for tracing
   Query: fetch spans, from: now() - 1h | filter status == "ERROR"
6. chat_with_davis_copilot       # Ask Davis for root cause insights
```

### Workflow 2: Security Assessment

```
1. list_vulnerabilities          # Get all active vulnerabilities
2. execute_dql                   # Query security events
   Query: fetch security_events, from: now() - 24h | summarize count(), by: {severity}
3. find_entity_by_name           # Find vulnerable hosts/services
4. execute_davis_analyzer        # Run security analysis
```

### Workflow 3: Performance Analysis

```
1. execute_dql                   # Get latency percentiles
   Query: fetch spans, from: now() - 1h
   | summarize p50=percentile(duration, 50), p95=percentile(duration, 95), p99=percentile(duration, 99), by: {span.name}
2. list_davis_analyzers          # Find available analyzers
3. execute_davis_analyzer        # Run anomaly detection
4. generate_dql_from_natural_language  # "Show me slow database queries"
```

### Workflow 4: Log Analysis

```
1. execute_dql                   # Search for errors
   Query: fetch logs, from: now() - 1h | filter loglevel == "ERROR" | summarize count(), by: {log.source}
2. execute_dql                   # Parse and extract fields
   Query: fetch logs | parse content, "status=INT:status duration=INT:duration" | filter status >= 400
3. explain_dql_in_natural_language   # Understand complex existing query
```

### Workflow 5: Natural Language to Query

When the user describes what they want in plain English:

```
1. generate_dql_from_natural_language  # Convert request to DQL
2. verify_dql                          # Validate generated query
3. execute_dql                         # Run the query
4. explain_dql_in_natural_language     # Explain what query does (if needed)
```

---

## DQL Quick Reference

### Essential Query Patterns

```dql
# Error count by source (last hour)
fetch logs, from: now() - 1h
| filter loglevel == "ERROR"
| summarize count(), by: {log.source}
| sort count() desc

# Top 10 slowest services
fetch spans, from: now() - 1h
| summarize avg_duration = avg(duration), by: {span.name}
| sort avg_duration desc
| limit 10

# Error rate calculation
fetch logs, from: now() - 1h
| summarize
    total = count(),
    errors = countIf(loglevel == "ERROR"),
    error_rate = 100.0 * countIf(loglevel == "ERROR") / count()

# Time series for graphing
fetch logs, from: now() - 6h
| filter loglevel == "ERROR"
| summarize count(), by: {bin(timestamp, 5m)}
| sort timestamp asc

# Text search in logs
fetch logs, from: now() - 1h
| filter matchesPhrase(content, "connection timeout")

# Find specific entities
fetch entities
| filter entity.type == "HOST"
| filter matchesValue(tags, "environment:production")
| fields entity.name, id, tags
```

### Data Sources Reference

| Source | Use For | Example Query |
|--------|---------|---------------|
| `logs` | Application/system logs | `fetch logs \| filter loglevel == "ERROR"` |
| `spans` | Distributed traces | `fetch spans \| filter duration > 1000000000` |
| `events` | Davis events | `fetch events \| filter event.type == "ERROR_EVENT"` |
| `entities` | Monitored components | `fetch entities \| filter entity.type == "SERVICE"` |
| `metrics` | Time series metrics | `fetch metrics \| filter metric.key == "cpu.usage"` |
| `bizevents` | Business events | `fetch bizevents \| filter event.type == "purchase"` |

### Common Functions

| Function | Purpose | Example |
|----------|---------|---------|
| `count()` | Count records | `summarize count()` |
| `countIf(cond)` | Conditional count | `summarize countIf(status >= 400)` |
| `avg(field)` | Average value | `summarize avg(duration)` |
| `percentile(field, p)` | Percentile calculation | `summarize percentile(latency, 95)` |
| `bin(ts, interval)` | Time bucketing | `by: {bin(timestamp, 5m)}` |
| `contains(str, substr)` | Substring check | `filter contains(content, "error")` |
| `matchesPhrase(str, phrase)` | Indexed text search | `filter matchesPhrase(content, "timeout")` |

### Time Ranges

```dql
from: now() - 1h      # Last hour
from: now() - 24h     # Last 24 hours
from: now() - 7d      # Last 7 days
from: "2024-01-15T00:00:00Z", to: "2024-01-15T23:59:59Z"  # Absolute range
```

### Performance Tips

1. **Filter early** - Put filters right after `fetch`
2. **Use `matchesPhrase`** - Faster than `contains` for indexed search
3. **Limit time range** - Always specify `from:` for large datasets
4. **Use `scanLimitGBytes`** - Control query cost: `fetch logs, scanLimitGBytes: 100`
5. **Select specific fields** - Use `fields` to reduce data transfer

---

## Available Tools (Legacy Format)

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
| `DT_LOG_QUERIES` | No | Log DQL queries to files (default: false) |
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

When `MCP_LOG_DIR` is set or `-log-dir` flag is used, logs are automatically placed in a subfolder named after the binary (`go-mcp-dynatrace`). This allows multiple MCP servers to share the same log directory:

```
MCP_LOG_DIR=/var/log/mcp
  └── go-mcp-dynatrace/
      └── go-mcp-dynatrace-2026-01-04.log
```

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
export DT_LOG_QUERIES=true
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
