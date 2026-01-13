# MCP Client Integration Guide

> **LLM Context**: This file explains how to configure MCP clients to connect to this server. Use this when helping users set up Claude Code, Continue.dev, or other MCP clients. Key files: `claude_code_config.json` (Claude Code), `config.json` (Continue.dev).

This guide explains how to configure MCP clients (Claude Code and Continue.dev) to connect to the go-mcp-dynatrace server running in HTTP mode, including authentication configuration.

## Authentication Overview

When running in HTTP mode with authentication enabled (via `MCP_AUTH_TOKEN` environment variable), all requests must include the `X-MCP-Auth-Token` header with the configured token value.

## Claude Code Integration

### Configuration Location

Claude Code configuration is stored in:
- **macOS/Linux**: `~/.claude/claude_code_config.json`
- **Windows**: `%USERPROFILE%\.claude\claude_code_config.json`

Alternatively, project-level configuration in `.mcp.json` in your project root.

### HTTP Mode Configuration

Add the following to your Claude Code configuration:

```json
{
  "mcpServers": {
    "dynatrace": {
      "type": "http",
      "url": "http://your-alb-url:3000",
      "headers": {
        "X-MCP-Auth-Token": "your-secure-auth-token"
      }
    }
  }
}
```

### Configuration with Environment Variable for Token

For better security, you can reference environment variables:

```json
{
  "mcpServers": {
    "dynatrace": {
      "type": "http",
      "url": "http://your-alb-url:3000",
      "headers": {
        "X-MCP-Auth-Token": "${MCP_DYNATRACE_TOKEN}"
      }
    }
  }
}
```

Then set the environment variable:
```bash
export MCP_DYNATRACE_TOKEN="your-secure-auth-token"
```

### Local Development (stdio mode)

For local development without HTTP:

```json
{
  "mcpServers": {
    "dynatrace": {
      "command": "/path/to/go-mcp-dynatrace",
      "args": [],
      "env": {
        "DT_ENVIRONMENT": "https://abc12345.apps.dynatrace.com",
        "OAUTH_CLIENT_ID": "your-client-id",
        "OAUTH_CLIENT_SECRET": "your-client-secret",
        "DT_ACCOUNT_URN": "urn:dtaccount:your-account-id"
      }
    }
  }
}
```

## Continue.dev Integration

### Configuration Location

Continue.dev configuration is stored in:
- **macOS/Linux**: `~/.continue/config.json`
- **Windows**: `%USERPROFILE%\.continue\config.json`

### HTTP Mode Configuration

Add the MCP server to your Continue.dev configuration:

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "name": "dynatrace",
        "transport": {
          "type": "http",
          "url": "http://your-alb-url:3000",
          "headers": {
            "X-MCP-Auth-Token": "your-secure-auth-token"
          }
        }
      }
    ]
  }
}
```

### Configuration with Dynamic Token

For dynamic token retrieval (future enhancement), you could use a token fetcher:

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "name": "dynatrace",
        "transport": {
          "type": "http",
          "url": "http://your-alb-url:3000",
          "headers": {
            "X-MCP-Auth-Token": "${env:MCP_DYNATRACE_TOKEN}"
          }
        }
      }
    ]
  }
}
```

### Local Development (stdio mode)

For local development without HTTP:

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "name": "dynatrace",
        "transport": {
          "type": "stdio",
          "command": "/path/to/go-mcp-dynatrace",
          "args": []
        },
        "env": {
          "DT_ENVIRONMENT": "https://abc12345.apps.dynatrace.com",
          "OAUTH_CLIENT_ID": "your-client-id",
          "OAUTH_CLIENT_SECRET": "your-client-secret",
          "DT_ACCOUNT_URN": "urn:dtaccount:your-account-id"
        }
      }
    ]
  }
}
```

## Dynamic Token Authentication (Future Enhancement)

For organizations that want dynamic token authentication, you can implement a token endpoint:

### Token Endpoint Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   MCP Client    │────▶│  Token Service  │────▶│  Identity       │
│                 │◀────│  (API Gateway)  │◀────│  Provider       │
└─────────────────┘     └─────────────────┘     └─────────────────┘
         │
         │ (with token)
         ▼
┌─────────────────┐
│  MCP Server     │
│  (ECS/Fargate)  │
└─────────────────┘
```

### Example Token Fetch Script

Create a wrapper script that fetches a token before connecting:

```bash
#!/bin/bash
# get-mcp-token.sh

# Fetch token from your authentication service
TOKEN=$(curl -s -X POST https://your-auth-service.com/token \
    -H "Content-Type: application/json" \
    -d '{"client_id": "your-client-id", "client_secret": "your-client-secret"}' \
    | jq -r '.access_token')

export MCP_DYNATRACE_TOKEN="$TOKEN"
echo "$TOKEN"
```

### Pre-request Hook (Continue.dev)

You can configure a pre-request hook in Continue.dev to fetch tokens:

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "name": "dynatrace",
        "transport": {
          "type": "http",
          "url": "http://your-alb-url:3000",
          "beforeRequest": {
            "command": "/path/to/get-mcp-token.sh",
            "headerName": "X-MCP-Auth-Token"
          }
        }
      }
    ]
  }
}
```

## Testing the Connection

### Using curl

```bash
# Test health endpoint (no auth required)
curl http://your-alb-url:3000/health

# Test MCP endpoint with auth
curl -X POST http://your-alb-url:3000/ \
    -H "Content-Type: application/json" \
    -H "X-MCP-Auth-Token: your-secure-auth-token" \
    -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}},"id":1}'

# List available tools
curl -X POST http://your-alb-url:3000/ \
    -H "Content-Type: application/json" \
    -H "X-MCP-Auth-Token: your-secure-auth-token" \
    -d '{"jsonrpc":"2.0","method":"tools/list","id":2}'
```

### Expected Responses

Health check:
```json
{"status": "healthy", "server": "Dynatrace MCP Server"}
```

Initialize:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {"tools": {"listChanged": false}},
    "serverInfo": {"name": "Dynatrace MCP Server", "version": "1.0.0"}
  }
}
```

Unauthorized (missing/invalid token):
```json
{
  "jsonrpc": "2.0",
  "id": null,
  "error": {"code": -32001, "message": "Unauthorized: invalid or missing authentication token"}
}
```

## Security Best Practices

1. **Use HTTPS in production**: Always use HTTPS (via ALB/CloudFront) for production deployments
2. **Rotate tokens regularly**: Implement token rotation policies
3. **Use environment variables**: Never hardcode tokens in configuration files committed to version control
4. **Restrict token scope**: Use different tokens for different environments/users
5. **Monitor access**: Enable CloudWatch logging to track authentication attempts
6. **Use VPN/Private Link**: For highly sensitive environments, restrict access to VPN or use AWS PrivateLink

## Troubleshooting

### Connection Refused
- Verify the server is running and accessible
- Check security group rules allow traffic on port 3000
- Verify ALB health checks are passing

### 401 Unauthorized
- Verify the `X-MCP-Auth-Token` header is set correctly
- Ensure the token matches the `MCP_AUTH_TOKEN` environment variable on the server
- Check for trailing whitespace in token values

### Timeout Errors
- Increase client timeout settings
- Check for network latency issues
- Verify the server is not overloaded

### SSL/TLS Errors
- Ensure certificates are valid and not expired
- Verify the client trusts the certificate authority
- Check for certificate chain issues
