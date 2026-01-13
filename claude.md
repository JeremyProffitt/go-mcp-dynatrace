# Project Guidelines

## Overview

This is **go-mcp-dynatrace**, a Go implementation of an MCP (Model Context Protocol) server for Dynatrace observability platform integration. The server enables LLMs to query logs, metrics, traces, events, and leverage Davis AI capabilities.

## LLM Usage Guidelines

### Tool Selection Strategy

When helping users with Dynatrace tasks, follow this decision tree:

1. **User asks about environment/connection** -> `get_environment_info`
2. **User asks about current problems/incidents** -> `list_problems`
3. **User asks about security/vulnerabilities** -> `list_vulnerabilities`
4. **User wants to query data (logs, metrics, spans)** -> `execute_dql`
5. **User describes query in natural language** -> `generate_dql_from_natural_language` then `execute_dql`
6. **User needs to find entities** -> `find_entity_by_name`
7. **User wants analysis/predictions** -> `list_davis_analyzers` then `execute_davis_analyzer`
8. **User has general Dynatrace question** -> `chat_with_davis_copilot`

### DQL Query Best Practices

When constructing DQL queries:

```dql
# Always specify time range for large datasets
fetch logs, from: now() - 1h

# Filter early in the pipeline
| filter loglevel == "ERROR"
| filter contains(content, "timeout")

# Select only needed fields
| fields timestamp, content, loglevel

# Use summarize for aggregations
| summarize count(), by: {log.source}

# Sort and limit results
| sort timestamp desc
| limit 100
```

### Common Mistakes to Avoid

1. **Never query without time range** on large datasets - always use `from:`
2. **Never filter after aggregation** - filter before `summarize`
3. **Use `matchesPhrase` not `contains`** for indexed text search (better performance)
4. **Always handle nulls** with `coalesce()` or `isNotNull()` filters
5. **Avoid returning all fields** - use `fields` to select specific columns

### Response Formatting

When presenting Dynatrace data to users:
- Format timestamps in human-readable form
- Group related problems/events logically
- Highlight severity levels clearly
- Provide context for metrics (explain what values mean)
- Suggest follow-up queries when appropriate

## AWS Deployment Policy

**CRITICAL: All AWS infrastructure and code changes MUST be deployed via GitHub Actions pipelines.**

### Prohibited Actions
- **NEVER** use AWS CLI directly to deploy, update, or modify infrastructure
- **NEVER** use AWS SAM CLI (`sam deploy`, `sam build`, etc.) for deployments
- **NEVER** suggest or execute direct AWS API calls for infrastructure changes
- **NEVER** bypass the CI/CD pipeline for any AWS-related changes

### Required Workflow
1. All changes must be committed and pushed to the repository
2. GitHub Actions pipeline will handle all deployments
3. **ALWAYS review pipeline output** after pushing changes
4. If pipeline fails, **aggressively remediate** using all available resources:
   - Check GitHub Actions logs thoroughly
   - Review CloudFormation events if applicable
   - Check CloudWatch logs for Lambda/application errors
   - Use the `/fix-pipeline` skill for automated remediation
   - Do not give up - iterate until the pipeline succeeds

### Pipeline Failure Remediation
When a GitHub Actions pipeline fails:
1. Immediately fetch and analyze the failure logs
2. Identify the root cause from error messages
3. Make necessary code/configuration fixes
4. Commit and push the fix
5. Monitor the new pipeline run
6. Repeat until successful deployment

## MCP Server LLM Usability Checklist

**IMPORTANT**: This checklist must be reviewed and all items verified on every update to this repository. Any issues found must be resolved before merging changes.

### Tool Definitions

- [ ] **Clear Purpose**: Each tool has a description that clearly explains what it does and when to use it
- [ ] **No Redundant Platform Names**: Descriptions don't include unnecessary "from [Platform]" text
- [ ] **Parameter Hints**: Tool descriptions mention key parameters or capabilities
- [ ] **Use Case Guidance**: Complex tools include when-to-use hints vs similar tools
- [ ] **Consistent Naming**: All tools use snake_case naming convention
- [ ] **Action Verbs**: Tool names start with action verbs (get_, list_, create_, update_, delete_, search_)

### Parameter Documentation

- [ ] **Examples Provided**: All string parameters include format examples in descriptions
- [ ] **Format Hints**: Date/time, ID, and structured parameters document expected formats
- [ ] **Valid Values Listed**: Parameters with fixed options list valid values (e.g., "Status: 'open', 'closed', 'all'")
- [ ] **No Redundant Defaults**: Default values are in the Default field, not repeated in description text
- [ ] **Array Format Clear**: Array parameters explain expected item format
- [ ] **Object Structure Documented**: Object parameters describe expected properties

### Schema Constraints

- [ ] **Numeric Bounds**: All limit/offset/count parameters have Minimum and Maximum constraints
- [ ] **Integer Types**: Pagination and count parameters use "integer" not "number"
- [ ] **Enum Values**: Categorical parameters have Enum arrays defined in schema
- [ ] **Array Items Typed**: All array parameters have Items property with type defined
- [ ] **Object Properties**: Complex object parameters have Properties defined where structure is known
- [ ] **Pattern Validation**: ID fields have Pattern regex where format is standardized (optional)

### Tool Annotations

- [ ] **Title Set**: All tools have a human-readable Title annotation
- [ ] **ReadOnlyHint**: All get_*, list_*, search_*, describe_* tools have ReadOnlyHint: true
- [ ] **DestructiveHint**: All delete_* tools have DestructiveHint: true
- [ ] **IdempotentHint**: Safe-to-retry operations have IdempotentHint: true
- [ ] **OpenWorldHint**: Tools interacting with external systems have OpenWorldHint: true (optional)

### Token Efficiency

- [ ] **Concise Descriptions**: Tool descriptions are under 200 characters where possible
- [ ] **No Duplicate Info**: Information isn't repeated between tool and parameter descriptions
- [ ] **Abbreviated Common Terms**: Use "Max results" instead of "Maximum number of results to return"
- [ ] **Consistent Parameter Docs**: Common parameters (limit, offset, page) use identical descriptions

### Documentation

- [ ] **README Tool Reference**: README includes descriptions of what each tool does
- [ ] **Workflow Examples**: Common multi-tool workflows are documented
- [ ] **Error Handling Guide**: Common errors and recovery strategies documented
- [ ] **Parameter Patterns**: Common parameter formats (IDs, dates, queries) documented once

### Code Quality

- [ ] **Compiles Successfully**: `go build ./...` completes without errors
- [ ] **Tests Pass**: `go test ./...` completes without failures
- [ ] **No Unused Code**: No commented-out code or unused variables
- [ ] **Consistent Formatting**: Code follows Go formatting standards (`go fmt`)

### Pre-Commit Verification

Before committing changes to this repository, run:

```bash
# Verify compilation
go build ./...

# Run all tests
go test ./...

# Check formatting
go fmt ./...

# Verify tool definitions (manual review)
# Review any new or modified tools against this checklist
```

### Issue Resolution Process

If any checklist item fails:

1. **Document the Issue**: Note which item failed and in which file
2. **Fix the Issue**: Make the necessary code changes
3. **Verify the Fix**: Re-run the relevant checks
4. **Update Tests**: Add tests for new functionality if applicable
5. **Re-verify Checklist**: Ensure fix didn't break other items
