// Package prompts provides MCP prompt templates for common Dynatrace operations
package prompts

import (
	"fmt"

	"github.com/dynatrace-oss/go-mcp-dynatrace/pkg/mcp"
)

// Registry holds all prompt registrations
type Registry struct {
	prompts  []mcp.Prompt
	handlers map[string]PromptHandler
}

// PromptHandler generates a prompt result for given arguments
type PromptHandler func(arguments map[string]interface{}) (*mcp.GetPromptResult, error)

// NewRegistry creates a new prompt registry
func NewRegistry() *Registry {
	r := &Registry{
		prompts:  make([]mcp.Prompt, 0),
		handlers: make(map[string]PromptHandler),
	}
	r.registerAll()
	return r
}

// ListPrompts returns the available prompts (implements mcp.PromptProvider)
func (r *Registry) ListPrompts() []mcp.Prompt {
	return r.prompts
}

// GetPrompt returns a prompt result for the given name and arguments (implements mcp.PromptProvider)
func (r *Registry) GetPrompt(name string, arguments map[string]interface{}) (*mcp.GetPromptResult, error) {
	handler, exists := r.handlers[name]
	if !exists {
		return nil, fmt.Errorf("prompt not found: %s", name)
	}
	return handler(arguments)
}

func (r *Registry) registerPrompt(prompt mcp.Prompt, handler PromptHandler) {
	r.prompts = append(r.prompts, prompt)
	r.handlers[prompt.Name] = handler
}

func (r *Registry) registerAll() {
	r.registerEntityDeepDive()
	r.registerDailySummary()
	r.registerExploreBucket()
	r.registerExploreTags()
}

func (r *Registry) registerEntityDeepDive() {
	r.registerPrompt(mcp.Prompt{
		Name:        "entity-deep-dive",
		Description: "Perform a comprehensive analysis of a specific Dynatrace monitored entity (service, host, application, process group, etc.)",
		Arguments: []mcp.PromptArgument{
			{
				Name:        "entity_name",
				Description: "Name or partial name of the entity to analyze",
				Required:    true,
			},
			{
				Name:        "timeframe",
				Description: "Timeframe for analysis (e.g., '1h', '24h', '7d'). Default: 24h",
				Required:    false,
			},
		},
	}, func(args map[string]interface{}) (*mcp.GetPromptResult, error) {
		entityName := getString(args, "entity_name", "")
		if entityName == "" {
			return nil, fmt.Errorf("entity_name is required")
		}

		timeframe := getString(args, "timeframe", "24h")

		promptText := fmt.Sprintf(`# Entity Deep Dive Analysis

Perform a comprehensive analysis of the entity "%s" over the last %s.

## Analysis Steps

### 1. Entity Discovery
First, find the entity using the find_entity_by_name tool:
- Search for: "%s"
- Note the entity ID, type, and any tags

### 2. Health Overview
Check for any problems affecting this entity:
- Use list_problems with a filter for this entity
- Look for both ACTIVE and recently CLOSED problems
- Note any recurring patterns

### 3. Performance Metrics
Query key metrics for this entity type using execute_dql:

For **services**:
`+"```"+`
fetch dt.metrics.series
| filter dt.smartscape.service == "<entity_id>"
| filter metric.key IN ("builtin:service.response.time", "builtin:service.errors.total.rate", "builtin:service.requestCount.total")
| fieldsAdd value = arrayAvg(values)
| summarize avg(value), by:{metric.key}
`+"```"+`

For **hosts**:
`+"```"+`
fetch dt.metrics.series
| filter dt.smartscape.host == "<entity_id>"
| filter metric.key IN ("builtin:host.cpu.usage", "builtin:host.mem.usage", "builtin:host.disk.usedPct")
| fieldsAdd value = arrayAvg(values)
| summarize avg(value), by:{metric.key}
`+"```"+`

### 4. Related Events
Query events related to this entity:
`+"```"+`
fetch events, from: now()-%s
| filter contains(toString(affected_entity_ids), "<entity_id>")
| sort timestamp desc
| limit 20
| fields event.type, event.name, event.status, timestamp
`+"```"+`

### 5. Dependencies (for services)
Explore service dependencies:
`+"```"+`
smartscapeNodes "service"
| filter id == "<entity_id>"
| fields name, calls, calledBy
`+"```"+`

### 6. Log Analysis (if applicable)
Check for errors in logs:
`+"```"+`
fetch logs, from: now()-%s
| filter dt.smartscape.service == "<entity_id>" OR dt.smartscape.host == "<entity_id>"
| filter loglevel == "ERROR" OR loglevel == "WARN"
| sort timestamp desc
| limit 50
| fields timestamp, loglevel, content
`+"```"+`

## Summary
After gathering all information:
1. Summarize the entity's current health status
2. Highlight any active or recent problems
3. Note performance trends (improving/degrading/stable)
4. Identify any concerning patterns in events or logs
5. Recommend next steps if issues are found

If Davis Copilot is available, use chat_with_davis_copilot for additional AI-powered insights about this entity.
`, entityName, timeframe, entityName, timeframe, timeframe)

		return &mcp.GetPromptResult{
			Description: fmt.Sprintf("Deep dive analysis of entity: %s", entityName),
			Messages: []mcp.PromptMessage{
				{
					Role: "user",
					Content: mcp.PromptContent{
						Type: "text",
						Text: promptText,
					},
				},
			},
		}, nil
	})
}

func (r *Registry) registerDailySummary() {
	r.registerPrompt(mcp.Prompt{
		Name:        "daily-summary",
		Description: "Generate a daily operations summary including problems, vulnerabilities, and exceptions",
		Arguments: []mcp.PromptArgument{
			{
				Name:        "timeframe",
				Description: "Timeframe for the summary (e.g., '12h', '24h'). Default: 24h",
				Required:    false,
			},
			{
				Name:        "focus_area",
				Description: "Optional focus area: 'all', 'problems', 'security', 'exceptions'. Default: all",
				Required:    false,
			},
		},
	}, func(args map[string]interface{}) (*mcp.GetPromptResult, error) {
		timeframe := getString(args, "timeframe", "24h")
		focusArea := getString(args, "focus_area", "all")

		promptText := fmt.Sprintf(`# Daily Operations Summary

Generate a comprehensive operations summary for the last %s.

## Overview
This summary covers the operational health of the Dynatrace-monitored environment.

`, timeframe)

		if focusArea == "all" || focusArea == "problems" {
			promptText += fmt.Sprintf(`## 1. Problems Summary
Use the list_problems tool to get recent problems:
- Timeframe: %s
- Status: ALL (to see both active and resolved)
- Max problems: 25

For each problem found, note:
- Problem ID and display ID
- Status (ACTIVE/CLOSED)
- Category and name
- Affected entities count
- Duration

Categorize problems by:
- **Critical**: Still active, affecting multiple entities
- **Resolved**: Fixed within the timeframe
- **Recurring**: Same problem type appearing multiple times

`, timeframe)
		}

		if focusArea == "all" || focusArea == "security" {
			promptText += `## 2. Security Vulnerabilities
Use the list_vulnerabilities tool to check for security issues:
- Risk score threshold: 7.0 (high and critical)
- Max vulnerabilities: 20

Summarize:
- Total count of high/critical vulnerabilities
- Most affected entities
- Any new vulnerabilities (if timestamps available)
- Vulnerabilities by risk level (CRITICAL, HIGH)

`
		}

		if focusArea == "all" || focusArea == "exceptions" {
			promptText += fmt.Sprintf(`## 3. Application Exceptions
Use the list_exceptions tool to review application errors:
- Timeframe: %s
- Max exceptions: 25

Analyze:
- Most common exception types
- Affected applications
- Error patterns or spikes

`, timeframe)
		}

		promptText += `## 4. Environment Health
Use get_environment_info to verify connectivity and get environment details.

## Summary Report Format

Please structure your final report as:

### Executive Summary
- Overall health status: 🟢 Healthy / 🟡 Degraded / 🔴 Critical
- Key metrics at a glance

### Active Issues Requiring Attention
1. [List critical/active problems]
2. [High-risk vulnerabilities]

### Resolved in Last ` + timeframe + `
- Problems fixed
- Recovery times

### Recommendations
- Immediate actions needed
- Monitoring suggestions
- Follow-up items

### Trends
- Improvement or degradation compared to previous periods (if data available)
`

		return &mcp.GetPromptResult{
			Description: fmt.Sprintf("Daily operations summary for the last %s", timeframe),
			Messages: []mcp.PromptMessage{
				{
					Role: "user",
					Content: mcp.PromptContent{
						Type: "text",
						Text: promptText,
					},
				},
			},
		}, nil
	})
}

func (r *Registry) registerExploreBucket() {
	r.registerPrompt(mcp.Prompt{
		Name:        "explore-bucket",
		Description: "Explore and analyze data in a specific Grail bucket. Discovers schema, shows sample data, and suggests useful queries.",
		Arguments: []mcp.PromptArgument{
			{
				Name:        "bucket",
				Description: "Name of the bucket to explore (e.g., 'logs', 'events', 'spans', 'dt.davis.problems')",
				Required:    true,
			},
			{
				Name:        "timeframe",
				Description: "Timeframe for analysis (e.g., '1h', '24h', '7d'). Default: 1h",
				Required:    false,
			},
		},
	}, func(args map[string]interface{}) (*mcp.GetPromptResult, error) {
		bucket := getString(args, "bucket", "")
		if bucket == "" {
			return nil, fmt.Errorf("bucket is required")
		}

		timeframe := getString(args, "timeframe", "1h")

		promptText := fmt.Sprintf(`# Bucket Exploration: %s

Perform a comprehensive exploration of the Grail bucket "%s" over the last %s.

## Step 1: Discover Available Buckets
First, verify the bucket exists and check what other buckets are available:

Use the **list_buckets** tool to see all available buckets with their metadata.

## Step 2: Describe Bucket Schema
Get detailed schema information for this bucket:

Use the **describe_bucket** tool with:
- bucket: "%s"
- sampleSize: 100

This will show you:
- All available fields
- Field types
- Sample values

## Step 3: Analyze Data Patterns
Run exploratory queries to understand the data:

### Record count and time distribution
`+"```"+`
fetch %s, from: now()-%s
| summarize count = count(), by: {bin(timestamp, 1h)}
| sort timestamp desc
`+"```"+`

### Top values for key fields
`+"```"+`
fetch %s, from: now()-%s
| summarize count = count(), by: {<key_field>}
| sort count desc
| limit 20
`+"```"+`

### Recent records
`+"```"+`
fetch %s, from: now()-%s
| sort timestamp desc
| limit 10
`+"```"+`

## Step 4: Identify Useful Filters
Based on the schema, suggest common filter patterns:
- Time-based filters (timestamp)
- Entity filters (dt.entity.*, dt.smartscape.*)
- Status/level filters (loglevel, event.status, etc.)
- Content search (contains, matches)

## Step 5: Create Query Templates
Based on your analysis, provide:
1. A basic query template for this bucket
2. A filtered query template with common use cases
3. An aggregation query for trends/summaries

## Summary
After exploration, summarize:
- Total record count in the timeframe
- Key fields and their purposes
- Recommended queries for common use cases
- Any interesting patterns or anomalies found
`, bucket, bucket, timeframe, bucket, bucket, timeframe, bucket, timeframe, bucket, timeframe)

		return &mcp.GetPromptResult{
			Description: fmt.Sprintf("Exploration of bucket: %s", bucket),
			Messages: []mcp.PromptMessage{
				{
					Role: "user",
					Content: mcp.PromptContent{
						Type: "text",
						Text: promptText,
					},
				},
			},
		}, nil
	})
}

func (r *Registry) registerExploreTags() {
	r.registerPrompt(mcp.Prompt{
		Name:        "explore-tags",
		Description: "Explore and analyze tags across your Dynatrace environment. Discover tag usage patterns, find untagged resources, and suggest tagging improvements.",
		Arguments: []mcp.PromptArgument{
			{
				Name:        "focus",
				Description: "Optional focus area: 'all', 'services', 'hosts', 'applications'. Default: all",
				Required:    false,
			},
			{
				Name:        "tag_key",
				Description: "Optional: Focus on a specific tag key (e.g., 'environment', 'owner', 'team')",
				Required:    false,
			},
		},
	}, func(args map[string]interface{}) (*mcp.GetPromptResult, error) {
		focus := getString(args, "focus", "all")
		tagKey := getString(args, "tag_key", "")

		promptText := `# Tag Exploration and Analysis

Perform a comprehensive analysis of tags in the Dynatrace environment.

## Step 1: Discover All Tags
`
		if tagKey != "" {
			promptText += fmt.Sprintf(`
Focus on tag key: **%s**

Use the **list_tags** tool with:
- tagKeyFilter: "%s"
`, tagKey, tagKey)
		} else {
			promptText += `
Use the **list_tags** tool to see all tags in the environment.
`
		}

		if focus != "all" {
			promptText += fmt.Sprintf(`
Filter by entity type: **%s**
`, focus)
		}

		promptText += `
## Step 2: Analyze Tag Distribution

### Tag coverage by entity type
`+"```"+`
smartscapeNodes "*"
| summarize
    total = count(),
    tagged = countIf(isNotNull(tags)),
    untagged = countIf(isNull(tags)),
    by: {type}
| fieldsAdd coverage = 100.0 * tagged / total
| sort total desc
`+"```"+`

### Most common tag keys
`+"```"+`
smartscapeNodes "*"
| filter isNotNull(tags)
| expand tag = tags
| parse tag, "LD:key ':'"
| summarize count = count(), by: {key}
| sort count desc
| limit 20
`+"```"+`

## Step 3: Find Untagged Resources
Identify entities that may need tagging:

`+"```"+`
smartscapeNodes "*"
| filter isNull(tags) OR arraySize(tags) == 0
| fields type, name, id
| summarize count = count(), by: {type}
| sort count desc
`+"```"+`

## Step 4: Tag Value Analysis
`

		if tagKey != "" {
			promptText += fmt.Sprintf(`
Analyze values for tag key "%s":

Use the **find_entities_by_tag** tool with:
- tag: "%s"
- maxResults: 100
`, tagKey, tagKey)
		} else {
			promptText += `
For each important tag key, analyze:
- Number of unique values
- Value distribution
- Entities per value

Common important tags to analyze:
- environment (prod, staging, dev)
- owner / team
- application
- cost-center
- criticality
`
		}

		promptText += `
## Step 5: Tagging Recommendations

Based on your analysis, provide recommendations for:

### Missing Tags
- Which critical entities lack important tags?
- What standard tags should be applied?

### Tag Standardization
- Are there inconsistent tag values (e.g., "prod" vs "production")?
- Are there typos or variations that should be consolidated?

### Suggested Tag Schema
Recommend a tagging schema based on observed patterns:
| Tag Key | Purpose | Example Values |
|---------|---------|----------------|
| environment | Deployment stage | prod, staging, dev |
| owner | Responsible team | platform, frontend |
| ... | ... | ... |

## Summary
Provide:
1. Tag coverage statistics (% of entities tagged)
2. Most important tag keys
3. Top issues found (untagged resources, inconsistencies)
4. Prioritized remediation recommendations
`

		return &mcp.GetPromptResult{
			Description: "Tag exploration and analysis",
			Messages: []mcp.PromptMessage{
				{
					Role: "user",
					Content: mcp.PromptContent{
						Type: "text",
						Text: promptText,
					},
				},
			},
		}, nil
	})
}

// Helper function to get string from args
func getString(args map[string]interface{}, key string, defaultVal string) string {
	if args == nil {
		return defaultVal
	}
	if val, ok := args[key].(string); ok && val != "" {
		return val
	}
	return defaultVal
}
