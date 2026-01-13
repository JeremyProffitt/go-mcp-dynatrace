package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dynatrace-oss/go-mcp-dynatrace/pkg/dynatrace"
	"github.com/dynatrace-oss/go-mcp-dynatrace/pkg/logging"
	"github.com/dynatrace-oss/go-mcp-dynatrace/pkg/mcp"
)

// Config holds configuration options for the tool registry
type Config struct {
	Client              *dynatrace.Client
	Logger              *logging.Logger
	SlackConnID         string
	DavisCopilotEnabled bool
}

// Registry holds all tool registrations
type Registry struct {
	client              *dynatrace.Client
	logger              *logging.Logger
	slackConnID         string
	davisCopilotEnabled bool
}

// NewRegistry creates a new tool registry
func NewRegistry(cfg Config) *Registry {
	return &Registry{
		client:              cfg.Client,
		logger:              cfg.Logger,
		slackConnID:         cfg.SlackConnID,
		davisCopilotEnabled: cfg.DavisCopilotEnabled,
	}
}

// RegisterAll registers all tools with the MCP server
func (r *Registry) RegisterAll(server *mcp.Server) {
	// Core tools - always registered
	r.registerGetEnvironmentInfo(server)
	r.registerListProblems(server)
	r.registerListVulnerabilities(server)
	r.registerFindEntityByName(server)
	r.registerExecuteDQL(server)
	r.registerVerifyDQL(server)
	r.registerGetKubernetesEvents(server)
	r.registerListExceptions(server)
	r.registerCreateWorkflowForNotification(server)
	r.registerMakeWorkflowPublic(server)
	r.registerSendEmail(server)
	r.registerSendSlackMessage(server)
	r.registerResetGrailBudget(server)

	// Bucket discovery tools
	r.registerListBuckets(server)
	r.registerDescribeBucket(server)

	// Tag discovery tools
	r.registerListTags(server)
	r.registerFindEntitiesByTag(server)

	// Davis Copilot tools - conditionally registered
	if r.davisCopilotEnabled {
		r.registerGenerateDQLFromNL(server)
		r.registerExplainDQLInNL(server)
		r.registerChatWithDavisCopilot(server)
		r.registerListDavisAnalyzers(server)
		r.registerExecuteDavisAnalyzer(server)
		logging.Info("Davis Copilot tools enabled")
	} else {
		logging.Info("Davis Copilot tools disabled (set DT_ENABLE_DAVIS_COPILOT=true to enable)")
	}
}

// Helper functions
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.ContentItem{{Type: "text", Text: text}},
	}
}

func errorResult(message string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.ContentItem{{Type: "text", Text: message}},
		IsError: true,
	}
}

func getString(args map[string]interface{}, key string, defaultVal string) string {
	if val, ok := args[key].(string); ok {
		return val
	}
	return defaultVal
}

func getInt(args map[string]interface{}, key string, defaultVal int) int {
	if val, ok := args[key].(float64); ok {
		return int(val)
	}
	return defaultVal
}

func getFloat(args map[string]interface{}, key string, defaultVal float64) float64 {
	if val, ok := args[key].(float64); ok {
		return val
	}
	return defaultVal
}

func getBool(args map[string]interface{}, key string, defaultVal bool) bool {
	if val, ok := args[key].(bool); ok {
		return val
	}
	return defaultVal
}

func getStringSlice(args map[string]interface{}, key string) []string {
	val, ok := args[key]
	if !ok {
		return nil
	}
	// Handle []interface{} from JSON unmarshaling
	if arr, ok := val.([]interface{}); ok {
		result := make([]string, 0, len(arr))
		for _, v := range arr {
			if s, ok := v.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// filterRecordFields returns records with only the specified fields
func filterRecordFields(records []map[string]interface{}, fields []string) []map[string]interface{} {
	if len(fields) == 0 {
		return records
	}
	fieldSet := make(map[string]bool, len(fields))
	for _, f := range fields {
		fieldSet[f] = true
	}

	result := make([]map[string]interface{}, len(records))
	for i, record := range records {
		filtered := make(map[string]interface{})
		for _, field := range fields {
			if val, ok := record[field]; ok {
				filtered[field] = val
			}
		}
		result[i] = filtered
	}
	return result
}

// formatRecords formats records according to the specified output format
func formatRecords(records []map[string]interface{}, format string) string {
	switch format {
	case "lines":
		// Extract content field only, one per line
		var lines []string
		for _, record := range records {
			if content, ok := record["content"].(string); ok {
				lines = append(lines, content)
			} else {
				// Fallback: serialize the record as compact JSON
				if b, err := json.Marshal(record); err == nil {
					lines = append(lines, string(b))
				}
			}
		}
		return strings.Join(lines, "\n")

	case "full":
		// Pretty-printed JSON (original behavior)
		recordsJSON, _ := json.MarshalIndent(records, "", "  ")
		return "```json\n" + string(recordsJSON) + "\n```"

	case "compact":
		fallthrough
	default:
		// One JSON object per line (JSONL format)
		var lines []string
		for _, record := range records {
			if b, err := json.Marshal(record); err == nil {
				lines = append(lines, string(b))
			}
		}
		return "```jsonl\n" + strings.Join(lines, "\n") + "\n```"
	}
}

// appendTimestampFilter modifies a DQL query to filter records after a given timestamp
func appendTimestampFilter(query string, continueFrom string) string {
	// Insert filter before any limit clause or at the end
	query = strings.TrimSpace(query)

	// Check if query already has a limit
	lowerQuery := strings.ToLower(query)
	limitIdx := strings.LastIndex(lowerQuery, "| limit")

	filter := fmt.Sprintf("| filter timestamp < %s", continueFrom)

	if limitIdx > 0 {
		// Insert before limit
		return query[:limitIdx] + filter + " " + query[limitIdx:]
	}
	// Append to end
	return query + " " + filter
}

// extractContinueFromCursor extracts the timestamp from the last record for pagination
func extractContinueFromCursor(records []map[string]interface{}, limit int) string {
	if len(records) <= limit || limit <= 0 {
		return ""
	}
	// Use the timestamp from the last returned record (at index limit-1)
	lastRecord := records[limit-1]
	if ts, ok := lastRecord["timestamp"]; ok {
		// Handle different timestamp formats
		switch v := ts.(type) {
		case string:
			return v
		case float64:
			return fmt.Sprintf("%.0f", v)
		case int64:
			return fmt.Sprintf("%d", v)
		}
	}
	return ""
}

// deriveDQLQueryName extracts a descriptive name from a DQL query for file logging
func deriveDQLQueryName(query string) string {
	// Trim whitespace and get the first line
	query = strings.TrimSpace(query)
	lines := strings.Split(query, "\n")
	if len(lines) == 0 {
		return "query"
	}

	firstLine := strings.TrimSpace(lines[0])

	// Extract the command (fetch, smartscapeNodes, etc.)
	parts := strings.Fields(firstLine)
	if len(parts) == 0 {
		return "query"
	}

	command := parts[0]

	// Build a descriptive name based on the command and first argument
	switch command {
	case "fetch":
		if len(parts) > 1 {
			// e.g., "fetch logs" -> "fetch_logs", "fetch dt.davis.problems" -> "fetch_dt.davis.problems"
			dataSource := strings.Split(parts[1], ",")[0] // Remove trailing comma if present
			return "fetch_" + dataSource
		}
		return "fetch"
	case "smartscapeNodes":
		if len(parts) > 1 {
			// e.g., smartscapeNodes "*" -> "smartscape_all", smartscapeNodes "host" -> "smartscape_host"
			nodeType := strings.Trim(parts[1], "\"")
			if nodeType == "*" {
				return "smartscape_all"
			}
			return "smartscape_" + nodeType
		}
		return "smartscape"
	default:
		return command
	}
}

func getStringArray(args map[string]interface{}, key string) []string {
	if val, ok := args[key].([]interface{}); ok {
		result := make([]string, 0, len(val))
		for _, v := range val {
			if s, ok := v.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// Tool implementations

func (r *Registry) registerGetEnvironmentInfo(server *mcp.Server) {
	server.RegisterTool(mcp.Tool{
		Name:        "get_environment_info",
		Description: "[Discovery Tool] Get information about the connected Dynatrace Environment (Tenant) and verify the connection and authentication. Use this first to confirm connectivity.",
		InputSchema: mcp.JSONSchema{
			Type:       "object",
			Properties: map[string]mcp.Property{},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:        "Get Environment Info",
			ReadOnlyHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("get_environment_info", args, 0, false)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		info, err := r.client.GetEnvironmentInfo(ctx)
		if err != nil {
			return errorResult(fmt.Sprintf("Failed to get environment info: %s", err.Error())), nil
		}

		resp := fmt.Sprintf(`Environment Information (also referred to as tenant):
- ID: %s
- Name: %s
- State: %s

You can reach it via %s`, info.ID, info.Name, info.State, r.client.GetBaseURL())

		return textResult(resp), nil
	})
}

func (r *Registry) registerListProblems(server *mcp.Server) {
	minVal := float64(1)
	maxVal := float64(5000)

	server.RegisterTool(mcp.Tool{
		Name:        "list_problems",
		Description: "[Query Tool] List all problems (based on \"fetch dt.davis.problems\") known on Dynatrace, sorted by their recency. Use this to monitor active incidents and historical issues.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"timeframe": {
					Type:        "string",
					Description: "Timeframe to query problems. Examples: '1h' (1 hour), '12h' (12 hours), '24h' (1 day), '7d' (1 week), '30d' (1 month). Default: '24h'.",
					Default:     "24h",
				},
				"status": {
					Type:        "string",
					Description: "Filter problems by status: ACTIVE (ongoing), CLOSED (resolved), or ALL (both). Default: ALL.",
					Enum:        []string{"ACTIVE", "CLOSED", "ALL"},
					Default:     "ALL",
				},
				"additionalFilter": {
					Type:        "string",
					Description: "Additional DQL filter expression for dt.davis.problems. Examples: 'event.category == \"AVAILABILITY\"', 'contains(event.name, \"CPU\")', 'affected_entity_count > 5'. Uses DQL filter syntax.",
				},
				"maxProblemsToDisplay": {
					Type:        "number",
					Description: "Maximum number of problems to return. Range: 1-5000. Default: 10.",
					Default:     10,
					Minimum:     &minVal,
					Maximum:     &maxVal,
				},
			},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:        "List Problems",
			ReadOnlyHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("list_problems", args, 0, false)

		timeframe := getString(args, "timeframe", "24h")
		status := getString(args, "status", "ALL")
		additionalFilter := getString(args, "additionalFilter", "")
		maxProblems := getInt(args, "maxProblemsToDisplay", 10)

		// Build DQL query
		query := fmt.Sprintf("fetch dt.davis.problems, from: now()-%s, to: now()", timeframe)

		if status == "ACTIVE" {
			query += " | filter event.status == \"ACTIVE\""
		} else if status == "CLOSED" {
			query += " | filter isNotNull(event.end)"
		}

		if additionalFilter != "" {
			query += " | filter " + additionalFilter
		}

		query += " | sort timestamp desc"
		query += fmt.Sprintf(" | limit %d", maxProblems)
		query += " | fields display_id, problem_id, event.status, event.category, event.name, affected_users_count, affected_entity_count, duration"

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		result, err := r.client.ExecuteDQL(ctx, query, maxProblems, 1024*1024)
		if err != nil {
			return errorResult(fmt.Sprintf("Failed to list problems: %s", err.Error())), nil
		}

		// Log DQL query to file if enabled
		r.logger.SaveDQLQueryToFile(query, "list_problems")

		if result.Result == nil || len(result.Result.Records) == 0 {
			return textResult("No problems found"), nil
		}

		resp := fmt.Sprintf("Found %d problems! Displaying the top %d problems:\n\n", len(result.Result.Records), maxProblems)

		for _, record := range result.Result.Records {
			displayID, _ := record["display_id"].(string)
			problemID, _ := record["problem_id"].(string)
			eventStatus, _ := record["event.status"].(string)
			eventCategory, _ := record["event.category"].(string)
			eventName, _ := record["event.name"].(string)

			resp += fmt.Sprintf("Problem %s (problemId: %s)\n  Status: %s, Category: %s\n  Name: %s\n\n",
				displayID, problemID, eventStatus, eventCategory, eventName)
		}

		resp += fmt.Sprintf(`
Next Steps:
1. Use "execute_dql" tool with a query to get more details about a specific problem
2. Use "chat_with_davis_copilot" tool for insights about a specific problem
3. Visit %s/ui/apps/dynatrace.davis.problems/problem/<problem-id> for more details`, r.client.GetBaseURL())

		return textResult(resp), nil
	})
}

func (r *Registry) registerListVulnerabilities(server *mcp.Server) {
	minRisk := float64(0)
	maxRisk := float64(10)
	minResults := float64(1)
	maxResults := float64(1000)

	server.RegisterTool(mcp.Tool{
		Name:        "list_vulnerabilities",
		Description: "[Security Tool] Retrieve all active (non-muted) vulnerabilities from Dynatrace for the last 30 days. Use for security posture assessment and CVE tracking.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"riskScore": {
					Type:        "number",
					Description: "Minimum risk score of vulnerabilities to list. Range: 0.0-10.0 (CVSS score). Default: 8.0 (High/Critical).",
					Default:     8.0,
					Minimum:     &minRisk,
					Maximum:     &maxRisk,
				},
				"additionalFilter": {
					Type:        "string",
					Description: "Additional DQL filter expression for vulnerabilities. Examples: 'vulnerability.risk.level == \"CRITICAL\"', 'contains(vulnerability.title, \"Log4j\")', 'affected_entity.type == \"SERVICE\"'. Uses DQL filter syntax.",
				},
				"maxVulnerabilitiesToDisplay": {
					Type:        "number",
					Description: "Maximum number of vulnerabilities to return. Range: 1-1000. Default: 25.",
					Default:     25,
					Minimum:     &minResults,
					Maximum:     &maxResults,
				},
			},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:        "List Vulnerabilities",
			ReadOnlyHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("list_vulnerabilities", args, 0, false)

		riskScore := getFloat(args, "riskScore", 8.0)
		additionalFilter := getString(args, "additionalFilter", "")
		maxVulns := getInt(args, "maxVulnerabilitiesToDisplay", 25)

		query := `fetch security.events, from: now()-30d, to: now()
| filter event.provider=="Dynatrace"
        AND event.type=="VULNERABILITY_STATE_REPORT_EVENT"
        AND event.level=="ENTITY"
| filter vulnerability.mute.status != "MUTED"
| filter vulnerability.parent.mute.status != "MUTED"`

		query += fmt.Sprintf("\n| filter vulnerability.risk.score >= %f", riskScore)

		if additionalFilter != "" {
			query += "\n| filter " + additionalFilter
		}

		query += `
| dedup {vulnerability.display_id, affected_entity.id}, sort:{timestamp desc}
| sort vulnerability.risk.score desc
| fields vulnerability.id, vulnerability.display_id, vulnerability.title, vulnerability.risk.score, vulnerability.risk.level, affected_entity.name, affected_entity.id`

		query += fmt.Sprintf("\n| limit %d", maxVulns)

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		result, err := r.client.ExecuteDQL(ctx, query, maxVulns, 2*1024*1024)
		if err != nil {
			return errorResult(fmt.Sprintf("Failed to list vulnerabilities: %s", err.Error())), nil
		}

		// Log DQL query to file if enabled
		r.logger.SaveDQLQueryToFile(query, "list_vulnerabilities")

		if result.Result == nil || len(result.Result.Records) == 0 {
			return textResult("No vulnerabilities found in the last 30 days"), nil
		}

		resp := fmt.Sprintf("Found %d vulnerabilities in the last 30 days! Displaying the top %d:\n\n", len(result.Result.Records), maxVulns)

		for _, record := range result.Result.Records {
			displayID, _ := record["vulnerability.display_id"].(string)
			title, _ := record["vulnerability.title"].(string)
			riskScore, _ := record["vulnerability.risk.score"].(float64)
			riskLevel, _ := record["vulnerability.risk.level"].(string)
			entityName, _ := record["affected_entity.name"].(string)

			resp += fmt.Sprintf("* %s: %s\n  Risk: %.1f (%s), Affected: %s\n\n",
				displayID, title, riskScore, riskLevel, entityName)
		}

		resp += fmt.Sprintf(`
Next Steps:
1. Use "execute_dql" tool with vulnerability.id filter for more details
2. Use "chat_with_davis_copilot" tool for insights
3. Visit %s/ui/apps/dynatrace.security.vulnerabilities/vulnerabilities/<vulnerability-id> for full details`, r.client.GetBaseURL())

		return textResult(resp), nil
	})
}

func (r *Registry) registerFindEntityByName(server *mcp.Server) {
	minResults := float64(1)
	maxResults := float64(500)

	server.RegisterTool(mcp.Tool{
		Name:        "find_entity_by_name",
		Description: "[Discovery Tool] Find the entityId and type of a monitored entity (service, host, process-group, application, etc.) based on name. Essential for getting entity IDs to use in other queries.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"entityNames": {
					Type:        "array",
					Description: "Names of the entities to search for. Supports partial matching. Example: ['payment-service', 'frontend'].",
					Items:       &mcp.Property{Type: "string"},
				},
				"maxEntitiesToDisplay": {
					Type:        "number",
					Description: "Maximum number of entities to return. Range: 1-500. Default: 10.",
					Default:     10,
					Minimum:     &minResults,
					Maximum:     &maxResults,
				},
				"extendedSearch": {
					Type:        "boolean",
					Description: "Set to true for comprehensive search over all entity types. Default: false.",
					Default:     false,
				},
			},
			Required: []string{"entityNames"},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:        "Find Entity By Name",
			ReadOnlyHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("find_entity_by_name", args, 0, false)

		entityNames := getStringArray(args, "entityNames")
		maxEntities := getInt(args, "maxEntitiesToDisplay", 10)

		if len(entityNames) == 0 {
			return errorResult("entityNames is required"), nil
		}

		// Build search query using Smartscape
		conditions := make([]string, 0, len(entityNames))
		for _, name := range entityNames {
			conditions = append(conditions, fmt.Sprintf("contains(name, \"%s\")", name))
		}

		query := fmt.Sprintf(`smartscapeNodes "*"
| filter %s
| fields id, type, name, tags
| limit %d`, strings.Join(conditions, " OR "), maxEntities)

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		result, err := r.client.ExecuteDQL(ctx, query, maxEntities, 1024*1024)
		if err != nil {
			return errorResult(fmt.Sprintf("Failed to find entities: %s", err.Error())), nil
		}

		// Log DQL query to file if enabled
		r.logger.SaveDQLQueryToFile(query, "find_entity_by_name")

		if result.Result == nil || len(result.Result.Records) == 0 {
			return textResult("No monitored entity found with the specified name. Try broadening your search or checking for typos."), nil
		}

		resp := fmt.Sprintf("Found %d monitored entities! Displaying the first %d:\n\n", len(result.Result.Records), maxEntities)

		for _, record := range result.Result.Records {
			id, _ := record["id"].(string)
			entityType, _ := record["type"].(string)
			name, _ := record["name"].(string)
			tags := record["tags"]

			tagsStr := "none"
			if tags != nil {
				tagsJSON, _ := json.Marshal(tags)
				tagsStr = string(tagsJSON)
			}

			resp += fmt.Sprintf("- Entity '%s' of type '%s'\n  ID: %s\n  Tags: %s\n  DQL Filter: '| filter dt.smartscape.%s == \"%s\"'\n\n",
				name, entityType, id, tagsStr, strings.ToLower(entityType), id)
		}

		resp += `
Next Steps:
1. Use execute_dql to fetch more details: "smartscapeNodes \"<entity-type>\" | filter id == <entity-id>"
2. Check for problems using list_problems with the DQL filter
3. Find metrics: "fetch metric.series | filter dt.smartscape.<entity-type> == <entity-id> | limit 20"`

		return textResult(resp), nil
	})
}

func (r *Registry) registerExecuteDQL(server *mcp.Server) {
	minRecords := float64(1)
	maxRecords := float64(100)
	minSize := float64(1)
	maxSize := float64(10)

	server.RegisterTool(mcp.Tool{
		Name:        "execute_dql",
		Description: "[Query Tool] Get data like Logs, Metrics, Spans, Events, or Entity Data from Dynatrace GRAIL by executing a DQL statement. This is the primary tool for querying Dynatrace data.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"dqlStatement": {
					Type:        "string",
					Description: "DQL (Dynatrace Query Language) statement to execute. Example: 'fetch logs | filter loglevel == \"ERROR\" | limit 10'. Use verify_dql first for complex queries.",
				},
				"recordLimit": {
					Type:        "number",
					Description: "Maximum number of records to return. Range: 1-100. Default: 50. Use pagination (continueFrom) for more records.",
					Default:     50,
					Minimum:     &minRecords,
					Maximum:     &maxRecords,
				},
				"recordSizeLimitMB": {
					Type:        "number",
					Description: "Maximum size of returned records in MB. Range: 1-10. Default: 1. Increase for queries returning large records.",
					Default:     1,
					Minimum:     &minSize,
					Maximum:     &maxSize,
				},
				"outputFormat": {
					Type:        "string",
					Description: "Output format: 'full' (indented JSON), 'compact' (JSONL, one record per line), 'lines' (content field only as plain text). Default: 'compact'.",
					Enum:        []string{"full", "compact", "lines"},
					Default:     "compact",
				},
				"fields": {
					Type:        "array",
					Description: "List of field names to include in output. If empty, all fields are returned. Example: ['timestamp', 'content', 'loglevel'].",
					Items:       &mcp.Property{Type: "string"},
				},
				"continueFrom": {
					Type:        "string",
					Description: "Pagination cursor from previous response. Pass the 'continueFrom' value from a previous result to get the next page of records.",
				},
			},
			Required: []string{"dqlStatement"},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:         "Execute DQL",
			ReadOnlyHint:  false,
			OpenWorldHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("execute_dql", args, 0, false)

		dqlStatement := getString(args, "dqlStatement", "")
		recordLimit := getInt(args, "recordLimit", 50)
		recordSizeLimitMB := getInt(args, "recordSizeLimitMB", 1)
		outputFormat := getString(args, "outputFormat", "compact")
		fields := getStringSlice(args, "fields")
		continueFrom := getString(args, "continueFrom", "")

		if dqlStatement == "" {
			return errorResult("dqlStatement is required"), nil
		}

		// Hard cap at 100 records
		const maxRecordLimit = 100
		if recordLimit > maxRecordLimit {
			recordLimit = maxRecordLimit
		}

		// Request one extra record to detect if more results exist
		queryLimit := recordLimit + 1

		// Apply continueFrom filter if provided (timestamp-based pagination)
		effectiveQuery := dqlStatement
		if continueFrom != "" {
			effectiveQuery = appendTimestampFilter(dqlStatement, continueFrom)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()

		result, err := r.client.ExecuteDQL(ctx, effectiveQuery, queryLimit, recordSizeLimitMB*1024*1024)
		if err != nil {
			return errorResult(fmt.Sprintf("DQL execution failed: %s", err.Error())), nil
		}

		if result.Error != nil {
			return errorResult(fmt.Sprintf("DQL error: %s", result.Error.Message)), nil
		}

		// Log DQL query to file if enabled
		queryName := deriveDQLQueryName(dqlStatement)
		r.logger.SaveDQLQueryToFile(dqlStatement, queryName)

		resp := "**DQL Query Results**\n\n"

		// Check budget warning
		budgetWarning := r.client.GetBudgetTracker().GetWarning()
		if budgetWarning != "" {
			resp += budgetWarning + "\n\n"
		}

		if result.Result != nil && result.Result.Metadata != nil && result.Result.Metadata.GrailMetrics != nil {
			metrics := result.Result.Metadata.GrailMetrics
			scannedGB := float64(metrics.ScannedBytes) / (1000 * 1000 * 1000)

			resp += fmt.Sprintf("- **Scanned Records:** %d\n", metrics.ScannedRecords)
			resp += fmt.Sprintf("- **Scanned Bytes:** %.2f GB\n", scannedGB)

			if metrics.Sampled {
				resp += "- **Sampling Used:** Yes (results may be approximate)\n"
			}
		}

		if result.Result != nil {
			records := result.Result.Records

			// Determine if there are more results
			hasMore := len(records) > recordLimit
			if hasMore {
				records = records[:recordLimit] // Trim to requested limit
			}

			// Apply field selection if specified
			if len(fields) > 0 {
				records = filterRecordFields(records, fields)
			}

			resp += fmt.Sprintf("\n**Results:** %d records", len(records))
			if hasMore {
				resp += " (more available)"
			}
			resp += "\n\n"

			if len(records) > 0 {
				resp += formatRecords(records, outputFormat)

				// Add pagination cursor if more results exist
				if hasMore {
					cursor := extractContinueFromCursor(result.Result.Records, recordLimit)
					if cursor != "" {
						resp += fmt.Sprintf("\n\n**Pagination:**\n- `hasMore`: true\n- `continueFrom`: `%s`", cursor)
					}
				}
			} else {
				resp += "No records returned."
			}
		}

		return textResult(resp), nil
	})
}

func (r *Registry) registerVerifyDQL(server *mcp.Server) {
	server.RegisterTool(mcp.Tool{
		Name:        "verify_dql",
		Description: "[Query Tool] Syntactically verify a DQL statement before executing it. Use this to validate complex queries and get error messages without consuming query budget.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"dqlStatement": {
					Type:        "string",
					Description: "DQL (Dynatrace Query Language) statement to verify. Validates syntax without executing the query.",
				},
			},
			Required: []string{"dqlStatement"},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:          "Verify DQL",
			ReadOnlyHint:   true,
			IdempotentHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("verify_dql", args, 0, false)

		dqlStatement := getString(args, "dqlStatement", "")
		if dqlStatement == "" {
			return errorResult("dqlStatement is required"), nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result, err := r.client.VerifyDQL(ctx, dqlStatement)
		if err != nil {
			return errorResult(fmt.Sprintf("DQL verification failed: %s", err.Error())), nil
		}

		resp := "**DQL Statement Verification:**\n\n"

		if len(result.Notifications) > 0 {
			resp += "**Notifications:**\n"
			for _, n := range result.Notifications {
				resp += fmt.Sprintf("- %s: %s\n", n.Severity, n.Message)
			}
			resp += "\n"
		}

		if result.Valid {
			resp += "The DQL statement is **valid** - you can use the \"execute_dql\" tool.\n"
		} else {
			resp += "The DQL statement is **invalid**. Please adapt your statement.\n"
		}

		return textResult(resp), nil
	})
}

func (r *Registry) registerGenerateDQLFromNL(server *mcp.Server) {
	server.RegisterTool(mcp.Tool{
		Name:        "generate_dql_from_natural_language",
		Description: "[AI Tool] Convert natural language queries to DQL using Davis CoPilot AI. Useful when you're unsure of the DQL syntax for a particular query.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"text": {
					Type:        "string",
					Description: "Natural language description of what you want to query. Example: 'show me all error logs from the payment service in the last hour'.",
				},
			},
			Required: []string{"text"},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:          "Generate DQL from Natural Language",
			ReadOnlyHint:   true,
			IdempotentHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("generate_dql_from_natural_language", args, 0, false)

		text := getString(args, "text", "")
		if text == "" {
			return errorResult("text is required"), nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		result, err := r.client.GenerateDQLFromNL(ctx, text)
		if err != nil {
			return errorResult(fmt.Sprintf("NL to DQL conversion failed: %s", err.Error())), nil
		}

		resp := fmt.Sprintf("**Natural Language to DQL:**\n\n**Query:** \"%s\"\n\n", text)

		if result.DQL != "" {
			resp += fmt.Sprintf("**Generated DQL:**\n```\n%s\n```\n\n", result.DQL)
		}

		resp += fmt.Sprintf("**Status:** %s\n", result.Status)

		if result.Metadata != nil && len(result.Metadata.Notifications) > 0 {
			resp += "\n**Notifications:**\n"
			for _, n := range result.Metadata.Notifications {
				resp += fmt.Sprintf("- %s: %s\n", n.Severity, n.Message)
			}
		}

		if result.Status != "FAILED" {
			resp += "\n**Next Steps:**\n1. Use \"execute_dql\" tool to run the query\n2. Refine your description if results don't match expectations\n"
		}

		return textResult(resp), nil
	})
}

func (r *Registry) registerExplainDQLInNL(server *mcp.Server) {
	server.RegisterTool(mcp.Tool{
		Name:        "explain_dql_in_natural_language",
		Description: "[AI Tool] Explain DQL statements in natural language using Davis CoPilot AI. Useful for understanding existing queries.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"dql": {
					Type:        "string",
					Description: "The DQL statement to explain. Can be any valid DQL query.",
				},
			},
			Required: []string{"dql"},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:          "Explain DQL in Natural Language",
			ReadOnlyHint:   true,
			IdempotentHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("explain_dql_in_natural_language", args, 0, false)

		dql := getString(args, "dql", "")
		if dql == "" {
			return errorResult("dql is required"), nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		result, err := r.client.ExplainDQLInNL(ctx, dql)
		if err != nil {
			return errorResult(fmt.Sprintf("DQL explanation failed: %s", err.Error())), nil
		}

		resp := fmt.Sprintf("**DQL to Natural Language:**\n\n**DQL Query:**\n```\n%s\n```\n\n", dql)
		resp += fmt.Sprintf("**Summary:** %s\n\n", result.Summary)
		resp += fmt.Sprintf("**Detailed Explanation:**\n%s\n\n", result.Explanation)
		resp += fmt.Sprintf("**Status:** %s\n", result.Status)

		return textResult(resp), nil
	})
}

func (r *Registry) registerChatWithDavisCopilot(server *mcp.Server) {
	server.RegisterTool(mcp.Tool{
		Name:        "chat_with_davis_copilot",
		Description: "[AI Tool] Use this tool to ask any Dynatrace related question when no other specific tool is available. Davis CoPilot has knowledge of Dynatrace concepts, best practices, and can provide guidance.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"text": {
					Type:        "string",
					Description: "Your question or request for Davis CoPilot. Example: 'How do I investigate high CPU usage on a host?'",
				},
				"context": {
					Type:        "string",
					Description: "Optional context to provide additional information. Example: 'I am investigating problem P-12345 which shows high error rates'.",
				},
				"instruction": {
					Type:        "string",
					Description: "Optional instruction for response formatting. Example: 'Provide a step-by-step guide' or 'Keep the response brief'.",
				},
			},
			Required: []string{"text"},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:          "Chat with Davis Copilot",
			ReadOnlyHint:   true,
			IdempotentHint: true,
			OpenWorldHint:  true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("chat_with_davis_copilot", args, 0, false)

		text := getString(args, "text", "")
		contextStr := getString(args, "context", "")
		instruction := getString(args, "instruction", "")

		if text == "" {
			return errorResult("text is required"), nil
		}

		var contexts []dynatrace.DavisCopilotContext
		if contextStr != "" {
			contexts = append(contexts, dynatrace.DavisCopilotContext{
				Type:  "supplementary",
				Value: contextStr,
			})
		}
		if instruction != "" {
			contexts = append(contexts, dynatrace.DavisCopilotContext{
				Type:  "instruction",
				Value: instruction,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()

		result, err := r.client.ChatWithDavisCopilot(ctx, text, contexts)
		if err != nil {
			return errorResult(fmt.Sprintf("Davis CoPilot request failed: %s", err.Error())), nil
		}

		resp := fmt.Sprintf("**Davis CoPilot Response:**\n\n**Your Question:** \"%s\"\n\n", text)

		if result.Text != "" {
			resp += fmt.Sprintf("**Answer:**\n%s\n\n", result.Text)
		}

		resp += fmt.Sprintf("**Status:** %s\n", result.Status)

		if result.Metadata != nil && len(result.Metadata.Sources) > 0 {
			resp += "\n**Sources:**\n"
			for _, s := range result.Metadata.Sources {
				resp += fmt.Sprintf("- %s: %s\n", s.Title, s.URL)
			}
		}

		if result.Status == "FAILED" {
			resp += "\n**Your request was not successful**\n"
		}

		return textResult(resp), nil
	})
}

func (r *Registry) registerListDavisAnalyzers(server *mcp.Server) {
	server.RegisterTool(mcp.Tool{
		Name:        "list_davis_analyzers",
		Description: "[Discovery Tool] List all available Davis Analyzers in Dynatrace (forecast, anomaly detection, correlation analyzers, and more). Use this to discover what analyzers can be used with execute_davis_analyzer.",
		InputSchema: mcp.JSONSchema{
			Type:       "object",
			Properties: map[string]mcp.Property{},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:        "List Davis Analyzers",
			ReadOnlyHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("list_davis_analyzers", args, 0, false)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		analyzers, err := r.client.ListDavisAnalyzers(ctx)
		if err != nil {
			return errorResult(fmt.Sprintf("Failed to list analyzers: %s", err.Error())), nil
		}

		if len(analyzers) == 0 {
			return textResult("No Davis Analyzers found."), nil
		}

		resp := fmt.Sprintf("Found %d Davis Analyzers:\n\n", len(analyzers))

		for _, a := range analyzers {
			resp += fmt.Sprintf("**%s** (%s)\n", a.DisplayName, a.Name)
			resp += fmt.Sprintf("Type: %s\n", a.Type)
			if a.Category != "" {
				resp += fmt.Sprintf("Category: %s\n", a.Category)
			}
			resp += fmt.Sprintf("Description: %s\n", a.Description)
			if len(a.Labels) > 0 {
				resp += fmt.Sprintf("Labels: %s\n", strings.Join(a.Labels, ", "))
			}
			resp += "\n"
		}

		resp += "\n**Next Steps:**\nUse \"execute_davis_analyzer\" tool to run a specific analyzer.\n"

		return textResult(resp), nil
	})
}

func (r *Registry) registerExecuteDavisAnalyzer(server *mcp.Server) {
	server.RegisterTool(mcp.Tool{
		Name:        "execute_davis_analyzer",
		Description: "[Analysis Tool] Execute a Davis Analyzer with custom input parameters. Use list_davis_analyzers first to see available analyzers and their required input parameters.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"analyzerName": {
					Type:        "string",
					Description: "The name of the Davis Analyzer to execute. Use list_davis_analyzers to get valid names.",
				},
				"input": {
					Type:        "object",
					Description: "Input parameters for the analyzer as a JSON object. Structure varies by analyzer - common fields include: 'timeseries' (array of metric data), 'query' (DQL query string), 'entityId' (target entity). Example: {\"timeseries\": [{\"timestamps\": [...], \"values\": [...]}]}",
				},
				"timeframeStart": {
					Type:        "string",
					Description: "Start time for the analysis. Supports relative (e.g., 'now-1h', 'now-24h', 'now-7d') or ISO 8601 timestamps. Default: 'now-1h'.",
					Default:     "now-1h",
				},
				"timeframeEnd": {
					Type:        "string",
					Description: "End time for the analysis. Supports relative (e.g., 'now') or ISO 8601 timestamps. Default: 'now'.",
					Default:     "now",
				},
			},
			Required: []string{"analyzerName"},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:        "Execute Davis Analyzer",
			ReadOnlyHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("execute_davis_analyzer", args, 0, false)

		analyzerName := getString(args, "analyzerName", "")
		timeframeStart := getString(args, "timeframeStart", "now-1h")
		timeframeEnd := getString(args, "timeframeEnd", "now")

		if analyzerName == "" {
			return errorResult("analyzerName is required"), nil
		}

		input := make(map[string]interface{})
		if inputArg, ok := args["input"].(map[string]interface{}); ok {
			input = inputArg
		}

		input["generalParameters"] = map[string]interface{}{
			"timeframe": map[string]interface{}{
				"startTime": timeframeStart,
				"endTime":   timeframeEnd,
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()

		result, err := r.client.ExecuteDavisAnalyzer(ctx, analyzerName, input)
		if err != nil {
			return errorResult(fmt.Sprintf("Analyzer execution failed: %s", err.Error())), nil
		}

		resp := fmt.Sprintf("**Davis Analyzer Execution Result:**\n\n")
		resp += fmt.Sprintf("**Analyzer:** %s\n", analyzerName)
		resp += fmt.Sprintf("**Execution Status:** %s\n", result.ExecutionStatus)
		resp += fmt.Sprintf("**Result Status:** %s\n\n", result.ResultStatus)

		if len(result.Logs) > 0 {
			resp += "**Logs:**\n"
			for _, log := range result.Logs {
				resp += fmt.Sprintf("- %s: %s\n", log.Level, log.Message)
			}
			resp += "\n"
		}

		if len(result.Output) > 0 {
			resp += "**Output:**\n"
			for i, output := range result.Output {
				outputJSON, _ := json.MarshalIndent(output, "", "  ")
				resp += fmt.Sprintf("Output %d:\n%s\n\n", i+1, string(outputJSON))
			}
		} else {
			resp += "**Output:** No output/findings returned by the analyzer.\n"
		}

		return textResult(resp), nil
	})
}

func (r *Registry) registerGetKubernetesEvents(server *mcp.Server) {
	minEvents := float64(1)
	maxEvents := float64(500)

	server.RegisterTool(mcp.Tool{
		Name:        "get_kubernetes_events",
		Description: "[Query Tool] Get all events from a specific Kubernetes (K8s) cluster. Use for monitoring cluster health and investigating K8s-related issues.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"clusterId": {
					Type:        "string",
					Description: "The Kubernetes Cluster Id (k8s.cluster.uid). Find this using find_entity_by_name or execute_dql.",
				},
				"kubernetesEntityId": {
					Type:        "string",
					Description: "The Dynatrace Kubernetes Entity Id (dt.entity.kubernetes_cluster). Alternative to clusterId.",
				},
				"eventType": {
					Type:        "string",
					Description: "Filter by event type. Leave empty for all event types.",
					Enum: []string{
						"COMPLIANCE_FINDING", "COMPLIANCE_SCAN_COMPLETED", "CUSTOM_INFO",
						"DETECTION_FINDING", "ERROR_EVENT", "OSI_UNEXPECTEDLY_UNAVAILABLE",
						"PROCESS_RESTART", "RESOURCE_CONTENTION_EVENT",
						"SERVICE_CLIENT_ERROR_RATE_INCREASED", "SERVICE_CLIENT_SLOWDOWN",
						"SERVICE_ERROR_RATE_INCREASED", "SERVICE_SLOWDOWN",
						"SERVICE_UNEXPECTED_HIGH_LOAD", "SERVICE_UNEXPECTED_LOW_LOAD",
					},
				},
				"maxEventsToDisplay": {
					Type:        "number",
					Description: "Maximum number of events to return. Range: 1-500. Default: 10.",
					Default:     10,
					Minimum:     &minEvents,
					Maximum:     &maxEvents,
				},
			},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:        "Get Kubernetes Events",
			ReadOnlyHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("get_kubernetes_events", args, 0, false)

		clusterId := getString(args, "clusterId", "")
		kubernetesEntityId := getString(args, "kubernetesEntityId", "")
		eventType := getString(args, "eventType", "")
		maxEvents := getInt(args, "maxEventsToDisplay", 10)

		query := "fetch events, from: now()-24h, to: now()"

		var filters []string
		if clusterId != "" {
			filters = append(filters, fmt.Sprintf("k8s.cluster.uid == \"%s\"", clusterId))
		}
		if kubernetesEntityId != "" {
			filters = append(filters, fmt.Sprintf("dt.entity.kubernetes_cluster == \"%s\"", kubernetesEntityId))
		}
		if eventType != "" {
			filters = append(filters, fmt.Sprintf("event.type == \"%s\"", eventType))
		}

		if len(filters) > 0 {
			query += " | filter " + strings.Join(filters, " AND ")
		}

		query += " | sort timestamp desc"
		query += fmt.Sprintf(" | limit %d", maxEvents)
		query += " | fields event.id, event.type, event.name, event.status, event.start, event.end, dt.entity.kubernetes_cluster, duration"

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		result, err := r.client.ExecuteDQL(ctx, query, maxEvents, 1024*1024)
		if err != nil {
			return errorResult(fmt.Sprintf("Failed to get K8s events: %s", err.Error())), nil
		}

		// Log DQL query to file if enabled
		r.logger.SaveDQLQueryToFile(query, "kubernetes_events")

		if result.Result == nil || len(result.Result.Records) == 0 {
			return textResult("No events found for the specified Kubernetes cluster."), nil
		}

		resp := fmt.Sprintf("Found %d events! Displaying the top %d:\n\n", len(result.Result.Records), maxEvents)

		for _, record := range result.Result.Records {
			eventID, _ := record["event.id"].(string)
			eventTypeVal, _ := record["event.type"].(string)
			eventName, _ := record["event.name"].(string)
			eventStatus, _ := record["event.status"].(string)

			resp += fmt.Sprintf("- Event %s (%s)\n  Name: %s\n  Status: %s\n\n",
				eventID, eventTypeVal, eventName, eventStatus)
		}

		resp += "\n**Next Steps:**\n1. Filter by eventType for specific events\n2. Use execute_dql for more details about a specific event\n"

		return textResult(resp), nil
	})
}

func (r *Registry) registerListExceptions(server *mcp.Server) {
	minExceptions := float64(1)
	maxExceptions := float64(500)

	server.RegisterTool(mcp.Tool{
		Name:        "list_exceptions",
		Description: "[Query Tool] List all exceptions known on Dynatrace starting with the most recent. Use for tracking application errors and investigating stack traces.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"timeframe": {
					Type:        "string",
					Description: "Timeframe to query exceptions. Examples: '1h' (1 hour), '12h' (12 hours), '24h' (1 day), '7d' (1 week). Default: '24h'.",
					Default:     "24h",
				},
				"additionalFilter": {
					Type:        "string",
					Description: "Additional DQL filter expression for user.events. Examples: 'error.type == \"NullPointerException\"', 'contains(exception.message, \"timeout\")', 'os.name == \"Linux\"'. Uses DQL filter syntax.",
				},
				"maxExceptionsToDisplay": {
					Type:        "number",
					Description: "Maximum number of exceptions to return. Range: 1-500. Default: 10.",
					Default:     10,
					Minimum:     &minExceptions,
					Maximum:     &maxExceptions,
				},
			},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:        "List Exceptions",
			ReadOnlyHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("list_exceptions", args, 0, false)

		timeframe := getString(args, "timeframe", "24h")
		additionalFilter := getString(args, "additionalFilter", "")
		maxExceptions := getInt(args, "maxExceptionsToDisplay", 10)

		query := fmt.Sprintf(`fetch user.events, from: now()-%s, to: now()
| filter event.type == "exception"`, timeframe)

		if additionalFilter != "" {
			query += " | filter " + additionalFilter
		}

		query += " | sort timestamp desc"
		query += fmt.Sprintf(" | limit %d", maxExceptions)
		query += " | fields error.id, error.type, exception.message, timestamp, os.name, dt.rum.application.id, dt.rum.application.entity"

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		result, err := r.client.ExecuteDQL(ctx, query, maxExceptions, 1024*1024)
		if err != nil {
			return errorResult(fmt.Sprintf("Failed to list exceptions: %s", err.Error())), nil
		}

		// Log DQL query to file if enabled
		r.logger.SaveDQLQueryToFile(query, "list_exceptions")

		if result.Result == nil || len(result.Result.Records) == 0 {
			return textResult("No exceptions found"), nil
		}

		resp := fmt.Sprintf("Found %d exceptions! Displaying the top %d:\n\n", len(result.Result.Records), maxExceptions)

		for _, record := range result.Result.Records {
			errorType, _ := record["error.type"].(string)
			errorID, _ := record["error.id"].(string)
			message, _ := record["exception.message"].(string)
			osName, _ := record["os.name"].(string)

			resp += fmt.Sprintf("- Error Type: %s\n  ID: %s\n  OS: %s\n  Message: %s\n\n",
				errorType, errorID, osName, message)
		}

		resp += fmt.Sprintf(`
Next Steps:
1. Use execute_dql with error.id filter for stack traces
2. Visit %s/ui/apps/dynatrace.error.inspector for more details`, r.client.GetBaseURL())

		return textResult(resp), nil
	})
}

func (r *Registry) registerCreateWorkflowForNotification(server *mcp.Server) {
	server.RegisterTool(mcp.Tool{
		Name:        "create_workflow_for_notification",
		Description: "[Write Tool] Create a notification workflow for a team based on a problem type within Dynatrace Workflows. Creates a new automation workflow that triggers notifications when problems occur.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"problemType": {
					Type:        "string",
					Description: "Type of problem to notify about (e.g., 'AVAILABILITY', 'ERROR', 'PERFORMANCE', 'RESOURCE', 'CUSTOM').",
				},
				"teamName": {
					Type:        "string",
					Description: "Name of the team to notify. Used in workflow title and description.",
				},
				"channel": {
					Type:        "string",
					Description: "Notification channel name (e.g., '#alerts', '#platform-team').",
				},
				"isPrivate": {
					Type:        "boolean",
					Description: "Make workflow private (only visible to creator). Default: false.",
					Default:     false,
				},
			},
			Required: []string{"problemType", "teamName", "channel"},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:          "Create Workflow for Notification",
			ReadOnlyHint:   false,
			IdempotentHint: false,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("create_workflow_for_notification", args, 0, false)

		problemType := getString(args, "problemType", "")
		teamName := getString(args, "teamName", "")
		channel := getString(args, "channel", "")
		isPrivate := getBool(args, "isPrivate", false)

		workflow := &dynatrace.WorkflowCreateRequest{
			Title:       fmt.Sprintf("Problem Notification - %s - %s", teamName, problemType),
			Description: fmt.Sprintf("Auto-created workflow to notify team %s about %s problems via %s", teamName, problemType, channel),
			IsPrivate:   isPrivate,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result, err := r.client.CreateWorkflow(ctx, workflow)
		if err != nil {
			return errorResult(fmt.Sprintf("Failed to create workflow: %s", err.Error())), nil
		}

		resp := fmt.Sprintf("**Workflow Created:** %s\n**Name:** %s\n\n", result.ID, result.Title)
		resp += fmt.Sprintf("Access the Workflow: %s/ui/apps/dynatrace.automations/workflows/%s\n\n", r.client.GetBaseURL(), result.ID)

		if isPrivate {
			resp += "This workflow is private. Use 'make_workflow_public' to share it.\n"
		}

		return textResult(resp), nil
	})
}

func (r *Registry) registerMakeWorkflowPublic(server *mcp.Server) {
	server.RegisterTool(mcp.Tool{
		Name:        "make_workflow_public",
		Description: "[Write Tool] Make a workflow publicly available to everyone on the Dynatrace Environment. Changes the workflow visibility from private to public.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"workflowId": {
					Type:        "string",
					Description: "ID of the workflow to make public. Get this from create_workflow_for_notification or the Dynatrace UI.",
				},
			},
			Required: []string{"workflowId"},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:          "Make Workflow Public",
			ReadOnlyHint:   false,
			IdempotentHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("make_workflow_public", args, 0, false)

		workflowId := getString(args, "workflowId", "")
		if workflowId == "" {
			return errorResult("workflowId is required"), nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result, err := r.client.UpdateWorkflow(ctx, workflowId, map[string]interface{}{
			"isPrivate": false,
		})
		if err != nil {
			return errorResult(fmt.Sprintf("Failed to update workflow: %s", err.Error())), nil
		}

		resp := fmt.Sprintf("**Workflow %s is now public!**\n\n", result.ID)
		resp += fmt.Sprintf("Access: %s/ui/apps/dynatrace.automations/workflows/%s\n", r.client.GetBaseURL(), result.ID)

		return textResult(resp), nil
	})
}

func (r *Registry) registerSendEmail(server *mcp.Server) {
	server.RegisterTool(mcp.Tool{
		Name:        "send_email",
		Description: "[Write Tool] Send an email using the Dynatrace Email API. Maximum 10 recipients total. Useful for notifications and alerts.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"toRecipients": {
					Type:        "array",
					Description: "Array of email addresses for TO recipients. Example: ['user@example.com', 'team@example.com'].",
					Items:       &mcp.Property{Type: "string"},
				},
				"ccRecipients": {
					Type:        "array",
					Description: "Array of email addresses for CC recipients (optional).",
					Items:       &mcp.Property{Type: "string"},
				},
				"bccRecipients": {
					Type:        "array",
					Description: "Array of email addresses for BCC recipients (optional).",
					Items:       &mcp.Property{Type: "string"},
				},
				"subject": {
					Type:        "string",
					Description: "Subject line of the email.",
				},
				"body": {
					Type:        "string",
					Description: "Body content of the email (plain text only).",
				},
			},
			Required: []string{"toRecipients", "subject", "body"},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:         "Send Email",
			ReadOnlyHint:  false,
			OpenWorldHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("send_email", args, 0, false)

		toRecipients := getStringArray(args, "toRecipients")
		ccRecipients := getStringArray(args, "ccRecipients")
		bccRecipients := getStringArray(args, "bccRecipients")
		subject := getString(args, "subject", "")
		body := getString(args, "body", "")

		if len(toRecipients) == 0 || subject == "" || body == "" {
			return errorResult("toRecipients, subject, and body are required"), nil
		}

		totalRecipients := len(toRecipients) + len(ccRecipients) + len(bccRecipients)
		if totalRecipients > 10 {
			return errorResult(fmt.Sprintf("Total recipients (%d) exceeds maximum of 10", totalRecipients)), nil
		}

		email := &dynatrace.EmailRequest{
			ToRecipients: dynatrace.EmailRecipients{EmailAddresses: toRecipients},
			Subject:      subject,
			Body: dynatrace.EmailBody{
				ContentType: "text/plain",
				Body:        body,
			},
		}

		if len(ccRecipients) > 0 {
			email.CCRecipients = &dynatrace.EmailRecipients{EmailAddresses: ccRecipients}
		}
		if len(bccRecipients) > 0 {
			email.BCCRecipients = &dynatrace.EmailRecipients{EmailAddresses: bccRecipients}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result, err := r.client.SendEmail(ctx, email)
		if err != nil {
			return errorResult(fmt.Sprintf("Failed to send email: %s", err.Error())), nil
		}

		resp := fmt.Sprintf("**Email send request accepted.**\n\nRequest ID: %s\nMessage: %s\n", result.RequestID, result.Message)

		if len(result.InvalidDestinations) > 0 {
			resp += fmt.Sprintf("Invalid destinations: %s\n", strings.Join(result.InvalidDestinations, ", "))
		}

		return textResult(resp), nil
	})
}

func (r *Registry) registerSendSlackMessage(server *mcp.Server) {
	server.RegisterTool(mcp.Tool{
		Name:        "send_slack_message",
		Description: "[Write Tool] Send a Slack message to a dedicated Slack Channel via Slack Connector on Dynatrace. Requires SLACK_CONNECTION_ID to be configured.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"channel": {
					Type:        "string",
					Description: "Slack channel to send the message to. Example: '#alerts' or '#platform-team'.",
				},
				"message": {
					Type:        "string",
					Description: "Message content. Supports Slack markdown formatting (e.g., *bold*, _italic_, `code`).",
				},
			},
			Required: []string{"channel", "message"},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:         "Send Slack Message",
			ReadOnlyHint:  false,
			OpenWorldHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("send_slack_message", args, 0, false)

		channel := getString(args, "channel", "")
		message := getString(args, "message", "")

		if channel == "" || message == "" {
			return errorResult("channel and message are required"), nil
		}

		if r.slackConnID == "" {
			return errorResult("SLACK_CONNECTION_ID not configured"), nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result, err := r.client.SendSlackMessage(ctx, r.slackConnID, channel, message)
		if err != nil {
			return errorResult(fmt.Sprintf("Failed to send Slack message: %s", err.Error())), nil
		}

		resultJSON, _ := json.MarshalIndent(result, "", "  ")
		return textResult(fmt.Sprintf("Message sent to Slack channel: %s", string(resultJSON))), nil
	})
}

func (r *Registry) registerResetGrailBudget(server *mcp.Server) {
	server.RegisterTool(mcp.Tool{
		Name:        "reset_grail_budget",
		Description: "[Admin Tool] Reset the Grail query budget after it was exhausted, allowing new queries to be executed. Use when you receive budget exceeded errors.",
		InputSchema: mcp.JSONSchema{
			Type:       "object",
			Properties: map[string]mcp.Property{},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:          "Reset Grail Budget",
			ReadOnlyHint:   false,
			IdempotentHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("reset_grail_budget", args, 0, false)

		r.client.ResetBudget()
		state := r.client.GetBudgetTracker().GetState()

		resp := fmt.Sprintf(`**Grail Budget Reset Successfully!**

Budget status after reset:
- Total bytes scanned: 0 GB
- Budget limit: %d GB
- Remaining budget: %d GB
- Budget exceeded: No

You can now execute new Grail queries again.`, state.BudgetLimitGB, state.BudgetLimitGB)

		return textResult(resp), nil
	})
}

func (r *Registry) registerListBuckets(server *mcp.Server) {
	server.RegisterTool(mcp.Tool{
		Name:        "list_buckets",
		Description: "[Discovery Tool] List all available Grail data buckets with their metadata including retention, record counts, and size estimates. Start here to discover what data sources are available for querying with execute_dql.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"includeSystem": {
					Type:        "boolean",
					Description: "Include system buckets (dt.system.*) in the results. Default: false.",
					Default:     false,
				},
			},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:        "List Buckets",
			ReadOnlyHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("list_buckets", args, 0, false)

		includeSystem := getBool(args, "includeSystem", false)

		query := `fetch dt.system.buckets
| fields name, display_name, type, estimated_uncompressed_bytes, retention_days, record, metric_interval
| sort name asc`

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		result, err := r.client.ExecuteDQL(ctx, query, 500, 1024*1024)
		if err != nil {
			return errorResult(fmt.Sprintf("Failed to list buckets: %s", err.Error())), nil
		}

		r.logger.SaveDQLQueryToFile(query, "list_buckets")

		if result.Result == nil || len(result.Result.Records) == 0 {
			return textResult("No buckets found."), nil
		}

		resp := "# Available Grail Buckets\n\n"

		userBuckets := make([]map[string]interface{}, 0)
		systemBuckets := make([]map[string]interface{}, 0)

		for _, record := range result.Result.Records {
			name, _ := record["name"].(string)
			if strings.HasPrefix(name, "dt.system.") {
				systemBuckets = append(systemBuckets, record)
			} else {
				userBuckets = append(userBuckets, record)
			}
		}

		formatBucket := func(record map[string]interface{}) string {
			name, _ := record["name"].(string)
			displayName, _ := record["display_name"].(string)
			bucketType, _ := record["type"].(string)
			sizeBytes, _ := record["estimated_uncompressed_bytes"].(float64)
			retentionDays, _ := record["retention_days"].(float64)
			recordCount, _ := record["record"].(float64)
			metricInterval, _ := record["metric_interval"].(string)

			sizeGB := sizeBytes / (1024 * 1024 * 1024)

			result := fmt.Sprintf("- **%s**", name)
			if displayName != "" && displayName != name {
				result += fmt.Sprintf(" (%s)", displayName)
			}
			result += fmt.Sprintf("\n  Type: %s | Records: %.0f | Size: %.2f GB | Retention: %.0f days",
				bucketType, recordCount, sizeGB, retentionDays)
			if metricInterval != "" {
				result += fmt.Sprintf(" | Metric Interval: %s", metricInterval)
			}
			result += "\n"
			return result
		}

		resp += fmt.Sprintf("## Data Buckets (%d)\n\n", len(userBuckets))
		for _, record := range userBuckets {
			resp += formatBucket(record)
		}

		if includeSystem && len(systemBuckets) > 0 {
			resp += fmt.Sprintf("\n## System Buckets (%d)\n\n", len(systemBuckets))
			for _, record := range systemBuckets {
				resp += formatBucket(record)
			}
		}

		resp += `
## Common Bucket Types

| Bucket | Purpose |
|--------|---------|
| logs | Application and infrastructure logs |
| events | System and custom events |
| spans | Distributed traces |
| metrics | Time series metrics |
| dt.davis.problems | Davis AI detected problems |
| dt.entity.* | Entity metadata |
| security.events | Security findings |

## Next Steps
1. Use **describe_bucket** to see the schema of a specific bucket
2. Use **execute_dql** to query data: ` + "`fetch <bucket_name>`"

		return textResult(resp), nil
	})
}

func (r *Registry) registerDescribeBucket(server *mcp.Server) {
	minSample := float64(1)
	maxSample := float64(500)

	server.RegisterTool(mcp.Tool{
		Name:        "describe_bucket",
		Description: "[Discovery Tool] Get detailed schema information for a specific Grail bucket, including field names, types, and sample values. Essential for understanding what fields are available before writing DQL queries.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"bucket": {
					Type:        "string",
					Description: "Name of the bucket to describe. Common buckets: 'logs', 'events', 'spans', 'metrics', 'dt.davis.problems', 'security.events'. Use list_buckets to see all available buckets.",
				},
				"sampleSize": {
					Type:        "number",
					Description: "Number of sample records to analyze for field discovery. Range: 1-500. Larger samples provide better field coverage but take longer. Default: 100.",
					Default:     100,
					Minimum:     &minSample,
					Maximum:     &maxSample,
				},
			},
			Required: []string{"bucket"},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:        "Describe Bucket",
			ReadOnlyHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("describe_bucket", args, 0, false)

		bucket := getString(args, "bucket", "")
		sampleSize := getInt(args, "sampleSize", 100)

		if bucket == "" {
			return errorResult("bucket is required"), nil
		}

		// Get sample data to discover fields
		query := fmt.Sprintf(`fetch %s, from: now()-1h
| limit %d`, bucket, sampleSize)

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		result, err := r.client.ExecuteDQL(ctx, query, sampleSize, 2*1024*1024)
		if err != nil {
			return errorResult(fmt.Sprintf("Failed to describe bucket '%s': %s", bucket, err.Error())), nil
		}

		r.logger.SaveDQLQueryToFile(query, "describe_bucket_"+bucket)

		if result.Result == nil || len(result.Result.Records) == 0 {
			return textResult(fmt.Sprintf("No data found in bucket '%s' in the last hour. The bucket may be empty or not exist.", bucket)), nil
		}

		// Analyze fields from sample data
		fieldInfo := make(map[string]map[string]interface{})

		for _, record := range result.Result.Records {
			for field, value := range record {
				if _, exists := fieldInfo[field]; !exists {
					fieldInfo[field] = map[string]interface{}{
						"type":         inferType(value),
						"sampleValues": make([]interface{}, 0),
						"nullCount":    0,
						"totalCount":   0,
					}
				}

				info := fieldInfo[field]
				info["totalCount"] = info["totalCount"].(int) + 1

				if value == nil {
					info["nullCount"] = info["nullCount"].(int) + 1
				} else {
					samples := info["sampleValues"].([]interface{})
					if len(samples) < 3 {
						info["sampleValues"] = append(samples, value)
					}
				}
			}
		}

		resp := fmt.Sprintf("# Bucket Schema: %s\n\n", bucket)
		resp += fmt.Sprintf("Analyzed %d sample records from the last hour.\n\n", len(result.Result.Records))
		resp += "## Fields\n\n"
		resp += "| Field | Type | Sample Values |\n"
		resp += "|-------|------|---------------|\n"

		// Sort fields for consistent output
		fields := make([]string, 0, len(fieldInfo))
		for field := range fieldInfo {
			fields = append(fields, field)
		}

		// Common fields first, then alphabetical
		commonFields := []string{"timestamp", "content", "loglevel", "dt.entity.host", "dt.entity.service", "event.type", "event.name"}
		orderedFields := make([]string, 0)

		for _, cf := range commonFields {
			for _, f := range fields {
				if f == cf {
					orderedFields = append(orderedFields, f)
					break
				}
			}
		}

		for _, f := range fields {
			found := false
			for _, of := range orderedFields {
				if f == of {
					found = true
					break
				}
			}
			if !found {
				orderedFields = append(orderedFields, f)
			}
		}

		for _, field := range orderedFields {
			info := fieldInfo[field]
			samples := info["sampleValues"].([]interface{})
			sampleStr := ""
			for i, s := range samples {
				if i > 0 {
					sampleStr += ", "
				}
				str := fmt.Sprintf("%v", s)
				if len(str) > 40 {
					str = str[:37] + "..."
				}
				sampleStr += "`" + str + "`"
			}
			resp += fmt.Sprintf("| %s | %s | %s |\n", field, info["type"], sampleStr)
		}

		resp += fmt.Sprintf(`
## Query Examples

### Basic query
`+"```"+`
fetch %s
| limit 10
`+"```"+`

### Filter by time
`+"```"+`
fetch %s, from: now()-24h, to: now()
| limit 100
`+"```"+`

### Common filters
`+"```"+`
fetch %s
| filter <field> == "<value>"
| sort timestamp desc
| limit 50
`+"```"+`
`, bucket, bucket, bucket)

		return textResult(resp), nil
	})
}

func inferType(value interface{}) string {
	if value == nil {
		return "null"
	}
	switch value.(type) {
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "boolean"
	case []interface{}:
		return "array"
	case map[string]interface{}:
		return "object"
	default:
		return fmt.Sprintf("%T", value)
	}
}

func (r *Registry) registerListTags(server *mcp.Server) {
	server.RegisterTool(mcp.Tool{
		Name:        "list_tags",
		Description: "[Discovery Tool] List all tags used across monitored entities in the Dynatrace environment. Tags help categorize and filter entities (e.g., environment:production, team:platform). Use this to discover available tags for filtering.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"entityType": {
					Type:        "string",
					Description: "Filter tags by entity type. Common types: 'host', 'service', 'process_group', 'application', 'kubernetes_cluster'. Leave empty for all entity types.",
				},
				"tagKeyFilter": {
					Type:        "string",
					Description: "Filter tag keys containing this substring (case-insensitive). Example: 'env' to find 'environment', 'env-type', etc.",
				},
			},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:        "List Tags",
			ReadOnlyHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("list_tags", args, 0, false)

		entityType := getString(args, "entityType", "")
		tagKeyFilter := getString(args, "tagKeyFilter", "")

		// Build query based on entity type
		var query string
		if entityType != "" {
			query = fmt.Sprintf(`smartscapeNodes "%s"
| filter isNotNull(tags)
| expand tag = tags
| summarize count = count(), by: {tag}
| sort count desc
| limit 200`, entityType)
		} else {
			query = `smartscapeNodes "*"
| filter isNotNull(tags)
| expand tag = tags
| summarize count = count(), by: {tag}
| sort count desc
| limit 200`
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		result, err := r.client.ExecuteDQL(ctx, query, 200, 2*1024*1024)
		if err != nil {
			return errorResult(fmt.Sprintf("Failed to list tags: %s", err.Error())), nil
		}

		r.logger.SaveDQLQueryToFile(query, "list_tags")

		if result.Result == nil || len(result.Result.Records) == 0 {
			return textResult("No tags found in the environment."), nil
		}

		// Group tags by key
		tagGroups := make(map[string][]struct {
			Value string
			Count float64
		})

		for _, record := range result.Result.Records {
			tag, _ := record["tag"].(string)
			count, _ := record["count"].(float64)

			// Parse tag format: "key:value" or just "key"
			parts := strings.SplitN(tag, ":", 2)
			key := parts[0]
			value := ""
			if len(parts) > 1 {
				value = parts[1]
			}

			// Apply filter if specified
			if tagKeyFilter != "" && !strings.Contains(strings.ToLower(key), strings.ToLower(tagKeyFilter)) {
				continue
			}

			if _, exists := tagGroups[key]; !exists {
				tagGroups[key] = make([]struct {
					Value string
					Count float64
				}, 0)
			}
			tagGroups[key] = append(tagGroups[key], struct {
				Value string
				Count float64
			}{value, count})
		}

		resp := "# Tags in Environment\n\n"
		if entityType != "" {
			resp += fmt.Sprintf("Filtered by entity type: **%s**\n\n", entityType)
		}
		if tagKeyFilter != "" {
			resp += fmt.Sprintf("Filtered by tag key containing: **%s**\n\n", tagKeyFilter)
		}

		resp += fmt.Sprintf("Found **%d** unique tag keys.\n\n", len(tagGroups))

		for key, values := range tagGroups {
			totalCount := 0.0
			for _, v := range values {
				totalCount += v.Count
			}

			resp += fmt.Sprintf("## %s (%.0f entities)\n", key, totalCount)

			if len(values) <= 10 {
				for _, v := range values {
					if v.Value != "" {
						resp += fmt.Sprintf("- `%s:%s` (%.0f)\n", key, v.Value, v.Count)
					} else {
						resp += fmt.Sprintf("- `%s` (%.0f)\n", key, v.Count)
					}
				}
			} else {
				resp += fmt.Sprintf("- %d unique values (showing top 5):\n", len(values))
				for i, v := range values {
					if i >= 5 {
						break
					}
					if v.Value != "" {
						resp += fmt.Sprintf("  - `%s:%s` (%.0f)\n", key, v.Value, v.Count)
					}
				}
			}
			resp += "\n"
		}

		resp += `## Using Tags in DQL

### Filter entities by tag
` + "```" + `
smartscapeNodes "service"
| filter contains(toString(tags), "environment:production")
` + "```" + `

### Find entities with specific tag key
` + "```" + `
smartscapeNodes "*"
| expand tag = tags
| filter startsWith(tag, "owner:")
| fields name, type, tag
` + "```" + `

## Next Steps
- Use **find_entities_by_tag** to find entities with specific tags
- Use **find_entity_by_name** to search by entity name
`

		return textResult(resp), nil
	})
}

func (r *Registry) registerFindEntitiesByTag(server *mcp.Server) {
	minResults := float64(1)
	maxResults := float64(500)

	server.RegisterTool(mcp.Tool{
		Name:        "find_entities_by_tag",
		Description: "[Discovery Tool] Find all monitored entities that have a specific tag or tag pattern. Useful for discovering resources by their classification (e.g., find all production services).",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"tag": {
					Type:        "string",
					Description: "Tag to search for. Use 'key:value' for exact match (e.g., 'environment:production') or just 'key' for all entities with that tag key (e.g., 'environment').",
				},
				"entityType": {
					Type:        "string",
					Description: "Filter by entity type. Common types: 'host', 'service', 'process_group', 'application'. Leave empty to search all entity types.",
				},
				"maxResults": {
					Type:        "number",
					Description: "Maximum number of entities to return. Range: 1-500. Default: 50.",
					Default:     50,
					Minimum:     &minResults,
					Maximum:     &maxResults,
				},
			},
			Required: []string{"tag"},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:        "Find Entities by Tag",
			ReadOnlyHint: true,
		},
	}, func(args map[string]interface{}) (*mcp.CallToolResult, error) {
		logging.ToolCall("find_entities_by_tag", args, 0, false)

		tag := getString(args, "tag", "")
		entityType := getString(args, "entityType", "")
		maxResults := getInt(args, "maxResults", 50)

		if tag == "" {
			return errorResult("tag is required"), nil
		}

		// Determine if this is a key:value search or key-only
		var tagFilter string
		if strings.Contains(tag, ":") {
			// Exact tag match
			tagFilter = fmt.Sprintf(`contains(toString(tags), "%s")`, tag)
		} else {
			// Key-only match (any value)
			tagFilter = fmt.Sprintf(`contains(toString(tags), "%s:")`, tag)
		}

		// Build query
		nodeType := "*"
		if entityType != "" {
			nodeType = entityType
		}

		query := fmt.Sprintf(`smartscapeNodes "%s"
| filter %s
| fields id, type, name, tags
| limit %d`, nodeType, tagFilter, maxResults)

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		result, err := r.client.ExecuteDQL(ctx, query, maxResults, 2*1024*1024)
		if err != nil {
			return errorResult(fmt.Sprintf("Failed to find entities by tag: %s", err.Error())), nil
		}

		r.logger.SaveDQLQueryToFile(query, "find_entities_by_tag")

		if result.Result == nil || len(result.Result.Records) == 0 {
			return textResult(fmt.Sprintf("No entities found with tag '%s'.", tag)), nil
		}

		resp := fmt.Sprintf("# Entities with Tag: %s\n\n", tag)
		resp += fmt.Sprintf("Found **%d** entities.\n\n", len(result.Result.Records))

		// Group by entity type
		byType := make(map[string][]map[string]interface{})
		for _, record := range result.Result.Records {
			eType, _ := record["type"].(string)
			if _, exists := byType[eType]; !exists {
				byType[eType] = make([]map[string]interface{}, 0)
			}
			byType[eType] = append(byType[eType], record)
		}

		for eType, entities := range byType {
			resp += fmt.Sprintf("## %s (%d)\n\n", eType, len(entities))
			for _, entity := range entities {
				name, _ := entity["name"].(string)
				id, _ := entity["id"].(string)
				tags := entity["tags"]

				resp += fmt.Sprintf("- **%s**\n", name)
				resp += fmt.Sprintf("  - ID: `%s`\n", id)

				if tags != nil {
					tagsJSON, _ := json.Marshal(tags)
					tagsStr := string(tagsJSON)
					if len(tagsStr) > 100 {
						tagsStr = tagsStr[:97] + "..."
					}
					resp += fmt.Sprintf("  - Tags: %s\n", tagsStr)
				}
				resp += "\n"
			}
		}

		resp += `## Next Steps
- Use **execute_dql** with the entity ID to get detailed metrics
- Use **list_problems** filtered by entity to check for issues
- Use **entity-deep-dive** prompt for comprehensive analysis
`

		return textResult(resp), nil
	})
}
