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
		Description: "Get information about the connected Dynatrace Environment (Tenant) and verify the connection and authentication.",
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
		Description: "List all problems (based on \"fetch dt.davis.problems\") known on Dynatrace, sorted by their recency.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"timeframe": {
					Type:        "string",
					Description: "Timeframe to query problems (e.g., \"12h\", \"24h\", \"7d\", \"30d\"). Default: \"24h\".",
					Default:     "24h",
				},
				"status": {
					Type:        "string",
					Description: "Filter problems by status: ACTIVE, CLOSED, or ALL (default).",
					Enum:        []string{"ACTIVE", "CLOSED", "ALL"},
					Default:     "ALL",
				},
				"additionalFilter": {
					Type:        "string",
					Description: "Additional DQL filter for dt.davis.problems.",
				},
				"maxProblemsToDisplay": {
					Type:        "number",
					Description: "Maximum number of problems to display (1-5000).",
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
	server.RegisterTool(mcp.Tool{
		Name:        "list_vulnerabilities",
		Description: "Retrieve all active (non-muted) vulnerabilities from Dynatrace for the last 30 days.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"riskScore": {
					Type:        "number",
					Description: "Minimum risk score of vulnerabilities to list (default: 8.0)",
					Default:     8.0,
				},
				"additionalFilter": {
					Type:        "string",
					Description: "Additional DQL-based filter for vulnerabilities.",
				},
				"maxVulnerabilitiesToDisplay": {
					Type:        "number",
					Description: "Maximum number of vulnerabilities to display.",
					Default:     25,
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
	server.RegisterTool(mcp.Tool{
		Name:        "find_entity_by_name",
		Description: "Find the entityId and type of a monitored entity (service, host, process-group, application, etc.) based on name.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"entityNames": {
					Type:        "array",
					Description: "Names of the entities to search for.",
					Items:       &mcp.Property{Type: "string"},
				},
				"maxEntitiesToDisplay": {
					Type:        "number",
					Description: "Maximum number of entities to display.",
					Default:     10,
				},
				"extendedSearch": {
					Type:        "boolean",
					Description: "Set to true for comprehensive search over all entity types.",
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
	server.RegisterTool(mcp.Tool{
		Name:        "execute_dql",
		Description: "Get data like Logs, Metrics, Spans, Events, or Entity Data from Dynatrace GRAIL by executing a DQL statement.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"dqlStatement": {
					Type:        "string",
					Description: "DQL Statement to execute.",
				},
				"recordLimit": {
					Type:        "number",
					Description: "Maximum number of records to return (default: 100).",
					Default:     100,
				},
				"recordSizeLimitMB": {
					Type:        "number",
					Description: "Maximum size of returned records in MB (default: 1).",
					Default:     1,
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
		recordLimit := getInt(args, "recordLimit", 100)
		recordSizeLimitMB := getInt(args, "recordSizeLimitMB", 1)

		if dqlStatement == "" {
			return errorResult("dqlStatement is required"), nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()

		result, err := r.client.ExecuteDQL(ctx, dqlStatement, recordLimit, recordSizeLimitMB*1024*1024)
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
			resp += fmt.Sprintf("\n**Query Results** (%d records):\n\n", len(records))

			if len(records) > 0 {
				recordsJSON, _ := json.MarshalIndent(records, "", "  ")
				resp += "```json\n" + string(recordsJSON) + "\n```"
			} else {
				resp += "No records returned."
			}

			if len(records) == recordLimit {
				resp += fmt.Sprintf("\n\n**Record Limit Reached:** Results limited to %d records.", recordLimit)
			}
		}

		return textResult(resp), nil
	})
}

func (r *Registry) registerVerifyDQL(server *mcp.Server) {
	server.RegisterTool(mcp.Tool{
		Name:        "verify_dql",
		Description: "Syntactically verify a DQL statement before executing it.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"dqlStatement": {
					Type:        "string",
					Description: "DQL Statement to verify.",
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
		Description: "Convert natural language queries to DQL using Davis CoPilot AI.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"text": {
					Type:        "string",
					Description: "Natural language description of what you want to query.",
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
		Description: "Explain DQL statements in natural language using Davis CoPilot AI.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"dql": {
					Type:        "string",
					Description: "The DQL statement to explain.",
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
		Description: "Use this tool to ask any Dynatrace related question when no other specific tool is available.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"text": {
					Type:        "string",
					Description: "Your question or request for Davis CoPilot.",
				},
				"context": {
					Type:        "string",
					Description: "Optional context to provide additional information.",
				},
				"instruction": {
					Type:        "string",
					Description: "Optional instruction for response formatting.",
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
		Description: "List all available Davis Analyzers in Dynatrace (forecast, anomaly detection, correlation analyzers, and more).",
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
		Description: "Execute a Davis Analyzer with custom input parameters.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"analyzerName": {
					Type:        "string",
					Description: "The name of the Davis Analyzer to execute.",
				},
				"input": {
					Type:        "object",
					Description: "Input parameters for the analyzer as a JSON object.",
				},
				"timeframeStart": {
					Type:        "string",
					Description: "Start time for the analysis (default: now-1h).",
					Default:     "now-1h",
				},
				"timeframeEnd": {
					Type:        "string",
					Description: "End time for the analysis (default: now).",
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
	server.RegisterTool(mcp.Tool{
		Name:        "get_kubernetes_events",
		Description: "Get all events from a specific Kubernetes (K8s) cluster.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"clusterId": {
					Type:        "string",
					Description: "The Kubernetes Cluster Id (k8s.cluster.uid).",
				},
				"kubernetesEntityId": {
					Type:        "string",
					Description: "The Dynatrace Kubernetes Entity Id (dt.entity.kubernetes_cluster).",
				},
				"eventType": {
					Type:        "string",
					Description: "Filter by event type.",
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
					Description: "Maximum number of events to display.",
					Default:     10,
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
	server.RegisterTool(mcp.Tool{
		Name:        "list_exceptions",
		Description: "List all exceptions known on Dynatrace starting with the most recent.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"timeframe": {
					Type:        "string",
					Description: "Timeframe to query exceptions (e.g., \"12h\", \"24h\", \"7d\"). Default: \"24h\".",
					Default:     "24h",
				},
				"additionalFilter": {
					Type:        "string",
					Description: "Additional DQL filter for user.events.",
				},
				"maxExceptionsToDisplay": {
					Type:        "number",
					Description: "Maximum number of exceptions to display.",
					Default:     10,
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
		Description: "Create a notification workflow for a team based on a problem type within Dynatrace Workflows.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"problemType": {
					Type:        "string",
					Description: "Type of problem to notify about.",
				},
				"teamName": {
					Type:        "string",
					Description: "Name of the team to notify.",
				},
				"channel": {
					Type:        "string",
					Description: "Notification channel (e.g., Slack channel).",
				},
				"isPrivate": {
					Type:        "boolean",
					Description: "Make workflow private (default: false).",
					Default:     false,
				},
			},
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
		Description: "Make a workflow publicly available to everyone on the Dynatrace Environment.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"workflowId": {
					Type:        "string",
					Description: "ID of the workflow to make public.",
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
		Description: "Send an email using the Dynatrace Email API. Maximum 10 recipients total.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"toRecipients": {
					Type:        "array",
					Description: "Array of email addresses for TO recipients.",
					Items:       &mcp.Property{Type: "string"},
				},
				"ccRecipients": {
					Type:        "array",
					Description: "Array of email addresses for CC recipients.",
					Items:       &mcp.Property{Type: "string"},
				},
				"bccRecipients": {
					Type:        "array",
					Description: "Array of email addresses for BCC recipients.",
					Items:       &mcp.Property{Type: "string"},
				},
				"subject": {
					Type:        "string",
					Description: "Subject line of the email.",
				},
				"body": {
					Type:        "string",
					Description: "Body content of the email (plain text).",
				},
			},
			Required: []string{"toRecipients", "subject", "body"},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:         "Send Email",
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
		Description: "Send a Slack message to a dedicated Slack Channel via Slack Connector on Dynatrace.",
		InputSchema: mcp.JSONSchema{
			Type: "object",
			Properties: map[string]mcp.Property{
				"channel": {
					Type:        "string",
					Description: "Slack channel to send the message to.",
				},
				"message": {
					Type:        "string",
					Description: "Message content (Slack markdown supported).",
				},
			},
			Required: []string{"channel", "message"},
		},
		Annotations: &mcp.ToolAnnotation{
			Title:        "Send Slack Message",
			ReadOnlyHint: false,
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
		Description: "Reset the Grail query budget after it was exhausted, allowing new queries to be executed.",
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
