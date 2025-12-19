package dynatrace

import (
	"fmt"
	"time"
)

// Environment information
type EnvironmentInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	State       string `json:"state"`
	ClusterID   string `json:"clusterId,omitempty"`
	CreatedAt   string `json:"createdAt,omitempty"`
	ProductType string `json:"productType,omitempty"`
}

// DQL Query types
type DQLQueryRequest struct {
	Query            string `json:"query"`
	MaxResultRecords int    `json:"maxResultRecords,omitempty"`
	MaxResultBytes   int    `json:"maxResultBytes,omitempty"`
	RequestTimeoutMs int    `json:"requestTimeoutMilliseconds,omitempty"`
}

type DQLQueryResponse struct {
	State        string          `json:"state"`
	Progress     int             `json:"progress"`
	Result       *DQLQueryResult `json:"result,omitempty"`
	Error        *DQLError       `json:"error,omitempty"`
	RequestToken string          `json:"requestToken,omitempty"`
}

type DQLQueryResult struct {
	Records  []map[string]interface{} `json:"records"`
	Types    []DQLFieldType           `json:"types,omitempty"`
	Metadata *DQLMetadata             `json:"metadata,omitempty"`
}

type DQLFieldType struct {
	Name string                 `json:"name"`
	Type map[string]interface{} `json:"type"`
}

type DQLMetadata struct {
	Notifications  []DQLNotification `json:"notifications,omitempty"`
	GrailMetrics   *GrailMetrics     `json:"grail,omitempty"`
	ExecutionStats *ExecutionStats   `json:"executionStats,omitempty"`
}

type DQLNotification struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type GrailMetrics struct {
	ScannedRecords  int64 `json:"scannedRecords"`
	ScannedBytes    int64 `json:"scannedBytes"`
	Sampled         bool  `json:"sampled"`
	EstimatedBytes  int64 `json:"estimatedBytes,omitempty"`
	QueryComplexity int   `json:"queryComplexity,omitempty"`
}

type ExecutionStats struct {
	ResultRecords int   `json:"resultRecords"`
	ResultBytes   int64 `json:"resultBytes"`
}

type DQLError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// DQL Verify types
type DQLVerifyRequest struct {
	Query string `json:"query"`
}

type DQLVerifyResponse struct {
	Valid         bool              `json:"valid"`
	Notifications []DQLNotification `json:"notifications,omitempty"`
}

// Entity types
type Entity struct {
	EntityID    string                 `json:"entityId"`
	Type        string                 `json:"type"`
	DisplayName string                 `json:"displayName"`
	Properties  map[string]interface{} `json:"properties,omitempty"`
	Tags        []Tag                  `json:"tags,omitempty"`
}

type Tag struct {
	Context string `json:"context,omitempty"`
	Key     string `json:"key"`
	Value   string `json:"value,omitempty"`
}

// Problem types
type Problem struct {
	ProblemID        string   `json:"problemId"`
	DisplayID        string   `json:"displayId"`
	Title            string   `json:"title"`
	Status           string   `json:"status"`
	SeverityLevel    string   `json:"severityLevel"`
	ImpactLevel      string   `json:"impactLevel"`
	AffectedEntities []string `json:"affectedEntities,omitempty"`
	StartTime        int64    `json:"startTime"`
	EndTime          int64    `json:"endTime,omitempty"`
	ManagementZones  []string `json:"managementZones,omitempty"`
	RootCauseEntity  string   `json:"rootCauseEntity,omitempty"`
}

// Vulnerability types
type Vulnerability struct {
	VulnerabilityID  string   `json:"vulnerabilityId"`
	DisplayID        string   `json:"displayId"`
	Title            string   `json:"title"`
	CVEIDs           []string `json:"cveIds,omitempty"`
	RiskLevel        string   `json:"riskLevel"`
	RiskScore        float64  `json:"riskScore"`
	Status           string   `json:"status"`
	AffectedEntities []string `json:"affectedEntities,omitempty"`
	FirstSeenAt      int64    `json:"firstSeenTimestamp,omitempty"`
	Technology       string   `json:"technology,omitempty"`
}

// Workflow types
type Workflow struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type,omitempty"`
	State       string `json:"state,omitempty"`
	IsPrivate   bool   `json:"isPrivate,omitempty"`
	Owner       string `json:"owner,omitempty"`
}

type WorkflowCreateRequest struct {
	Title       string                   `json:"title"`
	Description string                   `json:"description,omitempty"`
	IsPrivate   bool                     `json:"isPrivate,omitempty"`
	Trigger     *WorkflowTrigger         `json:"trigger,omitempty"`
	Tasks       map[string]*WorkflowTask `json:"tasks,omitempty"`
}

type WorkflowTrigger struct {
	EventTrigger *EventTrigger `json:"eventTrigger,omitempty"`
}

type EventTrigger struct {
	IsActive      bool           `json:"isActive"`
	TriggerConfig *TriggerConfig `json:"triggerConfiguration,omitempty"`
}

type TriggerConfig struct {
	Type  string                 `json:"type"`
	Value map[string]interface{} `json:"value,omitempty"`
}

type WorkflowTask struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Action      string                 `json:"action"`
	Input       map[string]interface{} `json:"input,omitempty"`
	Position    *TaskPosition          `json:"position,omitempty"`
}

type TaskPosition struct {
	X int `json:"x"`
	Y int `json:"y"`
}

// Davis CoPilot types
type DavisCopilotRequest struct {
	Text    string                `json:"text"`
	Context []DavisCopilotContext `json:"context,omitempty"`
}

type DavisCopilotContext struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type DavisCopilotResponse struct {
	Text         string                `json:"text,omitempty"`
	Status       string                `json:"status"`
	MessageToken string                `json:"messageToken,omitempty"`
	Metadata     *DavisCopilotMetadata `json:"metadata,omitempty"`
	State        *DavisCopilotState    `json:"state,omitempty"`
}

type DavisCopilotMetadata struct {
	Sources       []DavisSource       `json:"sources,omitempty"`
	Notifications []DavisNotification `json:"notifications,omitempty"`
}

type DavisSource struct {
	Title string `json:"title,omitempty"`
	URL   string `json:"url,omitempty"`
}

type DavisNotification struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type DavisCopilotState struct {
	ConversationID string `json:"conversationId,omitempty"`
}

// NL2DQL types
type NL2DQLRequest struct {
	Text string `json:"text"`
}

type NL2DQLResponse struct {
	DQL          string          `json:"dql,omitempty"`
	Status       string          `json:"status"`
	MessageToken string          `json:"messageToken,omitempty"`
	Metadata     *NL2DQLMetadata `json:"metadata,omitempty"`
}

type NL2DQLMetadata struct {
	Notifications []DQLNotification `json:"notifications,omitempty"`
}

// DQL2NL types
type DQL2NLRequest struct {
	DQL string `json:"dql"`
}

type DQL2NLResponse struct {
	Summary      string          `json:"summary,omitempty"`
	Explanation  string          `json:"explanation,omitempty"`
	Status       string          `json:"status"`
	MessageToken string          `json:"messageToken,omitempty"`
	Metadata     *DQL2NLMetadata `json:"metadata,omitempty"`
}

type DQL2NLMetadata struct {
	Notifications []DQLNotification `json:"notifications,omitempty"`
}

// Davis Analyzer types
type DavisAnalyzer struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"displayName"`
	Description string   `json:"description"`
	Type        string   `json:"type"`
	Category    string   `json:"category,omitempty"`
	Labels      []string `json:"labels,omitempty"`
}

type DavisAnalyzerExecuteRequest struct {
	Input map[string]interface{} `json:"input"`
}

type DavisAnalyzerResult struct {
	ExecutionStatus string                   `json:"executionStatus"`
	ResultStatus    string                   `json:"resultStatus"`
	Output          []map[string]interface{} `json:"output,omitempty"`
	Logs            []DavisAnalyzerLog       `json:"logs,omitempty"`
}

type DavisAnalyzerLog struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

// Email types
type EmailRequest struct {
	ToRecipients  EmailRecipients  `json:"toRecipients"`
	CCRecipients  *EmailRecipients `json:"ccRecipients,omitempty"`
	BCCRecipients *EmailRecipients `json:"bccRecipients,omitempty"`
	Subject       string           `json:"subject"`
	Body          EmailBody        `json:"body"`
}

type EmailRecipients struct {
	EmailAddresses []string `json:"emailAddresses"`
}

type EmailBody struct {
	ContentType string `json:"contentType"`
	Body        string `json:"body"`
}

type EmailResponse struct {
	RequestID               string   `json:"requestId"`
	Message                 string   `json:"message"`
	InvalidDestinations     []string `json:"invalidDestinations,omitempty"`
	BouncingDestinations    []string `json:"bouncingDestinations,omitempty"`
	ComplainingDestinations []string `json:"complainingDestinations,omitempty"`
}

// Slack types
type SlackMessageRequest struct {
	ConnectionID string `json:"connectionId"`
	Channel      string `json:"channel"`
	Message      string `json:"message"`
}

// Budget tracker
type GrailBudgetState struct {
	TotalBytesScanned int64
	BudgetLimitBytes  int64
	BudgetLimitGB     int
	IsBudgetExceeded  bool
}

type GrailBudgetTracker struct {
	state   GrailBudgetState
	limitGB int
}

func NewGrailBudgetTracker(limitGB int) *GrailBudgetTracker {
	return &GrailBudgetTracker{
		state: GrailBudgetState{
			BudgetLimitGB:    limitGB,
			BudgetLimitBytes: int64(limitGB) * 1000 * 1000 * 1000,
		},
		limitGB: limitGB,
	}
}

func (t *GrailBudgetTracker) AddBytesScanned(bytes int64) {
	t.state.TotalBytesScanned += bytes
	if t.state.TotalBytesScanned > t.state.BudgetLimitBytes {
		t.state.IsBudgetExceeded = true
	}
}

func (t *GrailBudgetTracker) GetState() GrailBudgetState {
	return t.state
}

func (t *GrailBudgetTracker) Reset() {
	t.state = GrailBudgetState{
		BudgetLimitGB:    t.limitGB,
		BudgetLimitBytes: int64(t.limitGB) * 1000 * 1000 * 1000,
	}
}

func (t *GrailBudgetTracker) GetWarning() string {
	if t.state.IsBudgetExceeded {
		return fmt.Sprintf("⚠️ BUDGET EXCEEDED: You have scanned %.2f GB of data, exceeding your %d GB budget. Use 'reset_grail_budget' tool to continue querying.",
			float64(t.state.TotalBytesScanned)/(1000*1000*1000), t.limitGB)
	}

	usagePercent := float64(t.state.TotalBytesScanned) / float64(t.state.BudgetLimitBytes) * 100
	if usagePercent >= 80 {
		return fmt.Sprintf("⚠️ WARNING: You have used %.1f%% of your %d GB Grail query budget.",
			usagePercent, t.limitGB)
	}
	return ""
}

// Exception types
type ExceptionInfo struct {
	ErrorID           string    `json:"error.id"`
	ErrorType         string    `json:"error.type"`
	ExceptionMessage  string    `json:"exception.message"`
	StartTime         time.Time `json:"start_time"`
	OSName            string    `json:"os.name"`
	ApplicationID     string    `json:"dt.rum.application.id"`
	ApplicationEntity string    `json:"dt.rum.application.entity"`
}
