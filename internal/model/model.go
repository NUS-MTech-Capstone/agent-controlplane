package model

import "time"

type IncidentState string

const (
	IncidentDiagnosing       IncidentState = "DIAGNOSING"
	IncidentAwaitingApproval IncidentState = "AWAITING_APPROVAL"
	IncidentExecuting        IncidentState = "EXECUTING"
	IncidentCompleted        IncidentState = "COMPLETED"
	IncidentRejected         IncidentState = "REJECTED"
	IncidentRecovered        IncidentState = "RECOVERED"
	IncidentFailed           IncidentState = "FAILED"
)

type AlertStatus string

const (
	AlertReceived        AlertStatus = "RECEIVED"
	AlertTriaging        AlertStatus = "TRIAGING"
	AlertTriaged         AlertStatus = "TRIAGED"
	AlertPendingApproval AlertStatus = "PENDING_APPROVAL"
	AlertExecuting       AlertStatus = "EXECUTING"
	AlertResolved        AlertStatus = "RESOLVED"
	AlertRejected        AlertStatus = "REJECTED"
	AlertFailed          AlertStatus = "FAILED"
)

type ApprovalOutcome string

const (
	ApprovalSucceeded ApprovalOutcome = "SUCCEEDED"
	ApprovalDenied    ApprovalOutcome = "DENIED"
	ApprovalConflict  ApprovalOutcome = "CONFLICT"
	ApprovalNotFound  ApprovalOutcome = "NOT_FOUND"
)

type AgentHealth struct {
	DatabaseReady           bool       `json:"databaseReady"`
	QueueConsumerConfigured bool       `json:"queueConsumerConfigured"`
	QueueConsumerRunning    bool       `json:"queueConsumerRunning"`
	LastAlertProcessedAt    *time.Time `json:"lastAlertProcessedAt"`
	LastErrorSummary        string     `json:"lastErrorSummary"`
	ActiveIncidentCount     int        `json:"activeIncidentCount"`
	FailedIncidentCount     int        `json:"failedIncidentCount"`
}

type Plan struct {
	Summary   string   `json:"summary"`
	Rationale string   `json:"rationale"`
	Actions   []Action `json:"actions"`
}

type Action struct {
	OperationID string `json:"operationId"`
	Reason      string `json:"reason"`
}

type TriageResult struct {
	Priority  string `json:"priority"`
	Category  string `json:"category"`
	Summary   string `json:"summary"`
	Rationale string `json:"rationale"`
}

type OperationResult struct {
	OperationID string `json:"operationId"`
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
	ExitCode    int    `json:"exitCode"`
}

type PostIncidentReport struct {
	RootCauseSummary    string     `json:"rootCauseSummary"`
	ActionTaken         string     `json:"actionTaken"`
	VerificationSummary string     `json:"verificationSummary"`
	FinalState          string     `json:"finalState"`
	StartedAt           *time.Time `json:"startedAt,omitempty"`
	ResolvedAt          *time.Time `json:"resolvedAt,omitempty"`
	DurationSeconds     *float64   `json:"durationSeconds,omitempty"`
}

type Incident struct {
	ID                 string             `json:"id"`
	SourceID           string             `json:"sourceId"`
	AlarmARN           string             `json:"alarmArn"`
	AlarmName          string             `json:"alarmName"`
	HostID             string             `json:"hostId"`
	RunbookVersion     string             `json:"runbookVersion"`
	State              IncidentState      `json:"state"`
	Reason             string             `json:"reason"`
	RunID              string             `json:"-"`
	OperationsURL      string             `json:"-"`
	Evidence           []OperationResult  `json:"evidence"`
	Triage             *TriageResult      `json:"triage"`
	Plan               Plan               `json:"plan"`
	PlanHash           string             `json:"planHash"`
	PlanExpiresAt      *time.Time         `json:"planExpiresAt"`
	ApproverSubject    string             `json:"approverSubject"`
	ApprovalDecision   string             `json:"approvalDecision"`
	ApprovalAt         *time.Time         `json:"approvalAt"`
	Report             string             `json:"report"`
	PostIncidentReport PostIncidentReport `json:"postIncidentReport"`
	ErrorMessage       string             `json:"errorMessage"`
	CreatedAt          time.Time          `json:"createdAt"`
	UpdatedAt          time.Time          `json:"updatedAt"`
}

type ManagedAlert struct {
	ID              string      `json:"id"`
	SourceID        string      `json:"sourceId"`
	SourceType      string      `json:"sourceType"`
	AlarmARN        string      `json:"alarmArn"`
	AlarmName       string      `json:"alarmName"`
	CloudWatchState string      `json:"cloudwatchState"`
	HostID          string      `json:"hostId"`
	Reason          string      `json:"reason"`
	Status          AlertStatus `json:"status"`
	GroupKey        string      `json:"groupKey"`
	IncidentID      string      `json:"incidentId"`
	Grouped         bool        `json:"grouped"`
	ErrorSummary    string      `json:"errorSummary"`
	OccurredAt      time.Time   `json:"occurredAt"`
	CreatedAt       time.Time   `json:"createdAt"`
	UpdatedAt       time.Time   `json:"updatedAt"`
}

type IncidentEvent struct {
	ID         string         `json:"id"`
	IncidentID string         `json:"incidentId"`
	AlertID    string         `json:"alertId"`
	EventType  string         `json:"eventType"`
	Actor      string         `json:"actor"`
	Message    string         `json:"message"`
	Metadata   map[string]any `json:"metadata"`
	CreatedAt  time.Time      `json:"createdAt"`
}

type ApprovalDecisionAudit struct {
	ID                string          `json:"id"`
	IncidentID        string          `json:"incidentId"`
	Actor             string          `json:"actor"`
	Decision          string          `json:"decision"`
	SubmittedPlanHash string          `json:"submittedPlanHash"`
	Outcome           ApprovalOutcome `json:"outcome"`
	ErrorReason       string          `json:"errorReason"`
	CreatedAt         time.Time       `json:"createdAt"`
}

type AlertListResponse struct {
	Alerts []ManagedAlert `json:"alerts"`
}

type IncidentListResponse struct {
	Incidents []IncidentSummary `json:"incidents"`
}

type IncidentSummary struct {
	ID            string        `json:"id"`
	AlarmName     string        `json:"alarmName"`
	HostID        string        `json:"hostId"`
	State         IncidentState `json:"state"`
	PlanHash      string        `json:"planHash"`
	PlanExpiresAt *time.Time    `json:"planExpiresAt"`
	CreatedAt     time.Time     `json:"createdAt"`
	UpdatedAt     time.Time     `json:"updatedAt"`
	ErrorMessage  string        `json:"errorMessage"`
}

type AlertDetail struct {
	ManagedAlert
	Incident *IncidentDetail `json:"incident"`
	Timeline []IncidentEvent `json:"timeline"`
}

type IncidentDetail struct {
	Incident
	Timeline          []IncidentEvent         `json:"timeline"`
	ApprovalDecisions []ApprovalDecisionAudit `json:"approvalDecisions"`
}

type AutomationRunRequest struct {
	IncidentID        string   `json:"incidentId"`
	HostID            string   `json:"hostId"`
	Phase             string   `json:"phase"`
	AllowedOperations []string `json:"allowedOperations"`
	PlanHash          string   `json:"planHash,omitempty"`
	WorkloadToken     string   `json:"-"`
}

type AutomationTokenRequest struct {
	Phase             string   `json:"phase"`
	AllowedOperations []string `json:"allowedOperations"`
	PlanHash          string   `json:"planHash,omitempty"`
	WorkloadToken     string   `json:"-"`
}

type AutomationRun struct {
	RunID           string    `json:"runId"`
	IncidentID      string    `json:"incidentId"`
	HostID          string    `json:"hostId"`
	OwnerPodID      string    `json:"ownerPodId"`
	OwnerInstanceID string    `json:"ownerInstanceId"`
	OperationsURL   string    `json:"operationsUrl"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"createdAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

type AutomationRunResponse struct {
	AutomationRun
	CapabilityToken string    `json:"capabilityToken"`
	TokenExpiresAt  time.Time `json:"tokenExpiresAt"`
}

type AutomationTokenResponse struct {
	CapabilityToken string    `json:"capabilityToken"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
