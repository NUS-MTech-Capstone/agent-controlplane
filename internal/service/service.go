package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/catalog"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/clients"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/events"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/model"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/observability"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/store"
)

var (
	ErrNotFound   = store.ErrNotFound
	ErrConflict   = store.ErrConflict
	ErrForbidden  = errors.New("forbidden")
	ErrBadRequest = errors.New("bad request")
)

type Store interface {
	Ping(context.Context) error
	ListAlerts(context.Context, model.AlertFilter) ([]model.ManagedAlert, error)
	GetAlert(context.Context, string) (model.ManagedAlert, error)
	ListIncidents(context.Context, model.IncidentFilter) ([]model.Incident, error)
	GetIncident(context.Context, string) (model.Incident, error)
	ListEvents(context.Context, string) ([]model.IncidentEvent, error)
	ListIncidentEvents(context.Context, model.IncidentEventFilter) ([]model.IncidentEvent, error)
	ListApprovalDecisions(context.Context, string) ([]model.ApprovalDecisionAudit, error)
	IncidentCounts(context.Context) (int, int, error)
	LastAlertProcessedAt(context.Context) (*time.Time, error)
	CreateEvent(context.Context, string, string, string, string, string, map[string]any) (model.IncidentEvent, error)
	CreateApprovalDecision(context.Context, string, string, string, string, model.ApprovalOutcome, string) error
	Approve(context.Context, string, string, string) error
	Reject(context.Context, model.Incident, string, string) error
	SetAlertStatusForIncident(context.Context, string, model.AlertStatus, string) error
	SetIncidentReport(context.Context, string, model.IncidentState, string, string, model.PostIncidentReport) error
	SetFailure(context.Context, string, string) error
}

type SessionManager interface {
	CreateAutomationRun(context.Context, string, string) (model.AutomationRun, error)
	GetAutomationRun(context.Context, string) (model.AutomationRun, error)
	CloseAutomationRun(context.Context, string) error
}

type STS interface {
	RequestAutomationToken(context.Context, string, clients.AutomationTokenRequest) (model.AutomationTokenResponse, error)
	ValidateWorkload(context.Context, string) (clients.WorkloadIdentity, error)
}

type ToolGateway interface {
	Execute(context.Context, string, string, string) (model.OperationResult, error)
}

type Worker interface {
	Health(context.Context) (model.AgentHealth, error)
}

type Service struct {
	store            Store
	sm               SessionManager
	sts              STS
	tools            ToolGateway
	worker           Worker
	operationTimeout time.Duration
	maxOutputBytes   int
	now              func() time.Time
	events           events.Publisher
}

func New(store Store, sm SessionManager, sts STS, tools ToolGateway, worker Worker, _ string, operationTimeout time.Duration, maxOutputBytes int, publishers ...events.Publisher) *Service {
	publisher := events.Publisher(events.NoopPublisher{})
	if len(publishers) > 0 && publishers[0] != nil {
		publisher = publishers[0]
	}
	return &Service{
		store: store, sm: sm, sts: sts, tools: tools, worker: worker,
		operationTimeout: operationTimeout, maxOutputBytes: maxOutputBytes,
		now:    func() time.Time { return time.Now().UTC() },
		events: publisher,
	}
}

func (s *Service) Ready(ctx context.Context) error {
	return s.store.Ping(ctx)
}

func (s *Service) Health(ctx context.Context) model.AgentHealth {
	databaseReady := true
	if err := s.store.Ping(ctx); err != nil {
		databaseReady = false
	}
	active, failed, _ := s.store.IncidentCounts(ctx)
	last, _ := s.store.LastAlertProcessedAt(ctx)
	health := model.AgentHealth{
		DatabaseReady: databaseReady, ActiveIncidentCount: active,
		FailedIncidentCount: failed, LastAlertProcessedAt: last,
	}
	if s.worker != nil {
		if workerHealth, err := s.worker.Health(ctx); err == nil {
			health.QueueConsumerConfigured = workerHealth.QueueConsumerConfigured
			health.QueueConsumerRunning = workerHealth.QueueConsumerRunning
			health.LastErrorSummary = workerHealth.LastErrorSummary
			if workerHealth.LastAlertProcessedAt != nil {
				health.LastAlertProcessedAt = workerHealth.LastAlertProcessedAt
			}
		} else if health.LastErrorSummary == "" {
			health.LastErrorSummary = "incident-agent worker health unavailable"
		}
	}
	return health
}

func boundedLimit(value, fallback, max int) int {
	if value <= 0 {
		return fallback
	}
	if value > max {
		return max
	}
	return value
}

func (s *Service) ListAlerts(ctx context.Context, filter model.AlertFilter) (model.AlertListResponse, error) {
	filter.Limit = boundedLimit(filter.Limit, 100, 200)
	alerts, err := s.store.ListAlerts(ctx, filter)
	if err != nil {
		return model.AlertListResponse{}, err
	}
	if alerts == nil {
		alerts = []model.ManagedAlert{}
	}
	response := model.AlertListResponse{Alerts: alerts}
	if len(alerts) == filter.Limit {
		response.NextCursor = strconv.Itoa(filter.Offset + len(alerts))
	}
	return response, nil
}

func (s *Service) GetAlertDetail(ctx context.Context, alertID string) (model.AlertDetail, error) {
	alert, err := s.store.GetAlert(ctx, alertID)
	if err != nil {
		return model.AlertDetail{}, err
	}
	detail := model.AlertDetail{ManagedAlert: alert}
	if alert.IncidentID != "" {
		incident, err := s.GetIncidentDetail(ctx, alert.IncidentID)
		if err == nil {
			detail.Incident = &incident
			detail.Timeline = incident.Timeline
		}
	}
	return detail, nil
}

func (s *Service) ListIncidents(ctx context.Context, filter model.IncidentFilter) (model.IncidentListResponse, error) {
	filter.Limit = boundedLimit(filter.Limit, 100, 200)
	incidents, err := s.store.ListIncidents(ctx, filter)
	if err != nil {
		return model.IncidentListResponse{}, err
	}
	summaries := make([]model.IncidentSummary, 0, len(incidents))
	for _, incident := range incidents {
		summaries = append(summaries, model.IncidentSummary{
			ID: incident.ID, AlarmName: incident.AlarmName, HostID: incident.HostID,
			State: incident.State, PlanHash: incident.PlanHash, PlanExpiresAt: incident.PlanExpiresAt,
			CreatedAt: incident.CreatedAt, UpdatedAt: incident.UpdatedAt, ErrorMessage: incident.ErrorMessage,
		})
	}
	response := model.IncidentListResponse{Incidents: summaries}
	if len(incidents) == filter.Limit {
		response.NextCursor = strconv.Itoa(filter.Offset + len(incidents))
	}
	return response, nil
}

func (s *Service) GetIncidentDetail(ctx context.Context, incidentID string) (model.IncidentDetail, error) {
	incident, err := s.store.GetIncident(ctx, incidentID)
	if err != nil {
		return model.IncidentDetail{}, err
	}
	timeline, err := s.store.ListEvents(ctx, incidentID)
	if err != nil {
		return model.IncidentDetail{}, err
	}
	decisions, err := s.store.ListApprovalDecisions(ctx, incidentID)
	if err != nil {
		return model.IncidentDetail{}, err
	}
	incident.Explanation.Trace = buildExplanationTrace(incident, timeline)
	return model.IncidentDetail{Incident: incident, Timeline: timeline, ApprovalDecisions: decisions}, nil
}

func (s *Service) ListIncidentEvents(ctx context.Context, filter model.IncidentEventFilter) (model.IncidentEventListResponse, error) {
	filter.Limit = boundedLimit(filter.Limit, 100, 200)
	events, err := s.store.ListIncidentEvents(ctx, filter)
	if err != nil {
		return model.IncidentEventListResponse{}, err
	}
	if events == nil {
		events = []model.IncidentEvent{}
	}
	response := model.IncidentEventListResponse{Events: events}
	if len(events) == filter.Limit {
		response.NextCursor = strconv.Itoa(filter.Offset + len(events))
	}
	return response, nil
}

func (s *Service) Approve(ctx context.Context, incidentID, planHash, subject string, groups []string) (model.IncidentDetail, error) {
	if !canDecide(groups) {
		_ = s.store.CreateApprovalDecision(ctx, incidentID, "APPROVE", planHash, subject, model.ApprovalDenied, "manager approval is required")
		return model.IncidentDetail{}, ErrForbidden
	}
	incident, err := s.loadForDecision(ctx, incidentID, "APPROVE", planHash, subject)
	if err != nil {
		return model.IncidentDetail{}, err
	}
	if planExpired(incident, s.now()) {
		_ = s.store.CreateApprovalDecision(ctx, incidentID, "APPROVE", planHash, subject, model.ApprovalConflict, "plan expired")
		_, _ = s.store.CreateEvent(ctx, incidentID, "PlanExpired", "", subject, "Plan expired before approval.", map[string]any{"planHash": incident.PlanHash})
		return model.IncidentDetail{}, ErrConflict
	}
	if err := s.store.Approve(ctx, incidentID, planHash, subject); err != nil {
		_ = s.store.CreateApprovalDecision(ctx, incidentID, "APPROVE", planHash, subject, model.ApprovalConflict, "incident changed")
		return model.IncidentDetail{}, err
	}
	_ = s.store.CreateApprovalDecision(ctx, incidentID, "APPROVE", planHash, subject, model.ApprovalSucceeded, "")
	_ = s.store.SetAlertStatusForIncident(ctx, incidentID, model.AlertExecuting, "")
	_, _ = s.store.CreateEvent(ctx, incidentID, "PlanApproved", "", subject, "Manager approved exact remediation plan.", map[string]any{"planHash": planHash})
	s.events.Emit(ctx, events.Event{
		EventType:  "PlanApproved",
		RequestID:  observability.RequestID(ctx),
		UserID:     subject,
		HostID:     incident.HostID,
		IncidentID: incidentID,
		RunID:      incident.RunID,
		Action:     "approve",
		Outcome:    "approved",
		PlanHash:   planHash,
	})
	s.Execute(ctx, incidentID, planHash)
	return s.GetIncidentDetail(ctx, incidentID)
}

func (s *Service) Reject(ctx context.Context, incidentID, planHash, subject string, groups []string) (model.IncidentDetail, error) {
	if !canDecide(groups) {
		_ = s.store.CreateApprovalDecision(ctx, incidentID, "REJECT", planHash, subject, model.ApprovalDenied, "manager approval is required")
		return model.IncidentDetail{}, ErrForbidden
	}
	incident, err := s.loadForDecision(ctx, incidentID, "REJECT", planHash, subject)
	if err != nil {
		return model.IncidentDetail{}, err
	}
	if planExpired(incident, s.now()) {
		_ = s.store.CreateApprovalDecision(ctx, incidentID, "REJECT", planHash, subject, model.ApprovalConflict, "plan expired")
		_, _ = s.store.CreateEvent(ctx, incidentID, "PlanExpired", "", subject, "Plan expired before rejection.", map[string]any{"planHash": incident.PlanHash})
		return model.IncidentDetail{}, ErrConflict
	}
	if err := s.store.Reject(ctx, incident, planHash, subject); err != nil {
		_ = s.store.CreateApprovalDecision(ctx, incidentID, "REJECT", planHash, subject, model.ApprovalConflict, "incident changed")
		return model.IncidentDetail{}, err
	}
	_ = s.store.CreateApprovalDecision(ctx, incidentID, "REJECT", planHash, subject, model.ApprovalSucceeded, "")
	_ = s.store.SetAlertStatusForIncident(ctx, incidentID, model.AlertRejected, "")
	_, _ = s.store.CreateEvent(ctx, incidentID, "PlanRejected", "", subject, "Manager rejected exact remediation plan.", map[string]any{"planHash": planHash})
	s.events.Emit(ctx, events.Event{
		EventType:  "PlanRejected",
		RequestID:  observability.RequestID(ctx),
		UserID:     subject,
		HostID:     incident.HostID,
		IncidentID: incidentID,
		RunID:      incident.RunID,
		Action:     "reject",
		Outcome:    "rejected",
		PlanHash:   planHash,
	})
	if incident.RunID != "" {
		go s.closeAfterReject(observability.ContextWithRequestID(context.WithoutCancel(ctx), observability.RequestID(ctx)), incident)
	}
	return s.GetIncidentDetail(ctx, incidentID)
}

func (s *Service) loadForDecision(ctx context.Context, incidentID, decision, planHash, subject string) (model.Incident, error) {
	incident, err := s.store.GetIncident(ctx, incidentID)
	if errors.Is(err, store.ErrNotFound) {
		_ = s.store.CreateApprovalDecision(ctx, incidentID, decision, planHash, subject, model.ApprovalNotFound, "incident not found")
		return model.Incident{}, err
	}
	return incident, err
}

func (s *Service) Execute(ctx context.Context, incidentID, approvedPlanHash string) {
	started := s.now()
	incident, err := s.store.GetIncident(ctx, incidentID)
	if err != nil {
		return
	}
	operation, err := validateExecution(incident, approvedPlanHash)
	if err != nil {
		s.failExecution(ctx, incident, started, err)
		return
	}
	_, _ = s.store.CreateEvent(ctx, incidentID, "RemediationStarted", "", "", "Approved remediation execution started.", map[string]any{"planHash": approvedPlanHash})
	operationStarted := time.Now()
	operationCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	remediation, err := s.tools.Execute(operationCtx, incident.RunID, operation, incident.PlanHash)
	cancel()
	duration := time.Since(operationStarted)
	if err != nil {
		failed := model.OperationResult{OperationID: operation, Stderr: truncate(err.Error(), s.maxOutputBytes), ExitCode: -1}
		s.recordToolCall(ctx, incident, "remediate", operation, failed, duration, wasTruncated(err.Error(), "", s.maxOutputBytes))
		s.failExecution(ctx, incident, started, err)
		return
	}
	outputTruncated := wasTruncated(remediation.Stdout, remediation.Stderr, s.maxOutputBytes)
	remediation.Stdout = truncate(remediation.Stdout, s.maxOutputBytes)
	remediation.Stderr = truncate(remediation.Stderr, s.maxOutputBytes)
	s.recordToolCall(ctx, incident, "remediate", operation, remediation, duration, outputTruncated)
	if remediation.ExitCode != 0 {
		s.failExecution(ctx, incident, started, fmt.Errorf("%s failed with exit code %d: %s", operation, remediation.ExitCode, remediation.Stderr))
		return
	}
	verification := make([]model.OperationResult, 0, len(catalog.VerifyOperations))
	success := true
	for _, operation := range catalog.VerifyOperations {
		operationStarted := time.Now()
		operationCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
		result, err := s.tools.Execute(operationCtx, incident.RunID, operation, incident.PlanHash)
		cancel()
		duration := time.Since(operationStarted)
		if err != nil {
			result = model.OperationResult{OperationID: operation, Stderr: truncate(err.Error(), s.maxOutputBytes), ExitCode: -1}
		}
		outputTruncated := wasTruncated(result.Stdout, result.Stderr, s.maxOutputBytes)
		result.Stdout = truncate(result.Stdout, s.maxOutputBytes)
		result.Stderr = truncate(result.Stderr, s.maxOutputBytes)
		verification = append(verification, result)
		success = success && result.ExitCode == 0
		s.recordToolCall(ctx, incident, "verify", operation, result, duration, outputTruncated)
	}
	state := model.IncidentCompleted
	alertStatus := model.AlertResolved
	errorMessage := ""
	eventType := "RemediationExecuted"
	eventMessage := "Remediation completed."
	if !success {
		state = model.IncidentFailed
		alertStatus = model.AlertFailed
		errorMessage = "post-remediation verification failed"
		eventType = "RemediationFailed"
		eventMessage = "Remediation verification failed."
	}
	report := buildReport(incident, remediation, verification)
	structured := buildStructuredReport(incident, remediation, verification, state, started, s.now())
	_ = s.store.SetIncidentReport(ctx, incidentID, state, report, errorMessage, structured)
	_ = s.store.SetAlertStatusForIncident(ctx, incidentID, alertStatus, errorMessage)
	_, _ = s.store.CreateEvent(ctx, incidentID, eventType, "", "", eventMessage, map[string]any{"planHash": incident.PlanHash})
	s.events.Emit(ctx, events.Event{
		EventType:  eventType,
		RequestID:  observability.RequestID(ctx),
		HostID:     incident.HostID,
		IncidentID: incidentID,
		RunID:      incident.RunID,
		Action:     "remediate",
		Outcome:    strings.TrimPrefix(strings.ToLower(eventType), "remediation"),
		ReasonCode: errorMessage,
		PlanHash:   incident.PlanHash,
	})
	verifyEvent := "VerificationPassed"
	verifyMessage := "Post-remediation verification passed."
	if !success {
		verifyEvent = "VerificationFailed"
		verifyMessage = "Post-remediation verification failed."
	}
	_, _ = s.store.CreateEvent(ctx, incidentID, verifyEvent, "", "", verifyMessage, map[string]any{"operationCount": len(verification)})
	_ = s.sm.CloseAutomationRun(ctx, incident.RunID)
	_, _ = s.store.CreateEvent(ctx, incidentID, "AutomationRunClosed", "", "", "Automation run closed after remediation workflow.", map[string]any{"runId": incident.RunID})
	slog.InfoContext(ctx, eventType, "requestId", observability.RequestID(ctx), "incidentId", incidentID, "runId", incident.RunID, "hostId", incident.HostID, "planHash", incident.PlanHash)
}

func (s *Service) recordToolCall(ctx context.Context, incident model.Incident, phase, operation string, result model.OperationResult, duration time.Duration, outputTruncated bool) {
	selectedBy, reason := toolDecision(incident.Explanation.ToolDecisions, phase, operation)
	status := "SUCCEEDED"
	if result.ExitCode != 0 {
		status = "FAILED"
	}
	eventType := "OperationExecuted"
	message := "Bounded operation executed."
	if phase == "verify" {
		eventType = "VerificationOperationExecuted"
		message = "Post-remediation verification operation executed."
	} else if phase == "remediate" {
		message = "Approved remediation operation executed."
	}
	_, _ = s.store.CreateEvent(ctx, incident.ID, eventType, "", "", message, map[string]any{
		"operationId":     operation,
		"phase":           phase,
		"selectedBy":      selectedBy,
		"reason":          reason,
		"status":          status,
		"durationMs":      float64(duration.Microseconds()) / 1000,
		"exitCode":        result.ExitCode,
		"resultDigest":    operationResultDigest(result),
		"outputTruncated": outputTruncated,
		"planHash":        incident.PlanHash,
	})
}

func buildExplanationTrace(incident model.Incident, timeline []model.IncidentEvent) model.ExplanationTrace {
	trace := model.ExplanationTrace{
		SchemaVersion: "v1",
		AgentActions:  []model.ExplanationAgentAction{},
		ToolCalls:     []model.ExplanationToolCall{},
	}
	for _, event := range timeline {
		switch event.EventType {
		case "AgentDelegated":
			trace.AgentActions = append(trace.AgentActions, model.ExplanationAgentAction{
				EventID: event.ID, Stage: metadataString(event.Metadata, "stage"),
				FromAgent: metadataString(event.Metadata, "fromAgent"), ToAgent: metadataString(event.Metadata, "toAgent"),
				Protocol: metadataString(event.Metadata, "protocol"), ActorType: metadataString(event.Metadata, "actorType"),
				Status: metadataString(event.Metadata, "status"), Summary: event.Message,
				DurationMS: metadataFloat(event.Metadata, "durationMs"), FallbackUsed: metadataBool(event.Metadata, "fallbackUsed"),
				OccurredAt: event.CreatedAt,
			})
		case "OperationExecuted", "VerificationOperationExecuted":
			operation := metadataString(event.Metadata, "operationId")
			if operation == "" {
				operation = metadataString(event.Metadata, "operation")
			}
			if operation == "" {
				continue
			}
			phase := metadataString(event.Metadata, "phase")
			if phase == "" && event.EventType == "VerificationOperationExecuted" {
				phase = "verify"
			} else if phase == "" {
				phase = "remediate"
			}
			selectedBy, reason := toolDecision(incident.Explanation.ToolDecisions, phase, operation)
			if value := metadataString(event.Metadata, "selectedBy"); value != "" {
				selectedBy = value
			}
			if value := metadataString(event.Metadata, "reason"); value != "" {
				reason = value
			}
			status := metadataString(event.Metadata, "status")
			exitCode := metadataInt(event.Metadata, "exitCode")
			if status == "" {
				status = "SUCCEEDED"
				if exitCode != 0 {
					status = "FAILED"
				}
			}
			trace.ToolCalls = append(trace.ToolCalls, model.ExplanationToolCall{
				EventID: event.ID, OperationID: operation, Phase: phase, SelectedBy: selectedBy,
				Status: status, Reason: reason, DurationMS: metadataFloat(event.Metadata, "durationMs"),
				ExitCode: exitCode, ResultDigest: metadataString(event.Metadata, "resultDigest"),
				OutputTruncated: metadataBool(event.Metadata, "outputTruncated"), OccurredAt: event.CreatedAt,
			})
		}
	}
	for index, result := range incident.Evidence {
		if hasToolCall(trace.ToolCalls, "diagnose", result.OperationID) {
			continue
		}
		selectedBy, reason := toolDecision(incident.Explanation.ToolDecisions, "diagnose", result.OperationID)
		status := "SUCCEEDED"
		if result.ExitCode != 0 {
			status = "FAILED"
		}
		trace.ToolCalls = append(trace.ToolCalls, model.ExplanationToolCall{
			EventID: fmt.Sprintf("legacy-diagnose-%d", index+1), OperationID: result.OperationID,
			Phase: "diagnose", SelectedBy: selectedBy, Status: status, Reason: reason,
			ExitCode: result.ExitCode, ResultDigest: operationResultDigest(result), OccurredAt: incident.UpdatedAt,
		})
	}
	sort.SliceStable(trace.AgentActions, func(i, j int) bool { return trace.AgentActions[i].OccurredAt.Before(trace.AgentActions[j].OccurredAt) })
	sort.SliceStable(trace.ToolCalls, func(i, j int) bool { return trace.ToolCalls[i].OccurredAt.Before(trace.ToolCalls[j].OccurredAt) })
	return trace
}

func toolDecision(decisions []model.ExplanationToolDecision, phase, operation string) (string, string) {
	for _, decision := range decisions {
		if decision.Phase == phase && decision.OperationID == operation {
			return decision.ChosenBy, decision.Reason
		}
	}
	return "policy", "Bounded operation selected by deterministic policy."
}

func hasToolCall(calls []model.ExplanationToolCall, phase, operation string) bool {
	for _, call := range calls {
		if call.Phase == phase && call.OperationID == operation {
			return true
		}
	}
	return false
}

func operationResultDigest(result model.OperationResult) string {
	payload, _ := json.Marshal(map[string]any{
		"exitCode": result.ExitCode, "operationId": result.OperationID,
		"stderr": result.Stderr, "stdout": result.Stdout,
	})
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func metadataString(metadata map[string]any, key string) string {
	value, _ := metadata[key].(string)
	return value
}

func metadataFloat(metadata map[string]any, key string) float64 {
	switch value := metadata[key].(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	default:
		return 0
	}
}

func metadataInt(metadata map[string]any, key string) int {
	return int(metadataFloat(metadata, key))
}

func metadataBool(metadata map[string]any, key string) bool {
	value, _ := metadata[key].(bool)
	return value
}

func (s *Service) failExecution(ctx context.Context, incident model.Incident, started time.Time, cause error) {
	message := truncate(cause.Error(), 2048)
	report := model.PostIncidentReport{
		RootCauseSummary:    rootCauseSummary(incident),
		ActionTaken:         "Approved remediation could not be completed.",
		VerificationSummary: message,
		FinalState:          string(model.IncidentFailed),
		StartedAt:           &started,
	}
	resolved := s.now()
	report.ResolvedAt = &resolved
	duration := resolved.Sub(started).Seconds()
	report.DurationSeconds = &duration
	_ = s.store.SetIncidentReport(ctx, incident.ID, model.IncidentFailed, "Approved remediation could not be completed.", message, report)
	_ = s.store.SetAlertStatusForIncident(ctx, incident.ID, model.AlertFailed, message)
	_, _ = s.store.CreateEvent(ctx, incident.ID, "RemediationFailed", "", "", "Approved remediation failed.", map[string]any{"errorKind": "execution"})
	s.events.Emit(ctx, events.Event{
		EventType:  "RemediationFailed",
		RequestID:  observability.RequestID(ctx),
		HostID:     incident.HostID,
		IncidentID: incident.ID,
		RunID:      incident.RunID,
		Action:     "remediate",
		Outcome:    "failed",
		ReasonCode: "execution",
		PlanHash:   incident.PlanHash,
	})
	slog.WarnContext(ctx, "RemediationFailed", "requestId", observability.RequestID(ctx), "incidentId", incident.ID, "runId", incident.RunID, "error", cause)
}

func (s *Service) StartAutomationRun(ctx context.Context, req model.AutomationRunRequest) (model.AutomationRunResponse, error) {
	if req.Phase != "diagnose" {
		return model.AutomationRunResponse{}, fmt.Errorf("%w: new automation runs must start in diagnose phase", ErrBadRequest)
	}
	identity, err := s.sts.ValidateWorkload(ctx, req.WorkloadToken)
	if err != nil || identity.Namespace != "dendenmushi-agentic" || identity.ServiceAccount != "incident-agent" {
		return model.AutomationRunResponse{}, ErrForbidden
	}
	incident, err := s.store.GetIncident(ctx, req.IncidentID)
	if err != nil {
		return model.AutomationRunResponse{}, err
	}
	if incident.State != model.IncidentDiagnosing || incident.HostID != req.HostID {
		return model.AutomationRunResponse{}, fmt.Errorf("%w: incident is not eligible for diagnosis", ErrConflict)
	}
	if len(req.AllowedOperations) == 0 {
		return model.AutomationRunResponse{}, fmt.Errorf("%w: diagnostic operations are required", ErrBadRequest)
	}
	for _, operation := range req.AllowedOperations {
		if !catalog.IsDiagnostic(operation) {
			return model.AutomationRunResponse{}, fmt.Errorf("%w: operation is not diagnostic", ErrBadRequest)
		}
	}
	run, err := s.sm.CreateAutomationRun(ctx, req.IncidentID, req.HostID)
	if err != nil {
		return model.AutomationRunResponse{}, err
	}
	return model.AutomationRunResponse{AutomationRun: run}, nil
}

func (s *Service) IssueAutomationToken(ctx context.Context, runID string, req model.AutomationTokenRequest) (model.AutomationRunResponse, error) {
	run, err := s.sm.GetAutomationRun(ctx, runID)
	if err != nil {
		return model.AutomationRunResponse{}, err
	}
	if run.Status != "ACTIVE" {
		return model.AutomationRunResponse{}, errors.New("automation run is not active")
	}
	incident, err := s.store.GetIncident(ctx, run.IncidentID)
	if err != nil {
		return model.AutomationRunResponse{}, err
	}
	if run.HostID != incident.HostID || len(req.AllowedOperations) != 1 {
		return model.AutomationRunResponse{}, fmt.Errorf("%w: run or operation mismatch", ErrConflict)
	}
	operation := req.AllowedOperations[0]
	switch req.Phase {
	case "diagnose":
		if incident.State != model.IncidentDiagnosing || !catalog.IsDiagnostic(operation) || req.PlanHash != "" {
			return model.AutomationRunResponse{}, fmt.Errorf("%w: diagnostic token request is not allowed", ErrConflict)
		}
	case "remediate":
		if incident.State != model.IncidentExecuting || incident.RunID != runID || incident.PlanHash == "" ||
			req.PlanHash != incident.PlanHash || len(incident.Plan.Actions) != 1 ||
			incident.Plan.Actions[0].OperationID != operation || !catalog.IsRemediation(operation) {
			return model.AutomationRunResponse{}, fmt.Errorf("%w: remediation token request is not approved", ErrConflict)
		}
	case "verify":
		if incident.State != model.IncidentExecuting || incident.RunID != runID || incident.PlanHash == "" ||
			req.PlanHash != incident.PlanHash || !catalog.IsVerification(operation) {
			return model.AutomationRunResponse{}, fmt.Errorf("%w: verification token request is not allowed", ErrConflict)
		}
	default:
		return model.AutomationRunResponse{}, fmt.Errorf("%w: unsupported automation phase", ErrBadRequest)
	}
	token, err := s.issueAutomationToken(ctx, run, req.WorkloadToken, req.Phase, req.AllowedOperations, req.PlanHash)
	if err != nil {
		return model.AutomationRunResponse{}, err
	}
	return model.AutomationRunResponse{AutomationRun: run, CapabilityToken: token.CapabilityToken, TokenExpiresAt: token.ExpiresAt}, nil
}

func (s *Service) CloseAutomationRun(ctx context.Context, runID, capabilityToken string) error {
	identity, err := s.sts.ValidateWorkload(ctx, capabilityToken)
	if err != nil {
		return err
	}
	if identity.Namespace != "dendenmushi-agentic" || identity.ServiceAccount != "incident-agent" {
		return ErrForbidden
	}
	return s.sm.CloseAutomationRun(ctx, runID)
}

func (s *Service) issueAutomationToken(ctx context.Context, run model.AutomationRun, workloadToken, phase string, operations []string, planHash string) (model.AutomationTokenResponse, error) {
	if workloadToken == "" {
		return model.AutomationTokenResponse{}, errors.New("projected workload token is required")
	}
	return s.sts.RequestAutomationToken(ctx, workloadToken, clients.AutomationTokenRequest{
		RunID: run.RunID, IncidentID: run.IncidentID, HostID: run.HostID,
		Phase: phase, AllowedOperations: operations, PlanHash: planHash,
		OwnerPodID: run.OwnerPodID, OwnerInstanceID: run.OwnerInstanceID,
	})
}

func (s *Service) closeAfterReject(ctx context.Context, incident model.Incident) {
	_ = s.sm.CloseAutomationRun(ctx, incident.RunID)
}

func canDecide(groups []string) bool {
	for _, group := range groups {
		group = strings.TrimSpace(group)
		if strings.EqualFold(group, "Manager") || strings.EqualFold(group, "Admin") {
			return true
		}
	}
	return false
}

func planExpired(incident model.Incident, now time.Time) bool {
	return incident.PlanExpiresAt != nil && !incident.PlanExpiresAt.After(now)
}

func validateExecution(incident model.Incident, approvedPlanHash string) (string, error) {
	if incident.State != model.IncidentExecuting {
		return "", errors.New("incident is not approved for execution")
	}
	if incident.PlanHash == "" || incident.PlanHash != approvedPlanHash {
		return "", errors.New("approved plan hash mismatch")
	}
	if incident.RunID == "" || incident.OperationsURL == "" {
		return "", errors.New("incident has no automation run")
	}
	if len(incident.Plan.Actions) != 1 || !catalog.IsRemediation(incident.Plan.Actions[0].OperationID) {
		return "", errors.New("approved plan is outside the remediation catalog")
	}
	return incident.Plan.Actions[0].OperationID, nil
}

func buildReport(incident model.Incident, remediation model.OperationResult, verification []model.OperationResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Incident %s on host %s\n\n", incident.ID, incident.HostID)
	fmt.Fprintf(&b, "Approved plan: %s\n", incident.Plan.Summary)
	fmt.Fprintf(&b, "Remediation: %s exit=%d\n", remediation.OperationID, remediation.ExitCode)
	for _, result := range verification {
		fmt.Fprintf(&b, "Verification: %s exit=%d\n", result.OperationID, result.ExitCode)
	}
	return b.String()
}

func buildStructuredReport(incident model.Incident, remediation model.OperationResult, verification []model.OperationResult, state model.IncidentState, started, resolved time.Time) model.PostIncidentReport {
	verificationSummary := make([]string, 0, len(verification))
	for _, result := range verification {
		verificationSummary = append(verificationSummary, fmt.Sprintf("%s exit=%d", result.OperationID, result.ExitCode))
	}
	duration := resolved.Sub(started).Seconds()
	return model.PostIncidentReport{
		RootCauseSummary:    rootCauseSummary(incident),
		ActionTaken:         fmt.Sprintf("%s exit=%d", remediation.OperationID, remediation.ExitCode),
		VerificationSummary: strings.Join(verificationSummary, ", "),
		FinalState:          string(state),
		StartedAt:           &started,
		ResolvedAt:          &resolved,
		DurationSeconds:     &duration,
	}
}

func rootCauseSummary(incident model.Incident) string {
	if incident.Triage != nil && incident.Triage.Summary != "" {
		return incident.Triage.Summary
	}
	return incident.Reason
}

func truncate(value string, maxBytes int) string {
	if maxBytes <= 0 || len(value) <= maxBytes {
		return value
	}
	return value[:maxBytes]
}

func wasTruncated(stdout, stderr string, maxBytes int) bool {
	return maxBytes > 0 && (len(stdout) > maxBytes || len(stderr) > maxBytes)
}
