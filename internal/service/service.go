package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/clients"
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

var (
	remediationOperations = []string{"restart_service"}
	verifyOperations      = []string{"service_status", "health_check"}
)

type Store interface {
	Ping(context.Context) error
	ListAlerts(context.Context, int) ([]model.ManagedAlert, error)
	GetAlert(context.Context, string) (model.ManagedAlert, error)
	ListIncidents(context.Context, int) ([]model.Incident, error)
	GetIncident(context.Context, string) (model.Incident, error)
	ListEvents(context.Context, string) ([]model.IncidentEvent, error)
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
	ValidateAutomationToken(context.Context, string, string) error
}

type Dataplane interface {
	Execute(context.Context, string, string, string, string, string) (model.OperationResult, error)
}

type Worker interface {
	Health(context.Context) (model.AgentHealth, error)
}

type Service struct {
	store             Store
	sm                SessionManager
	sts               STS
	dataplane         Dataplane
	worker            Worker
	workloadTokenFile string
	operationTimeout  time.Duration
	maxOutputBytes    int
	now               func() time.Time
}

func New(store Store, sm SessionManager, sts STS, dataplane Dataplane, worker Worker, workloadTokenFile string, operationTimeout time.Duration, maxOutputBytes int) *Service {
	return &Service{
		store: store, sm: sm, sts: sts, dataplane: dataplane, worker: worker,
		workloadTokenFile: workloadTokenFile, operationTimeout: operationTimeout,
		maxOutputBytes: maxOutputBytes,
		now:            func() time.Time { return time.Now().UTC() },
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

func (s *Service) ListAlerts(ctx context.Context) ([]model.ManagedAlert, error) {
	return s.store.ListAlerts(ctx, 100)
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

func (s *Service) ListIncidents(ctx context.Context) ([]model.Incident, error) {
	return s.store.ListIncidents(ctx, 100)
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
	return model.IncidentDetail{Incident: incident, Timeline: timeline, ApprovalDecisions: decisions}, nil
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
	if incident.RunID != "" {
		go s.closeAfterReject(observability.ContextWithRequestID(context.Background(), observability.RequestID(ctx)), incident)
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
	if err := validateExecution(incident, approvedPlanHash); err != nil {
		s.failExecution(ctx, incident, started, err)
		return
	}
	_, _ = s.store.CreateEvent(ctx, incidentID, "RemediationStarted", "", "", "Approved remediation execution started.", map[string]any{"planHash": approvedPlanHash})
	token, err := s.issueRunToken(ctx, incident.RunID, "remediate", remediationOperations, incident.PlanHash)
	if err != nil {
		s.failExecution(ctx, incident, started, err)
		return
	}
	operationCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	restart, err := s.dataplane.Execute(operationCtx, incident.OperationsURL, incident.RunID, token.CapabilityToken, "restart_service", incident.PlanHash)
	cancel()
	if err != nil {
		s.failExecution(ctx, incident, started, err)
		return
	}
	restart.Stdout = truncate(restart.Stdout, s.maxOutputBytes)
	restart.Stderr = truncate(restart.Stderr, s.maxOutputBytes)
	if restart.ExitCode != 0 {
		s.failExecution(ctx, incident, started, fmt.Errorf("restart_service failed with exit code %d: %s", restart.ExitCode, restart.Stderr))
		return
	}
	verifyToken, err := s.issueRunToken(ctx, incident.RunID, "verify", verifyOperations, "")
	if err != nil {
		s.failExecution(ctx, incident, started, err)
		return
	}
	verification := make([]model.OperationResult, 0, len(verifyOperations))
	success := true
	for _, operation := range verifyOperations {
		operationCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
		result, err := s.dataplane.Execute(operationCtx, incident.OperationsURL, incident.RunID, verifyToken.CapabilityToken, operation, "")
		cancel()
		if err != nil {
			result = model.OperationResult{OperationID: operation, Stderr: truncate(err.Error(), s.maxOutputBytes), ExitCode: -1}
		}
		result.Stdout = truncate(result.Stdout, s.maxOutputBytes)
		result.Stderr = truncate(result.Stderr, s.maxOutputBytes)
		verification = append(verification, result)
		success = success && result.ExitCode == 0
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
	report := buildReport(incident, restart, verification)
	structured := buildStructuredReport(incident, restart, verification, state, started, s.now())
	_ = s.store.SetIncidentReport(ctx, incidentID, state, report, errorMessage, structured)
	_ = s.store.SetAlertStatusForIncident(ctx, incidentID, alertStatus, errorMessage)
	_, _ = s.store.CreateEvent(ctx, incidentID, eventType, "", "", eventMessage, map[string]any{"planHash": incident.PlanHash})
	verifyEvent := "VerificationPassed"
	verifyMessage := "Post-remediation verification passed."
	if !success {
		verifyEvent = "VerificationFailed"
		verifyMessage = "Post-remediation verification failed."
	}
	_, _ = s.store.CreateEvent(ctx, incidentID, verifyEvent, "", "", verifyMessage, map[string]any{"operationCount": len(verification)})
	_ = s.CloseAutomationRun(ctx, incident.RunID, verifyToken.CapabilityToken)
	slog.InfoContext(ctx, eventType, "requestId", observability.RequestID(ctx), "incidentId", incidentID, "runId", incident.RunID, "hostId", incident.HostID, "planHash", incident.PlanHash)
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
	slog.WarnContext(ctx, "RemediationFailed", "requestId", observability.RequestID(ctx), "incidentId", incident.ID, "runId", incident.RunID, "error", cause)
}

func (s *Service) StartAutomationRun(ctx context.Context, req model.AutomationRunRequest) (model.AutomationRunResponse, error) {
	if req.Phase != "diagnose" {
		return model.AutomationRunResponse{}, fmt.Errorf("%w: new automation runs must start in diagnose phase", ErrBadRequest)
	}
	run, err := s.sm.CreateAutomationRun(ctx, req.IncidentID, req.HostID)
	if err != nil {
		return model.AutomationRunResponse{}, err
	}
	token, err := s.issueAutomationToken(ctx, run, req.WorkloadToken, req.Phase, req.AllowedOperations, req.PlanHash)
	if err != nil {
		_ = s.sm.CloseAutomationRun(ctx, run.RunID)
		return model.AutomationRunResponse{}, err
	}
	return model.AutomationRunResponse{AutomationRun: run, CapabilityToken: token.CapabilityToken, TokenExpiresAt: token.ExpiresAt}, nil
}

func (s *Service) IssueAutomationToken(ctx context.Context, runID string, req model.AutomationTokenRequest) (model.AutomationRunResponse, error) {
	run, err := s.sm.GetAutomationRun(ctx, runID)
	if err != nil {
		return model.AutomationRunResponse{}, err
	}
	if run.Status != "ACTIVE" {
		return model.AutomationRunResponse{}, errors.New("automation run is not active")
	}
	token, err := s.issueAutomationToken(ctx, run, req.WorkloadToken, req.Phase, req.AllowedOperations, req.PlanHash)
	if err != nil {
		return model.AutomationRunResponse{}, err
	}
	return model.AutomationRunResponse{AutomationRun: run, CapabilityToken: token.CapabilityToken, TokenExpiresAt: token.ExpiresAt}, nil
}

func (s *Service) CloseAutomationRun(ctx context.Context, runID, capabilityToken string) error {
	if err := s.sts.ValidateAutomationToken(ctx, runID, capabilityToken); err != nil {
		return err
	}
	return s.sm.CloseAutomationRun(ctx, runID)
}

func (s *Service) issueRunToken(ctx context.Context, runID, phase string, operations []string, planHash string) (model.AutomationTokenResponse, error) {
	run, err := s.sm.GetAutomationRun(ctx, runID)
	if err != nil {
		return model.AutomationTokenResponse{}, err
	}
	workloadToken, err := s.workloadToken()
	if err != nil {
		return model.AutomationTokenResponse{}, err
	}
	return s.issueAutomationToken(ctx, run, workloadToken, phase, operations, planHash)
}

func (s *Service) issueAutomationToken(ctx context.Context, run model.AutomationRun, workloadToken, phase string, operations []string, planHash string) (model.AutomationTokenResponse, error) {
	if workloadToken == "" {
		var err error
		workloadToken, err = s.workloadToken()
		if err != nil {
			return model.AutomationTokenResponse{}, err
		}
	}
	return s.sts.RequestAutomationToken(ctx, workloadToken, clients.AutomationTokenRequest{
		RunID: run.RunID, IncidentID: run.IncidentID, HostID: run.HostID,
		Phase: phase, AllowedOperations: operations, PlanHash: planHash,
		OwnerPodID: run.OwnerPodID, OwnerInstanceID: run.OwnerInstanceID,
	})
}

func (s *Service) workloadToken() (string, error) {
	body, err := os.ReadFile(s.workloadTokenFile) // #nosec G304 -- path is deployment config for projected service-account token.
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(body))
	if token == "" {
		return "", errors.New("projected workload token is empty")
	}
	return token, nil
}

func (s *Service) closeAfterReject(ctx context.Context, incident model.Incident) {
	token, err := s.issueRunToken(ctx, incident.RunID, "verify", []string{"health_check"}, "")
	if err != nil {
		return
	}
	_ = s.CloseAutomationRun(ctx, incident.RunID, token.CapabilityToken)
}

func canDecide(groups []string) bool {
	for _, group := range groups {
		if group == "Manager" || group == "Admin" {
			return true
		}
	}
	return false
}

func planExpired(incident model.Incident, now time.Time) bool {
	return incident.PlanExpiresAt != nil && !incident.PlanExpiresAt.After(now)
}

func validateExecution(incident model.Incident, approvedPlanHash string) error {
	if incident.State != model.IncidentExecuting {
		return errors.New("incident is not approved for execution")
	}
	if incident.PlanHash == "" || incident.PlanHash != approvedPlanHash {
		return errors.New("approved plan hash mismatch")
	}
	if incident.RunID == "" || incident.OperationsURL == "" {
		return errors.New("incident has no automation run")
	}
	if len(incident.Plan.Actions) != 1 || incident.Plan.Actions[0].OperationID != "restart_service" {
		return errors.New("approved plan is outside the remediation allowlist")
	}
	return nil
}

func buildReport(incident model.Incident, restart model.OperationResult, verification []model.OperationResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Incident %s on host %s\n\n", incident.ID, incident.HostID)
	fmt.Fprintf(&b, "Approved plan: %s\n", incident.Plan.Summary)
	fmt.Fprintf(&b, "Remediation: restart_service exit=%d\n", restart.ExitCode)
	for _, result := range verification {
		fmt.Fprintf(&b, "Verification: %s exit=%d\n", result.OperationID, result.ExitCode)
	}
	return b.String()
}

func buildStructuredReport(incident model.Incident, restart model.OperationResult, verification []model.OperationResult, state model.IncidentState, started, resolved time.Time) model.PostIncidentReport {
	verificationSummary := make([]string, 0, len(verification))
	for _, result := range verification {
		verificationSummary = append(verificationSummary, fmt.Sprintf("%s exit=%d", result.OperationID, result.ExitCode))
	}
	duration := resolved.Sub(started).Seconds()
	return model.PostIncidentReport{
		RootCauseSummary:    rootCauseSummary(incident),
		ActionTaken:         fmt.Sprintf("restart_service exit=%d", restart.ExitCode),
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
