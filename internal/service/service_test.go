package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/clients"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/model"
)

func TestExecuteUsesApprovedCatalogOperation(t *testing.T) {
	incident := model.Incident{
		ID: "inc-1", HostID: "host-1", State: model.IncidentExecuting,
		RunID: "run-1", OperationsURL: "http://dataplane", PlanHash: "hash",
		Plan: model.Plan{
			Summary: "Recover demo app",
			Actions: []model.Action{{OperationID: "recover_demo_app", Reason: "health_check failed"}},
		},
	}
	store := &executeStore{incident: incident}
	sts := &executeSTS{}
	dataplane := &executeDataplane{}
	workloadToken := t.TempDir() + "/token"
	if err := os.WriteFile(workloadToken, []byte("workload"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := New(
		store,
		executeSM{},
		sts,
		dataplane,
		nil,
		workloadToken,
		time.Second,
		4096,
	)

	svc.Execute(t.Context(), incident.ID, incident.PlanHash)

	if len(sts.requests) == 0 {
		t.Fatal("no STS token requests recorded")
	}
	remediate := sts.requests[0]
	if remediate.Phase != "remediate" || len(remediate.AllowedOperations) != 1 || remediate.AllowedOperations[0] != "recover_demo_app" {
		t.Fatalf("remediation token request = %#v", remediate)
	}
	if len(dataplane.operations) == 0 || dataplane.operations[0] != "recover_demo_app" {
		t.Fatalf("dataplane operations = %#v", dataplane.operations)
	}
	if store.report.ActionTaken != "recover_demo_app exit=0" {
		t.Fatalf("action taken = %q", store.report.ActionTaken)
	}
	if !store.hasEvent("AutomationTokenIssued") || !store.hasEvent("OperationExecuted") ||
		!store.hasEvent("VerificationOperationExecuted") || !store.hasEvent("AutomationRunClosed") {
		t.Fatalf("events = %#v", store.events)
	}
}

func TestValidateExecutionRejectsNonRemediationOperation(t *testing.T) {
	incident := model.Incident{
		State: model.IncidentExecuting, RunID: "run-1", OperationsURL: "http://dataplane", PlanHash: "hash",
		Plan: model.Plan{Actions: []model.Action{{OperationID: "health_check", Reason: "bad plan"}}},
	}
	if _, err := validateExecution(incident, "hash"); err == nil {
		t.Fatal("diagnostic operation was accepted as remediation")
	}
}

func TestIncidentExplanationJSONShape(t *testing.T) {
	temperature := 0.0
	incident := model.Incident{
		Explanation: model.IncidentExplanation{
			Model: model.ExplanationModel{
				Provider:        "bedrock",
				PlannerType:     "bedrock",
				ModelID:         "global.amazon.nova-2-lite-v1:0",
				AWSRegion:       "ap-southeast-1",
				Temperature:     &temperature,
				MaxPromptBytes:  1024,
				PromptTemplates: map[string]string{"plan_system.md.j2": "hash"},
			},
			Workflow: model.ExplanationWorkflow{
				CatalogVersion:         "v1",
				DiagnosticOperations:   []string{"target_probe"},
				VerificationOperations: []string{"health_check"},
				RunID:                  "run-1",
				PlanHash:               "hash",
			},
			Agents: []model.ExplanationAgent{{
				Name:             "Action Plan Reviewer Agent",
				Purpose:          "Validate the proposed plan before it can be stored or approved.",
				Responsibilities: []string{"Reject unsupported operation IDs."},
				ReasoningType:    "deterministic safety rules",
				Memory:           "none beyond the candidate plan",
				Tools:            []string{"operation catalog"},
				Inputs:           []string{"candidate Plan"},
				Outputs:          []string{"validated Plan"},
				HandoffTo:        "Manager/Admin approval",
			}},
			ToolDecisions: []model.ExplanationToolDecision{{
				OperationID: "target_probe", Phase: "diagnose", ChosenBy: "policy", Reason: "default diagnostic",
			}},
			Guardrails: []model.ExplanationGuardrail{{Name: "catalog_validation", Passed: true}},
			Responsibility: model.ExplanationResponsibility{
				ModelAdvisory: true, HumanApprovalRequired: true, ExecutionOwner: "agent-controlplane",
				TokenIssuer: "sts", TerminalTraffic: "not handled",
			},
		},
	}
	body, err := json.Marshal(incident)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	explanation, ok := decoded["explanation"].(map[string]any)
	if !ok {
		t.Fatalf("missing explanation in %s", string(body))
	}
	if _, ok := explanation["toolDecisions"]; !ok {
		t.Fatalf("missing toolDecisions in %s", string(body))
	}
	agents, ok := explanation["agents"].([]any)
	if !ok || len(agents) != 1 {
		t.Fatalf("missing agents in %s", string(body))
	}
	if string(body) == "" || json.Valid(body) == false {
		t.Fatalf("invalid json %s", string(body))
	}
}

func TestOpenAPIIncludesExplanationAgents(t *testing.T) {
	body, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "agents:") || !strings.Contains(string(body), "reasoningType:") {
		t.Fatalf("openapi.yaml does not document explanation agents")
	}
}

func TestListQueriesApplyFiltersAndCursors(t *testing.T) {
	store := &executeStore{
		alerts: []model.ManagedAlert{
			{ID: "alert-1"},
			{ID: "alert-2"},
		},
		incidents: []model.Incident{
			{ID: "inc-1"},
			{ID: "inc-2"},
		},
		incidentEvents: []model.IncidentEvent{
			{ID: "evt-1"},
			{ID: "evt-2"},
		},
	}
	svc := New(store, nil, nil, nil, nil, "", time.Second, 4096)
	from := time.Date(2026, 7, 6, 1, 0, 0, 0, time.UTC)

	alerts, err := svc.ListAlerts(t.Context(), model.AlertFilter{
		IncidentID: "inc-1", HostID: "host-1", Status: "PENDING_APPROVAL",
		CloudWatchState: "ALARM", From: from, Limit: 2,
	})
	if err != nil {
		t.Fatalf("ListAlerts() error = %v", err)
	}
	if alerts.NextCursor != "2" || store.alertFilter.IncidentID != "inc-1" || !store.alertFilter.From.Equal(from) {
		t.Fatalf("alerts=%#v filter=%#v", alerts, store.alertFilter)
	}

	incidents, err := svc.ListIncidents(t.Context(), model.IncidentFilter{
		IncidentID: "inc-1", AlertID: "alert-1", HostID: "host-1", State: "FAILED", Limit: 2, Offset: 4,
	})
	if err != nil {
		t.Fatalf("ListIncidents() error = %v", err)
	}
	if incidents.NextCursor != "6" || store.incidentFilter.AlertID != "alert-1" || len(incidents.Incidents) != 2 {
		t.Fatalf("incidents=%#v filter=%#v", incidents, store.incidentFilter)
	}

	events, err := svc.ListIncidentEvents(t.Context(), model.IncidentEventFilter{
		IncidentID: "inc-1", AlertID: "alert-1", EventType: "PlanApproved", Actor: "user-1", Limit: 2,
	})
	if err != nil {
		t.Fatalf("ListIncidentEvents() error = %v", err)
	}
	if events.NextCursor != "2" || store.eventFilter.EventType != "PlanApproved" || len(events.Events) != 2 {
		t.Fatalf("events=%#v filter=%#v", events, store.eventFilter)
	}
}

func TestListResponsesUseEmptyArrays(t *testing.T) {
	store := &executeStore{}
	svc := New(store, nil, nil, nil, nil, "", time.Second, 4096)

	alerts, err := svc.ListAlerts(t.Context(), model.AlertFilter{})
	if err != nil {
		t.Fatalf("ListAlerts() error = %v", err)
	}
	if alerts.Alerts == nil || len(alerts.Alerts) != 0 {
		t.Fatalf("alerts should be an empty array, got %#v", alerts.Alerts)
	}

	incidents, err := svc.ListIncidents(t.Context(), model.IncidentFilter{})
	if err != nil {
		t.Fatalf("ListIncidents() error = %v", err)
	}
	if incidents.Incidents == nil || len(incidents.Incidents) != 0 {
		t.Fatalf("incidents should be an empty array, got %#v", incidents.Incidents)
	}

	events, err := svc.ListIncidentEvents(t.Context(), model.IncidentEventFilter{})
	if err != nil {
		t.Fatalf("ListIncidentEvents() error = %v", err)
	}
	if events.Events == nil || len(events.Events) != 0 {
		t.Fatalf("events should be an empty array, got %#v", events.Events)
	}
}

func TestApproveRequiresManagerGroupAndRecordsDeniedDecision(t *testing.T) {
	store := &executeStore{incident: model.Incident{ID: "inc-1", State: model.IncidentAwaitingApproval, PlanHash: "hash"}}
	svc := New(store, nil, nil, nil, nil, "", time.Second, 4096)

	_, err := svc.Approve(t.Context(), "inc-1", "hash", "user-1", []string{"Operator"})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("Approve() error = %v, want ErrForbidden", err)
	}
	if len(store.approvals) != 1 || store.approvals[0].outcome != model.ApprovalDenied {
		t.Fatalf("approvals = %#v", store.approvals)
	}
}

func TestApproveRejectsExpiredPlanBeforeMutation(t *testing.T) {
	expired := time.Date(2026, 7, 6, 1, 0, 0, 0, time.UTC)
	store := &executeStore{incident: model.Incident{
		ID: "inc-1", State: model.IncidentAwaitingApproval, PlanHash: "hash", PlanExpiresAt: &expired,
	}}
	svc := New(store, nil, nil, nil, nil, "", time.Second, 4096)
	svc.now = func() time.Time { return expired.Add(time.Second) }

	_, err := svc.Approve(t.Context(), "inc-1", "hash", "manager-1", []string{"Manager"})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Approve() error = %v, want ErrConflict", err)
	}
	if store.approveCalled {
		t.Fatal("store.Approve was called for an expired plan")
	}
	if len(store.approvals) != 1 || store.approvals[0].outcome != model.ApprovalConflict || !store.hasEvent("PlanExpired") {
		t.Fatalf("approvals=%#v events=%#v", store.approvals, store.events)
	}
}

func TestRejectRecordsDecisionAndHydratesDetail(t *testing.T) {
	store := &executeStore{incident: model.Incident{
		ID: "inc-1", HostID: "host-1", State: model.IncidentAwaitingApproval, PlanHash: "hash",
	}}
	svc := New(store, nil, nil, nil, nil, "", time.Second, 4096)

	detail, err := svc.Reject(t.Context(), "inc-1", "hash", "manager-1", []string{"Admin"})
	if err != nil {
		t.Fatalf("Reject() error = %v", err)
	}
	if !store.rejectCalled || store.alertStatus != model.AlertRejected || detail.State != model.IncidentRejected {
		t.Fatalf("rejectCalled=%v alertStatus=%q detail=%#v", store.rejectCalled, store.alertStatus, detail)
	}
	if len(store.approvals) != 1 || store.approvals[0].outcome != model.ApprovalSucceeded || !store.hasEvent("PlanRejected") {
		t.Fatalf("approvals=%#v events=%#v", store.approvals, store.events)
	}
}

func TestHealthMergesStoreAndWorkerState(t *testing.T) {
	last := time.Date(2026, 7, 6, 2, 0, 0, 0, time.UTC)
	workerLast := last.Add(time.Minute)
	store := &executeStore{activeIncidents: 2, failedIncidents: 1, lastAlert: &last}
	svc := New(store, nil, nil, nil, fakeWorker{health: model.AgentHealth{
		QueueConsumerConfigured: true,
		QueueConsumerRunning:    true,
		LastAlertProcessedAt:    &workerLast,
	}}, "", time.Second, 4096)

	health := svc.Health(t.Context())
	if !health.DatabaseReady || health.ActiveIncidentCount != 2 || health.FailedIncidentCount != 1 ||
		!health.QueueConsumerRunning || !health.LastAlertProcessedAt.Equal(workerLast) {
		t.Fatalf("Health() = %#v", health)
	}

	store.pingErr = errors.New("database down")
	health = svc.Health(t.Context())
	if health.DatabaseReady {
		t.Fatalf("Health() databaseReady = true for ping failure")
	}
	if err := svc.Ready(t.Context()); !errors.Is(err, store.pingErr) {
		t.Fatalf("Ready() error = %v, want %v", err, store.pingErr)
	}
}

func TestAutomationRunLifecycleErrors(t *testing.T) {
	sts := &executeSTS{}
	sm := &automationSM{}
	svc := New(&executeStore{}, sm, sts, nil, nil, "", time.Second, 4096)

	_, err := svc.StartAutomationRun(t.Context(), model.AutomationRunRequest{
		IncidentID: "inc-1", HostID: "host-1", Phase: "verify",
		AllowedOperations: []string{"health_check"}, WorkloadToken: "workload",
	})
	if !errors.Is(err, ErrBadRequest) {
		t.Fatalf("StartAutomationRun() error = %v, want ErrBadRequest", err)
	}

	sts.err = errors.New("sts unavailable")
	_, err = svc.StartAutomationRun(t.Context(), model.AutomationRunRequest{
		IncidentID: "inc-1", HostID: "host-1", Phase: "diagnose",
		AllowedOperations: []string{"health_check"}, WorkloadToken: "workload",
	})
	if !errors.Is(err, sts.err) || sm.closedRunID != "run-1" {
		t.Fatalf("err=%v closedRunID=%q", err, sm.closedRunID)
	}

	sts.err = nil
	sm.run.Status = "CLOSED"
	_, err = svc.IssueAutomationToken(t.Context(), "run-1", model.AutomationTokenRequest{
		Phase: "verify", AllowedOperations: []string{"health_check"}, WorkloadToken: "workload",
	})
	if err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("IssueAutomationToken() error = %v, want inactive run", err)
	}
}

type executeStore struct {
	incident        model.Incident
	alerts          []model.ManagedAlert
	incidents       []model.Incident
	incidentEvents  []model.IncidentEvent
	alertFilter     model.AlertFilter
	incidentFilter  model.IncidentFilter
	eventFilter     model.IncidentEventFilter
	report          model.PostIncidentReport
	events          []string
	pingErr         error
	activeIncidents int
	failedIncidents int
	lastAlert       *time.Time
	approvals       []approvalCall
	approveCalled   bool
	rejectCalled    bool
	alertStatus     model.AlertStatus
}

type approvalCall struct {
	decision string
	planHash string
	actor    string
	outcome  model.ApprovalOutcome
	reason   string
}

func (s *executeStore) Ping(context.Context) error { return s.pingErr }
func (s *executeStore) ListAlerts(_ context.Context, filter model.AlertFilter) ([]model.ManagedAlert, error) {
	s.alertFilter = filter
	return s.alerts, nil
}
func (s *executeStore) GetAlert(context.Context, string) (model.ManagedAlert, error) {
	return model.ManagedAlert{}, nil
}
func (s *executeStore) ListIncidents(_ context.Context, filter model.IncidentFilter) ([]model.Incident, error) {
	s.incidentFilter = filter
	return s.incidents, nil
}
func (s *executeStore) GetIncident(context.Context, string) (model.Incident, error) {
	return s.incident, nil
}
func (s *executeStore) ListEvents(context.Context, string) ([]model.IncidentEvent, error) {
	return nil, nil
}
func (s *executeStore) ListIncidentEvents(_ context.Context, filter model.IncidentEventFilter) ([]model.IncidentEvent, error) {
	s.eventFilter = filter
	return s.incidentEvents, nil
}
func (s *executeStore) ListApprovalDecisions(context.Context, string) ([]model.ApprovalDecisionAudit, error) {
	return nil, nil
}
func (s *executeStore) IncidentCounts(context.Context) (int, int, error) {
	return s.activeIncidents, s.failedIncidents, nil
}
func (s *executeStore) LastAlertProcessedAt(context.Context) (*time.Time, error) {
	return s.lastAlert, nil
}
func (s *executeStore) CreateEvent(_ context.Context, _, eventType, _, _, _ string, _ map[string]any) (model.IncidentEvent, error) {
	s.events = append(s.events, eventType)
	return model.IncidentEvent{}, nil
}
func (s *executeStore) CreateApprovalDecision(_ context.Context, _ string, decision, planHash, actor string, outcome model.ApprovalOutcome, reason string) error {
	s.approvals = append(s.approvals, approvalCall{
		decision: decision, planHash: planHash, actor: actor, outcome: outcome, reason: reason,
	})
	return nil
}
func (s *executeStore) Approve(context.Context, string, string, string) error {
	s.approveCalled = true
	s.incident.State = model.IncidentExecuting
	return nil
}
func (s *executeStore) Reject(context.Context, model.Incident, string, string) error {
	s.rejectCalled = true
	s.incident.State = model.IncidentRejected
	return nil
}
func (s *executeStore) SetAlertStatusForIncident(_ context.Context, _ string, status model.AlertStatus, _ string) error {
	s.alertStatus = status
	return nil
}
func (s *executeStore) SetIncidentReport(_ context.Context, _ string, _ model.IncidentState, _ string, _ string, report model.PostIncidentReport) error {
	s.report = report
	return nil
}
func (s *executeStore) SetFailure(context.Context, string, string) error { return nil }

func (s *executeStore) hasEvent(eventType string) bool {
	for _, event := range s.events {
		if event == eventType {
			return true
		}
	}
	return false
}

type executeSM struct{}

func (executeSM) CreateAutomationRun(context.Context, string, string) (model.AutomationRun, error) {
	return model.AutomationRun{}, nil
}
func (executeSM) GetAutomationRun(context.Context, string) (model.AutomationRun, error) {
	return model.AutomationRun{
		RunID: "run-1", IncidentID: "inc-1", HostID: "host-1",
		OwnerPodID: "pod-1", OwnerInstanceID: "instance-1",
		OperationsURL: "http://dataplane", Status: "ACTIVE",
	}, nil
}
func (executeSM) CloseAutomationRun(context.Context, string) error { return nil }

type executeSTS struct {
	requests []clients.AutomationTokenRequest
	err      error
}

func (s *executeSTS) RequestAutomationToken(_ context.Context, _ string, req clients.AutomationTokenRequest) (model.AutomationTokenResponse, error) {
	if s.err != nil {
		return model.AutomationTokenResponse{}, s.err
	}
	s.requests = append(s.requests, req)
	return model.AutomationTokenResponse{CapabilityToken: req.Phase + "-token", ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (s *executeSTS) ValidateAutomationToken(context.Context, string, string) error { return nil }

type executeDataplane struct {
	operations []string
}

func (d *executeDataplane) Execute(_ context.Context, _ string, _ string, _ string, operationID, _ string) (model.OperationResult, error) {
	d.operations = append(d.operations, operationID)
	return model.OperationResult{OperationID: operationID, Stdout: "ok", ExitCode: 0}, nil
}

type fakeWorker struct {
	health model.AgentHealth
	err    error
}

func (w fakeWorker) Health(context.Context) (model.AgentHealth, error) {
	return w.health, w.err
}

type automationSM struct {
	run         model.AutomationRun
	closedRunID string
}

func (s *automationSM) CreateAutomationRun(context.Context, string, string) (model.AutomationRun, error) {
	if s.run.RunID == "" {
		s.run = model.AutomationRun{
			RunID: "run-1", IncidentID: "inc-1", HostID: "host-1",
			OwnerPodID: "pod-1", OwnerInstanceID: "instance-1", Status: "ACTIVE",
		}
	}
	return s.run, nil
}

func (s *automationSM) GetAutomationRun(context.Context, string) (model.AutomationRun, error) {
	return s.run, nil
}

func (s *automationSM) CloseAutomationRun(_ context.Context, runID string) error {
	s.closedRunID = runID
	return nil
}
