package service

import (
	"context"
	"encoding/json"
	"os"
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
	if string(body) == "" || json.Valid(body) == false {
		t.Fatalf("invalid json %s", string(body))
	}
}

type executeStore struct {
	incident model.Incident
	report   model.PostIncidentReport
	events   []string
}

func (s *executeStore) Ping(context.Context) error { return nil }
func (s *executeStore) ListAlerts(context.Context, int) ([]model.ManagedAlert, error) {
	return nil, nil
}
func (s *executeStore) GetAlert(context.Context, string) (model.ManagedAlert, error) {
	return model.ManagedAlert{}, nil
}
func (s *executeStore) ListIncidents(context.Context, int) ([]model.Incident, error) {
	return nil, nil
}
func (s *executeStore) GetIncident(context.Context, string) (model.Incident, error) {
	return s.incident, nil
}
func (s *executeStore) ListEvents(context.Context, string) ([]model.IncidentEvent, error) {
	return nil, nil
}
func (s *executeStore) ListApprovalDecisions(context.Context, string) ([]model.ApprovalDecisionAudit, error) {
	return nil, nil
}
func (s *executeStore) IncidentCounts(context.Context) (int, int, error) { return 0, 0, nil }
func (s *executeStore) LastAlertProcessedAt(context.Context) (*time.Time, error) {
	return nil, nil
}
func (s *executeStore) CreateEvent(_ context.Context, _, eventType, _, _, _ string, _ map[string]any) (model.IncidentEvent, error) {
	s.events = append(s.events, eventType)
	return model.IncidentEvent{}, nil
}
func (s *executeStore) CreateApprovalDecision(context.Context, string, string, string, string, model.ApprovalOutcome, string) error {
	return nil
}
func (s *executeStore) Approve(context.Context, string, string, string) error { return nil }
func (s *executeStore) Reject(context.Context, model.Incident, string, string) error {
	return nil
}
func (s *executeStore) SetAlertStatusForIncident(context.Context, string, model.AlertStatus, string) error {
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
}

func (s *executeSTS) RequestAutomationToken(_ context.Context, _ string, req clients.AutomationTokenRequest) (model.AutomationTokenResponse, error) {
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
