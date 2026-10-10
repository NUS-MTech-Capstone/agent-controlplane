package service

import (
	"context"
	"errors"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/clients"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/model"
	"testing"
	"time"
)

type decisionStore struct {
	*executeStore
	getErr, approveErr, rejectErr error
	alert                         model.ManagedAlert
}

func (s *decisionStore) GetIncident(context.Context, string) (model.Incident, error) {
	return s.incident, s.getErr
}
func (s *decisionStore) GetAlert(context.Context, string) (model.ManagedAlert, error) {
	return s.alert, s.getErr
}
func (s *decisionStore) Approve(ctx context.Context, id, hash, actor string) error {
	if s.approveErr != nil {
		return s.approveErr
	}
	return s.executeStore.Approve(ctx, id, hash, actor)
}
func (s *decisionStore) Reject(ctx context.Context, inc model.Incident, hash, actor string) error {
	if s.rejectErr != nil {
		return s.rejectErr
	}
	return s.executeStore.Reject(ctx, inc, hash, actor)
}

type failingSM struct {
	*automationSM
	createErr, closeErr error
	creates             int
}

func (s *failingSM) CreateAutomationRun(ctx context.Context, inc, host string) (model.AutomationRun, error) {
	s.creates++
	if s.createErr != nil {
		return model.AutomationRun{}, s.createErr
	}
	return s.automationSM.CreateAutomationRun(ctx, inc, host)
}
func (s *failingSM) CloseAutomationRun(ctx context.Context, id string) error {
	s.closedRunID = id
	return s.closeErr
}

func TestApprovalConflictNeverExecutes(t *testing.T) {
	for _, tc := range []struct {
		name               string
		getErr, approveErr error
		want               model.ApprovalOutcome
	}{
		{"missing incident", ErrNotFound, nil, model.ApprovalNotFound},
		{"changed state or hash", nil, ErrConflict, model.ApprovalConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &decisionStore{executeStore: &executeStore{incident: model.Incident{ID: "inc", PlanHash: "stored-hash"}}, getErr: tc.getErr, approveErr: tc.approveErr}
			gateway := &executeGateway{}
			svc := New(st, executeSM{}, &executeSTS{}, gateway, nil, "", time.Second, 4096)
			_, err := svc.Approve(t.Context(), "inc", "submitted-hash", "manager", []string{"Manager"})
			if err == nil || len(gateway.operations) != 0 || len(st.approvals) != 1 || st.approvals[0].outcome != tc.want || st.approvals[0].planHash != "submitted-hash" {
				t.Fatalf("err=%v decisions=%+v operations=%v", err, st.approvals, gateway.operations)
			}
		})
	}
}
func TestApprovalExecutesStoredPlanAndFixedVerification(t *testing.T) {
	future := time.Now().Add(time.Hour)
	st := &executeStore{incident: model.Incident{ID: "inc", HostID: "host", State: model.IncidentAwaitingApproval, RunID: "run", OperationsURL: "http://proxy", PlanHash: "hash", PlanExpiresAt: &future, Plan: model.Plan{Actions: []model.Action{{OperationID: "restart_service"}}}}}
	gateway := &executeGateway{}
	sm := &automationSM{}
	svc := New(st, sm, &executeSTS{}, gateway, nil, "", time.Second, 4096)
	_, err := svc.Approve(t.Context(), "inc", "hash", "admin", []string{"Admin"})
	if err != nil || !st.approveCalled || len(st.approvals) != 1 || st.approvals[0].outcome != model.ApprovalSucceeded {
		t.Fatalf("approval=%+v err=%v", st.approvals, err)
	}
	if len(gateway.operations) != 3 || gateway.operations[0] != "restart_service" || gateway.operations[1] != "service_status" || gateway.operations[2] != "health_check" || sm.closedRunID != "run" {
		t.Fatalf("operations=%v closed=%q", gateway.operations, sm.closedRunID)
	}
	if st.report.FinalState != string(model.IncidentCompleted) || !st.hasEvent("PlanApproved") || !st.hasEvent("AutomationRunClosed") {
		t.Fatalf("report=%+v events=%v", st.report, st.events)
	}
}
func TestRejectionGuardsAndCleanup(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	for _, tc := range []struct {
		name              string
		groups            []string
		expiry            *time.Time
		getErr, rejectErr error
		want              error
	}{
		{"unauthorized", []string{"Employee"}, nil, nil, nil, ErrForbidden},
		{"expired", []string{"Manager"}, &past, nil, nil, ErrConflict},
		{"missing", []string{"Manager"}, nil, ErrNotFound, nil, ErrNotFound},
		{"changed", []string{"Admin"}, nil, nil, ErrConflict, ErrConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &decisionStore{executeStore: &executeStore{incident: model.Incident{ID: "inc", PlanHash: "hash", PlanExpiresAt: tc.expiry}}, getErr: tc.getErr, rejectErr: tc.rejectErr}
			svc := New(st, executeSM{}, &executeSTS{}, nil, nil, "", time.Second, 4096)
			_, err := svc.Reject(t.Context(), "inc", "hash", "user", tc.groups)
			if !errors.Is(err, tc.want) || st.rejectCalled || len(st.approvals) != 1 {
				t.Fatalf("err=%v rejected=%v decisions=%+v", err, st.rejectCalled, st.approvals)
			}
		})
	}
	sm := &automationSM{}
	svc := New(&executeStore{}, sm, nil, nil, nil, "", time.Second, 4096)
	svc.closeAfterReject(t.Context(), model.Incident{RunID: "run"})
	if sm.closedRunID != "run" {
		t.Fatal("rejected run not closed")
	}
}
func TestStartRunValidatesContextBeforeAssignment(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		state                   model.IncidentState
		host                    string
		ops                     []string
		getErr, createErr, want error
	}{
		{"eligible", model.IncidentDiagnosing, "host", []string{"health_check"}, nil, nil, nil},
		{"wrong state", model.IncidentCompleted, "host", []string{"health_check"}, nil, nil, ErrConflict},
		{"wrong host", model.IncidentDiagnosing, "other", []string{"health_check"}, nil, nil, ErrConflict},
		{"no operations", model.IncidentDiagnosing, "host", nil, nil, nil, ErrBadRequest},
		{"mutation", model.IncidentDiagnosing, "host", []string{"restart_service"}, nil, nil, ErrBadRequest},
		{"missing", model.IncidentDiagnosing, "host", []string{"health_check"}, ErrNotFound, nil, ErrNotFound},
		{"no capacity", model.IncidentDiagnosing, "host", []string{"health_check"}, nil, ErrConflict, ErrConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &decisionStore{executeStore: &executeStore{incident: model.Incident{ID: "inc", HostID: "host", State: tc.state}}, getErr: tc.getErr}
			sm := &failingSM{automationSM: &automationSM{}, createErr: tc.createErr}
			svc := New(st, sm, &executeSTS{}, nil, nil, "", time.Second, 4096)
			got, err := svc.StartAutomationRun(t.Context(), model.AutomationRunRequest{IncidentID: "inc", HostID: tc.host, Phase: "diagnose", AllowedOperations: tc.ops, WorkloadToken: "test-token"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
			if tc.want == nil && (got.RunID == "" || sm.creates != 1) {
				t.Fatalf("run=%+v creates=%d", got, sm.creates)
			}
			if tc.want != nil && tc.createErr == nil && sm.creates != 0 {
				t.Fatal("assigned before validation")
			}
		})
	}
}
func TestCloseRunRequiresCoordinatorAndPropagatesFailure(t *testing.T) {
	failure := errors.New("upstream unavailable")
	for _, tc := range []struct {
		name                   string
		identity               clients.WorkloadIdentity
		stsErr, closeErr, want error
	}{
		{name: "success"},
		{name: "STS failure", stsErr: failure, want: failure},
		{name: "wrong workload", identity: clients.WorkloadIdentity{Subject: "gateway", Namespace: "dendenmushi-agentic", ServiceAccount: "agent-tool-gateway"}, want: ErrForbidden},
		{name: "close failure", closeErr: failure, want: failure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sm := &failingSM{automationSM: &automationSM{}, closeErr: tc.closeErr}
			svc := New(&executeStore{}, sm, &executeSTS{identity: tc.identity, err: tc.stsErr}, nil, nil, "", time.Second, 4096)
			err := svc.CloseAutomationRun(t.Context(), "run", "test-token")
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v", err)
			}
			if (tc.stsErr != nil || tc.want == ErrForbidden) && sm.closedRunID != "" {
				t.Fatal("unauthorized close")
			}
		})
	}
}
func TestAlertDetailHydratesIncidentAndToleratesMissingLink(t *testing.T) {
	for _, linked := range []bool{false, true} {
		st := &decisionStore{executeStore: &executeStore{incident: model.Incident{ID: "inc"}, incidentEvents: []model.IncidentEvent{{ID: "evt"}}}, alert: model.ManagedAlert{ID: "alert"}}
		if linked {
			st.alert.IncidentID = "inc"
		}
		svc := New(st, nil, nil, nil, nil, "", time.Second, 4096)
		got, err := svc.GetAlertDetail(t.Context(), "alert")
		if err != nil || (got.Incident != nil) != linked {
			t.Fatalf("detail=%+v err=%v", got, err)
		}
		if linked && len(got.Timeline) != 1 {
			t.Fatal("missing timeline")
		}
	}
	st := &decisionStore{executeStore: &executeStore{}, getErr: ErrNotFound}
	if _, err := New(st, nil, nil, nil, nil, "", time.Second, 4096).GetAlertDetail(t.Context(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
