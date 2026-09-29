package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/clients"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/model"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/service"
)

func TestAutomationHTTPValidationAndLifecycle(t *testing.T) {
	store := &handlerStore{incident: model.Incident{
		ID: "inc-1", HostID: "host-1", State: model.IncidentDiagnosing,
	}}
	svc := service.New(store, fakeSM{}, fakeSTS{}, nil, nil, "", time.Second, 1024)
	server := New(svc, fakeVerifier{})

	do(t, server, http.MethodPost, "/automation/runs/start", `{}`, "", http.StatusBadRequest)
	do(t, server, http.MethodPost, "/automation/runs/start", `{"incidentId":"inc-1","hostId":"host-1","phase":"diagnose","allowedOperations":["health_check"]}`, "Bearer workload", http.StatusCreated)
	do(t, server, http.MethodPost, "/automation/runs/run-1/token", `{"phase":"diagnose","allowedOperations":["health_check"]}`, "Bearer workload", http.StatusCreated)
	do(t, server, http.MethodPost, "/automation/runs/run-1/close", `{}`, "", http.StatusUnauthorized)
	do(t, server, http.MethodPost, "/automation/runs/run-1/close", `{}`, "Bearer capability", http.StatusNoContent)
}

func TestAutomationPathParsing(t *testing.T) {
	runID, action := parseAutomationPath("/automation/runs/run-1/token")
	if runID != "run-1" || action != "token" {
		t.Fatalf("parseAutomationPath() = %q/%q", runID, action)
	}
	if got := bearerToken("Bearer token"); got != "token" {
		t.Fatalf("bearerToken() = %q", got)
	}
}

func do(t *testing.T, server http.Handler, method, path, body, auth string, want int) {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	req.Header.Set(apiVersionHeader, supportedAPIVersion)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("%s %s status = %d want %d body=%s", method, path, rec.Code, want, rec.Body.String())
	}
}

type fakeSM struct{}

func (fakeSM) CreateAutomationRun(context.Context, string, string) (model.AutomationRun, error) {
	return fakeRun(), nil
}
func (fakeSM) GetAutomationRun(context.Context, string) (model.AutomationRun, error) {
	return fakeRun(), nil
}
func (fakeSM) CloseAutomationRun(context.Context, string) error { return nil }

type fakeSTS struct{}

func (fakeSTS) RequestAutomationToken(context.Context, string, clients.AutomationTokenRequest) (model.AutomationTokenResponse, error) {
	return model.AutomationTokenResponse{CapabilityToken: "capability", ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (fakeSTS) ValidateWorkload(context.Context, string) (clients.WorkloadIdentity, error) {
	return clients.WorkloadIdentity{
		Subject:        "system:serviceaccount:dendenmushi-agentic:incident-agent",
		Namespace:      "dendenmushi-agentic",
		ServiceAccount: "incident-agent",
	}, nil
}

func fakeRun() model.AutomationRun {
	return model.AutomationRun{
		RunID: "run-1", IncidentID: "inc-1", HostID: "host-1",
		OwnerPodID: "pod-1", OwnerInstanceID: "instance-1",
		OperationsURL: "http://ops", Status: "ACTIVE",
	}
}

type fakeVerifier struct{}

func (fakeVerifier) Verify(context.Context, string) (map[string]any, error) {
	return map[string]any{"sub": "user-1", "email": "user@example.com", "cognito:groups": []any{"Manager"}}, nil
}
