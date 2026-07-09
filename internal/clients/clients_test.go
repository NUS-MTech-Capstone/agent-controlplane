package clients

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/model"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/observability"
)

func TestSTSClientAutomationTokenRequests(t *testing.T) {
	var auth string
	var requestID string
	var tokenReq AutomationTokenRequest
	expiresAt := time.Date(2026, 7, 6, 1, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		requestID = r.Header.Get("X-Request-Id")
		if r.URL.Path != "/tokens/automation" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&tokenReq); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(model.AutomationTokenResponse{CapabilityToken: "capability", ExpiresAt: expiresAt})
	}))
	defer server.Close()

	ctx := observability.ContextWithRequestID(t.Context(), "req-1")
	resp, err := NewSTS(server.URL, server.Client()).RequestAutomationToken(ctx, "workload", AutomationTokenRequest{
		RunID: "run-1", IncidentID: "inc-1", HostID: "host-1", Phase: "diagnose",
		AllowedOperations: []string{"health_check"}, OwnerPodID: "pod-1", OwnerInstanceID: "inst-1",
	})
	if err != nil {
		t.Fatalf("RequestAutomationToken() error = %v", err)
	}
	if auth != "Bearer workload" || requestID != "req-1" || tokenReq.RunID != "run-1" || resp.CapabilityToken != "capability" {
		t.Fatalf("auth=%q requestID=%q tokenReq=%#v resp=%#v", auth, requestID, tokenReq, resp)
	}
}

func TestSTSClientValidateAutomationTokenRejectsDeniedAndHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": false, "reason": "expired"})
	}))
	defer server.Close()

	client := NewSTS(server.URL, server.Client())
	if err := client.ValidateAutomationToken(t.Context(), "run-1", "token"); err == nil {
		t.Fatal("ValidateAutomationToken() accepted denied response")
	}

	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer badServer.Close()
	client = NewSTS(badServer.URL, badServer.Client())
	if err := client.ValidateAutomationToken(t.Context(), "run-1", "token"); err == nil {
		t.Fatal("ValidateAutomationToken() accepted HTTP failure")
	}
}

func TestSessionManagerClientLifecycleRequests(t *testing.T) {
	var createBody map[string]string
	var closed bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/automation/runs":
			if err := json.NewDecoder(r.Body).Decode(&createBody); err != nil {
				t.Fatalf("decode create: %v", err)
			}
			_ = json.NewEncoder(w).Encode(model.AutomationRun{RunID: "run-1", Status: "ACTIVE"})
		case r.Method == http.MethodGet && r.URL.Path == "/automation/runs/run-1":
			_ = json.NewEncoder(w).Encode(model.AutomationRun{RunID: "run-1", Status: "ACTIVE"})
		case r.Method == http.MethodPost && r.URL.Path == "/automation/runs/run-1/close":
			closed = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewSessionManager(server.URL, server.Client())
	run, err := client.CreateAutomationRun(t.Context(), "inc-1", "host-1")
	if err != nil {
		t.Fatalf("CreateAutomationRun() error = %v", err)
	}
	if run.RunID != "run-1" || createBody["incidentId"] != "inc-1" || createBody["hostId"] != "host-1" {
		t.Fatalf("run=%#v body=%#v", run, createBody)
	}
	run, err = client.GetAutomationRun(t.Context(), "run-1")
	if err != nil || run.Status != "ACTIVE" {
		t.Fatalf("GetAutomationRun() = %#v, %v", run, err)
	}
	if err := client.CloseAutomationRun(t.Context(), "run-1"); err != nil || !closed {
		t.Fatalf("CloseAutomationRun() err=%v closed=%v", err, closed)
	}
}

func TestDataplaneAndWorkerClients(t *testing.T) {
	var auth string
	var operationBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/automation/runs/run-1/operations":
			auth = r.Header.Get("Authorization")
			if err := json.NewDecoder(r.Body).Decode(&operationBody); err != nil {
				t.Fatalf("decode operation: %v", err)
			}
			_ = json.NewEncoder(w).Encode(model.OperationResult{OperationID: "health_check", ExitCode: 0})
		case "/internal/worker/health":
			_ = json.NewEncoder(w).Encode(model.AgentHealth{QueueConsumerRunning: true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result, err := NewDataplane(server.Client()).Execute(t.Context(), server.URL, "run-1", "capability", "health_check", "hash")
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if auth != "Bearer capability" || operationBody["operationId"] != "health_check" || operationBody["planHash"] != "hash" ||
		result.OperationID != "health_check" {
		t.Fatalf("auth=%q body=%#v result=%#v", auth, operationBody, result)
	}

	health, err := NewWorker(server.URL, server.Client()).Health(t.Context())
	if err != nil || !health.QueueConsumerRunning {
		t.Fatalf("Health() = %#v, %v", health, err)
	}
}
