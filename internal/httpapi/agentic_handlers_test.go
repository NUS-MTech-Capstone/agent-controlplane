package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/model"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/service"
)

func TestAgenticHandlersServeJSONAndHTML(t *testing.T) {
	store := &handlerStore{
		alerts: []model.ManagedAlert{{ID: "alert-1", IncidentID: "inc-1", HostID: "host-1"}},
		alert:  model.ManagedAlert{ID: "alert-1", IncidentID: "inc-1", HostID: "host-1"},
		incident: model.Incident{
			ID: "inc-1", AlarmName: "CPUHigh", HostID: "host-1", State: model.IncidentAwaitingApproval,
			PlanHash: "hash", Plan: model.Plan{Summary: "Restart", Actions: []model.Action{{OperationID: "restart_service", Reason: "hung"}}},
			Explanation: model.IncidentExplanation{Workflow: model.ExplanationWorkflow{CatalogVersion: "v1"}},
		},
		events: []model.IncidentEvent{
			{ID: "evt-1", IncidentID: "inc-1", EventType: "PlanProposed"},
			{ID: "evt-2", IncidentID: "inc-1", EventType: "OperationExecuted", Metadata: map[string]any{
				"operationId": "health_check", "phase": "diagnose", "status": "SUCCEEDED", "exitCode": 0,
			}},
		},
	}
	server := New(service.New(store, nil, nil, nil, nil, "", time.Second, 1024), fakeVerifier{})

	rec := serveAgentic(t, server, http.MethodGet, "/alerts?hostId=host-1", "", "application/json")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"alert-1"`) {
		t.Fatalf("alerts status=%d body=%s", rec.Code, rec.Body.String())
	}
	if store.alertFilter.HostID != "host-1" {
		t.Fatalf("alert filter = %#v", store.alertFilter)
	}

	rec = serveAgentic(t, server, http.MethodGet, "/alerts/alert-1", "", "application/json")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"timeline"`) ||
		!strings.Contains(rec.Body.String(), `"trace":{"schemaVersion":"v1"`) ||
		!strings.Contains(rec.Body.String(), `"operationId":"health_check"`) {
		t.Fatalf("alert detail status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = serveAgentic(t, server, http.MethodGet, "/incidents", "", "text/html")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<table>") || !strings.Contains(rec.Body.String(), "CPUHigh") {
		t.Fatalf("incident HTML status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = serveAgentic(t, server, http.MethodGet, "/incidents/inc-1", "", "text/html")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Approve exact plan") ||
		!strings.Contains(rec.Body.String(), "Explainability") {
		t.Fatalf("incident detail HTML status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = serveAgentic(t, server, http.MethodGet, "/incidents/events?eventType=PlanProposed", "", "application/json")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"evt-1"`) ||
		store.eventFilter.EventType != "PlanProposed" {
		t.Fatalf("events status=%d filter=%#v body=%s", rec.Code, store.eventFilter, rec.Body.String())
	}
}

func TestDecideIncidentRequiresCognitoAndPlanHash(t *testing.T) {
	server := New(service.New(&handlerStore{}, nil, nil, nil, nil, "", time.Second, 1024), fakeVerifier{})

	req := httptest.NewRequest(http.MethodPost, "/incidents/inc-1/approve", strings.NewReader(`{"planHash":"hash"}`))
	req.Header.Set(apiVersionHeader, supportedAPIVersion)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.decideIncident(rec, req, "inc-1", "approve")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing identity status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/incidents/inc-1/approve", strings.NewReader(`{}`))
	req = req.WithContext(context.WithValue(req.Context(), cognitoUserContextKey{}, CognitoUser{Subject: "user-1", Groups: []string{"Manager"}}))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	server.decideIncident(rec, req, "inc-1", "approve")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing planHash status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCognitoGroupsFromClaimsAndAccessToken(t *testing.T) {
	claims := map[string]any{"sub": "user-1", "cognito:groups": []any{"Manager", "", 12}}
	user, err := cognitoUserFromALBHeaders(cognitoRequest("", "user-1"), claimsVerifier{claims: claims})
	if err != nil {
		t.Fatalf("cognitoUserFromALBHeaders() error = %v", err)
	}
	if len(user.Groups) != 1 || user.Groups[0] != "Manager" {
		t.Fatalf("groups = %#v", user.Groups)
	}

	accessToken := unsignedJWT(map[string]any{"groups": "Admin,Auditor"})
	claims = map[string]any{"sub": "user-1"}
	user, err = cognitoUserFromALBHeaders(cognitoRequest(accessToken, "user-1"), claimsVerifier{claims: claims})
	if err != nil {
		t.Fatalf("fallback groups error = %v", err)
	}
	if len(user.Groups) != 2 || user.Groups[0] != "Admin" || user.Groups[1] != "Auditor" {
		t.Fatalf("fallback groups = %#v", user.Groups)
	}

	if groups := groupsFromJWT("not-a-jwt"); groups != nil {
		t.Fatalf("groupsFromJWT(invalid) = %#v", groups)
	}
}

func TestCanDecideUICanonicalizesApprovedGroupCase(t *testing.T) {
	if !canDecideUI([]string{"admin"}) || !canDecideUI([]string{" MANAGER "}) {
		t.Fatal("expected canonical Admin and Manager groups to be accepted case-insensitively")
	}
	if canDecideUI([]string{"Administrator"}) || canDecideUI([]string{"Operator"}) {
		t.Fatal("unexpected decision access for an unapproved group")
	}
}

func TestCognitoMiddlewareRejectsVerifierErrorAndIdentityMismatch(t *testing.T) {
	handler := cognitoMiddleware(fakeVerifierWithError{err: errors.New("bad token")}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not run")
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, cognitoRequest("", "user-1"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("verifier error status = %d", rec.Code)
	}

	handler = cognitoMiddleware(claimsVerifier{claims: map[string]any{"sub": "user-1"}}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not run")
	}))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, cognitoRequest("", "other-user"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("identity mismatch status = %d", rec.Code)
	}
}

func TestHealthEndpointsReportReadyAndUnavailable(t *testing.T) {
	store := &handlerStore{}
	server := New(service.New(store, nil, nil, nil, nil, "", time.Second, 1024), fakeVerifier{})
	rec := serveAgentic(t, server, http.MethodGet, "/readyz", "", "application/json")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ready"`) {
		t.Fatalf("ready response status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = serveAgentic(t, server, http.MethodGet, "/agentic-ai/health", "", "application/json")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"databaseReady":true`) {
		t.Fatalf("health response status=%d body=%s", rec.Code, rec.Body.String())
	}

	store.pingErr = errors.New("database unavailable")
	rec = serveAgentic(t, server, http.MethodGet, "/readyz", "", "application/json")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable response status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func serveAgentic(t *testing.T, server http.Handler, method, path, body, accept string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set(apiVersionHeader, supportedAPIVersion)
	req.Header.Set("x-amzn-oidc-data", "signed-token")
	req.Header.Set("x-amzn-oidc-identity", "user-1")
	req.Header.Set("Accept", accept)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	return rec
}

func cognitoRequest(accessToken, identity string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("x-amzn-oidc-data", "signed-token")
	req.Header.Set("x-amzn-oidc-identity", identity)
	if accessToken != "" {
		req.Header.Set("x-amzn-oidc-accesstoken", accessToken)
	}
	return req
}

func unsignedJWT(claims map[string]any) string {
	header, _ := json.Marshal(map[string]any{"alg": "none"})
	body, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(body) + ".signature"
}

type fakeVerifierWithError struct {
	err error
}

func (v fakeVerifierWithError) Verify(context.Context, string) (map[string]any, error) {
	return nil, v.err
}

type claimsVerifier struct {
	claims map[string]any
}

func (v claimsVerifier) Verify(context.Context, string) (map[string]any, error) {
	return v.claims, nil
}

type handlerStore struct {
	alert       model.ManagedAlert
	alerts      []model.ManagedAlert
	incident    model.Incident
	events      []model.IncidentEvent
	alertFilter model.AlertFilter
	eventFilter model.IncidentEventFilter
	pingErr     error
}

func (s *handlerStore) Ping(context.Context) error { return s.pingErr }
func (s *handlerStore) ListAlerts(_ context.Context, filter model.AlertFilter) ([]model.ManagedAlert, error) {
	s.alertFilter = filter
	return s.alerts, nil
}
func (s *handlerStore) GetAlert(context.Context, string) (model.ManagedAlert, error) {
	return s.alert, nil
}
func (s *handlerStore) ListIncidents(context.Context, model.IncidentFilter) ([]model.Incident, error) {
	return []model.Incident{s.incident}, nil
}
func (s *handlerStore) GetIncident(context.Context, string) (model.Incident, error) {
	return s.incident, nil
}
func (s *handlerStore) ListEvents(context.Context, string) ([]model.IncidentEvent, error) {
	return s.events, nil
}
func (s *handlerStore) ListIncidentEvents(_ context.Context, filter model.IncidentEventFilter) ([]model.IncidentEvent, error) {
	s.eventFilter = filter
	return s.events, nil
}
func (s *handlerStore) ListApprovalDecisions(context.Context, string) ([]model.ApprovalDecisionAudit, error) {
	return nil, nil
}
func (s *handlerStore) IncidentCounts(context.Context) (int, int, error) { return 0, 0, nil }
func (s *handlerStore) LastAlertProcessedAt(context.Context) (*time.Time, error) {
	return nil, nil
}
func (s *handlerStore) CreateEvent(context.Context, string, string, string, string, string, map[string]any) (model.IncidentEvent, error) {
	return model.IncidentEvent{}, nil
}
func (s *handlerStore) CreateApprovalDecision(context.Context, string, string, string, string, model.ApprovalOutcome, string) error {
	return nil
}
func (s *handlerStore) Approve(context.Context, string, string, string) error { return nil }
func (s *handlerStore) Reject(context.Context, model.Incident, string, string) error {
	return nil
}
func (s *handlerStore) SetAlertStatusForIncident(context.Context, string, model.AlertStatus, string) error {
	return nil
}
func (s *handlerStore) SetIncidentReport(context.Context, string, model.IncidentState, string, string, model.PostIncidentReport) error {
	return nil
}
func (s *handlerStore) SetFailure(context.Context, string, string) error { return nil }
