package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAgenticQueryFiltersParse(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/alerts?incidentId=inc-1&hostId=host-1&status=FAILED&cloudwatchState=ALARM&from=2026-07-06T01:00:00Z&to=2026-07-06T02:00:00Z&limit=25&cursor=50", nil)
	rec := httptest.NewRecorder()
	alerts, ok := alertFilterFromQuery(rec, req)
	if !ok {
		t.Fatalf("alertFilterFromQuery() failed: %s", rec.Body.String())
	}
	if alerts.IncidentID != "inc-1" || alerts.HostID != "host-1" || alerts.Status != "FAILED" ||
		alerts.CloudWatchState != "ALARM" || alerts.Limit != 25 || alerts.Offset != 50 {
		t.Fatalf("alerts = %#v", alerts)
	}

	req = httptest.NewRequest(http.MethodGet, "/incidents?incidentId=inc-1&alertId=alert-1&hostId=host-1&state=FAILED&limit=10&cursor=20", nil)
	rec = httptest.NewRecorder()
	incidents, ok := incidentFilterFromQuery(rec, req)
	if !ok {
		t.Fatalf("incidentFilterFromQuery() failed: %s", rec.Body.String())
	}
	if incidents.IncidentID != "inc-1" || incidents.AlertID != "alert-1" || incidents.State != "FAILED" ||
		incidents.Limit != 10 || incidents.Offset != 20 {
		t.Fatalf("incidents = %#v", incidents)
	}

	req = httptest.NewRequest(http.MethodGet, "/incidents/events?incidentId=inc-1&alertId=alert-1&eventType=PlanApproved&actor=user-1&limit=5", nil)
	rec = httptest.NewRecorder()
	events, ok := incidentEventFilterFromQuery(rec, req)
	if !ok {
		t.Fatalf("incidentEventFilterFromQuery() failed: %s", rec.Body.String())
	}
	if events.IncidentID != "inc-1" || events.AlertID != "alert-1" || events.EventType != "PlanApproved" ||
		events.Actor != "user-1" || events.Limit != 5 {
		t.Fatalf("events = %#v", events)
	}
}

func TestAgenticQueryFiltersRejectInvalidTime(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/incidents/events?from=bad", nil)
	rec := httptest.NewRecorder()
	if _, ok := incidentEventFilterFromQuery(rec, req); ok {
		t.Fatal("incidentEventFilterFromQuery() accepted invalid time")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}
