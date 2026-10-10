package httpapi

import (
	"context"
	"errors"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/model"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/service"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type rejectedDecisionStore struct {
	*handlerStore
	err         error
	hash, actor string
}

func (s *rejectedDecisionStore) Approve(_ context.Context, _ string, hash, actor string) error {
	s.hash = hash
	s.actor = actor
	return s.err
}
func (s *rejectedDecisionStore) Reject(_ context.Context, _ model.Incident, hash, actor string) error {
	s.hash = hash
	s.actor = actor
	return s.err
}

func TestIncidentDecisionMapsServiceFailures(t *testing.T) {
	for _, action := range []string{"approve", "reject"} {
		for _, tc := range []struct {
			err    error
			status int
		}{
			{service.ErrNotFound, 404}, {service.ErrConflict, 409}, {service.ErrForbidden, 403}, {service.ErrBadRequest, 400}, {errors.New("upstream unavailable"), 502},
		} {
			t.Run(action+"/"+http.StatusText(tc.status), func(t *testing.T) {
				st := &rejectedDecisionStore{handlerStore: &handlerStore{incident: model.Incident{ID: "inc", PlanHash: "stored"}}, err: tc.err}
				server := New(service.New(st, nil, nil, nil, nil, "", time.Second, 1024), fakeVerifier{})
				r := httptest.NewRequest(http.MethodPost, "/incidents/inc/"+action, strings.NewReader(`{"planHash":" submitted "}`))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Accept", "application/json")
				r = r.WithContext(context.WithValue(r.Context(), cognitoUserContextKey{}, CognitoUser{Subject: "manager-1", Groups: []string{"Manager"}}))
				w := httptest.NewRecorder()
				server.incidentAction(w, r)
				if w.Code != tc.status || st.hash != "submitted" || st.actor != "manager-1" {
					t.Fatalf("status=%d hash=%q actor=%q", w.Code, st.hash, st.actor)
				}
				if !strings.Contains(w.Body.String(), `"error"`) {
					t.Fatal("missing structured error")
				}
			})
		}
	}
}
func TestIncidentActionRejectsUnsupportedRoutes(t *testing.T) {
	server := &Server{}
	for _, tc := range []struct{ method, path string }{{"GET", "/incidents/"}, {"GET", "/incidents/inc/approve"}, {"POST", "/incidents/inc/execute"}, {"DELETE", "/incidents/inc"}, {"POST", "/incidents/inc/approve/extra"}} {
		w := httptest.NewRecorder()
		server.incidentAction(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != 404 {
			t.Fatalf("%s %s status=%d", tc.method, tc.path, w.Code)
		}
	}
}
func TestPlanHashFormAndJSONValidation(t *testing.T) {
	for _, tc := range []struct{ name, kind, body, want string }{
		{"form", "application/x-www-form-urlencoded", "planHash=+hash+", "hash"},
		{"empty form", "application/x-www-form-urlencoded", "planHash=+", ""},
		{"bad form", "application/x-www-form-urlencoded", "planHash=%ZZ", ""},
		{"malformed JSON", "application/json", "{", ""},
		{"JSON", "application/json", `{"planHash":" hash "}`, "hash"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/incidents/inc/approve", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", tc.kind)
			got, err := planHashFromRequest(r)
			if tc.want == "" {
				if err == nil {
					t.Fatal("invalid plan hash accepted")
				}
			} else if err != nil || got != tc.want {
				t.Fatalf("hash=%q err=%v", got, err)
			}
		})
	}
}
