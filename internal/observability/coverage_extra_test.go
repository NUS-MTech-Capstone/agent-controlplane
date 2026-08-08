package observability

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestIDHelpersAndMiddleware(t *testing.T) {
	ctx := ContextWithRequestID(context.Background(), "request-1")
	if got := RequestID(ctx); got != "request-1" {
		t.Fatalf("RequestID() = %q", got)
	}
	req := httptest.NewRequest(http.MethodGet, "/alerts", nil)
	SetRequestHeaders(ctx, req)
	if req.Header.Get("x-api-version") != "1" || req.Header.Get("X-Request-ID") != "request-1" {
		t.Fatalf("headers = %#v", req.Header)
	}

	var observed string
	handler := RequestIDMiddleware(LogRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed = RequestID(r.Context())
		w.WriteHeader(http.StatusAccepted)
	})))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/alerts", nil)
	request.Header.Set("X-Request-ID", "caller-id")
	handler.ServeHTTP(recorder, request)
	if observed != "caller-id" || recorder.Header().Get("X-Request-ID") != "caller-id" || recorder.Code != http.StatusAccepted {
		t.Fatalf("observed=%q headers=%#v status=%d", observed, recorder.Header(), recorder.Code)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	RequestIDMiddleware(LogRequests(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))).ServeHTTP(recorder, request)
	if got := recorder.Header().Get("X-Request-ID"); len(got) != 32 {
		t.Fatalf("generated request id = %q", got)
	}
}

func TestMetricsAndErrorClassification(t *testing.T) {
	t.Setenv("ENV", "test")
	t.Setenv("CLOUDWATCH_NAMESPACE", "CustomNamespace")
	ConfigureLogger("agent-controlplane")
	EmitMetric("agent-controlplane", nil, nil)
	EmitMetric("agent-controlplane", []Metric{{Name: "Requests", Value: 2}, {Name: "Latency", Unit: "Milliseconds", Value: 3}}, map[string]string{"Component": "test", "Empty": ""})
	if namespace() != "CustomNamespace" {
		t.Fatalf("namespace() = %q", namespace())
	}
	t.Setenv("CLOUDWATCH_NAMESPACE", "")
	if namespace() != "DenDenMushi" {
		t.Fatalf("default namespace() = %q", namespace())
	}

	cases := []struct {
		err  error
		want string
	}{{nil, ""}, {context.DeadlineExceeded, "timeout"}, {context.Canceled, "cancelled"}, {errors.New("boom"), "error"}}
	for _, tc := range cases {
		if got := ErrorKind(tc.err); got != tc.want {
			t.Fatalf("ErrorKind(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
	if got := newRequestID(); len(got) != 32 {
		t.Fatalf("newRequestID() length = %d", len(got))
	}
}
