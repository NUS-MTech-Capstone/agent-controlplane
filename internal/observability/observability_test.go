package observability

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestShouldSkipRequestLogSuppressesOnlySuccessfulProbeRequests(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		status int
		want   bool
	}{
		{name: "successful healthz", method: http.MethodGet, path: "/healthz", status: http.StatusOK, want: true},
		{name: "successful readyz", method: http.MethodGet, path: "/readyz", status: http.StatusNoContent, want: true},
		{name: "failed readyz", method: http.MethodGet, path: "/readyz", status: http.StatusServiceUnavailable, want: false},
		{name: "business route", method: http.MethodGet, path: "/incidents", status: http.StatusOK, want: false},
		{name: "non-get probe", method: http.MethodPost, path: "/healthz", status: http.StatusOK, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if got := shouldSkipRequestLog(req, tc.status); got != tc.want {
				t.Fatalf("shouldSkipRequestLog() = %v, want %v", got, tc.want)
			}
		})
	}
}
