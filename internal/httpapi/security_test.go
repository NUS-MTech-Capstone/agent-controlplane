package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := securityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	assertSecurityHeaders(t, recorder.Header())
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want empty", got)
	}
}

func TestServerAddsSecurityHeadersToErrors(t *testing.T) {
	recorder := httptest.NewRecorder()
	New(nil, nil).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/alerts", nil))
	assertSecurityHeaders(t, recorder.Header())
}

func assertSecurityHeaders(t *testing.T, headers http.Header) {
	t.Helper()
	want := map[string]string{
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for name, value := range want {
		if got := headers.Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
}
