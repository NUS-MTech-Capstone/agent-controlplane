package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIVersionMiddleware(t *testing.T) {
	handler := apiVersionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/alerts", nil)
	req.Header.Set(apiVersionHeader, supportedAPIVersion)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("versioned status = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/alerts", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing version status = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("exempt status = %d", rec.Code)
	}
}
