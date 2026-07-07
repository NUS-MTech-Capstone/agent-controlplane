package httpapi

import "net/http"

const (
	apiVersionHeader    = "x-api-version"
	supportedAPIVersion = "1"
)

func apiVersionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isAPIVersionExempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get(apiVersionHeader) != supportedAPIVersion {
			writeError(w, http.StatusBadRequest, `missing or unsupported x-api-version, expected "1"`)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isAPIVersionExempt(path string) bool {
	switch path {
	case "/healthz", "/readyz", "/openapi.yaml", "/asyncapi.yaml":
		return true
	default:
		return false
	}
}
