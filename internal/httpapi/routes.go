package httpapi

import (
	"net/http"

	"github.com/NUS-MTech-Capstone/agent-controlplane/api"
)

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.HandleFunc("GET /readyz", s.readyz)
	s.mux.HandleFunc("GET /openapi.yaml", serveYAML(api.OpenAPI))
	s.mux.Handle("GET /agentic-ai/health", cognitoMiddleware(s.identityVerifier, http.HandlerFunc(s.agenticHealth)))
	s.mux.Handle("GET /alerts", cognitoMiddleware(s.identityVerifier, http.HandlerFunc(s.listAlerts)))
	s.mux.Handle("GET /alerts/", cognitoMiddleware(s.identityVerifier, http.HandlerFunc(s.alertDetail)))
	s.mux.Handle("GET /incidents", cognitoMiddleware(s.identityVerifier, http.HandlerFunc(s.listIncidents)))
	s.mux.Handle("GET /incidents/", cognitoMiddleware(s.identityVerifier, http.HandlerFunc(s.incidentAction)))
	s.mux.Handle("POST /incidents/", cognitoMiddleware(s.identityVerifier, http.HandlerFunc(s.incidentAction)))
	s.mux.HandleFunc("POST /automation/runs/start", s.startAutomationRun)
	s.mux.HandleFunc("POST /automation/runs/", s.automationRunAction)
}
