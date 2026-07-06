package httpapi

import (
	"net/http"
	"strings"

	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/model"
)

func (s *Server) startAutomationRun(w http.ResponseWriter, r *http.Request) {
	var req model.AutomationRunRequest
	if !decode(w, r, &req) {
		return
	}
	req.WorkloadToken = bearerToken(r.Header.Get("Authorization"))
	if req.WorkloadToken == "" || req.IncidentID == "" || req.HostID == "" ||
		req.Phase == "" || len(req.AllowedOperations) == 0 {
		writeError(w, http.StatusBadRequest, "workload token, incidentId, hostId, phase and allowedOperations are required")
		return
	}
	resp, err := s.svc.StartAutomationRun(r.Context(), req)
	if err != nil {
		writeError(w, statusForError(err), err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) automationRunAction(w http.ResponseWriter, r *http.Request) {
	runID, action := parseAutomationPath(r.URL.Path)
	if runID == "" {
		http.NotFound(w, r)
		return
	}
	switch action {
	case "token":
		var req model.AutomationTokenRequest
		if !decode(w, r, &req) {
			return
		}
		req.WorkloadToken = bearerToken(r.Header.Get("Authorization"))
		if req.WorkloadToken == "" || req.Phase == "" || len(req.AllowedOperations) == 0 {
			writeError(w, http.StatusBadRequest, "workload token, phase and allowedOperations are required")
			return
		}
		resp, err := s.svc.IssueAutomationToken(r.Context(), runID, req)
		if err != nil {
			writeError(w, statusForError(err), err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, resp)
	case "close":
		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			writeError(w, http.StatusUnauthorized, "capability token is required")
			return
		}
		if err := s.svc.CloseAutomationRun(r.Context(), runID, token); err != nil {
			writeError(w, statusForError(err), err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func parseAutomationPath(path string) (string, string) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 4 || parts[0] != "automation" || parts[1] != "runs" {
		return "", ""
	}
	return parts[2], parts[3]
}
