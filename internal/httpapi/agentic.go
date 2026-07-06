package httpapi

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/model"
)

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.Ready(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "service is not ready")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) agenticHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Health(r.Context()))
}

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, err := s.svc.ListAlerts(r.Context())
	if err != nil {
		writeError(w, statusForError(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, model.AlertListResponse{Alerts: alerts})
}

func (s *Server) alertDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(strings.Trim(r.URL.Path, "/"), "alerts/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	detail, err := s.svc.GetAlertDetail(r.Context(), id)
	if err != nil {
		writeError(w, statusForError(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	user, _ := cognitoUserFromContext(r.Context())
	incidents, err := s.svc.ListIncidents(r.Context())
	if err != nil {
		writeError(w, statusForError(err), err.Error())
		return
	}
	if wantsJSON(r) {
		summaries := make([]model.IncidentSummary, 0, len(incidents))
		for _, incident := range incidents {
			summaries = append(summaries, model.IncidentSummary{
				ID: incident.ID, AlarmName: incident.AlarmName, HostID: incident.HostID,
				State: incident.State, PlanHash: incident.PlanHash, PlanExpiresAt: incident.PlanExpiresAt,
				CreatedAt: incident.CreatedAt, UpdatedAt: incident.UpdatedAt, ErrorMessage: incident.ErrorMessage,
			})
		}
		writeJSON(w, http.StatusOK, model.IncidentListResponse{Incidents: summaries})
		return
	}
	rows := ""
	for _, incident := range incidents {
		rows += fmt.Sprintf("<tr><td>%s</td><td><a href='/incidents/%s'>%s</a></td><td>%s</td><td class='state'>%s</td></tr>",
			html.EscapeString(incident.CreatedAt.String()),
			url.PathEscape(incident.ID),
			html.EscapeString(incident.AlarmName),
			html.EscapeString(incident.HostID),
			html.EscapeString(string(incident.State)),
		)
	}
	if rows == "" {
		rows = "<tr><td colspan='4'>No incidents</td></tr>"
	}
	writeHTML(w, http.StatusOK, page("Incidents",
		fmt.Sprintf("<h1>Incidents</h1><p>Signed in as %s</p><table><thead><tr><th>Created</th><th>Alarm</th><th>Host</th><th>State</th></tr></thead><tbody>%s</tbody></table>",
			html.EscapeString(user.Email), rows)))
}

func (s *Server) incidentAction(w http.ResponseWriter, r *http.Request) {
	incidentID, action := parseIncidentPath(r.URL.Path)
	if incidentID == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if action != "" {
			http.NotFound(w, r)
			return
		}
		s.incidentDetail(w, r, incidentID)
	case http.MethodPost:
		if action != "approve" && action != "reject" {
			http.NotFound(w, r)
			return
		}
		s.decideIncident(w, r, incidentID, action)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) incidentDetail(w http.ResponseWriter, r *http.Request, incidentID string) {
	user, _ := cognitoUserFromContext(r.Context())
	detail, err := s.svc.GetIncidentDetail(r.Context(), incidentID)
	if err != nil {
		writeError(w, statusForError(err), err.Error())
		return
	}
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, detail)
		return
	}
	actions := ""
	for _, action := range detail.Plan.Actions {
		actions += fmt.Sprintf("<p><code>%s</code>: %s</p>", html.EscapeString(action.OperationID), html.EscapeString(action.Reason))
	}
	plan := ""
	if detail.Plan.Summary != "" {
		plan = fmt.Sprintf("<div class='card'><h2>Proposed plan</h2><p><b>%s</b></p><p>%s</p>%s</div>",
			html.EscapeString(detail.Plan.Summary), html.EscapeString(detail.Plan.Rationale), actions)
	}
	decision := ""
	if detail.State == model.IncidentAwaitingApproval && canDecideUI(user.Groups) {
		decision = fmt.Sprintf("<form method='post' action='/incidents/%s/approve'><input type='hidden' name='planHash' value='%s'><button class='approve' type='submit'>Approve exact plan</button></form><form method='post' action='/incidents/%s/reject'><input type='hidden' name='planHash' value='%s'><button class='danger' type='submit'>Reject</button></form>",
			url.PathEscape(detail.ID), html.EscapeString(detail.PlanHash), url.PathEscape(detail.ID), html.EscapeString(detail.PlanHash))
	}
	evidence := ""
	for _, result := range detail.Evidence {
		evidence += fmt.Sprintf("<div class='card'><b>%s</b> (exit %d)<pre>%s%s</pre></div>",
			html.EscapeString(result.OperationID), result.ExitCode, html.EscapeString(result.Stdout), html.EscapeString(result.Stderr))
	}
	body := fmt.Sprintf("<p><a href='/incidents'>Back</a></p><h1>%s</h1><div class='card'><b>State:</b> %s<br><b>Host:</b> %s<br><b>Reason:</b> %s</div>%s%s",
		html.EscapeString(detail.AlarmName), html.EscapeString(string(detail.State)), html.EscapeString(detail.HostID),
		html.EscapeString(detail.Reason), plan, decision)
	if evidence != "" {
		body += "<h2>Evidence</h2>" + evidence
	}
	if detail.Report != "" {
		body += "<h2>Report</h2><pre>" + html.EscapeString(detail.Report) + "</pre>"
	}
	if detail.ErrorMessage != "" {
		body += "<h2>Error</h2><pre>" + html.EscapeString(detail.ErrorMessage) + "</pre>"
	}
	writeHTML(w, http.StatusOK, page(detail.AlarmName, body))
}

func (s *Server) decideIncident(w http.ResponseWriter, r *http.Request, incidentID, action string) {
	user, ok := cognitoUserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing Cognito identity")
		return
	}
	planHash, err := planHashFromRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "planHash is required")
		return
	}
	var detail model.IncidentDetail
	if action == "approve" {
		detail, err = s.svc.Approve(r.Context(), incidentID, planHash, user.Subject, user.Groups)
	} else {
		detail, err = s.svc.Reject(r.Context(), incidentID, planHash, user.Subject, user.Groups)
	}
	if err != nil {
		writeError(w, statusForError(err), err.Error())
		return
	}
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, detail)
		return
	}
	http.Redirect(w, r, "/incidents/"+url.PathEscape(incidentID), http.StatusSeeOther)
}

func planHashFromRequest(r *http.Request) (string, error) {
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		var body struct {
			PlanHash string `json:"planHash"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return "", err
		}
		if strings.TrimSpace(body.PlanHash) == "" {
			return "", io.ErrUnexpectedEOF
		}
		return strings.TrimSpace(body.PlanHash), nil
	}
	if err := r.ParseForm(); err != nil {
		return "", err
	}
	planHash := strings.TrimSpace(r.Form.Get("planHash"))
	if planHash == "" {
		return "", io.ErrUnexpectedEOF
	}
	return planHash, nil
}

func wantsJSON(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	contentType := r.Header.Get("Content-Type")
	return strings.Contains(accept, "application/json") || strings.Contains(contentType, "application/json")
}

func parseIncidentPath(path string) (string, string) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 || parts[0] != "incidents" {
		return "", ""
	}
	if len(parts) == 2 {
		return parts[1], ""
	}
	if len(parts) == 3 {
		return parts[1], parts[2]
	}
	return "", ""
}

func canDecideUI(groups []string) bool {
	for _, group := range groups {
		if group == "Manager" || group == "Admin" {
			return true
		}
	}
	return false
}

func writeHTML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func page(title, body string) string {
	return "<!doctype html><html><head><meta charset='utf-8'><title>" + html.EscapeString(title) + "</title><style>body{font-family:system-ui;margin:2rem;line-height:1.5}.card{border:1px solid #ddd;padding:1rem;margin:1rem 0}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:.5rem;text-align:left}.danger{background:#b42318;color:white}.approve{background:#067647;color:white}button{border:0;padding:.6rem 1rem;margin:.2rem;cursor:pointer}</style></head><body>" + body + "</body></html>"
}
