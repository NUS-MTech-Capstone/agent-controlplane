package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/model"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/observability"
)

type SessionManager struct {
	baseURL string
	client  *http.Client
}

func NewSessionManager(baseURL string, client *http.Client) *SessionManager {
	return &SessionManager{baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

func (c *SessionManager) CreateAutomationRun(ctx context.Context, incidentID, hostID string) (model.AutomationRun, error) {
	var resp model.AutomationRun
	err := c.post(ctx, "/automation/runs", map[string]string{"incidentId": incidentID, "hostId": hostID}, &resp)
	return resp, err
}

func (c *SessionManager) GetAutomationRun(ctx context.Context, runID string) (model.AutomationRun, error) {
	var resp model.AutomationRun
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/automation/runs/"+runID, nil)
	if err != nil {
		return resp, err
	}
	observability.SetRequestHeaders(ctx, req)
	httpResp, err := c.client.Do(req)
	if err != nil {
		return resp, err
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return resp, fmt.Errorf("session-manager returned status %d", httpResp.StatusCode)
	}
	return resp, json.NewDecoder(httpResp.Body).Decode(&resp)
}

func (c *SessionManager) CloseAutomationRun(ctx context.Context, runID string) error {
	return c.post(ctx, "/automation/runs/"+runID+"/close", map[string]string{}, nil)
}

func (c *SessionManager) post(ctx context.Context, path string, req any, resp any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	observability.SetRequestHeaders(ctx, httpReq)
	httpResp, err := c.client.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return fmt.Errorf("session-manager returned status %d", httpResp.StatusCode)
	}
	if resp == nil {
		return nil
	}
	return json.NewDecoder(httpResp.Body).Decode(resp)
}
