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

type STS struct {
	baseURL string
	client  *http.Client
}

type AutomationTokenRequest struct {
	RunID             string   `json:"runId"`
	IncidentID        string   `json:"incidentId"`
	HostID            string   `json:"hostId"`
	Phase             string   `json:"phase"`
	AllowedOperations []string `json:"allowedOperations"`
	PlanHash          string   `json:"planHash,omitempty"`
	OwnerPodID        string   `json:"ownerPodId"`
	OwnerInstanceID   string   `json:"ownerInstanceId"`
}

type WorkloadIdentity struct {
	Subject        string `json:"subject"`
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"serviceAccount"`
}

func NewSTS(baseURL string, client *http.Client) *STS {
	return &STS{baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

func (c *STS) RequestAutomationToken(ctx context.Context, workloadToken string, req AutomationTokenRequest) (model.AutomationTokenResponse, error) {
	var resp model.AutomationTokenResponse
	body, err := json.Marshal(req)
	if err != nil {
		return resp, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/tokens/automation", bytes.NewReader(body))
	if err != nil {
		return resp, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+workloadToken)
	observability.SetRequestHeaders(ctx, httpReq)
	httpResp, err := c.client.Do(httpReq)
	if err != nil {
		return resp, err
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return resp, fmt.Errorf("sts returned status %d", httpResp.StatusCode)
	}
	return resp, json.NewDecoder(httpResp.Body).Decode(&resp)
}

func (c *STS) ValidateAutomationToken(ctx context.Context, runID, token string) error {
	var resp struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	if err := c.post(ctx, "/tokens/automation/validate", map[string]string{"runId": runID, "token": token}, &resp); err != nil {
		return err
	}
	if !resp.Allowed {
		return fmt.Errorf("automation token rejected: %s", resp.Reason)
	}
	return nil
}

func (c *STS) ValidateWorkload(ctx context.Context, workloadToken string) (WorkloadIdentity, error) {
	var identity WorkloadIdentity
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/workloads/validate", nil)
	if err != nil {
		return identity, err
	}
	req.Header.Set("Authorization", "Bearer "+workloadToken)
	observability.SetRequestHeaders(ctx, req)
	resp, err := c.client.Do(req)
	if err != nil {
		return identity, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return identity, fmt.Errorf("sts returned status %d", resp.StatusCode)
	}
	return identity, json.NewDecoder(resp.Body).Decode(&identity)
}

func (c *STS) post(ctx context.Context, path string, req any, resp any) error {
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
		return fmt.Errorf("sts returned status %d", httpResp.StatusCode)
	}
	if resp == nil {
		return nil
	}
	return json.NewDecoder(httpResp.Body).Decode(resp)
}
