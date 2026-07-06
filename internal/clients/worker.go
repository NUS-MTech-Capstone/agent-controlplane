package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/model"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/observability"
)

type Worker struct {
	baseURL string
	client  *http.Client
}

func NewWorker(baseURL string, client *http.Client) *Worker {
	return &Worker{baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

func (c *Worker) Health(ctx context.Context) (model.AgentHealth, error) {
	var resp model.AgentHealth
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/internal/worker/health", nil)
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
		return resp, fmt.Errorf("incident-agent returned status %d", httpResp.StatusCode)
	}
	return resp, json.NewDecoder(httpResp.Body).Decode(&resp)
}
