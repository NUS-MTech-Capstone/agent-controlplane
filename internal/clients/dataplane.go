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

type Dataplane struct {
	client *http.Client
}

func NewDataplane(client *http.Client) *Dataplane {
	return &Dataplane{client: client}
}

func (c *Dataplane) Execute(ctx context.Context, operationsURL, runID, capabilityToken, operationID, planHash string) (model.OperationResult, error) {
	var resp model.OperationResult
	body, err := json.Marshal(map[string]string{"operationId": operationID, "planHash": planHash})
	if err != nil {
		return resp, err
	}
	url := strings.TrimRight(operationsURL, "/") + "/automation/runs/" + runID + "/operations"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body)) // #nosec G107 -- operationsURL comes from Session Manager assignment metadata.
	if err != nil {
		return resp, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+capabilityToken)
	observability.SetRequestHeaders(ctx, req)
	httpResp, err := c.client.Do(req)
	if err != nil {
		return resp, err
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return resp, fmt.Errorf("dataplane returned status %d", httpResp.StatusCode)
	}
	return resp, json.NewDecoder(httpResp.Body).Decode(&resp)
}
