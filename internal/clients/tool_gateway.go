package clients

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/model"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ToolGateway struct {
	endpoint  string
	tokenFile string
	client    *http.Client
}

func NewToolGateway(endpoint, tokenFile string, client *http.Client) *ToolGateway {
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &ToolGateway{
		endpoint:  endpoint,
		tokenFile: tokenFile,
		client: &http.Client{
			Timeout:   client.Timeout,
			Transport: &workloadTokenTransport{base: transport, tokenFile: tokenFile},
		},
	}
}

func (c *ToolGateway) Execute(ctx context.Context, runID, operationID, planHash string) (model.OperationResult, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "agent-controlplane", Version: "v1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             c.endpoint,
		HTTPClient:           c.client,
		MaxRetries:           -1,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		return model.OperationResult{}, fmt.Errorf("connect tool gateway: %w", err)
	}
	defer session.Close()
	arguments := map[string]any{"runId": runID}
	if planHash != "" {
		arguments["planHash"] = planHash
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: operationID, Arguments: arguments})
	if err != nil {
		return model.OperationResult{}, fmt.Errorf("call tool gateway: %w", err)
	}
	if result.IsError {
		return model.OperationResult{}, errors.New("tool gateway denied or failed the operation")
	}
	for _, content := range result.Content {
		text, ok := content.(*mcp.TextContent)
		if !ok {
			continue
		}
		var operation model.OperationResult
		if err := json.Unmarshal([]byte(text.Text), &operation); err == nil && operation.OperationID != "" {
			return operation, nil
		}
	}
	return model.OperationResult{}, errors.New("tool gateway returned no operation result")
}

type workloadTokenTransport struct {
	base      http.RoundTripper
	tokenFile string
}

func (t *workloadTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := os.ReadFile(t.tokenFile) // #nosec G304 -- deployment-controlled projected token path.
	if err != nil {
		return nil, err
	}
	value := strings.TrimSpace(string(token))
	if value == "" {
		return nil, errors.New("projected workload token is empty")
	}
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	clone.Header.Set("Authorization", "Bearer "+value)
	return t.base.RoundTrip(clone)
}
