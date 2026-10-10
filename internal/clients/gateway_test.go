package clients

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/observability"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type captureTransport func(*http.Request) (*http.Response, error)

func (f captureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestProjectedTokenIsReloadedWithoutMutatingRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	calls := 0
	tr := &workloadTokenTransport{tokenFile: path, base: captureTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("Authorization") != "Bearer rotated" {
			t.Errorf("token not reloaded")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	req, _ := http.NewRequestWithContext(t.Context(), "GET", "http://gateway", nil)
	req.Header.Set("Authorization", "original")
	if _, err := tr.RoundTrip(req); err == nil || calls != 0 {
		t.Fatalf("missing token err=%v calls=%d", err, calls)
	}
	if err := os.WriteFile(path, []byte(" \n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.RoundTrip(req); err == nil || calls != 0 {
		t.Fatalf("empty token err=%v calls=%d", err, calls)
	}
	if err := os.WriteFile(path, []byte("rotated\n"), 0600); err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if calls != 1 || req.Header.Get("Authorization") != "original" {
		t.Fatal("transport mutated caller request")
	}
}

func TestToolGatewayBoundedCallAndResultHandling(t *testing.T) {
	for _, tc := range []struct {
		name, text, hash, wantErr string
		denied                    bool
	}{
		{name: "valid", text: `{"operationId":"restart_service","exitCode":0}`, hash: "approved-hash"},
		{name: "no plan for diagnose", text: `{"operationId":"restart_service","exitCode":0}`},
		{name: "denied", denied: true, wantErr: "denied or failed"},
		{name: "invalid result", text: `invalid`, wantErr: "no operation result"},
		{name: "missing operation", text: `{"exitCode":0}`, wantErr: "no operation result"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokenFile := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(tokenFile, []byte("test-workload"), 0600); err != nil {
				t.Fatal(err)
			}
			srv := mcp.NewServer(&mcp.Implementation{Name: "test-gateway", Version: "v1"}, nil)
			srv.AddTool(&mcp.Tool{Name: "restart_service", InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				var args map[string]any
				if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
					return nil, err
				}
				if args["runId"] != "run-1" {
					t.Error("run binding lost")
				}
				if tc.hash != "" && args["planHash"] != tc.hash {
					t.Error("plan hash binding lost")
				}
				if tc.hash == "" {
					if _, ok := args["planHash"]; ok {
						t.Error("unexpected plan hash")
					}
				}
				return &mcp.CallToolResult{IsError: tc.denied, Content: []mcp.Content{&mcp.TextContent{Text: tc.text}}}, nil
			})
			handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{JSONResponse: true, Stateless: true})
			h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-workload" {
					t.Error("workload identity missing")
				}
				handler.ServeHTTP(w, r)
			}))
			defer h.Close()
			c := NewToolGateway(h.URL, tokenFile, h.Client())
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			got, err := c.Execute(ctx, "run-1", "restart_service", tc.hash)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v", err)
				}
			} else if err != nil || got.OperationID != "restart_service" || got.ExitCode != 0 {
				t.Fatalf("result=%+v err=%v", got, err)
			}
		})
	}
}

func TestToolGatewayConnectionFailure(t *testing.T) {
	c := NewToolGateway("http://gateway", filepath.Join(t.TempDir(), "missing"), &http.Client{Timeout: time.Second})
	if _, err := c.Execute(t.Context(), "run", "health_check", ""); err == nil || !strings.Contains(err.Error(), "connect tool gateway") {
		t.Fatalf("error=%v", err)
	}
}

func TestSTSWorkloadIdentityFailuresAndHeaders(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantErr string
		status              int
		network             error
	}{
		{name: "allowed", body: `{"subject":"worker","namespace":"dendenmushi-agentic","serviceAccount":"incident-agent"}`, status: 200},
		{name: "denied", status: 403, wantErr: "status 403"},
		{name: "invalid", status: 200, body: `bad`, wantErr: "invalid character"},
		{name: "cancelled", network: context.Canceled, wantErr: "context canceled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: captureTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/workloads/validate" || r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("X-Request-ID") != "req-1" {
					t.Error("workload validation headers/path incorrect")
				}
				if tc.network != nil {
					return nil, tc.network
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}
			got, err := NewSTS("http://sts/", client).ValidateWorkload(observability.ContextWithRequestID(t.Context(), "req-1"), "test-token")
			if tc.wantErr == "" {
				if err != nil || got.Subject != "worker" || got.ServiceAccount != "incident-agent" {
					t.Fatalf("identity=%+v err=%v", got, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error=%v", err)
			}
			if tc.network != nil && !errors.Is(err, tc.network) {
				t.Fatal("lost cancellation cause")
			}
		})
	}
}
