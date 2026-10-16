# Agent Control Plane

Go service that owns DenDenMushi Agentic AI HTTP APIs and the internal bounded
automation run control bridge.

It does not proxy terminal streams. Live SSH traffic remains direct between the
browser, Proxy Dataplane, and target host. The service reads and writes the
existing incident-agent Postgres tables, while incident-agent continues to own
SQS ingestion, durable workflow coordination, and schema migrations. A private
Reasoning Agent owns model-backed triage and planning.

## Configuration

```text
PORT=8092
DATABASE_URL=
DATABASE_SECRET_ID=
AWS_REGION=ap-southeast-1
STS_URL=http://sts:8082
SESSION_MANAGER_URL=http://session-manager:8081
INCIDENT_AGENT_URL=http://incident-agent:8091
TOOL_GATEWAY_URL=http://agent-tool-gateway:8094/mcp
WORKLOAD_TOKEN_FILE=/var/run/secrets/tokens/agent-controlplane-token
HTTP_TIMEOUT_SECONDS=10
OPERATION_TIMEOUT_SECONDS=45
MAX_OPERATION_OUTPUT_BYTES=262144
ALB_ARN=
COGNITO_USER_POOL_ID=
COGNITO_ISSUER=
COGNITO_CLIENT_ID=
EVENT_PUBLISHER_ENABLED=false
EVENTS_TOPIC_ARN=
```

`DATABASE_SECRET_ID` should contain the raw Postgres connection URL. The
Kubernetes deployment uses IRSA to read that secret.

When `EVENT_PUBLISHER_ENABLED=true`, Agent Control Plane publishes sanitized
`PlanApproved`, `PlanRejected`, `RemediationExecuted`, and
`RemediationFailed` metadata events to the configured SNS topic after the
existing Postgres timeline write. Publish failures are logged and do not change
approval, rejection, remediation, verification, or run cleanup behavior. Events
include correlation fields such as `incidentId`, `runId`, `hostId`, `userId`,
and `planHash`, but never include prompts, raw model responses, tokens, command
bodies, terminal streams, or secrets.

## Endpoints

Public routes require ALB Cognito headers:

```http
GET  /agentic-ai/health
GET  /alerts
GET  /alerts/{alertId}
GET  /incidents
GET  /incidents/events
GET  /incidents/{incidentId}
POST /incidents/{incidentId}/approve
POST /incidents/{incidentId}/reject
```

Dashboard query parameters:

```text
/alerts?incidentId=&hostId=&status=&cloudwatchState=&from=&to=&limit=&cursor=
/incidents?incidentId=&alertId=&hostId=&state=&from=&to=&limit=&cursor=
/incidents/events?incidentId=&alertId=&eventType=&actor=&from=&to=&limit=&cursor=
```

`/incidents/events` returns metadata timeline events only. It must not return
model prompts, secrets, tokens, private keys, raw terminal streams, or
unrestricted command bodies.

Internal automation routes require projected workload bearer tokens:

```http
POST /automation/runs/start
POST /automation/runs/{runId}/token
POST /automation/runs/{runId}/close
```

Only the coordinator identity may start or close a run. The token route is
called by the Tool Gateway, and STS accepts automation capability issuance only
from the gateway identity. Diagnostics require a live `DIAGNOSING` incident;
remediation requires `EXECUTING`, the exact stored approved plan hash, and the
sole approved catalog action; verification requires the same run and plan plus
a fixed verification operation.

Operational routes:

```http
GET /healthz
GET /readyz
GET /openapi.yaml
```

Business endpoints require `x-api-version: 1`. `GET /healthz`, `GET /readyz`,
and `GET /openapi.yaml` are exempt so probes and spec reads do not need custom
headers.
Successful probe request logs are suppressed; failed probe responses still emit
request logs.

All HTTP responses use `Cache-Control: no-store`, disable MIME sniffing and
framing, and apply `Referrer-Policy: no-referrer`. The service does not emit
CORS allow headers: browser access is intentionally same-origin through the
public ALB.

## Safety Model

Approval and rejection require a Cognito user in `Manager` or `Admin`. Group names
come only from verified Cognito claims and are matched case-insensitively so legacy
pool groups such as `admin` retain the same canonical authorization boundary.
Approval checks the exact stored `planHash`, records an approval decision, and
requests only the single approved operation from the code-reviewed v1
remediation catalog through the MCP Tool Gateway, followed by bounded
verification operations. The Tool Gateway mediates operation execution.
Automation authority still comes from STS capability tokens and Session Manager run
assignment metadata; managers approve plans, they do not create runtime
actions.

Incident detail responses include an additive `explanation` object populated by
Incident Agent. It shows safe model metadata, catalog version, named runtime
agents, reasoning types, memory scope, tools, inputs, outputs, handoffs,
diagnostic and verification operation IDs, tool-selection reasons, guardrail
outcomes, and responsibility boundaries. `explanation.trace` is a versioned,
sanitized projection of append-only `incident_events`. Its `agentActions`
distinguish successful, failed, and deterministic-fallback A2A handoffs; its
`toolCalls` record diagnose, remediate, and verify operation IDs, selection
authority, status, duration, exit code, truncation, and a SHA-256 digest of the
already bounded/redacted result. Agent Control Plane joins selection reasons
from `toolDecisions`, orders trace entries chronologically, and reconstructs
diagnostic calls from stored evidence for older incidents when detailed event
metadata is unavailable. `GET /incidents/{incidentId}` and the incident nested
under `GET /alerts/{alertId}` use the same additive contract.

Remediation and verification attempts are written before normal failure
handling, so non-zero exits, timeouts, and transport errors remain visible.
Timeline metadata also covers automation token issuance and run closeout.
Tokens, command bodies, prompts, raw provider reasoning, unrestricted
arguments, secrets, and terminal streams are never returned.

The physical A2A boundary separates durable coordination from stateless model
reasoning, while the named workflow roles remain useful explainability labels.
Neither A2A nor MCP weakens the existing security model: model output remains
advisory, deterministic review and exact plan-hash approval remain mandatory,
and live terminal traffic still bypasses Agent Control Plane.

## Development

Executor evaluations in `internal/service/r12_evaluation_test.go` exercise the
service with simulated tools, authorization and session metadata. Run
`go test -json ./internal/service -run '^TestR12RoleCases$' -count=1` to emit
sanitized `R12_RECORD` results for the sibling Incident Agent evaluation runner.
The separately supplied workspace document
`capstone/documentation/R12_SIX_ROLE_EVALUATION.md` contains the evaluation results.

Automation runs close after execution on both success and failure, using a
separate context bounded by `OPERATION_TIMEOUT_SECONDS`. Cleanup records
`AutomationRunClosed` or `AutomationRunCloseFailed`; run TTL provides expiry.
Rejected execution requests preserve any other active run.

```bash
go test ./...
go run ./cmd/server
```

## API contract and CI

[OpenAPI contract](api/openapi.yaml), served byte-for-byte at `GET /openapi.yaml`.
CI validates it with `openapi-spec-validator==0.9.0`; handler tests check success,
error and API-version responses. Update the specification alongside handler changes.

After successful `main` CI, the Image workflow builds the tested source SHA
and opens a Kubernetes promotion PR with its immutable image digest. Argo CD
deploys after that PR is merged; the commit tag provides source traceability.
