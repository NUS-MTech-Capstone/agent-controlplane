# Agent Control Plane

Go service that owns DenDenMushi Agentic AI HTTP APIs and the internal bounded
automation run control bridge.

It does not proxy terminal streams. Live SSH traffic remains direct between the
browser, Proxy Dataplane, and target host. The service reads and writes the
existing incident-agent Postgres tables, while incident-agent continues to own
SQS ingestion, Bedrock triage, evidence gathering, and schema migrations.

## Configuration

```text
PORT=8092
DATABASE_URL=
DATABASE_SECRET_ID=
AWS_REGION=ap-southeast-1
STS_URL=http://sts:8082
SESSION_MANAGER_URL=http://session-manager:8081
INCIDENT_AGENT_URL=http://incident-agent:8091
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

Internal automation routes require workload or capability bearer tokens:

```http
POST /automation/runs/start
POST /automation/runs/{runId}/token
POST /automation/runs/{runId}/close
```

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

Approval and rejection require a Cognito user in `Manager` or `Admin`.
Approval checks the exact stored `planHash`, records an approval decision, and
executes only the single approved operation from the code-reviewed v1
remediation catalog, followed by bounded verification operations. Automation
authority still comes from STS capability tokens and Session Manager run
assignment metadata; managers approve plans, they do not create runtime
actions.

Incident detail responses include an additive `explanation` object populated by
Incident Agent. It shows safe model metadata, catalog version, named runtime
agents, reasoning types, memory scope, tools, inputs, outputs, handoffs,
diagnostic and verification operation IDs, tool-selection reasons, guardrail
outcomes, and responsibility boundaries. Agent Control Plane also records
timeline metadata for automation token issuance, approved operation execution,
verification operations, and automation run closeout. Tokens, command bodies,
prompts, raw model responses, secrets, and terminal streams are never returned.

The named agents are reportable runtime roles inside the bounded workflow:
Incident Manager Agent, Triage Agent, Evidence Collector Agent, Action Plan
Agent, Action Plan Reviewer Agent, and Remediation Executor Agent. They do not
weaken the existing security model: model output remains advisory, deterministic
review and exact plan-hash approval remain mandatory, and live terminal traffic
still bypasses Agent Control Plane.

## Development

```bash
go test ./...
go run ./cmd/server
```
