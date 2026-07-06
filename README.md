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
```

`DATABASE_SECRET_ID` should contain the raw Postgres connection URL. The
Kubernetes deployment uses IRSA to read that secret.

## Endpoints

Public routes require ALB Cognito headers:

```http
GET  /agentic-ai/health
GET  /alerts
GET  /alerts/{alertId}
GET  /incidents
GET  /incidents/{incidentId}
POST /incidents/{incidentId}/approve
POST /incidents/{incidentId}/reject
```

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

## Safety Model

Approval and rejection require a Cognito user in `Manager` or `Admin`.
Approval checks the exact stored `planHash`, records an approval decision, and
only executes the fixed `restart_service` operation followed by bounded
verification operations. Automation authority still comes from STS capability
tokens and Session Manager run assignment metadata.

## Development

```bash
go test ./...
go run ./cmd/server
```

