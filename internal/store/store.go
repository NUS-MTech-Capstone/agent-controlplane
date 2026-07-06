package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func New(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	return &Store{pool: pool, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

func (s *Store) ListAlerts(ctx context.Context, filter model.AlertFilter) ([]model.ManagedAlert, error) {
	if filter.Limit <= 0 || filter.Limit > 200 {
		filter.Limit = 100
	}
	rows, err := s.pool.Query(ctx, `select id, source_id, source_type, alarm_arn, alarm_name, cloudwatch_state,
host_id, reason, status, group_key, incident_id, grouped, error_summary, occurred_at, created_at, updated_at
from alerts
where ($1 = '' or incident_id = $1)
	and ($2 = '' or host_id = $2)
	and ($3 = '' or status = $3)
	and ($4 = '' or cloudwatch_state = $4)
	and ($5::timestamptz is null or occurred_at >= $5)
	and ($6::timestamptz is null or occurred_at <= $6)
order by occurred_at desc, id
limit $7 offset $8`, filter.IncidentID, filter.HostID, filter.Status, filter.CloudWatchState,
		nullableTime(filter.From), nullableTime(filter.To), filter.Limit, filter.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var alerts []model.ManagedAlert
	for rows.Next() {
		alert, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, alert)
	}
	return alerts, rows.Err()
}

func (s *Store) GetAlert(ctx context.Context, alertID string) (model.ManagedAlert, error) {
	row := s.pool.QueryRow(ctx, `select id, source_id, source_type, alarm_arn, alarm_name, cloudwatch_state,
host_id, reason, status, group_key, incident_id, grouped, error_summary, occurred_at, created_at, updated_at
from alerts where id=$1`, alertID)
	alert, err := scanAlert(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.ManagedAlert{}, ErrNotFound
	}
	return alert, err
}

func (s *Store) ListIncidents(ctx context.Context, filter model.IncidentFilter) ([]model.Incident, error) {
	if filter.Limit <= 0 || filter.Limit > 200 {
		filter.Limit = 100
	}
	rows, err := s.pool.Query(ctx, incidentSelect()+`
where ($1 = '' or id = $1)
	and ($2 = '' or host_id = $2)
	and ($3 = '' or state = $3)
	and ($4::timestamptz is null or created_at >= $4)
	and ($5::timestamptz is null or created_at <= $5)
	and ($6 = '' or exists (select 1 from alerts where alerts.incident_id = incidents.id and alerts.id = $6))
order by created_at desc, id
limit $7 offset $8`, filter.IncidentID, filter.HostID, filter.State,
		nullableTime(filter.From), nullableTime(filter.To), filter.AlertID, filter.Limit, filter.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var incidents []model.Incident
	for rows.Next() {
		incident, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		incidents = append(incidents, incident)
	}
	return incidents, rows.Err()
}

func (s *Store) GetIncident(ctx context.Context, incidentID string) (model.Incident, error) {
	incident, err := scanIncident(s.pool.QueryRow(ctx, incidentSelect()+` where id=$1`, incidentID))
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Incident{}, ErrNotFound
	}
	return incident, err
}

func (s *Store) ListEvents(ctx context.Context, incidentID string) ([]model.IncidentEvent, error) {
	rows, err := s.pool.Query(ctx, `select id, incident_id, alert_id, event_type, actor, message,
metadata_json, created_at from incident_events where incident_id=$1 order by created_at asc`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []model.IncidentEvent
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) ListIncidentEvents(ctx context.Context, filter model.IncidentEventFilter) ([]model.IncidentEvent, error) {
	if filter.Limit <= 0 || filter.Limit > 200 {
		filter.Limit = 100
	}
	rows, err := s.pool.Query(ctx, `select id, incident_id, alert_id, event_type, actor, message,
metadata_json, created_at from incident_events
where ($1 = '' or incident_id = $1)
	and ($2 = '' or alert_id = $2)
	and ($3 = '' or event_type = $3)
	and ($4 = '' or actor = $4)
	and ($5::timestamptz is null or created_at >= $5)
	and ($6::timestamptz is null or created_at <= $6)
order by created_at desc, id
limit $7 offset $8`, filter.IncidentID, filter.AlertID, filter.EventType, filter.Actor,
		nullableTime(filter.From), nullableTime(filter.To), filter.Limit, filter.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []model.IncidentEvent
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) ListApprovalDecisions(ctx context.Context, incidentID string) ([]model.ApprovalDecisionAudit, error) {
	rows, err := s.pool.Query(ctx, `select id, incident_id, actor, decision, submitted_plan_hash, outcome,
error_reason, created_at from approval_decisions where incident_id=$1 order by created_at asc`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var decisions []model.ApprovalDecisionAudit
	for rows.Next() {
		decision, err := scanApprovalDecision(rows)
		if err != nil {
			return nil, err
		}
		decisions = append(decisions, decision)
	}
	return decisions, rows.Err()
}

func (s *Store) IncidentCounts(ctx context.Context) (int, int, error) {
	rows, err := s.pool.Query(ctx, `select state from incidents`)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	active, failed := 0, 0
	for rows.Next() {
		var state string
		if err := rows.Scan(&state); err != nil {
			return 0, 0, err
		}
		switch model.IncidentState(state) {
		case model.IncidentDiagnosing, model.IncidentAwaitingApproval, model.IncidentExecuting:
			active++
		case model.IncidentFailed:
			failed++
		}
	}
	return active, failed, rows.Err()
}

func (s *Store) LastAlertProcessedAt(ctx context.Context) (*time.Time, error) {
	var ts time.Time
	err := s.pool.QueryRow(ctx, `select updated_at from alerts order by updated_at desc limit 1`).Scan(&ts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ts, nil
}

func (s *Store) CreateEvent(ctx context.Context, incidentID, eventType, alertID, actor, message string, metadata map[string]any) (model.IncidentEvent, error) {
	now := s.now()
	id := "evt-" + randomHex(16)
	if metadata == nil {
		metadata = map[string]any{}
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return model.IncidentEvent{}, err
	}
	_, err = s.pool.Exec(ctx, `insert into incident_events
(id, incident_id, alert_id, event_type, actor, message, metadata_json, created_at)
values ($1,$2,$3,$4,$5,$6,$7,$8)`, id, incidentID, alertID, eventType, actor, message, data, now)
	if err != nil {
		return model.IncidentEvent{}, err
	}
	return model.IncidentEvent{
		ID: id, IncidentID: incidentID, AlertID: alertID, EventType: eventType,
		Actor: actor, Message: message, Metadata: metadata, CreatedAt: now,
	}, nil
}

func (s *Store) CreateApprovalDecision(ctx context.Context, incidentID, decision, planHash, actor string, outcome model.ApprovalOutcome, reason string) error {
	_, err := s.pool.Exec(ctx, `insert into approval_decisions
(id, incident_id, actor, decision, submitted_plan_hash, outcome, error_reason, created_at)
values ($1,$2,$3,$4,$5,$6,$7,$8)`,
		"appr-"+randomHex(16), incidentID, actor, decision, planHash, string(outcome), reason, s.now())
	return err
}

func (s *Store) Approve(ctx context.Context, incidentID, planHash, subject string) error {
	tag, err := s.pool.Exec(ctx, `update incidents set state=$1, approver_subject=$2,
approval_decision=$3, approval_at=$4, updated_at=$4
where id=$5 and state=$6 and plan_hash=$7`,
		string(model.IncidentExecuting), subject, "APPROVED", s.now(), incidentID, string(model.IncidentAwaitingApproval), planHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}

func (s *Store) Reject(ctx context.Context, incident model.Incident, planHash, subject string) error {
	now := s.now()
	report := model.PostIncidentReport{
		RootCauseSummary:    rootCauseSummary(incident),
		ActionTaken:         "Plan rejected before remediation.",
		VerificationSummary: "No remediation was executed.",
		FinalState:          string(model.IncidentRejected),
		ResolvedAt:          &now,
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `update incidents set state=$1, approver_subject=$2,
approval_decision=$3, approval_at=$4, report=$5, report_json=$6, error_message='', updated_at=$4
where id=$7 and state=$8 and plan_hash=$9`,
		string(model.IncidentRejected), subject, "REJECTED", now,
		"Remediation plan was rejected by a manager.", reportJSON,
		incident.ID, string(model.IncidentAwaitingApproval), planHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}

func (s *Store) SetAlertStatusForIncident(ctx context.Context, incidentID string, status model.AlertStatus, errorSummary string) error {
	_, err := s.pool.Exec(ctx, `update alerts set status=$1, error_summary=$2, updated_at=$3 where incident_id=$4`,
		string(status), errorSummary, s.now(), incidentID)
	return err
}

func (s *Store) SetIncidentReport(ctx context.Context, incidentID string, state model.IncidentState, report, errorMessage string, structured model.PostIncidentReport) error {
	reportJSON, err := json.Marshal(structured)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `update incidents set state=$1, report=$2, error_message=$3,
report_json=$4, updated_at=$5 where id=$6`, string(state), report, errorMessage, reportJSON, s.now(), incidentID)
	return err
}

func (s *Store) SetFailure(ctx context.Context, incidentID, message string) error {
	tag, err := s.pool.Exec(ctx, `update incidents set state=$1, error_message=$2, updated_at=$3
where id=$4 and state in ($5,$6)`, string(model.IncidentFailed), message, s.now(),
		incidentID, string(model.IncidentDiagnosing), string(model.IncidentExecuting))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}

func incidentSelect() string {
	return `select id, source_id, alarm_arn, alarm_name, host_id, runbook_version, state, reason,
run_id, operations_url, evidence_json, triage_json, plan_json, plan_hash, explanation_json, plan_expires_at,
approver_subject, approval_decision, approval_at, report, report_json, error_message, created_at, updated_at from incidents`
}

type scanner interface {
	Scan(dest ...any) error
}

func scanAlert(row scanner) (model.ManagedAlert, error) {
	var alert model.ManagedAlert
	var status string
	err := row.Scan(&alert.ID, &alert.SourceID, &alert.SourceType, &alert.AlarmARN, &alert.AlarmName,
		&alert.CloudWatchState, &alert.HostID, &alert.Reason, &status, &alert.GroupKey,
		&alert.IncidentID, &alert.Grouped, &alert.ErrorSummary, &alert.OccurredAt,
		&alert.CreatedAt, &alert.UpdatedAt)
	alert.Status = model.AlertStatus(status)
	return alert, err
}

func scanIncident(row scanner) (model.Incident, error) {
	var incident model.Incident
	var state string
	var evidenceJSON, triageJSON, planJSON, explanationJSON, reportJSON []byte
	err := row.Scan(&incident.ID, &incident.SourceID, &incident.AlarmARN, &incident.AlarmName,
		&incident.HostID, &incident.RunbookVersion, &state, &incident.Reason, &incident.RunID,
		&incident.OperationsURL, &evidenceJSON, &triageJSON, &planJSON, &incident.PlanHash,
		&explanationJSON, &incident.PlanExpiresAt, &incident.ApproverSubject, &incident.ApprovalDecision,
		&incident.ApprovalAt, &incident.Report, &reportJSON, &incident.ErrorMessage,
		&incident.CreatedAt, &incident.UpdatedAt)
	if err != nil {
		return incident, err
	}
	incident.State = model.IncidentState(state)
	_ = json.Unmarshal(defaultJSON(evidenceJSON, "[]"), &incident.Evidence)
	_ = json.Unmarshal(defaultJSON(planJSON, "{}"), &incident.Plan)
	_ = json.Unmarshal(defaultJSON(explanationJSON, "{}"), &incident.Explanation)
	if len(triageJSON) > 0 && string(triageJSON) != "{}" {
		var triage model.TriageResult
		if err := json.Unmarshal(triageJSON, &triage); err == nil {
			incident.Triage = &triage
		}
	}
	_ = json.Unmarshal(defaultJSON(reportJSON, "{}"), &incident.PostIncidentReport)
	return incident, nil
}

func scanEvent(row scanner) (model.IncidentEvent, error) {
	var event model.IncidentEvent
	var metadataJSON []byte
	err := row.Scan(&event.ID, &event.IncidentID, &event.AlertID, &event.EventType,
		&event.Actor, &event.Message, &metadataJSON, &event.CreatedAt)
	if err != nil {
		return event, err
	}
	event.Metadata = map[string]any{}
	_ = json.Unmarshal(defaultJSON(metadataJSON, "{}"), &event.Metadata)
	return event, nil
}

func scanApprovalDecision(row scanner) (model.ApprovalDecisionAudit, error) {
	var decision model.ApprovalDecisionAudit
	var outcome string
	err := row.Scan(&decision.ID, &decision.IncidentID, &decision.Actor, &decision.Decision,
		&decision.SubmittedPlanHash, &outcome, &decision.ErrorReason, &decision.CreatedAt)
	decision.Outcome = model.ApprovalOutcome(outcome)
	return decision, err
}

func defaultJSON(data []byte, fallback string) []byte {
	if len(data) == 0 {
		return []byte(fallback)
	}
	return data
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(buf)
}

func rootCauseSummary(incident model.Incident) string {
	if incident.Triage != nil && incident.Triage.Summary != "" {
		return incident.Triage.Summary
	}
	return incident.Reason
}
