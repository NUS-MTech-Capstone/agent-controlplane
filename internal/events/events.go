package events

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/observability"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
)

const SchemaVersion = "2026-07-ops-timeline.v1"

type Event struct {
	SchemaVersion string    `json:"schemaVersion"`
	EventID       string    `json:"eventId"`
	EventType     string    `json:"eventType"`
	Source        string    `json:"source"`
	OccurredAt    time.Time `json:"occurredAt"`
	RequestID     string    `json:"requestId,omitempty"`
	UserID        string    `json:"userId,omitempty"`
	HostID        string    `json:"hostId,omitempty"`
	IncidentID    string    `json:"incidentId,omitempty"`
	RunID         string    `json:"runId,omitempty"`
	Action        string    `json:"action,omitempty"`
	Outcome       string    `json:"outcome,omitempty"`
	ReasonCode    string    `json:"reasonCode,omitempty"`
	PlanHash      string    `json:"planHash,omitempty"`
}

type Publisher interface {
	Emit(context.Context, Event)
}

type NoopPublisher struct{}

func (NoopPublisher) Emit(context.Context, Event) {}

type SNSPublisher struct {
	topicARN string
	region   string
	creds    aws.CredentialsProvider
	client   *http.Client
}

func NewPublisher(ctx context.Context, enabled bool, region, topicARN string) (Publisher, error) {
	if !enabled {
		return NoopPublisher{}, nil
	}
	if topicARN == "" {
		return nil, errors.New("EVENTS_TOPIC_ARN is required when EVENT_PUBLISHER_ENABLED=true")
	}
	if region == "" {
		return nil, errors.New("AWS_REGION is required when EVENT_PUBLISHER_ENABLED=true")
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, err
	}
	return &SNSPublisher{topicARN: topicARN, region: region, creds: cfg.Credentials, client: &http.Client{Timeout: 2 * time.Second}}, nil
}

func (p *SNSPublisher) Emit(_ context.Context, event Event) {
	event.SchemaVersion = SchemaVersion
	if event.EventID == "" {
		event.EventID = newID()
	}
	if event.Source == "" {
		event.Source = "agent-controlplane"
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	if event.EventType == "" || event.EventID == "" || event.Source == "" {
		emitFailure("invalid_event")
		slog.Warn("MetadataEventInvalid", "eventType", event.EventType)
		return
	}
	data, err := json.Marshal(event)
	if err != nil {
		emitFailure("marshal_failed")
		slog.Warn("MetadataEventMarshalFailed", "eventType", event.EventType, "error", err)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := p.publish(ctx, string(data)); err != nil {
			emitFailure(observability.ErrorKind(err))
			slog.WarnContext(ctx, "MetadataEventPublishFailed", "eventId", event.EventID, "eventType", event.EventType, "error", err)
		}
	}()
}

func emitFailure(reason string) {
	observability.EmitMetric("agent-controlplane", []observability.Metric{{
		Name:  "MetadataEventPublishFailures",
		Unit:  "Count",
		Value: 1,
	}}, map[string]string{"Component": "event_publisher", "Reason": reason})
}

func (p *SNSPublisher) publish(ctx context.Context, message string) error {
	form := url.Values{}
	form.Set("Action", "Publish")
	form.Set("Version", "2010-03-31")
	form.Set("TopicArn", p.topicARN)
	form.Set("Message", message)
	body := []byte(form.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://sns."+p.region+".amazonaws.com/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sum := sha256.Sum256(body)
	creds, err := p.creds.Retrieve(ctx)
	if err != nil {
		return err
	}
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), "sns", p.region, time.Now().UTC()); err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("sns publish returned status %d", resp.StatusCode)
	}
	return nil
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
