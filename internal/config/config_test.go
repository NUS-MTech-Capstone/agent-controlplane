package config

import (
	"context"
	"testing"
	"time"
)

func TestLoadDefaultsAndDerivedIssuer(t *testing.T) {
	t.Setenv("AWS_REGION", "us-west-2")
	t.Setenv("COGNITO_USER_POOL_ID", "pool-1")

	cfg, err := Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Port != "8092" || cfg.STSURL != "http://localhost:8082" ||
		cfg.SessionManagerURL != "http://localhost:8081" || cfg.IncidentAgentURL != "http://localhost:8091" {
		t.Fatalf("defaults = %#v", cfg)
	}
	if cfg.CognitoIssuer != "https://cognito-idp.us-west-2.amazonaws.com/pool-1" {
		t.Fatalf("CognitoIssuer = %q", cfg.CognitoIssuer)
	}
	if cfg.HTTPTimeout != 10*time.Second || cfg.OperationTimeout != 45*time.Second || cfg.MaxOperationBytes != 262144 {
		t.Fatalf("timeouts/limits = %#v", cfg)
	}
}

func TestLoadParsesOverridesAndFallbacks(t *testing.T) {
	t.Setenv("PORT", "9092")
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("STS_URL", "http://sts")
	t.Setenv("SESSION_MANAGER_URL", "http://session-manager")
	t.Setenv("INCIDENT_AGENT_URL", "http://incident-agent")
	t.Setenv("WORKLOAD_TOKEN_FILE", "/tmp/token")
	t.Setenv("HTTP_TIMEOUT_SECONDS", "bad")
	t.Setenv("OPERATION_TIMEOUT_SECONDS", "60")
	t.Setenv("MAX_OPERATION_OUTPUT_BYTES", "-1")
	t.Setenv("COGNITO_ISSUER", "https://issuer")
	t.Setenv("ALB_ARN", "alb")
	t.Setenv("COGNITO_CLIENT_ID", "client")
	t.Setenv("EVENT_PUBLISHER_ENABLED", "true")
	t.Setenv("EVENTS_TOPIC_ARN", "topic")

	cfg, err := Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Port != "9092" || cfg.DatabaseURL != "postgres://example" || cfg.STSURL != "http://sts" ||
		cfg.SessionManagerURL != "http://session-manager" || cfg.IncidentAgentURL != "http://incident-agent" ||
		cfg.WorkloadTokenFile != "/tmp/token" || cfg.CognitoIssuer != "https://issuer" ||
		cfg.ALBARN != "alb" || cfg.CognitoClientID != "client" || !cfg.EventPublisher ||
		cfg.EventsTopicARN != "topic" {
		t.Fatalf("Load() = %#v", cfg)
	}
	if cfg.HTTPTimeout != 10*time.Second || cfg.OperationTimeout != 60*time.Second || cfg.MaxOperationBytes != 262144 {
		t.Fatalf("fallbacks = %#v", cfg)
	}
}

func TestEnvHelpersRejectInvalidValues(t *testing.T) {
	t.Setenv("SECONDS", "0")
	t.Setenv("INT", "not-an-int")
	t.Setenv("BOOL", "not-a-bool")

	if got := secondsEnv("SECONDS", 7); got != 7*time.Second {
		t.Fatalf("secondsEnv() = %v", got)
	}
	if got := intEnv("INT", 99); got != 99 {
		t.Fatalf("intEnv() = %d", got)
	}
	if got := boolEnv("BOOL", true); !got {
		t.Fatalf("boolEnv() = false, want fallback true")
	}
}
