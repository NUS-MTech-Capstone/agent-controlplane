package config

import (
	"context"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type Config struct {
	Port                  string
	DatabaseURL           string
	DatabaseSecretID      string
	AWSRegion             string
	STSURL                string
	SessionManagerURL     string
	IncidentAgentURL      string
	WorkloadTokenFile     string
	HTTPTimeout           time.Duration
	OperationTimeout      time.Duration
	MaxOperationBytes     int
	ALBARN                string
	CognitoIssuer         string
	CognitoClientID       string
	AutomationServiceName string
}

func Load(ctx context.Context) (Config, error) {
	region := env("AWS_REGION", "ap-southeast-1")
	userPoolID := os.Getenv("COGNITO_USER_POOL_ID")
	issuer := os.Getenv("COGNITO_ISSUER")
	if issuer == "" && userPoolID != "" {
		issuer = "https://cognito-idp." + region + ".amazonaws.com/" + userPoolID
	}
	cfg := Config{
		Port:                  env("PORT", "8092"),
		DatabaseURL:           os.Getenv("DATABASE_URL"),
		DatabaseSecretID:      os.Getenv("DATABASE_SECRET_ID"),
		AWSRegion:             region,
		STSURL:                env("STS_URL", "http://localhost:8082"),
		SessionManagerURL:     env("SESSION_MANAGER_URL", "http://localhost:8081"),
		IncidentAgentURL:      env("INCIDENT_AGENT_URL", "http://localhost:8091"),
		WorkloadTokenFile:     env("WORKLOAD_TOKEN_FILE", "/var/run/secrets/tokens/agent-controlplane-token"),
		HTTPTimeout:           secondsEnv("HTTP_TIMEOUT_SECONDS", 10),
		OperationTimeout:      secondsEnv("OPERATION_TIMEOUT_SECONDS", 45),
		MaxOperationBytes:     intEnv("MAX_OPERATION_OUTPUT_BYTES", 262144),
		ALBARN:                os.Getenv("ALB_ARN"),
		CognitoIssuer:         issuer,
		CognitoClientID:       os.Getenv("COGNITO_CLIENT_ID"),
		AutomationServiceName: "agent-controlplane",
	}
	if cfg.DatabaseURL == "" && cfg.DatabaseSecretID != "" {
		databaseURL, err := databaseURLFromSecret(ctx, cfg.DatabaseSecretID, cfg.AWSRegion)
		if err != nil {
			return cfg, err
		}
		cfg.DatabaseURL = databaseURL
	}
	return cfg, nil
}

func databaseURLFromSecret(ctx context.Context, secretID, region string) (string, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return "", err
	}
	resp, err := secretsmanager.NewFromConfig(awsCfg).GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &secretID,
	})
	if err != nil {
		return "", err
	}
	if resp.SecretString == nil {
		return "", nil
	}
	return *resp.SecretString, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func secondsEnv(key string, fallback int) time.Duration {
	value, err := strconv.Atoi(env(key, strconv.Itoa(fallback)))
	if err != nil || value <= 0 {
		value = fallback
	}
	return time.Duration(value) * time.Second
}

func intEnv(key string, fallback int) int {
	value, err := strconv.Atoi(env(key, strconv.Itoa(fallback)))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
