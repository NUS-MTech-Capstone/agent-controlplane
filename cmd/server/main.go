package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/clients"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/config"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/events"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/httpapi"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/observability"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/service"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/store"
)

func main() {
	ctx := context.Background()
	observability.ConfigureLogger("agent-controlplane")
	cfg, err := config.Load(ctx)
	if err != nil {
		slog.Error("configuration failed", "error", err)
		os.Exit(1)
	}
	if cfg.DatabaseURL == "" {
		slog.Error("DATABASE_URL or DATABASE_SECRET_ID is required")
		os.Exit(1)
	}
	httpClient := &http.Client{Timeout: cfg.HTTPTimeout}
	db, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("database setup failed", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	identityVerifier, err := httpapi.NewALBJWTVerifier(httpapi.ALBJWTVerifierConfig{
		Region: cfg.AWSRegion, ALBARN: cfg.ALBARN, Issuer: cfg.CognitoIssuer, ClientID: cfg.CognitoClientID,
	})
	if err != nil {
		slog.Error("identity verifier setup failed", "error", err)
		os.Exit(1)
	}
	eventPublisher, err := events.NewPublisher(ctx, cfg.EventPublisher, cfg.AWSRegion, cfg.EventsTopicARN)
	if err != nil {
		slog.Error("metadata event publisher setup failed", "error", err)
		os.Exit(1)
	}
	svc := service.New(
		db,
		clients.NewSessionManager(cfg.SessionManagerURL, httpClient),
		clients.NewSTS(cfg.STSURL, httpClient),
		clients.NewDataplane(httpClient),
		clients.NewWorker(cfg.IncidentAgentURL, httpClient),
		cfg.WorkloadTokenFile,
		cfg.OperationTimeout,
		cfg.MaxOperationBytes,
		eventPublisher,
	)
	addr := ":" + cfg.Port
	slog.Info("server_listening", "addr", addr)
	server := &http.Server{
		Addr:              addr,
		Handler:           httpapi.New(svc, identityVerifier),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}
