package store

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/model"
)

func TestPureStoreHelpers(t *testing.T) {
	if got := string(defaultJSON(nil, "{}")); got != "{}" {
		t.Fatalf("defaultJSON(nil) = %q", got)
	}
	if got := string(defaultJSON([]byte(`{"ok":true}`), "{}")); got != `{"ok":true}` {
		t.Fatalf("defaultJSON(non-empty) = %q", got)
	}
	if got := nullableTime(time.Time{}); got != nil {
		t.Fatalf("nullableTime(zero) = %#v", got)
	}
	now := time.Date(2026, 7, 6, 1, 0, 0, 0, time.UTC)
	if got := nullableTime(now); got != now {
		t.Fatalf("nullableTime(non-zero) = %#v", got)
	}
	incident := model.Incident{Reason: "alarm reason", Triage: &model.TriageResult{Summary: "triage summary"}}
	if got := rootCauseSummary(incident); got != "triage summary" {
		t.Fatalf("rootCauseSummary() = %q", got)
	}
	incident.Triage = nil
	if got := rootCauseSummary(incident); got != "alarm reason" {
		t.Fatalf("rootCauseSummary() fallback = %q", got)
	}
	id := randomHex(8)
	if len(id) != 16 {
		t.Fatalf("randomHex length = %d", len(id))
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Fatalf("randomHex is not hex: %v", err)
	}
}
