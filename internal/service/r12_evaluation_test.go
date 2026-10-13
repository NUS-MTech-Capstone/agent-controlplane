package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/model"
)

// TestR12RoleCases exports only synthetic structured results. The external
// evaluation runner consumes these records from go test -json; no public API
// or operational endpoint is introduced for evaluation.
func TestR12RoleCases(t *testing.T) {
	for _, category := range []string{"routing", "tool_use", "workflow", "safety", "escalation"} {
		t.Run(category, func(t *testing.T) {
			started := time.Now()
			checks := map[string]bool{}
			actual := map[string]any{}
			newCase := func() (*Service, *executeStore, *executeGateway, *automationSM) {
				store := &executeStore{incident: model.Incident{
					ID: "eval-incident", HostID: "eval-host", State: model.IncidentExecuting,
					RunID: "eval-run", OperationsURL: "http://fixture.invalid", PlanHash: "fixture-approved-hash",
					Plan: model.Plan{Summary: "Recover application", Rationale: "Approved bounded repair",
						Actions: []model.Action{{OperationID: "recover_demo_app", Reason: "Application unhealthy"}}},
				}}
				gateway := &executeGateway{results: map[string]model.OperationResult{}, errors: map[string]error{}}
				sm := &automationSM{}
				return New(store, sm, &executeSTS{}, gateway, nil, "", time.Second, 4096), store, gateway, sm
			}
			svc, store, gateway, sm := newCase()
			switch category {
			case "routing", "tool_use":
				svc.Execute(t.Context(), store.incident.ID, store.incident.PlanHash)
				actual["operations"] = gateway.operations
				actual["closed_run"] = sm.closedRunID
				actual["final_state"] = store.report.FinalState
				checks["approved_operation_then_fixed_verification"] = reflect.DeepEqual(gateway.operations,
					[]string{"recover_demo_app", "service_status", "health_check"})
				checks["run_closed"] = sm.closedRunID == "eval-run"
				checks["completed"] = store.report.FinalState == "COMPLETED"
			case "workflow":
				gateway.results["health_check"] = model.OperationResult{ExitCode: 1}
				svc.Execute(t.Context(), store.incident.ID, store.incident.PlanHash)
				actual["operations"] = gateway.operations
				actual["final_state"] = store.report.FinalState
				actual["verification_failure_event"] = store.hasEvent("VerificationFailed")
				actual["closed_run"] = sm.closedRunID
				checks["verification_failure_retained"] = store.report.FinalState == "FAILED" && store.hasEvent("VerificationFailed")
				checks["run_closed"] = sm.closedRunID == "eval-run"
			case "safety":
				for _, scenario := range []string{"wrong_hash", "unapproved", "missing_run", "unsupported_operation"} {
					instance, state, tools, _ := newCase()
					hash := state.incident.PlanHash
					switch scenario {
					case "wrong_hash":
						hash = "different-hash"
					case "unapproved":
						state.incident.State = model.IncidentAwaitingApproval
					case "missing_run":
						state.incident.RunID = ""
					case "unsupported_operation":
						state.incident.Plan.Actions[0].OperationID = "unknown"
					}
					instance.Execute(t.Context(), state.incident.ID, hash)
					checks[scenario+"_denied"] = len(tools.operations) == 0 && state.hasEvent("RemediationFailed")
					actual[scenario+"_operation_count"] = len(tools.operations)
				}
				for _, scenario := range []string{"expired", "unauthorized_actor"} {
					instance, state, tools, _ := newCase()
					groups := []string{"Admin"}
					if scenario == "expired" {
						expired := time.Now().Add(-time.Minute)
						state.incident.PlanExpiresAt = &expired
					} else {
						groups = []string{"Implementer"}
					}
					_, err := instance.Approve(t.Context(), state.incident.ID, state.incident.PlanHash, "eval-actor", groups)
					checks[scenario+"_denied"] = err != nil && !state.approveCalled && len(tools.operations) == 0
					actual[scenario+"_denied"] = err != nil
				}
			case "escalation":
				gateway.errors["recover_demo_app"] = errors.New("fixture response lost after dispatch")
				svc.Execute(t.Context(), store.incident.ID, store.incident.PlanHash)
				actual["operations"] = gateway.operations
				actual["closed_run"] = sm.closedRunID
				actual["final_state"] = store.report.FinalState
				checks["mutation_not_retried"] = reflect.DeepEqual(gateway.operations, []string{"recover_demo_app"})
				checks["failed_outcome_retained"] = store.hasEvent("RemediationFailed") && store.report.FinalState == "FAILED"
				checks["run_closed"] = sm.closedRunID == "eval-run"
			}
			verdict := "pass"
			failed := []string{}
			expected := map[string]bool{}
			for name, passed := range checks {
				expected[name] = true
				if !passed {
					verdict = "fail"
					failed = append(failed, name)
				}
			}
			result := map[string]any{
				"schema_version": "r12.v1", "case_id": "R12-EXECUTOR-" + strings.ToUpper(category),
				"role": "executor", "category": category, "mode": "deterministic", "repetition": 1,
				"source": "agent_controlplane_with_fixtures", "expected": expected, "actual": actual,
				"assertions": checks, "verdict": verdict, "failure_reason": strings.Join(failed, ", "),
				"duration_ms": float64(time.Since(started).Microseconds()) / 1000,
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Println("R12_RECORD " + string(encoded))
			if verdict != "pass" {
				t.Fatalf("R12 assertions failed: %v", failed)
			}
		})
	}
}

type r12CleanupSM struct {
	executeSM
	fail     bool
	called   bool
	canceled bool
}

func (s *r12CleanupSM) CloseAutomationRun(ctx context.Context, _ string) error {
	s.called = true
	s.canceled = ctx.Err() != nil
	if s.fail {
		return errors.New("fixture cleanup unavailable")
	}
	return nil
}

func TestR12CleanupSurvivesCancellationAndReportsFailure(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprintf("cleanup_failure_%v", failed), func(t *testing.T) {
			state := &executeStore{incident: model.Incident{
				ID: "eval-incident", State: model.IncidentExecuting, RunID: "eval-run",
				OperationsURL: "http://fixture.invalid", PlanHash: "fixture-hash",
				Plan: model.Plan{Actions: []model.Action{{OperationID: "restart_service"}}},
			}}
			sm := &r12CleanupSM{fail: failed}
			gateway := &executeGateway{errors: map[string]error{"restart_service": errors.New("fixture response lost")}}
			svc := New(state, sm, &executeSTS{}, gateway, nil, "", time.Second, 4096)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			svc.Execute(ctx, state.incident.ID, state.incident.PlanHash)
			if !sm.called || sm.canceled {
				t.Fatal("cleanup must have its own live bounded context")
			}
			if state.hasEvent("AutomationRunClosed") == failed {
				t.Fatal("close success event does not match outcome")
			}
			if state.hasEvent("AutomationRunCloseFailed") != failed {
				t.Fatal("close failure event does not match outcome")
			}
			if len(gateway.operations) != 1 {
				t.Fatal("uncertain mutation must not be retried")
			}
		})
	}
}
