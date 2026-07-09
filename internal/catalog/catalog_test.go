package catalog

import "testing"

func TestIsRemediation(t *testing.T) {
	for _, operation := range RemediationOperations {
		if !IsRemediation(operation) {
			t.Fatalf("IsRemediation(%q) = false", operation)
		}
	}
	for _, operation := range []string{"health_check", "target_probe", "", "restart_service "} {
		if IsRemediation(operation) {
			t.Fatalf("IsRemediation(%q) = true", operation)
		}
	}
}
