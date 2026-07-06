package catalog

const Version = "v1"

var DiagnosticOperations = []string{
	"system_overview",
	"disk_usage",
	"memory_usage",
	"top_processes",
	"service_status",
	"service_logs",
	"health_check",
	"target_probe",
}

var RemediationOperations = []string{
	"restart_service",
	"recover_demo_app",
	"reload_service",
}

var VerifyOperations = []string{
	"service_status",
	"health_check",
}

func IsRemediation(operation string) bool {
	for _, candidate := range RemediationOperations {
		if operation == candidate {
			return true
		}
	}
	return false
}
