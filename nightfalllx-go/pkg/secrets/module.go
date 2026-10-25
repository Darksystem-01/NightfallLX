package secrets

import (
	"fmt"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/modules"
)

// Module implements modules.Module for secret detection.
type Module struct {
	scanner *SecretScanner
}

func NewModule() *Module {
	return &Module{
		scanner: NewSecretScanner(),
	}
}

func (m *Module) Name() string {
	return "secrets"
}

func (m *Module) Description() string {
	return "Scans HTML, API responses, and client-side JS for exposed credentials & API keys"
}

func (m *Module) Run(target *modules.Target, c *client.Client) ([]*modules.Finding, error) {
	secretFindings, err := m.scanner.ScanURL(c, target.URL)
	if err != nil {
		return nil, err
	}

	var results []*modules.Finding
	for _, sf := range secretFindings {
		var sev modules.Severity
		switch sf.Severity {
		case "CRITICAL":
			sev = modules.SeverityCritical
		case "HIGH":
			sev = modules.SeverityHigh
		case "MEDIUM":
			sev = modules.SeverityMedium
		default:
			sev = modules.SeverityLow
		}

		results = append(results, &modules.Finding{
			Module:      m.Name(),
			Title:       fmt.Sprintf("Exposed Credential: %s", sf.Pattern),
			Severity:    sev,
			Confidence:  sf.Confidence,
			URL:         sf.URL,
			Parameter:   "body",
			Payload:     sf.Match,
			Detail:      fmt.Sprintf("Identified confidential token of type '%s'. %s", sf.Pattern, sf.Context),
			Evidence:    sf.Match,
			Remediation: sf.Remediation,
			CWEID:       798, // Use of Hard-coded Credentials
			CVSS:        7.5,
		})
	}

	return results, nil
}
