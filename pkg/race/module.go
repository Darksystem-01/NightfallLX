package race

import (
	"fmt"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/modules"
)

// Module implements modules.Module for race condition testing.
type Module struct{}

func NewModule() *Module {
	return &Module{}
}

func (m *Module) Name() string {
	return "race"
}

func (m *Module) Description() string {
	return "Tests endpoints for race conditions, double-spend, and limit bypass using nanosecond burst requests"
}

func (m *Module) Run(target *modules.Target, c *client.Client) ([]*modules.Finding, error) {
	var body string
	if len(target.Data) > 0 {
		body = target.BuildDataWithParam("", "")
	}

	headers := make(map[string]string)
	for k, v := range target.Headers {
		headers[k] = v
	}
	if c.Cookie != "" {
		headers["Cookie"] = c.Cookie
	}

	cfg := RaceConfig{
		URL:      target.URL,
		Method:   target.Method,
		Body:     body,
		Headers:  headers,
		Threads:  15,
		Rounds:   2,
		Insecure: c.Insecure,
	}

	report, err := Run(cfg)
	if err != nil {
		return nil, err
	}

	var findings []*modules.Finding
	if report.AnomalyDetected {
		findings = append(findings, &modules.Finding{
			Module:      m.Name(),
			Title:       "Race Condition / Concurrency Collision Identified",
			Severity:    modules.SeverityHigh,
			Confidence:  85,
			URL:         target.URL,
			Parameter:   "burst",
			Payload:     fmt.Sprintf("%d parallel requests", cfg.Threads),
			Detail:      report.AnomalyReason,
			Evidence:    fmt.Sprintf("Status distributions: %v, Body hash variants: %d", report.UniqueStatuses, len(report.UniqueBodyHashes)),
			Remediation: "Implement database-level atomic operations, distributed locks (e.g. Redis Redlock), or strict mutex concurrency controls.",
			CWEID:       362, // Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
			CVSS:        7.5,
		})
	}

	return findings, nil
}
