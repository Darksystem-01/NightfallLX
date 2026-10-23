package modules

import (
	"fmt"
	"nightfalllx/pkg/client"
	"strings"
)

type CORSModule struct{}

func NewCORSModule() *CORSModule {
	return &CORSModule{}
}

func (m *CORSModule) Name() string {
	return "cors"
}

func (m *CORSModule) Description() string {
	return "Cross-Origin Resource Sharing (CORS) misconfiguration detector"
}

func (m *CORSModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding

	testOrigins := []struct {
		Label  string
		Origin string
	}{
		{"Arbitrary Origin", "https://attacker-nightfall.lab"},
		{"Null Origin", "null"},
		{"Pre-domain Bypass", target.URL + ".attacker.lab"},
	}

	for _, item := range testOrigins {
		headers := map[string]string{
			"Origin": item.Origin,
		}

		resp, err := c.Request("GET", target.URL, "", headers)
		if err != nil || resp == nil {
			continue
		}

		acao := resp.Headers.Get("Access-Control-Allow-Origin")
		acac := strings.ToLower(resp.Headers.Get("Access-Control-Allow-Credentials"))

		if acao == "" {
			continue
		}

		// Vulnerable case 1: Origin reflected + credentials allowed
		if (acao == item.Origin || acao == "*") && acac == "true" {
			f := &Finding{
				Module:      m.Name(),
				Title:       fmt.Sprintf("CORS Misconfiguration (Creds Allowed with %s)", item.Label),
				Severity:    SeverityHigh,
				URL:         target.URL,
				Parameter:   "Header: Origin",
				Payload:     fmt.Sprintf("Origin: %s", item.Origin),
				Detail:      fmt.Sprintf("Server dynamically reflects arbitrary origin '%s' while permitting authenticated credentials (ACAC: true).", acao),
				Evidence:    fmt.Sprintf("ACAO: %s, ACAC: %s", acao, acac),
				Remediation: "Implement an allowlist of trusted origins. Never dynamically reflect untrusted origins with Access-Control-Allow-Credentials: true.",
				CWEID:       942,
			}
			if acao == item.Origin && acac == "true" {
				f.SetConfidence(ConfidenceConfirmed)
			} else {
				f.SetConfidence(ConfidenceProbable)
			}
			findings = append(findings, f)
			break
		}

		// Vulnerable case 2: Origin null trusted
		if item.Origin == "null" && acao == "null" {
			f := &Finding{
				Module:      m.Name(),
				Title:       "CORS Misconfiguration (Null Origin Allowed)",
				Severity:    SeverityMedium,
				URL:         target.URL,
				Parameter:   "Header: Origin",
				Payload:     "Origin: null",
				Detail:      "Server trusts the 'null' origin, which can be triggered via sandboxed iframes or data URIs.",
				Evidence:    fmt.Sprintf("ACAO: %s", acao),
				Remediation: "Disallow the 'null' origin in CORS configuration.",
				CWEID:       942,
			}
			f.SetConfidence(ConfidenceProbable)
			findings = append(findings, f)
			break
		}
	}

	return findings, nil
}
