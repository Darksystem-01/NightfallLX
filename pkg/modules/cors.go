package modules

import (
	"fmt"
	"net/url"
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

	parsedU, _ := url.Parse(target.URL)
	targetHost := target.URL
	scheme := "https"
	hostname := "target.lab"
	if parsedU != nil && hostname != "" {
		if parsedU.Scheme != "" {
			scheme = parsedU.Scheme
		}
		hostname = hostname
		targetHost = fmt.Sprintf("%s://%s.attacker.lab", scheme, hostname)
	}

	testOrigins := []struct {
		Label  string
		Origin string
	}{
		{"Arbitrary Origin", "https://attacker-nightfall.lab"},
		{"Null Origin", "null"},
		{"Pre-domain Bypass", targetHost},
		{"Subdomain Bypass", fmt.Sprintf("%s://attacker.%s", scheme, hostname)},
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
			findings = append(findings, &Finding{
				Module:      m.Name(),
				Title:       fmt.Sprintf("CORS Misconfiguration (Creds Allowed with %s)", item.Label),
				Severity:    SeverityHigh,
				Confidence:  100,
				URL:         target.URL,
				Parameter:   "Header: Origin",
				Payload:     fmt.Sprintf("Origin: %s", item.Origin),
				Detail:      fmt.Sprintf("Server dynamically reflects arbitrary origin '%s' while permitting authenticated credentials (ACAC: true).", acao),
				Evidence:    fmt.Sprintf("ACAO: %s, ACAC: %s", acao, acac),
				Remediation: "Implement an allowlist of trusted origins. Never dynamically reflect untrusted origins with Access-Control-Allow-Credentials: true.",
				CWEID:       942,
			})
			break
		}

		// Vulnerable case 2: Origin null trusted
		if item.Origin == "null" && acao == "null" {
			findings = append(findings, &Finding{
				Module:      m.Name(),
				Title:       "CORS Misconfiguration (Null Origin Allowed)",
				Severity:    SeverityMedium,
				Confidence:  90,
				URL:         target.URL,
				Parameter:   "Header: Origin",
				Payload:     "Origin: null",
				Detail:      "Server trusts the 'null' origin, which can be triggered via sandboxed iframes or data URIs.",
				Evidence:    fmt.Sprintf("ACAO: %s", acao),
				Remediation: "Disallow the 'null' origin in CORS configuration.",
				CWEID:       942,
			})
			break
		}
	}

	return findings, nil
}
