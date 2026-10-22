package modules

import (
	"fmt"
	"nightfalllx/pkg/client"
	"strings"
)

type SSRFModule struct{}

func NewSSRFModule() *SSRFModule {
	return &SSRFModule{}
}

func (m *SSRFModule) Name() string {
	return "ssrf"
}

func (m *SSRFModule) Description() string {
	return "Server-Side Request Forgery (SSRF) and Cloud Metadata exposure detector"
}

var ssrfProbes = []struct {
	TargetType string
	Payload    string
	Indicators []string
}{
	{"Cloud Metadata (AWS/OpenStack)", "http://169.254.169.254/latest/meta-data/", []string{"ami-id", "instance-id", "local-ipv4", "security-groups"}},
	{"Local Loopback", "http://127.0.0.1:80/", []string{"nginx", "apache", "iis", "html", "doctype"}},
	{"Localhost IPv6", "http://[::1]:80/", []string{"nginx", "apache", "iis", "html"}},
}

func (m *SSRFModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	for _, param := range target.Parameters() {
		// Only test parameters that typically take URLs or paths
		paramLower := strings.ToLower(param)
		if !strings.Contains(paramLower, "url") &&
			!strings.Contains(paramLower, "uri") &&
			!strings.Contains(paramLower, "dest") &&
			!strings.Contains(paramLower, "link") &&
			!strings.Contains(paramLower, "feed") &&
			!strings.Contains(paramLower, "image") &&
			!strings.Contains(paramLower, "path") &&
			!strings.Contains(paramLower, "fetch") &&
			!strings.Contains(paramLower, "host") {
			// Also test if there's only 1 or 2 parameters in total
			if len(target.Parameters()) > 3 {
				continue
			}
		}

		for _, probe := range ssrfProbes {
			var resp *client.Response
			var err error

			if isPost {
				resp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, probe.Payload), nil)
			} else {
				resp, err = c.Request("GET", target.BuildURLWithParam(param, probe.Payload), "", nil)
			}

			if err != nil || resp == nil || resp.Body == "" {
				continue
			}

			bodyLower := strings.ToLower(resp.Body)
			matched := false
			for _, ind := range probe.Indicators {
				if strings.Contains(bodyLower, ind) {
					matched = true
					break
				}
			}

			if matched {
				findings = append(findings, &Finding{
					Module:      m.Name(),
					Title:       fmt.Sprintf("Server-Side Request Forgery (%s)", probe.TargetType),
					Severity:    SeverityCritical,
					Confidence:  90,
					URL:         target.URL,
					Parameter:   param,
					Payload:     probe.Payload,
					Detail:      fmt.Sprintf("Server-side request dispatched to internal target '%s' and returned sensitive indicators.", probe.Payload),
					Evidence:    fmt.Sprintf("Response snippet: %s", resp.Body[:min(len(resp.Body), 200)]),
					Remediation: "Implement strict server-side egress filtering. Restrict outgoing requests to an allowlist and block 127.0.0.0/8 and 169.254.169.254.",
					CWEID:       918,
				})
				break
			}
		}
	}

	return findings, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
