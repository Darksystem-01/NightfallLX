package modules

import (
	"fmt"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/wordlists"
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

func (m *SSRFModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	for _, param := range target.Parameters() {
		// Only test parameters that typically take URLs, hosts, or endpoints
		paramLower := strings.ToLower(param)
		if !strings.Contains(paramLower, "url") &&
			!strings.Contains(paramLower, "uri") &&
			!strings.Contains(paramLower, "dest") &&
			!strings.Contains(paramLower, "link") &&
			!strings.Contains(paramLower, "feed") &&
			!strings.Contains(paramLower, "image") &&
			!strings.Contains(paramLower, "path") &&
			!strings.Contains(paramLower, "fetch") &&
			!strings.Contains(paramLower, "host") &&
			!strings.Contains(paramLower, "target") &&
			!strings.Contains(paramLower, "endpoint") {
			// Also test if there are very few parameters in total
			if len(target.Parameters()) > 3 {
				continue
			}
		}

		// Fetch baseline to ensure indicators are not already present on normal landing page
		var baseResp *client.Response
		if isPost {
			baseResp, _ = c.Request("POST", target.URL, target.BuildDataWithParam(param, "https://example.com"), nil)
		} else {
			baseResp, _ = c.Request("GET", target.BuildURLWithParam(param, "https://example.com"), "", nil)
		}
		baseBodyLower := ""
		if baseResp != nil {
			baseBodyLower = strings.ToLower(baseResp.Body)
		}

		// Track categories found so we report one best finding per category (e.g. LFI, loopback, cloud)
		foundCategories := make(map[string]bool)

		type ssrfProbeItem struct {
			TargetType string
			Category   string
			Payload    string
			Indicators []string
		}

		var activeProbes []ssrfProbeItem
		for _, p := range wordlists.SSRFProbes {
			activeProbes = append(activeProbes, ssrfProbeItem{
				TargetType: p.TargetType,
				Category:   p.Category,
				Payload:    p.Payload,
				Indicators: p.Indicators,
			})
		}

		for _, line := range wordlists.GetWordlist("ssrf", target.Wordlist) {
			cat := "custom"
			ind := []string{"root:x:0:0:", "127.0.0.1", "localhost", "discover.hard", "+pong", "-err", "nginx", "apache", "ami-id", "computemetadata"}
			if strings.HasPrefix(line, "file://") {
				cat = "lfi"
				ind = []string{"root:x:0:0:", "root:/root:", "/bin/bash", "/bin/sh", "daemon:x:"}
			} else if strings.Contains(line, "169.254") || strings.Contains(line, "metadata") {
				cat = "cloud"
				ind = []string{"ami-id", "instance-id", "computemetadata", "azenvironment", "droplet_id"}
			} else if strings.Contains(line, "127.") || strings.Contains(line, "localhost") || strings.Contains(line, "::1") {
				cat = "loopback"
			}
			activeProbes = append(activeProbes, ssrfProbeItem{
				TargetType: fmt.Sprintf("SSRF Payload (%s)", line),
				Category:   cat,
				Payload:    line,
				Indicators: ind,
			})
		}

		for _, probe := range activeProbes {
			if foundCategories[probe.Category] {
				continue
			}

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
			matchedIndicator := ""
			for _, ind := range probe.Indicators {
				indLower := strings.ToLower(ind)
				if strings.Contains(bodyLower, indLower) && !strings.Contains(baseBodyLower, indLower) {
					matched = true
					matchedIndicator = ind
					break
				}
			}

			// Also check for sensitive flags/tokens reflected
			hasFlag := strings.Contains(resp.Body, "flag{") || strings.Contains(resp.Body, "FLAG{") || strings.Contains(resp.Body, "CTF{") || strings.Contains(resp.Body, "SSRF{") || strings.Contains(resp.Body, "IDOR{")

			if matched || hasFlag {
				foundCategories[probe.Category] = true
				preview := resp.Body
				if len(preview) > 250 {
					preview = preview[:250] + "..."
				}

				title := fmt.Sprintf("Server-Side Request Forgery (%s)", probe.TargetType)
				sev := SeverityHigh
				cvss := 8.6
				cwe := 918

				if probe.Category == "lfi" {
					title = fmt.Sprintf("Server-Side Request Forgery & Local File Inclusion (SSRF+LFI - %s)", probe.TargetType)
					sev = SeverityCritical
					cvss = 9.8
				} else if probe.Category == "cloud" {
					sev = SeverityCritical
					cvss = 9.8
				}

				if hasFlag {
					title = fmt.Sprintf("SSRF Sensitive Data & Flag Disclosure (%s)", probe.TargetType)
					sev = SeverityCritical
					cvss = 9.8
				}

				detail := fmt.Sprintf("Server-side request dispatched to '%s' and disclosed internal resource/file indicator '%s'.", probe.Payload, matchedIndicator)
				if probe.Category == "lfi" {
					detail = fmt.Sprintf("Arbitrary local file access achieved via SSRF using 'file://' scheme with payload '%s'. Disclosed system contents.", probe.Payload)
				}

				findings = append(findings, &Finding{
					Module:      m.Name(),
					Title:       title,
					Severity:    sev,
					Confidence:  100,
					URL:         target.URL,
					Parameter:   param,
					Payload:     probe.Payload,
					Detail:      detail,
					Evidence:    fmt.Sprintf("Disclosed content snippet: %s", preview),
					Remediation: "Implement strict server-side egress filtering. Restrict outgoing URL schemes to http/https (disable file://, gopher://, dict://), and block access to loopback (127.0.0.0/8, [::1]) and cloud metadata (169.254.169.254).",
					CWEID:       cwe,
					CVSS:        cvss,
				})
			}
		}
	}

	return findings, nil
}
