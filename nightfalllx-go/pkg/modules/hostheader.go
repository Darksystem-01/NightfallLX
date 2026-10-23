package modules

import (
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"strings"
)

type HostHeaderModule struct{}

func NewHostHeaderModule() *HostHeaderModule {
	return &HostHeaderModule{}
}

func (m *HostHeaderModule) Name() string {
	return "hostheader"
}

func (m *HostHeaderModule) Description() string {
	return "Host Header Injection & Password Reset / Cache Poisoning Assessment"
}

func (m *HostHeaderModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	canary := "canary.nflx-poison.lab"

	testHeaders := []struct {
		HeaderName  string
		HeaderValue string
	}{
		{"X-Forwarded-Host", canary},
		{"X-Host", canary},
		{"X-Forwarded-Server", canary},
	}

	for _, th := range testHeaders {
		customHeaders := map[string]string{
			th.HeaderName: th.HeaderValue,
		}

		resp, err := c.Request(target.Method, target.URL, "", customHeaders)
		if err != nil || resp == nil {
			continue
		}

		// 1. Check Location header reflection (Redirect Poisoning)
		location := resp.Location
		if location != "" && strings.Contains(location, canary) {
			evidence := location
			if len(evidence) > 200 {
				evidence = evidence[:200]
			}
			f := &Finding{
				Module:      m.Name(),
				Title:       "Host Header Injection (Redirect Poisoning via Location Header)",
				Severity:    SeverityHigh,
				URL:         target.URL,
				Parameter:   th.HeaderName,
				Payload:     fmt.Sprintf("%s: %s", th.HeaderName, th.HeaderValue),
				Detail:      fmt.Sprintf("Server reflected untrusted header '%s' into the HTTP Location redirect header.", th.HeaderName),
				Evidence:    fmt.Sprintf("Location: %s", evidence),
				Remediation: "Do not trust X-Forwarded-Host or raw Host headers for generating absolute redirect URLs; use a fixed server configuration base URL.",
				CWEID:       74,
			}
			parsedLoc, parseErr := url.Parse(location)
			locHost := ""
			if parseErr == nil {
				locHost = parsedLoc.Hostname()
				if locHost == "" && strings.HasPrefix(location, "//") {
					locHost = strings.Split(strings.TrimPrefix(location, "//"), "/")[0]
				}
			}
			if locHost == canary || (parseErr == nil && parsedLoc.Host == canary) {
				f.SetConfidence(ConfidenceConfirmed)
			} else {
				f.SetConfidence(ConfidenceProbable)
			}
			findings = append(findings, f)
			break
		}

		// 2. Check Body link reflection (Password reset poisoning / Script source poisoning)
		if strings.Contains(resp.Body, canary) {
			evidenceIdx := strings.Index(resp.Body, canary)
			start := evidenceIdx - 20
			if start < 0 {
				start = 0
			}
			end := evidenceIdx + len(canary) + 40
			if end > len(resp.Body) {
				end = len(resp.Body)
			}
			evidence := resp.Body[start:end]

			f := &Finding{
				Module:      m.Name(),
				Title:       "Host Header Reflection in Response Body (Link Poisoning)",
				Severity:    SeverityMedium,
				URL:         target.URL,
				Parameter:   th.HeaderName,
				Payload:     fmt.Sprintf("%s: %s", th.HeaderName, th.HeaderValue),
				Detail:      fmt.Sprintf("Injected header '%s' was reflected into web links/DOM content inside the response body.", th.HeaderName),
				Evidence:    evidence,
				Remediation: "Validate the Host header against a whitelist of authorized domains and avoid relying on incoming headers for generating resource links.",
				CWEID:       74,
			}
			f.SetConfidence(ConfidenceProbable)
			findings = append(findings, f)
			break
		}
	}

	return findings, nil
}
