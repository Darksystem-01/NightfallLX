package modules

import (
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/wordlists"
	"regexp"
	"strings"
)

type RedirectModule struct{}

func NewRedirectModule() *RedirectModule {
	return &RedirectModule{}
}

func (m *RedirectModule) Name() string {
	return "redirect"
}

func (m *RedirectModule) Description() string {
	return "Open URL Redirection and header/meta injection detector"
}

var (
	metaRefreshRegex = regexp.MustCompile(`(?i)<meta[^>]+http-equiv=["']refresh["'][^>]+content=["'][^"']*url=([^\s"'>]+)`)
	jsRedirectRegex  = regexp.MustCompile(`(?i)(window\.location|location\.href)\s*=\s*["']([^"']+)["']`)
)

func (m *RedirectModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	for _, param := range target.Parameters() {
		// Baseline check to eliminate natural site redirects from being falsely flagged
		var baseResp *client.Response
		if isPost {
			baseResp, _ = c.Request("POST", target.URL, target.BuildDataWithParam(param, "nflx_safe_url"), nil)
		} else {
			baseResp, _ = c.Request("GET", target.BuildURLWithParam(param, "nflx_safe_url"), "", nil)
		}
		baseLoc := ""
		if baseResp != nil {
			baseLoc = baseResp.Location
			if baseLoc == "" {
				baseLoc = baseResp.Headers.Get("Location")
			}
		}

		for _, payload := range wordlists.RedirectPayloads {
			// Skip if baseline already redirects to this host
			if baseLoc != "" && strings.Contains(baseLoc, "example.com") {
				continue
			}
			var resp *client.Response
			var err error

			if isPost {
				resp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, payload), nil)
			} else {
				resp, err = c.Request("GET", target.BuildURLWithParam(param, payload), "", nil)
			}

			if err != nil || resp == nil {
				continue
			}

			loc := resp.Location
			if loc == "" {
				loc = resp.Headers.Get("Location")
			}

			// 1. HTTP 3xx Location header check
			if loc != "" {
				u, parseErr := url.Parse(loc)
				if parseErr == nil && (strings.HasPrefix(loc, "//example.com") || (u.Host == "example.com" || strings.HasSuffix(u.Host, ".example.com"))) {
					findings = append(findings, &Finding{
						Module:      m.Name(),
						Title:       "Open URL Redirection (HTTP 3xx Header)",
						Severity:    SeverityMedium,
						Confidence:  100,
						URL:         target.URL,
						Parameter:   param,
						Payload:     payload,
						Detail:      fmt.Sprintf("Parameter '%s' directs user to an external unvalidated domain via HTTP redirect (Location: %s).", param, loc),
						Evidence:    fmt.Sprintf("HTTP %d, Location header: %s", resp.StatusCode, loc),
						Remediation: "Validate redirect targets against an internal relative path allowlist or strictly trusted domain list.",
						CWEID:       601,
					})
					break
				}
			}

			// 2. Client-side HTML / Meta-refresh check
			if metaRefreshRegex.MatchString(resp.Body) {
				match := metaRefreshRegex.FindStringSubmatch(resp.Body)
				if len(match) > 1 && strings.Contains(match[1], "example.com") {
					findings = append(findings, &Finding{
						Module:      m.Name(),
						Title:       "Open URL Redirection (HTML Meta Refresh)",
						Severity:    SeverityMedium,
						Confidence:  95,
						URL:         target.URL,
						Parameter:   param,
						Payload:     payload,
						Detail:      fmt.Sprintf("Parameter '%s' directs user to an external unvalidated domain via HTML meta refresh: %s", param, match[1]),
						Evidence:    fmt.Sprintf("Meta refresh tag: %s", match[0]),
						Remediation: "Validate redirect targets against an internal allowlist.",
						CWEID:       601,
					})
					break
				}
			}

			// 3. Client-side JavaScript redirection
			if jsRedirectRegex.MatchString(resp.Body) {
				match := jsRedirectRegex.FindStringSubmatch(resp.Body)
				if len(match) > 2 && strings.Contains(match[2], "example.com") {
					findings = append(findings, &Finding{
						Module:      m.Name(),
						Title:       "Open URL Redirection (JavaScript Location)",
						Severity:    SeverityMedium,
						Confidence:  95,
						URL:         target.URL,
						Parameter:   param,
						Payload:     payload,
						Detail:      fmt.Sprintf("Parameter '%s' directs user to an external unvalidated domain via JavaScript window.location: %s", param, match[2]),
						Evidence:    fmt.Sprintf("JavaScript redirect assignment: %s", match[0]),
						Remediation: "Validate redirect targets against an internal allowlist.",
						CWEID:       601,
					})
					break
				}
			}
		}
	}

	return findings, nil
}
