package modules

import (
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
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
	return "Open URL Redirection and header injection detector"
}

var redirectPayloads = []string{
	"https://example.com",
	"//example.com",
	"/\\example.com",
	"https://example.com%23",
	"https:example.com",
}

func (m *RedirectModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	for _, param := range target.Parameters() {
		for _, payload := range redirectPayloads {
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

			if loc != "" {
				u, parseErr := url.Parse(loc)
				if parseErr == nil && (strings.HasPrefix(loc, "//example.com") || (u.Host == "example.com" || strings.HasSuffix(u.Host, ".example.com"))) {
					findings = append(findings, &Finding{
						Module:      m.Name(),
						Title:       "Open URL Redirection",
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
		}
	}

	return findings, nil
}
