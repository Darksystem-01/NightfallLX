package modules

import (
	"fmt"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/wordlists"
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

func (m *CRLFModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	for _, param := range target.Parameters() {
		// Baseline to ensure header does not already exist
		var baseResp *client.Response
		if isPost {
			baseResp, _ = c.Request("POST", target.URL, target.BuildDataWithParam(param, "test"), nil)
		} else {
			baseResp, _ = c.Request("GET", target.BuildURLWithParam(param, "test"), "", nil)
		}
		baseHeaders := ""
		if baseResp != nil {
			baseHeaders = fmt.Sprintf("%v", baseResp.Headers)
		}

		if strings.Contains(baseHeaders, "nflx_crlf") {
			continue
		}

		for _, probe := range wordlists.CRLFPayloads {
			var resp *client.Response
			var err error
			if isPost {
				resp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, probe.Payload), nil)
			} else {
				resp, err = c.Request("GET", target.BuildURLWithParam(param, probe.Payload), "", nil)
			}

			if err != nil || resp == nil {
				continue
			}

			// Check if injected header was processed into HTTP response headers
			injectedVal := resp.Headers.Get("X-Injected-Header")
			cookieVal := resp.Headers.Get("Set-Cookie")

			if injectedVal == "nflx_crlf" || strings.Contains(cookieVal, "nflx_crlf=1") {
				evidence := fmt.Sprintf("X-Injected-Header: %s | Set-Cookie: %s", injectedVal, cookieVal)
				findings = append(findings, &Finding{
					Module:      m.Name(),
					Title:       "CRLF / HTTP Header Injection (Response Splitting)",
					Severity:    SeverityHigh,
					Confidence:  100,
					URL:         target.URL,
					Parameter:   param,
					Payload:     probe.Payload,
					Detail:      fmt.Sprintf("Parameter '%s' permitted carriage return/line feed injection into server response headers via '%s'.", param, probe.Name),
					Evidence:    evidence,
					Remediation: "Strip or reject CR (%0d, \\r) and LF (%0a, \\n) characters from all user input before including it in HTTP response headers.",
					CWEID:       113,
				})
				break
			}
		}
	}

	return findings, nil
}
