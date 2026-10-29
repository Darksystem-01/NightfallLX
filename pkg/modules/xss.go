package modules

import (
	"fmt"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/wordlists"
	"strings"
)

type XSSModule struct{}

func NewXSSModule() *XSSModule {
	return &XSSModule{}
}

func (m *XSSModule) Name() string {
	return "xss"
}

func (m *XSSModule) Description() string {
	return "Reflected Cross-Site Scripting (XSS) context and filter analyzer"
}

func (m *XSSModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	for _, param := range target.Parameters() {
		// Baseline check to eliminate static HTML False Positives (e.g. security docs, blogs, tutorial pages)
		var baseResp *client.Response
		if isPost {
			baseResp, _ = c.Request("POST", target.URL, target.BuildDataWithParam(param, "nflx_baseline_safe_val"), nil)
		} else {
			baseResp, _ = c.Request("GET", target.BuildURLWithParam(param, "nflx_baseline_safe_val"), "", nil)
		}
		baseBody := ""
		if baseResp != nil {
			baseBody = baseResp.Body
		}

		for _, probe := range wordlists.XSSProbes {
			// Skip if baseline already contains this pattern naturally
			if baseBody != "" && strings.Contains(baseBody, probe.MustContain) {
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

			// Reject non-executable response types (JSON, plain text, PDF, images)
			cType := strings.ToLower(resp.Headers.Get("Content-Type"))
			if strings.Contains(cType, "application/json") ||
				strings.Contains(cType, "text/plain") ||
				strings.Contains(cType, "application/pdf") ||
				strings.Contains(cType, "image/") ||
				strings.Contains(cType, "audio/") ||
				strings.Contains(cType, "video/") ||
				strings.Contains(cType, "font/") {
				continue
			}

			// Check if payload is reflected unescaped in an active HTML / JavaScript execution context
			if strings.Contains(resp.Body, probe.MustContain) && isExecutableXSSReflection(resp.Body, probe.MustContain) {
				findings = append(findings, &Finding{
					Module:      m.Name(),
					Title:       fmt.Sprintf("Reflected Cross-Site Scripting (%s)", probe.Context),
					Severity:    SeverityHigh,
					Confidence:  95,
					URL:         target.URL,
					Parameter:   param,
					Payload:     probe.Payload,
					Detail:      fmt.Sprintf("Unescaped reflection confirmed in %s context for parameter '%s'.", probe.Context, param),
					Evidence:    fmt.Sprintf("Found raw unescaped payload '%s' in executable context.", probe.MustContain),
					Remediation: "Contextually encode user input before rendering in HTML, attributes, or JavaScript contexts. Use CSP.",
					CWEID:       79,
				})
				break
			}
		}
	}

	return findings, nil
}

// isExecutableXSSReflection verifies that the reflected probe is in an active HTML/attribute context
// and NOT safely neutralized inside a JSON string literal (e.g. Next.js/React hydration state, application/json).
func isExecutableXSSReflection(body, payload string) bool {
	idx := 0
	for {
		pos := strings.Index(body[idx:], payload)
		if pos == -1 {
			break
		}
		matchPos := idx + pos
		idx = matchPos + len(payload)

		start := matchPos - 60
		if start < 0 {
			start = 0
		}
		end := matchPos + len(payload) + 60
		if end > len(body) {
			end = len(body)
		}
		surrounding := body[start:end]

		// If reflection is inside a JSON string literal (e.g. \"param\": \"...\" or Next.js payload)
		if strings.Contains(surrounding, `\"`) ||
			strings.Contains(surrounding, `self.__next_f`) ||
			strings.Contains(surrounding, `__NEXT_DATA__`) ||
			strings.Contains(surrounding, `application/json`) {
			continue
		}

		// If payload contains HTML tag brackets < >, verify it was not entity-encoded
		if strings.Contains(payload, "<") {
			return true
		}

		// For attribute/JS payload without tags, verify it is inside an active HTML tag <tag ... attr='...'>
		lastOpenTag := strings.LastIndex(body[:matchPos], "<")
		lastCloseTag := strings.LastIndex(body[:matchPos], ">")
		if lastOpenTag > lastCloseTag {
			return true
		}
	}
	return false
}
