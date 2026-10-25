package modules

import (
	"fmt"
	"html"
	"nightfalllx/pkg/client"
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

var xssProbes = []struct {
	Context     string
	Payload     string
	MustContain string
}{
	{"HTML Body", "<script>alert(1)</script>", "<script>alert(1)</script>"},
	{"Attribute Breakout", "\"><script>alert(1)</script>", "\"><script>alert(1)</script>"},
	{"Single-Quote Attribute", "'-alert(1)-'", "'-alert(1)-'"},
	{"JavaScript Context", "';alert(1)//", "';alert(1)//"},
	{"Event Handler (IMG)", "<img src=x onerror=alert(1)>", "<img src=x onerror=alert(1)>"},
	{"Event Handler (SVG)", "<svg onload=alert(1)>", "<svg onload=alert(1)>"},
}

func (m *XSSModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	for _, param := range target.Parameters() {
		for _, probe := range xssProbes {
			var resp *client.Response
			var err error

			if isPost {
				resp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, probe.Payload), nil)
			} else {
				resp, err = c.Request("GET", target.BuildURLWithParam(param, probe.Payload), "", nil)
			}

			if err != nil || resp.Body == "" {
				continue
			}

			// Check if payload is reflected unescaped
			escaped := html.EscapeString(probe.Payload)
			if strings.Contains(resp.Body, probe.MustContain) && !strings.Contains(resp.Body, escaped) {
				findings = append(findings, &Finding{
					Module:      m.Name(),
					Title:       fmt.Sprintf("Reflected Cross-Site Scripting (%s)", probe.Context),
					Severity:    SeverityHigh,
					Confidence:  95,
					URL:         target.URL,
					Parameter:   param,
					Payload:     probe.Payload,
					Detail:      fmt.Sprintf("Unescaped reflection confirmed in %s context for parameter '%s'.", probe.Context, param),
					Evidence:    fmt.Sprintf("Found raw unescaped payload '%s' in HTTP response body.", probe.MustContain),
					Remediation: "Contextually encode user input before rendering in HTML, attributes, or JavaScript contexts. Use CSP.",
					CWEID:       79,
				})
				break
			}
		}
	}

	return findings, nil
}
