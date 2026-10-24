package modules

import (
	"fmt"
	"html"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/xss"
	"strings"
)

type XSSModule struct {
	engine *xss.Engine
}

func NewXSSModule() *XSSModule {
	return NewXSSModuleWithConfig(xss.DefaultEngineConfig())
}

func NewXSSModuleWithConfig(cfg *xss.EngineConfig) *XSSModule {
	return &XSSModule{
		engine: xss.NewEngine(cfg),
	}
}

func (m *XSSModule) Name() string {
	return "xss"
}

func (m *XSSModule) Description() string {
	return "Reflected and DOM Cross-Site Scripting (XSS) context and filter analyzer"
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
	// 1. Primary: Run native Go intelligent XSS engine
	if m.engine != nil {
		xTarget := &xss.Target{
			URL:     target.URL,
			Method:  target.Method,
			Params:  target.Params,
			Data:    target.Data,
			Headers: target.Headers,
			IsJSON:  target.IsJSON,
			RawJSON: target.RawJSON,
		}
		xFindings, err := m.engine.ScanTarget(xTarget, c)
		if err == nil {
			var findings []*Finding
			for _, xf := range xFindings {
				conf := ConfidencePossible
				switch xf.ConfidenceLevel {
				case "confirmed":
					conf = ConfidenceConfirmed
				case "probable":
					conf = ConfidenceProbable
				}
				sev := SeverityMedium
				switch xf.Severity {
				case "HIGH":
					sev = SeverityHigh
				case "LOW":
					sev = SeverityLow
				}
				f := &Finding{
					Module:          m.Name(),
					Title:           xf.Title,
					Severity:        sev,
					Confidence:      xf.Confidence,
					ConfidenceLevel: conf,
					URL:             xf.URL,
					Parameter:       xf.Parameter,
					Payload:         xf.Payload,
					Detail:          xf.Detail,
					Evidence:        xf.Evidence,
					Remediation:     xf.Remediation,
					CWEID:           xf.CWEID,
				}
				findings = append(findings, f)
			}
			return findings, nil
		}
	}

	// 2. Fallback: Fast heuristic probe loop
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	headers := map[string]string{}
	if target.IsJSON {
		headers["Content-Type"] = "application/json"
	}

	for _, param := range target.Parameters() {
		for _, probe := range xssProbes {
			var resp *client.Response
			var err error

			if isPost {
				resp, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, probe.Payload), headers)
			} else {
				resp, err = c.Request("GET", target.BuildURLWithParam(param, probe.Payload), "", nil)
			}

			if err != nil || resp == nil || resp.Body == "" {
				continue
			}

			// Check if payload is reflected unescaped
			escaped := html.EscapeString(probe.Payload)
			if strings.Contains(resp.Body, probe.MustContain) && !strings.Contains(resp.Body, escaped) {
				f := &Finding{
					Module:      m.Name(),
					Title:       fmt.Sprintf("Reflected Cross-Site Scripting (%s)", probe.Context),
					Severity:    SeverityHigh,
					URL:         target.URL,
					Parameter:   param,
					Payload:     probe.Payload,
					Detail:      fmt.Sprintf("Unescaped reflection confirmed in %s context for parameter '%s'.", probe.Context, param),
					Evidence:    fmt.Sprintf("Found raw unescaped payload '%s' in HTTP response body.", probe.MustContain),
					Remediation: "Contextually encode user input before rendering in HTML, attributes, or JavaScript contexts. Use CSP.",
					CWEID:       79,
				}
				f.SetConfidence(ConfidenceConfirmed)
				findings = append(findings, f)
				break
			}
		}
	}

	return findings, nil
}
