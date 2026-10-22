package modules

import (
	"fmt"
	"nightfalllx/pkg/client"
	"strings"
)

type SSTIModule struct{}

func NewSSTIModule() *SSTIModule {
	return &SSTIModule{}
}

func (m *SSTIModule) Name() string {
	return "ssti"
}

func (m *SSTIModule) Description() string {
	return "Differential Server-Side Template Injection verification"
}

type sstiEngine struct {
	Name    string
	First   string
	Second  string
	Expect1 string
	Expect2 string
}

var sstiEngines = []sstiEngine{
	{"Jinja2/Python", "{{7*7}}", "{{7*8}}", "49", "56"},
	{"Twig/PHP", "{{7*'7'}}", "{{7*'8'}}", "49", "56"},
	{"Smarty/PHP", "{7*7}", "{7*8}", "49", "56"},
	{"Freemarker/Java", "${7*7}", "${7*8}", "49", "56"},
	{"SpringEL/Java", "*{7*7}", "*{7*8}", "49", "56"},
	{"ERB/Ruby", "<%= 7*7 %>", "<%= 7*8 %>", "49", "56"},
	{"Ruby/Inline", "#{7*7}", "#{7*8}", "49", "56"},
}

func (m *SSTIModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	headers := map[string]string{}
	if target.IsJSON {
		headers["Content-Type"] = "application/json"
	}

	for _, param := range target.Parameters() {
		origVal := target.Params[param]
		if isPost && !target.IsJSON {
			origVal = target.Data[param]
		}

		// Baseline
		var baseResp *client.Response
		var err error
		if isPost {
			baseResp, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, origVal), headers)
		} else {
			baseResp, err = c.Request("GET", target.BuildURLWithParam(param, origVal), "", nil)
		}
		if err != nil || baseResp == nil {
			continue
		}

		for _, eng := range sstiEngines {
			if strings.Contains(baseResp.Body, eng.Expect1) || strings.Contains(baseResp.Body, eng.Expect2) {
				continue
			}

			// First probe
			var resp1 *client.Response
			if isPost {
				resp1, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, eng.First), headers)
			} else {
				resp1, err = c.Request("GET", target.BuildURLWithParam(param, eng.First), "", nil)
			}
			if err != nil || resp1 == nil || !strings.Contains(resp1.Body, eng.Expect1) {
				continue
			}

			// Second probe (differential check)
			var resp2 *client.Response
			if isPost {
				resp2, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, eng.Second), headers)
			} else {
				resp2, err = c.Request("GET", target.BuildURLWithParam(param, eng.Second), "", nil)
			}
			if err != nil || resp2 == nil || !strings.Contains(resp2.Body, eng.Expect2) {
				continue
			}

			f := &Finding{
				Module:      m.Name(),
				Title:       fmt.Sprintf("Server-Side Template Injection (%s)", eng.Name),
				Severity:    SeverityCritical,
				URL:         target.URL,
				Parameter:   param,
				Payload:     fmt.Sprintf("%s -> %s", eng.First, eng.Second),
				Detail:      fmt.Sprintf("Confirmed dynamic mathematical evaluation in template engine (%s evaluates to %s, %s evaluates to %s).", eng.First, eng.Expect1, eng.Second, eng.Expect2),
				Evidence:    fmt.Sprintf("Payload %s produced expected evaluated output %s in response body.", eng.First, eng.Expect1),
				Remediation: "Never concatenate user input directly into templates. Use static templates with contextual data models.",
				CWEID:       1336,
			}
			f.SetConfidence(ConfidenceConfirmed)
			findings = append(findings, f)
			break
		}
	}

	return findings, nil
}
