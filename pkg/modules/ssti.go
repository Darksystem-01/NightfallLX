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

	for _, param := range target.Parameters() {
		origVal := target.Params[param]
		if isPost {
			origVal = target.Data[param]
		}

		// Baseline
		var baseResp *client.Response
		var err error
		if isPost {
			baseResp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, origVal), nil)
		} else {
			baseResp, err = c.Request("GET", target.BuildURLWithParam(param, origVal), "", nil)
		}
		if err != nil {
			continue
		}

		for _, eng := range sstiEngines {
			// Ensure canaries are not already in baseline
			if strings.Contains(baseResp.Body, eng.Expect1) || strings.Contains(baseResp.Body, eng.Expect2) {
				continue
			}

			// First probe
			var resp1 *client.Response
			if isPost {
				resp1, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, eng.First), nil)
			} else {
				resp1, err = c.Request("GET", target.BuildURLWithParam(param, eng.First), "", nil)
			}
			if err != nil || !strings.Contains(resp1.Body, eng.Expect1) {
				continue
			}

			// Second probe (differential check)
			var resp2 *client.Response
			if isPost {
				resp2, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, eng.Second), nil)
			} else {
				resp2, err = c.Request("GET", target.BuildURLWithParam(param, eng.Second), "", nil)
			}
			if err != nil || !strings.Contains(resp2.Body, eng.Expect2) {
				continue
			}

			findings = append(findings, &Finding{
				Module:      m.Name(),
				Title:       fmt.Sprintf("Server-Side Template Injection (%s)", eng.Name),
				Severity:    SeverityHigh,
				Confidence:  100,
				URL:         target.URL,
				Parameter:   param,
				Payload:     fmt.Sprintf("%s -> %s and %s -> %s", eng.First, eng.Expect1, eng.Second, eng.Expect2),
				Detail:      fmt.Sprintf("Confirmed SSTI: template engine evaluated independent expressions inside parameter '%s'.", param),
				Evidence:    fmt.Sprintf("Engine: %s, probe 1 returned %s, probe 2 returned %s", eng.Name, eng.Expect1, eng.Expect2),
				Remediation: "Do not pass user input directly into template renderers. Use context-aware logic.",
				CWEID:       1336,
			})
			break
		}
	}

	return findings, nil
}
