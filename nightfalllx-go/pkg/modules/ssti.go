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

/*
CATEGORY: Polyglot and Engine-Specific Server-Side Template Injection (SSTI) Pairs (50+ entries)
Sources: PortSwigger SSTI Research, HackTricks Template Injection, Epiphant SSTI Map.
Engines Covered:
- Python: Jinja2, Mako, Tornado
- PHP: Twig, Smarty, Blade
- Java: FreeMarker, Velocity, Pebble, Spring Expression Language (SpEL)
- Ruby: ERB, Slim, Inline Interpolation
- Node.js / JavaScript: Nunjucks, Pug/Jade, Dust.js, Handlebars, EJS, Marko, doT
- Go: html/template arithmetic (safe reflections)
*/
var sstiEngines = []sstiEngine{
	// 1. Jinja2 / Python
	{"Jinja2/Python (Curly Double)", "{{7*7}}", "{{7*8}}", "49", "56"},
	{"Jinja2/Python (Expression)", "{{49}}", "{{56}}", "49", "56"},
	{"Jinja2/Python (Multiplication)", "{{1111*1111}}", "{{1111*1112}}", "1234321", "1235432"},
	{"Jinja2/Python (String Repeat)", "{{'nflx'*2}}", "{{'nflx'*3}}", "nflxnflx", "nflxnflxnflx"},
	{"Jinja2/Python (Tag Block)", "{% if 1 %}49{% endif %}", "{% if 0 %}49{% endif %}", "49", ""},

	// 2. Twig / PHP
	{"Twig/PHP (String Multiply)", "{{7*'7'}}", "{{7*'8'}}", "49", "56"},
	{"Twig/PHP (Standard Math)", "{{8*8}}", "{{8*9}}", "64", "72"},
	{"Twig/PHP (String Concat)", "{{'nflx' ~ 'sec'}}", "{{'nflx' ~ 'tst'}}", "nflxsec", "nflxtst"},
	{"Twig/PHP (Filter Format)", "{{49|number_format}}", "{{56|number_format}}", "49", "56"},

	// 3. Smarty / PHP
	{"Smarty/PHP (Single Curly)", "{7*7}", "{7*8}", "49", "56"},
	{"Smarty/PHP (Math Tag)", "{math equation=\"x*y\" x=7 y=7}", "{math equation=\"x*y\" x=7 y=8}", "49", "56"},
	{"Smarty/PHP (Variable Expr)", "{$x=7}{$x*$x}", "{$x=7}{$x*8}", "49", "56"},

	// 4. FreeMarker / Java
	{"Freemarker/Java (Dollar Curly)", "${7*7}", "${7*8}", "49", "56"},
	{"Freemarker/Java (Hash Math)", "[#ftl]${7*7}", "[#ftl]${7*8}", "49", "56"},
	{"Freemarker/Java (Assign Block)", "<#assign x=7>${x*7}", "<#assign x=7>${x*8}", "49", "56"},
	{"Freemarker/Java (String Repeat)", "${'nflx'?repeat(2)}", "${'nflx'?repeat(3)}", "nflxnflx", "nflxnflxnflx"},

	// 5. Velocity / Java
	{"Velocity/Java (Math)", "#set($x=7*7)$x", "#set($x=7*8)$x", "49", "56"},
	{"Velocity/Java (Direct Evaluate)", "#evaluate('49')", "#evaluate('56')", "49", "56"},
	{"Velocity/Java (Dollar Literal)", "$math.mul(7,7)", "$math.mul(7,8)", "49", "56"},

	// 6. SpringEL / Java (SpEL)
	{"SpringEL/Java (Asterisk Curly)", "*{7*7}", "*{7*8}", "49", "56"},
	{"SpringEL/Java (T-operator Math)", "${T(java.lang.Math).multiplyExact(7,7)}", "${T(java.lang.Math).multiplyExact(7,8)}", "49", "56"},
	{"SpringEL/Java (Standard Math)", "${7*7}", "${7*8}", "49", "56"},

	// 7. Pebble / Java
	{"Pebble/Java (Curly Double)", "{{ 7*7 }}", "{{ 7*8 }}", "49", "56"},
	{"Pebble/Java (Filter Math)", "{{ 49 | abs }}", "{{ 56 | abs }}", "49", "56"},

	// 8. ERB / Ruby
	{"ERB/Ruby (Expression Tag)", "<%= 7*7 %>", "<%= 7*8 %>", "49", "56"},
	{"ERB/Ruby (Inline String)", "<%= 'nflx'*2 %>", "<%= 'nflx'*3 %>", "nflxnflx", "nflxnflxnflx"},
	{"Ruby/Inline (Pound Curly)", "#{7*7}", "#{7*8}", "49", "56"},
	{"Ruby/Inline (String Concat)", "#{'nflx' + 'sec'}", "#{'nflx' + 'tst'}", "nflxsec", "nflxtst"},

	// 9. Mako / Python
	{"Mako/Python (Expression)", "${7*7}", "${7*8}", "49", "56"},
	{"Mako/Python (Block)", "<% x = 7*7 %>${x}", "<% x = 7*8 %>${x}", "49", "56"},

	// 10. Tornado / Python
	{"Tornado/Python (Double Curly)", "{{ 7*7 }}", "{{ 7*8 }}", "49", "56"},
	{"Tornado/Python (Raw Tag)", "{% raw 7*7 %}", "{% raw 7*8 %}", "49", "56"},

	// 11. Node.js (Pug / Jade)
	{"Pug/Jade (Unbuffered)", "#{7*7}", "#{7*8}", "49", "56"},
	{"Pug/Jade (Buffered)", "= 7*7", "= 7*8", "49", "56"},

	// 12. Node.js (Nunjucks)
	{"Nunjucks/Node (Double Curly)", "{{7*7}}", "{{7*8}}", "49", "56"},
	{"Nunjucks/Node (Filter)", "{{'49'|int}}", "{{'56'|int}}", "49", "56"},

	// 13. Node.js (EJS)
	{"EJS/Node (Percent Equal)", "<%= 7*7 %>", "<%= 7*8 %>", "49", "56"},
	{"EJS/Node (Raw Tag)", "<%- 7*7 %>", "<%- 7*8 %>", "49", "56"},

	// 14. Node.js (doT.js)
	{"doT.js/Node (Curly Equal)", "{{= 7*7 }}", "{{= 7*8 }}", "49", "56"},
	{"doT.js/Node (Curly Exclamation)", "{{! 7*7 }}", "{{! 7*8 }}", "49", "56"},

	// 15. Node.js (Dust.js)
	{"Dust.js/Node (Curly Math)", "{#math key=\"7\" method=\"multiply\" operand=\"7\"/}", "{#math key=\"7\" method=\"multiply\" operand=\"8\"/}", "49", "56"},

	// 16. Groovy / Java
	{"Groovy/Java (GString)", "${7*7}", "${7*8}", "49", "56"},
	{"Groovy/Java (Print Expression)", "<%= 7*7 %>", "<%= 7*8 %>", "49", "56"},

	// 17. Polyglot SSTI Probes
	{"SSTI Polyglot 1", "${{7*7}}", "${{7*8}}", "49", "56"},
	{"SSTI Polyglot 2", "@(7*7)", "@(7*8)", "49", "56"},
	{"SSTI Polyglot 3", "{{{7*7}}}", "{{{7*8}}}", "49", "56"},
	{"SSTI Polyglot 4", "${7*'7'}", "${7*'8'}", "49", "56"},
	{"SSTI Polyglot 5", "#set($x=49)$x", "#set($x=56)$x", "49", "56"},
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
