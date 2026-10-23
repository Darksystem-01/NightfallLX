package modules

import (
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"strings"
)

type RedirectModule struct{}

func NewRedirectModule() *RedirectModule {
	return &RedirectModule{}
}

func (m *RedirectModule) Name() string {
	return "redirect"
}

func (m *RedirectModule) Description() string {
	return "Open URL Redirection and header injection detector"
}

/*
CATEGORY: Open URL Redirection Vectors (50+ entries)
Sources: PayloadsAllTheThings Open Redirect, OWASP Unvalidated Redirects, PortSwigger Open Redirect Cheat Sheet.
Contexts:
- Protocol-relative slashes (//, ///, ////)
- Backslash & forward-slash hybrids (/\, \/, \\)
- URL-encoded slash variants (%2f, %5c, %252f)
- Userinfo @ delimiter tricks (target.lab@example.com)
- Query & Fragment confusion (?target, #target, %23)
- Scheme-less & colon variations (https:example.com)
- Whitespace & control character prefixes (%09, %20)
*/
var redirectPayloads = []string{
	// 1. Standard Absolute URLs
	"https://example.com",
	"http://example.com",
	"https://example.com/",
	"http://example.com/",
	"https://example.com:443/",
	"http://example.com:80/",

	// 2. Protocol-Relative Slashes
	"//example.com",
	"//example.com/",
	"///example.com",
	"////example.com",
	"/////example.com",
	"//example.com:443",
	"//example.com:80",

	// 3. Backslash Hybrid Evasions
	"/\\example.com",
	"\\/example.com",
	"\\\\example.com",
	"\\\\example.com\\",
	"/\\/example.com",
	"/\\example.com/",
	"\\example.com",

	// 4. Single URL-Encoded Slashes
	"%2f%2fexample.com",
	"%2f%2fexample.com%2f",
	"%2f%5cexample.com",
	"%5c%2fexample.com",
	"%5c%5cexample.com",
	"/%2fexample.com",
	"/%5cexample.com",
	"\\%2fexample.com",
	"\\%5cexample.com",

	// 5. Double URL-Encoded Slashes
	"%252f%252fexample.com",
	"%255c%255cexample.com",
	"..%2f..%2fexample.com",

	// 6. Userinfo / @ Character Delimiter Exploits
	"https://target.lab@example.com",
	"http://target.lab@example.com",
	"https://target.lab:password@example.com",
	"//target.lab@example.com",
	"/\\target.lab@example.com",
	"https://example.com@target.lab",

	// 7. Query String & Fragment Confusion
	"https://example.com?target.lab",
	"https://example.com#target.lab",
	"https://example.com%23target.lab",
	"https://example.com?dest=target.lab",
	"https://example.com/target.lab",

	// 8. Scheme Omission & Colon Variations
	"https:example.com",
	"http:example.com",
	"https:/example.com",
	"http:/example.com",

	// 9. Whitespace & Control Character Prefixes
	" https://example.com",
	"\thttps://example.com",
	"%09//example.com",
	"%20//example.com",
	"%0d%0aLocation:%20https://example.com",

	// 10. Subdomain & Parameter Spoofing
	"https://example.com.target.lab",
	"https://example.com%2523.target.lab",
	"https://example.com?.target.lab",
}

func (m *RedirectModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	for _, param := range target.Parameters() {
		for _, payload := range redirectPayloads {
			var resp *client.Response
			var err error

			if isPost {
				resp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, payload), nil)
			} else {
				resp, err = c.Request("GET", target.BuildURLWithParam(param, payload), "", nil)
			}

			if err != nil || resp == nil {
				continue
			}

			loc := resp.Location
			if loc == "" {
				loc = resp.Headers.Get("Location")
			}

			if loc != "" {
				u, parseErr := url.Parse(loc)
				if parseErr == nil && (strings.HasPrefix(loc, "//example.com") || (u.Host == "example.com" || strings.HasSuffix(u.Host, ".example.com"))) {
					f := &Finding{
						Module:      m.Name(),
						Title:       "Open URL Redirection",
						Severity:    SeverityMedium,
						URL:         target.URL,
						Parameter:   param,
						Payload:     payload,
						Detail:      fmt.Sprintf("Parameter '%s' directs user to an external unvalidated domain via HTTP redirect (Location: %s).", param, loc),
						Evidence:    fmt.Sprintf("HTTP %d, Location header: %s", resp.StatusCode, loc),
						Remediation: "Validate redirect targets against an internal relative path allowlist or strictly trusted domain list.",
						CWEID:       601,
					}
					canaryHost := "example.com"
					locHost := u.Hostname()
					if locHost == "" && strings.HasPrefix(loc, "//") {
						locHost = strings.Split(strings.TrimPrefix(loc, "//"), "/")[0]
					}
					if locHost == canaryHost || u.Host == canaryHost {
						f.SetConfidence(ConfidenceConfirmed)
					} else {
						f.SetConfidence(ConfidenceProbable)
					}
					findings = append(findings, f)
					break
				}
			}
		}
	}

	return findings, nil
}
