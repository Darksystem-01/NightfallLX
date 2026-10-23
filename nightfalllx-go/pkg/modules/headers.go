package modules

import (
	"fmt"
	"nightfalllx/pkg/client"
	"regexp"
	"strings"
)

type HeadersModule struct{}

func NewHeadersModule() *HeadersModule {
	return &HeadersModule{}
}

func (m *HeadersModule) Name() string {
	return "headers"
}

func (m *HeadersModule) Description() string {
	return "Defensive HTTP Security Headers, Information Disclosure & Cookie Flags Audit"
}

var versionDisclosureRegex = regexp.MustCompile(`(?i)([\w\-]+/\d+(\.\d+)+)`)

func (m *HeadersModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding

	resp, err := c.Request(target.Method, target.URL, "", nil)
	if err != nil || resp == nil {
		return nil, nil
	}

	headers := resp.Headers

	// 1. Missing Security Headers
	missingHeaders := []struct {
		Header      string
		CWE         int
		Severity    Severity
		Title       string
		Remediation string
	}{
		{"Content-Security-Policy", 1021, SeverityMedium, "Missing Content-Security-Policy (CSP) Header", "Define a robust Content-Security-Policy to mitigate Cross-Site Scripting (XSS) and data injection attacks."},
		{"X-Frame-Options", 1021, SeverityMedium, "Missing X-Frame-Options (Clickjacking Protection)", "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent the page from being rendered inside an iframe."},
		{"X-Content-Type-Options", 16, SeverityLow, "Missing X-Content-Type-Options Header", "Set 'X-Content-Type-Options: nosniff' to prevent browsers from MIME-sniffing response content."},
		{"Referrer-Policy", 116, SeverityLow, "Missing Referrer-Policy Header", "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer' to avoid leaking referrer information."},
	}

	for _, mh := range missingHeaders {
		if headers.Get(mh.Header) == "" {
			f := &Finding{
				Module:      m.Name(),
				Title:       mh.Title,
				Severity:    mh.Severity,
				URL:         target.URL,
				Parameter:   mh.Header,
				Payload:     "N/A (Header Check)",
				Detail:      fmt.Sprintf("Defensive security header '%s' is not set on HTTP responses.", mh.Header),
				Evidence:    fmt.Sprintf("Header %s is omitted in response from %s", mh.Header, target.URL),
				Remediation: mh.Remediation,
				CWEID:       mh.CWE,
			}
			f.SetConfidence(ConfidencePossible)
			findings = append(findings, f)
		}
	}

	// HSTS on HTTPS targets
	if strings.HasPrefix(strings.ToLower(target.URL), "https://") && headers.Get("Strict-Transport-Security") == "" {
		f := &Finding{
			Module:      m.Name(),
			Title:       "Missing HTTP Strict-Transport-Security (HSTS) Header",
			Severity:    SeverityMedium,
			URL:         target.URL,
			Parameter:   "Strict-Transport-Security",
			Payload:     "N/A",
			Detail:      "The HTTPS endpoint does not enforce HSTS, allowing potential SSL-stripping attacks.",
			Evidence:    "Strict-Transport-Security header omitted",
			Remediation: "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce encrypted transport.",
			CWEID:       319,
		}
		f.SetConfidence(ConfidencePossible)
		findings = append(findings, f)
	}

	// 2. Verbose Server / Technology Version Disclosure
	for _, bannerHeader := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"} {
		if val := headers.Get(bannerHeader); val != "" {
			if versionDisclosureRegex.MatchString(val) {
				f := &Finding{
					Module:      m.Name(),
					Title:       fmt.Sprintf("Software Version Disclosure via '%s' Header", bannerHeader),
					Severity:    SeverityLow,
					URL:         target.URL,
					Parameter:   bannerHeader,
					Payload:     val,
					Detail:      fmt.Sprintf("Response header '%s' reveals exact software version information ('%s').", bannerHeader, val),
					Evidence:    fmt.Sprintf("%s: %s", bannerHeader, val),
					Remediation: "Remove or mask detailed software version banners in web server configuration.",
					CWEID:       200,
				}
				f.SetConfidence(ConfidenceProbable)
				findings = append(findings, f)
			}
		}
	}

	// 3. Cookie Flags (Secure, HttpOnly, SameSite)
	for _, cookie := range headers.Values("Set-Cookie") {
		lowerCookie := strings.ToLower(cookie)
		var missingFlags []string
		if !strings.Contains(lowerCookie, "httponly") {
			missingFlags = append(missingFlags, "HttpOnly")
		}
		if !strings.Contains(lowerCookie, "secure") && strings.HasPrefix(strings.ToLower(target.URL), "https://") {
			missingFlags = append(missingFlags, "Secure")
		}
		if !strings.Contains(lowerCookie, "samesite") {
			missingFlags = append(missingFlags, "SameSite")
		}

		if len(missingFlags) > 0 {
			cookieName := strings.Split(cookie, "=")[0]
			f := &Finding{
				Module:      m.Name(),
				Title:       fmt.Sprintf("Insecure Cookie Flags on '%s'", cookieName),
				Severity:    SeverityLow,
				URL:         target.URL,
				Parameter:   cookieName,
				Payload:     cookie,
				Detail:      fmt.Sprintf("Cookie '%s' is missing security attributes: %s.", cookieName, strings.Join(missingFlags, ", ")),
				Evidence:    cookie,
				Remediation: "Configure all sensitive cookies with Secure, HttpOnly, and SameSite=Lax/Strict flags.",
				CWEID:       614,
			}
			f.SetConfidence(ConfidenceProbable)
			findings = append(findings, f)
		}
	}

	return findings, nil
}
