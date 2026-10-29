package modules

import (
	"fmt"
	"nightfalllx/pkg/client"
	"regexp"
	"strings"
)

type CSRFModule struct{}

func NewCSRFModule() *CSRFModule {
	return &CSRFModule{}
}

func (m *CSRFModule) Name() string {
	return "csrf"
}

func (m *CSRFModule) Description() string {
	return "Cross-Site Request Forgery (CSRF) & Missing Anti-CSRF Token / SameSite Protection"
}

var (
	csrfTokenRegex  = regexp.MustCompile(`(?i)(csrf|xsrf|_token|authenticity_token|nonce|protect|forgery)`)
	formMethodRegex = regexp.MustCompile(`(?i)<form[^>]+method=["'](post|put|delete)["']`)
	formActionRegex = regexp.MustCompile(`(?i)<form[^>]*action=["']([^"']*)["']`)
)

func (m *CSRFModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	methodUpper := strings.ToUpper(target.Method)
	isStateChanging := methodUpper == "POST" || methodUpper == "PUT" || methodUpper == "DELETE"

	// Fetch baseline page
	resp, err := c.Request(target.Method, target.URL, "", nil)
	if err != nil || resp == nil {
		return nil, nil
	}

	// 1. Check if direct POST/PUT/DELETE has anti-CSRF protection
	if isStateChanging {
		// APIs using application/json or Bearer authorization are inherently protected against simple cross-site browser CSRF
		isJSONBody := strings.HasPrefix(strings.TrimSpace(target.Data["_raw"]), "{") ||
			strings.HasPrefix(strings.TrimSpace(target.Data["_raw"]), "[")
		cType := strings.ToLower(resp.Headers.Get("Content-Type"))
		isJSONAPI := strings.Contains(cType, "application/json") || isJSONBody

		hasTokenParam := false
		for _, p := range target.Parameters() {
			if csrfTokenRegex.MatchString(p) {
				hasTokenParam = true
				break
			}
		}

		// Only flag CSRF if state-changing request relies on cookies without anti-CSRF token and is not a JSON API
		if !hasTokenParam && !isJSONAPI {
			setCookie := resp.Headers.Get("Set-Cookie")
			hasSameSiteStrictOrLax := strings.Contains(strings.ToLower(setCookie), "samesite=strict") ||
				strings.Contains(strings.ToLower(setCookie), "samesite=lax")

			confidence := 95
			severity := SeverityHigh
			detail := fmt.Sprintf("State-changing request (%s) lacks an anti-CSRF token and session cookies lack SameSite=Strict/Lax protection.", methodUpper)
			if hasSameSiteStrictOrLax {
				confidence = 70
				severity = SeverityMedium
				detail = fmt.Sprintf("State-changing request (%s) lacks an anti-CSRF token, though SameSite cookie attribute is present.", methodUpper)
			}

			findings = append(findings, &Finding{
				Module:      m.Name(),
				Title:       "Cross-Site Request Forgery (CSRF) / Missing Anti-CSRF Token",
				Severity:    severity,
				Confidence:  confidence,
				URL:         target.URL,
				Parameter:   "(request body/headers)",
				Payload:     "N/A (Missing Token)",
				Detail:      detail,
				Evidence:    fmt.Sprintf("Method: %s, Set-Cookie: %s", methodUpper, setCookie),
				Remediation: "Implement unique, unpredictable anti-CSRF tokens for all state-changing requests and enforce SameSite=Lax/Strict on session cookies.",
				CWEID:       352,
			})
		}
	} else if resp.StatusCode == 200 && strings.Contains(strings.ToLower(resp.Body), "<form") {
		// 2. Check HTML forms on GET responses
		if formMethodRegex.MatchString(resp.Body) {
			hasCSRFField := csrfTokenRegex.MatchString(resp.Body)
			if !hasCSRFField {
				action := target.URL
				if actMatch := formActionRegex.FindStringSubmatch(resp.Body); len(actMatch) > 1 {
					action = actMatch[1]
				}

				evidenceSnippet := resp.Body
				if len(evidenceSnippet) > 200 {
					evidenceSnippet = evidenceSnippet[:200]
				}

				findings = append(findings, &Finding{
					Module:      m.Name(),
					Title:       "State-Changing HTML Form Lacks Anti-CSRF Protection",
					Severity:    SeverityMedium,
					Confidence:  90,
					URL:         target.URL,
					Parameter:   action,
					Payload:     "<form method='POST'> without CSRF token",
					Detail:      "Discovered HTML state-changing POST form without an anti-CSRF token input field.",
					Evidence:    evidenceSnippet,
					Remediation: "Embed server-validated cryptographically secure anti-CSRF tokens into HTML forms.",
					CWEID:       352,
				})
			}
		}
	}

	return findings, nil
}
