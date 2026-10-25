package modules

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"regexp"
	"strings"
	"time"
)

// UserEnumModule implements automated user enumeration with intelligent differential regex inference.
type UserEnumModule struct{}

func NewUserEnumModule() *UserEnumModule {
	return &UserEnumModule{}
}

func (m *UserEnumModule) Name() string {
	return "userenum"
}

func (m *UserEnumModule) Description() string {
	return "Automated username enumeration with intelligent differential regex inference and timing anomaly detection"
}

// Common auth parameters tested on endpoints
var authUserParams = []string{"username", "user", "email", "login", "account", "identity", "handle", "id"}

// Default candidate users to probe
var candidateUsers = []string{"admin", "administrator", "root", "user", "support", "test", "demo", "guest"}

// Builtin generic error signatures to aid regex inference
var knownFailurePatterns = []string{
	`(?i)user(?:name)?\s+(?:not\s+found|doesn't\s+exist|does\s+not\s+exist|invalid|unknown|not\s+registered)`,
	`(?i)account\s+(?:not\s+found|does\s+not\s+exist|doesn't\s+exist|unknown|disabled)`,
	`(?i)no\s+such\s+user`,
	`(?i)unknown\s+(?:user|account|email)`,
	`(?i)email\s+(?:not\s+found|does\s+not\s+exist|unrecognized)`,
	`(?i)bunday\s+foydalanuvchi\s+mavjud\s+emas`,
	`(?i)пользовател[ья]\s+не\s+найден`,
}

func randomCanaryUser() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("nflx_ghost_%s", hex.EncodeToString(b))
}

func (m *UserEnumModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding

	// Step 1: Discover testable user parameters
	testParams := m.identifyUserParams(target)
	if len(testParams) == 0 {
		return findings, nil
	}

	for _, param := range testParams {
		// Step 2: Establish Non-Existent Baseline (Canaries)
		canary1 := randomCanaryUser()
		canary2 := randomCanaryUser()

		respCanary1, err1 := m.sendProbe(target, c, param, canary1)
		respCanary2, err2 := m.sendProbe(target, c, param, canary2)
		if err1 != nil || err2 != nil || respCanary1 == nil || respCanary2 == nil {
			continue
		}

		// Step 3: Infer Failure Regex from baseline canaries
		inferredFailRegex, inferredSuccessRegex := m.inferRegexSignatures(respCanary1.Body, respCanary2.Body)

		// Step 4: Differential evaluation against candidate usernames
		for _, cand := range candidateUsers {
			respCand, err := m.sendProbe(target, c, param, cand)
			if err != nil || respCand == nil {
				continue
			}

			// Heuristic 1: Inferred Failure Regex breaks (e.g. server no longer says "User not found")
			failureRegexBypassed := false
			if inferredFailRegex != nil && inferredFailRegex.MatchString(respCanary1.Body) && !inferredFailRegex.MatchString(respCand.Body) {
				failureRegexBypassed = true
			}

			// Heuristic 2: Inferred Success/Auth Regex matches (e.g. server says "Password incorrect", "Account locked")
			successRegexHit := false
			var matchedRegexStr string
			if inferredSuccessRegex != nil && inferredSuccessRegex.MatchString(respCand.Body) {
				successRegexHit = true
				matchedRegexStr = inferredSuccessRegex.String()
			}

			// Heuristic 3: HTTP Status code divergence
			statusDiverged := respCand.StatusCode != respCanary1.StatusCode

			// Heuristic 4: Body content similarity divergence (< 0.82)
			sim := Similarity(respCanary1.Body, respCand.Body)
			bodyDiverged := sim < 0.82

			// Heuristic 5: Timing anomaly (> 180ms delay due to password hashing execution)
			timingDelta := respCand.Duration - respCanary1.Duration
			timingAnomaly := timingDelta > 180*time.Millisecond

			if failureRegexBypassed || successRegexHit || (statusDiverged && respCand.StatusCode != 404) || (bodyDiverged && timingAnomaly) {
				evidence := fmt.Sprintf("Candidate '%s' produced differential response:\n", cand)
				if failureRegexBypassed {
					evidence += fmt.Sprintf(" - Baseline failure regex '%s' matched bogus users but did NOT match candidate.\n", inferredFailRegex.String())
				}
				if successRegexHit {
					evidence += fmt.Sprintf(" - Inferred credential/password regex '%s' matched candidate response.\n", matchedRegexStr)
				}
				if statusDiverged {
					evidence += fmt.Sprintf(" - HTTP Status changed: %d (canary) -> %d (candidate).\n", respCanary1.StatusCode, respCand.StatusCode)
				}
				if bodyDiverged {
					evidence += fmt.Sprintf(" - Response body divergence: similarity was %.2f (Size diff: %+d bytes).\n", sim, respCand.Bytes-respCanary1.Bytes)
				}
				if timingAnomaly {
					evidence += fmt.Sprintf(" - Timing anomaly: candidate took +%v longer to respond.\n", timingDelta.Round(time.Millisecond))
				}

				reqStr := m.buildCurlPoC(target, param, cand)

				findings = append(findings, &Finding{
					Module:      m.Name(),
					Title:       fmt.Sprintf("User Enumeration via Differential Response (%s='%s')", param, cand),
					Severity:    SeverityMedium,
					Confidence:  90,
					URL:         target.URL,
					Parameter:   param,
					Payload:     cand,
					Detail:      fmt.Sprintf("Application exhibits distinguishable responses for valid vs non-existent usernames on parameter '%s'. An attacker can enumerate registered accounts without authentication.", param),
					Evidence:    strings.TrimSpace(evidence),
					Remediation: "Ensure generic error messages are returned on login and authentication endpoints (e.g. 'Invalid username or password'). Ensure constant-time response execution even when users do not exist.",
					CWEID:       200,
					CVSS:        5.3,
					RawRequest:  reqStr,
					RawResponse: respCand.Body,
				})
				// One confirmed finding per parameter is sufficient
				break
			}
		}
	}

	return findings, nil
}

func (m *UserEnumModule) identifyUserParams(target *Target) []string {
	var identified []string
	allParams := target.Parameters()

	for _, p := range allParams {
		lower := strings.ToLower(p)
		for _, authKey := range authUserParams {
			if strings.Contains(lower, authKey) {
				identified = append(identified, p)
				break
			}
		}
	}

	// If no explicit param found, check if POST data or query exists and test top candidates
	if len(identified) == 0 {
		u := strings.ToLower(target.URL)
		if strings.Contains(u, "login") || strings.Contains(u, "auth") || strings.Contains(u, "user") || strings.Contains(u, "signin") {
			identified = append(identified, "username", "user", "email")
		}
	}

	return identified
}

func (m *UserEnumModule) sendProbe(target *Target, c *client.Client, param, value string) (*client.Response, error) {
	method := strings.ToUpper(target.Method)
	if method == "POST" {
		postBody := target.BuildDataWithParam(param, value)
		if postBody == "" {
			vals := url.Values{}
			vals.Set(param, value)
			vals.Set("password", "TestPassword123!")
			postBody = vals.Encode()
		}
		hdrs := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
		return c.Request("POST", target.URL, postBody, hdrs)
	}

	reqURL := target.BuildURLWithParam(param, value)
	return c.Request("GET", reqURL, "", nil)
}

func (m *UserEnumModule) inferRegexSignatures(bodyCanary1, bodyCanary2 string) (*regexp.Regexp, *regexp.Regexp) {
	var inferredFail *regexp.Regexp

	// Check if known failure signatures match the canary responses
	for _, pat := range knownFailurePatterns {
		re, err := regexp.Compile(pat)
		if err == nil && re.MatchString(bodyCanary1) && re.MatchString(bodyCanary2) {
			inferredFail = re
			break
		}
	}

	// Dynamic inference fallback: if no static pattern matched, extract diff keywords
	if inferredFail == nil {
		words1 := strings.Fields(bodyCanary1)
		words2 := strings.Fields(bodyCanary2)
		commonWords := make(map[string]bool)
		for _, w := range words1 {
			wLower := strings.ToLower(strings.Trim(w, ".,!?:;\"'()[]{}"))
			if len(wLower) >= 4 {
				commonWords[wLower] = true
			}
		}
		var matchedPhrases []string
		for _, w := range words2 {
			wLower := strings.ToLower(strings.Trim(w, ".,!?:;\"'()[]{}"))
			if commonWords[wLower] && (strings.Contains(wLower, "user") || strings.Contains(wLower, "not") || strings.Contains(wLower, "invalid") || strings.Contains(wLower, "exist")) {
				matchedPhrases = append(matchedPhrases, regexp.QuoteMeta(wLower))
			}
		}
		if len(matchedPhrases) > 0 {
			pattern := "(?i)\\b(" + strings.Join(matchedPhrases, "|") + ")\\b"
			inferredFail, _ = regexp.Compile(pattern)
		}
	}

	// Success / Password discrepancy signature
	inferredSuccess, _ := regexp.Compile(`(?i)(password\s+(?:incorrect|invalid|wrong)|incorrect\s+password|account\s+locked|bad\s+credentials)`)

	return inferredFail, inferredSuccess
}

func (m *UserEnumModule) buildCurlPoC(target *Target, param, val string) string {
	if strings.ToUpper(target.Method) == "POST" {
		data := target.BuildDataWithParam(param, val)
		return fmt.Sprintf("curl -i -s -k -X POST '%s' -d '%s'", target.URL, data)
	}
	return fmt.Sprintf("curl -i -s -k -X GET '%s'", target.BuildURLWithParam(param, val))
}
