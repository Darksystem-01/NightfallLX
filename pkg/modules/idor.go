package modules

import (
	"fmt"
	"nightfalllx/pkg/client"
	"regexp"
	"strconv"
	"strings"
)

type IDORModule struct{}

func NewIDORModule() *IDORModule {
	return &IDORModule{}
}

func (m *IDORModule) Name() string {
	return "idor"
}

func (m *IDORModule) Description() string {
	return "Insecure Direct Object Reference (IDOR) & Horizontal Privilege Escalation"
}

// Target private object identifiers rather than public navigational parameters
var privateIDParamRegex = regexp.MustCompile(`(?i)(ticket|order|invoice|billing|user|account|customer|profile|doc|document|payment|card|message|case|note|booking|reservation|item|id)`)

// Sensitive indicators suggesting private PII, credentials, or CTF flags
var (
	piiRegex           = regexp.MustCompile(`(?i)(email["':\s]+[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|credit_?card|phone["':\s]+[\+0-9\- ]{7,}|balance["':\s]+[0-9\.]+|ssn|passport)`)
	sensitiveFlagRegex = regexp.MustCompile(`(?i)(IDOR\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}|FLAG_[a-zA-Z0-9_\-]+|secret_key|private_key|auth_token)`)
)

// Known public navigational parameters to ignore for single-identity IDOR
var publicNavParams = map[string]bool{
	"page": true, "p": true, "category": true, "cat": true, "limit": true,
	"sort": true, "order": true, "dir": true, "tab": true, "type": true,
	"lang": true, "locale": true, "mode": true, "view": true,
}

func (m *IDORModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	for _, param := range target.Parameters() {
		paramLower := strings.ToLower(param)
		if publicNavParams[paramLower] {
			continue
		}

		origVal := target.Params[param]
		if isPost {
			origVal = target.Data[param]
		}

		// Check if parameter name or value looks like an identifier
		isNumeric := false
		numVal, err := strconv.Atoi(origVal)
		if err == nil && numVal > 0 {
			isNumeric = true
		}

		// Must either be a recognized private resource name or numeric ID
		if !isNumeric && !privateIDParamRegex.MatchString(paramLower) {
			continue
		}

		// Baseline request with original identity
		var baseResp *client.Response
		if isPost {
			baseResp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, origVal), nil)
		} else {
			baseResp, err = c.Request("GET", target.BuildURLWithParam(param, origVal), "", nil)
		}
		if err != nil || baseResp == nil || baseResp.StatusCode != 200 {
			continue
		}

		// Candidate test values
		var testValues []string
		testedSet := make(map[string]bool)
		addTestVal := func(v string) {
			if v != "" && v != origVal && !testedSet[v] {
				testedSet[v] = true
				testValues = append(testValues, v)
			}
		}

		if isNumeric {
			// 1. Broad neighborhood sweep around the target ID (e.g. from numVal-30 to numVal+15)
			minBound := numVal - 30
			if minBound < 0 {
				minBound = 0
			}
			maxBound := numVal + 15
			for i := minBound; i <= maxBound; i++ {
				addTestVal(strconv.Itoa(i))
			}

			// 2. Hundred roundings and base block (e.g. 4200 to 4215)
			if numVal > 100 {
				hundredBase := (numVal / 100) * 100
				for i := hundredBase; i <= hundredBase+15; i++ {
					addTestVal(strconv.Itoa(i))
				}
			}

			// 3. Common administrative and initial records
			for _, fixed := range []string{"1", "0", "2", "3", "4", "5", "10", "100", "1000"} {
				addTestVal(fixed)
			}
		} else {
			addTestVal(origVal + "1")
			addTestVal("1")
			addTestVal("2")
			addTestVal("admin")
			addTestVal("root")
		}

		for _, testVal := range testValues {
			// Case A: Multi-Identity Verification (-b2 / -H2)
			if target.Cookie2 != "" || len(target.Headers2) > 0 {
				headers2 := make(map[string]string)
				for k, v := range target.Headers2 {
					headers2[k] = v
				}
				if target.Cookie2 != "" {
					headers2["Cookie"] = target.Cookie2
				}

				var resp2 *client.Response
				if isPost {
					resp2, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, origVal), headers2)
				} else {
					resp2, err = c.Request("GET", target.BuildURLWithParam(param, origVal), "", headers2)
				}

				if err == nil && resp2 != nil && resp2.StatusCode == 200 {
					sim := Similarity(baseResp.Body, resp2.Body)
					if sim >= 0.70 && len(resp2.Body) > 20 {
						snippet := resp2.Body
						if len(snippet) > 200 {
							snippet = snippet[:200]
						}
						findings = append(findings, &Finding{
							Module:      m.Name(),
							Title:       "Insecure Direct Object Reference (IDOR) / BOLA",
							Severity:    SeverityHigh,
							Confidence:  100,
							URL:         target.URL,
							Parameter:   param,
							Payload:     origVal,
							Detail:      fmt.Sprintf("Secondary identity accessed object '%s' belonging to primary identity (similarity: %.2f)", origVal, sim),
							Evidence:    snippet,
							Remediation: "Enforce server-side object-level authorization checks validating the requesting identity against object ownership.",
							CWEID:       639,
						})
						break
					}
				}
			} else {
				// Case B: Single Identity parameter swapping (Collect ALL accessible records, without breaking early!)
				var swapResp *client.Response
				var swapURL string
				if isPost {
					swapResp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, testVal), nil)
					swapURL = target.URL
				} else {
					swapURL = target.BuildURLWithParam(param, testVal)
					swapResp, err = c.Request("GET", swapURL, "", nil)
				}

				if err == nil && swapResp != nil && swapResp.StatusCode == 200 {
					// B1: Sensitive Flag / Credential Disclosed in Swapped Record
					if sensitiveFlagRegex.MatchString(swapResp.Body) && !sensitiveFlagRegex.MatchString(baseResp.Body) {
						flagSnippet := sensitiveFlagRegex.FindString(swapResp.Body)
						findings = append(findings, &Finding{
							Module:      m.Name(),
							Title:       fmt.Sprintf("Insecure Direct Object Reference (IDOR) - Flag/Secret Disclosed (ID: %s)", testVal),
							Severity:    SeverityCritical,
							Confidence:  100,
							URL:         swapURL,
							Parameter:   param,
							Payload:     testVal,
							Detail:      fmt.Sprintf("Parameter '%s' accessed another object (%s) disclosing sensitive data/flag.", param, testVal),
							Evidence:    fmt.Sprintf("Disclosed sensitive indicator: '%s'", flagSnippet),
							Remediation: "Enforce strict object-level authorization checking that the authenticated user owns the requested object ID.",
							CWEID:       639,
						})
						continue
					}

					// B2: Sensitive PII Disclosed
					if piiRegex.MatchString(swapResp.Body) && !piiRegex.MatchString(baseResp.Body) {
						snippet := piiRegex.FindString(swapResp.Body)
						findings = append(findings, &Finding{
							Module:      m.Name(),
							Title:       fmt.Sprintf("Insecure Direct Object Reference (IDOR) - PII Disclosed (ID: %s)", testVal),
							Severity:    SeverityHigh,
							Confidence:  95,
							URL:         swapURL,
							Parameter:   param,
							Payload:     testVal,
							Detail:      fmt.Sprintf("Parameter '%s' returned private PII when swapped from '%s' to '%s'.", param, origVal, testVal),
							Evidence:    snippet,
							Remediation: "Verify user authorization against the requested resource ID server-side before returning records.",
							CWEID:       639,
						})
						continue
					}

					// B3: Structural Object Switch on private resource
					sim := Similarity(baseResp.Body, swapResp.Body)
					if sim >= 0.35 && sim <= 0.95 && len(swapResp.Body) > 40 && privateIDParamRegex.MatchString(paramLower) {
						snippet := swapResp.Body
						if len(snippet) > 200 {
							snippet = snippet[:200]
						}
						findings = append(findings, &Finding{
							Module:      m.Name(),
							Title:       fmt.Sprintf("Insecure Direct Object Reference (IDOR) - Object #%s Accessible", testVal),
							Severity:    SeverityMedium,
							Confidence:  85,
							URL:         swapURL,
							Parameter:   param,
							Payload:     testVal,
							Detail:      fmt.Sprintf("Parameter '%s' returned HTTP 200 with distinct object data when swapped from '%s' to '%s'.", param, origVal, testVal),
							Evidence:    snippet,
							Remediation: "Verify user authorization against the requested resource ID server-side before returning records.",
							CWEID:       639,
						})
						continue
					}
				}
			}
		}
	}

	return findings, nil
}
