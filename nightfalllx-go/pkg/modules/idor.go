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

var idParamRegex = regexp.MustCompile(`(?i)(id|user|account|order|doc|file|invoice|item|num|profile)`)

func (m *IDORModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
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
		if origVal == "" && target.IsJSON && target.JSONLeaves != nil {
			if v, ok := target.JSONLeaves[param]; ok {
				origVal = fmt.Sprintf("%v", v)
			}
		}

		// Check if parameter name or value looks like an identifier
		isNumeric := false
		numVal, err := strconv.Atoi(origVal)
		if err == nil && numVal > 0 {
			isNumeric = true
		}

		if !isNumeric && !idParamRegex.MatchString(param) {
			continue
		}

		// Baseline request with original identity
		var baseResp *client.Response
		if isPost {
			baseResp, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, origVal), headers)
		} else {
			baseResp, err = c.Request("GET", target.BuildURLWithParam(param, origVal), "", nil)
		}
		if err != nil || baseResp == nil || baseResp.StatusCode != 200 {
			continue
		}

		// Candidate test values (numeric +/-1)
		var testValues []string
		if isNumeric {
			testValues = append(testValues, strconv.Itoa(numVal+1))
			if numVal > 1 {
				testValues = append(testValues, strconv.Itoa(numVal-1))
			}
		} else {
			testValues = append(testValues, origVal+"1", "1", "2")
		}

		for _, testVal := range testValues {
			// Case A: Secondary Identity Provided (-b2 / -H2)
			if target.Cookie2 != "" || len(target.Headers2) > 0 {
				headers2 := make(map[string]string)
				for k, v := range target.Headers2 {
					headers2[k] = v
				}
				if target.Cookie2 != "" {
					headers2["Cookie"] = target.Cookie2
				}
				if target.IsJSON {
					headers2["Content-Type"] = "application/json"
				}

				var resp2 *client.Response
				if isPost {
					resp2, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, origVal), headers2)
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
						f := &Finding{
							Module:      m.Name(),
							Title:       "Insecure Direct Object Reference (IDOR) / BOLA",
							Severity:    SeverityHigh,
							URL:         target.URL,
							Parameter:   param,
							Payload:     origVal,
							Detail:      fmt.Sprintf("Secondary identity accessed object '%s' belonging to primary identity (similarity: %.2f)", origVal, sim),
							Evidence:    snippet,
							Remediation: "Enforce server-side object-level authorization checks validating the requesting identity against object ownership.",
							CWEID:       639,
						}
						f.SetConfidence(ConfidenceConfirmed)
						findings = append(findings, f)
						break
					}
				}
			} else {
				// Case B: Single Identity parameter swapping
				var swapResp *client.Response
				if isPost {
					swapResp, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, testVal), headers)
				} else {
					swapResp, err = c.Request("GET", target.BuildURLWithParam(param, testVal), "", nil)
				}

				if err == nil && swapResp != nil && swapResp.StatusCode == 200 {
					sim := Similarity(baseResp.Body, swapResp.Body)
					// If status is 200 and returns substantive distinct content with moderate similarity
					if sim >= 0.50 && sim < 0.98 && len(swapResp.Body) > 50 {
						snippet := swapResp.Body
						if len(snippet) > 200 {
							snippet = snippet[:200]
						}
						f := &Finding{
							Module:      m.Name(),
							Title:       "Possible Insecure Direct Object Reference (IDOR)",
							Severity:    SeverityMedium,
							URL:         target.URL,
							Parameter:   param,
							Payload:     testVal,
							Detail:      fmt.Sprintf("Parameter '%s' returned 200 OK with distinct object data when swapped from '%s' to '%s'. Verify cross-user authorization with -b2.", param, origVal, testVal),
							Evidence:    snippet,
							Remediation: "Verify user authorization against the requested resource ID server-side before returning records.",
							CWEID:       639,
						}
						f.SetConfidence(ConfidencePossible)
						findings = append(findings, f)
						break
					}
				}
			}
		}
	}

	return findings, nil
}
