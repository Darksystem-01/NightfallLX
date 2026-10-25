package secrets

import (
	"fmt"
	"math"
	"net/url"
	"nightfalllx/pkg/client"
	"regexp"
	"strings"
)

var reScriptSrc = regexp.MustCompile(`(?i)<script[^>]+src=['"]([^'"]+)['"]`)

// SecretFinding represents an identified credential leak.
type SecretFinding struct {
	Pattern     string `json:"pattern"`
	Match       string `json:"match"`
	Context     string `json:"context"`
	URL         string `json:"url"`
	Severity    string `json:"severity"`
	Confidence  int    `json:"confidence"`
	Remediation string `json:"remediation"`
}

// SecretScanner scans strings and URLs for confidential tokens.
type SecretScanner struct {
	Patterns []SecretPattern
}

// NewSecretScanner returns a new instance with default patterns.
func NewSecretScanner() *SecretScanner {
	return &SecretScanner{
		Patterns: BuiltinPatterns,
	}
}

// Redact formats sensitive matches safely for reporting (first 4 + ... + last 4).
func Redact(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 8 {
		return "******"
	}
	return s[:4] + "..." + s[len(s)-4:]
}

// Shannon calculates the Shannon entropy of a string (bits per char).
func Shannon(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]float64)
	for _, r := range s {
		counts[r]++
	}
	length := float64(len(s))
	entropy := 0.0
	for _, count := range counts {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// ScanString scans text content and reports findings.
func (s *SecretScanner) ScanString(content, sourceURL string) []SecretFinding {
	var findings []SecretFinding
	seen := make(map[string]bool)

	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}

		for _, pat := range s.Patterns {
			matches := pat.Regex.FindAllString(trimmed, -1)
			for _, m := range matches {
				dedupKey := pat.Name + ":" + m
				if seen[dedupKey] {
					continue
				}
				seen[dedupKey] = true

				context := trimmed
				if len(context) > 120 {
					context = context[:120] + "..."
				}

				findings = append(findings, SecretFinding{
					Pattern:     pat.Name,
					Match:       Redact(m),
					Context:     fmt.Sprintf("Line %d: %s", lineNum+1, context),
					URL:         sourceURL,
					Severity:    pat.Severity,
					Confidence:  pat.Confidence,
					Remediation: pat.Remediation,
				})
			}
		}
	}

	return findings
}

// ScanURL fetches a target URL and inspects response body plus linked JS scripts.
func (s *SecretScanner) ScanURL(c *client.Client, targetURL string) ([]SecretFinding, error) {
	resp, err := c.Request("GET", targetURL, "", nil)
	if err != nil || resp == nil {
		return nil, err
	}

	findings := s.ScanString(resp.Body, targetURL)

	// If HTML, parse and scan external scripts
	ct := strings.ToLower(resp.Headers.Get("Content-Type"))
	if strings.Contains(ct, "text/html") {
		matches := reScriptSrc.FindAllStringSubmatch(resp.Body, -1)
		baseU, _ := url.Parse(targetURL)

		scriptCount := 0
		for _, m := range matches {
			if len(m) < 2 || scriptCount >= 10 {
				continue
			}
			src := m[1]
			if strings.HasPrefix(src, "data:") {
				continue
			}

			scriptURL := src
			if baseU != nil {
				if relU, err := url.Parse(src); err == nil {
					scriptURL = baseU.ResolveReference(relU).String()
				}
			}

			jsResp, err := c.Request("GET", scriptURL, "", nil)
			if err == nil && jsResp != nil && len(jsResp.Body) > 0 {
				scriptFindings := s.ScanString(jsResp.Body, scriptURL)
				findings = append(findings, scriptFindings...)
				scriptCount++
			}
		}
	}

	return findings, nil
}
