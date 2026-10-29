package modules

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"nightfalllx/pkg/client"
)

// JSEndpoint represents an API route or endpoint found in JavaScript.
type JSEndpoint struct {
	Path         string `json:"path"`
	SourceScript string `json:"source_script"`
	Type         string `json:"type"` // "REST API", "GraphQL", "Auth/SSO", "Admin Portal", "Route"
}

// JSSecret represents a sensitive credential found inside JavaScript.
type JSSecret struct {
	Name         string `json:"name"`
	Secret       string `json:"secret"`
	Severity     string `json:"severity"`
	SourceScript string `json:"source_script"`
}

// JSScriptResult holds mining results for a single JavaScript file.
type JSScriptResult struct {
	ScriptURL string        `json:"script_url"`
	Size      int           `json:"size"`
	Endpoints []*JSEndpoint `json:"endpoints"`
	Secrets   []*JSSecret   `json:"secrets"`
}

// JSMiningReport is the overall summary of JS intelligence gathering.
type JSMiningReport struct {
	TargetURL      string            `json:"target_url"`
	TotalScripts   int               `json:"total_scripts"`
	TotalEndpoints int               `json:"total_endpoints"`
	TotalSecrets   int               `json:"total_secrets"`
	Scripts        []*JSScriptResult `json:"scripts"`
	AllEndpoints   []string          `json:"all_endpoints"`
}

// JSMinerModule audits client-side JavaScript for hidden API endpoints and leaked credentials.
type JSMinerModule struct{}

// NewJSMinerModule creates a new JS miner instance.
func NewJSMinerModule() *JSMinerModule {
	return &JSMinerModule{}
}

func (m *JSMinerModule) Name() string {
	return "jsminer"
}

func (m *JSMinerModule) Description() string {
	return "Mines client-side JavaScript bundles for hidden API endpoints, GraphQL routes, and hardcoded secrets"
}

func (m *JSMinerModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	_, findings, err := MineJavaScript(target.URL, c)
	return findings, err
}

// Internal secret detection pattern for JS scanning
type jsSecretPattern struct {
	Name        string
	Regex       *regexp.Regexp
	Severity    string
	Confidence  int
	Remediation string
}

var (
	// Regex for script tags: <script ... src="url" ...> or <link rel="modulepreload" ... href="url">
	reScriptSrc    = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	reLinkPreload  = regexp.MustCompile(`(?i)<link[^>]+rel=["'](?:modulepreload|preload)["'][^>]+href=["']([^"']+\.js[^"']*)["']`)
	reInlineScript = regexp.MustCompile(`(?is)<script(?:|[^>]+)>(.*?)</script>`)

	// LinkFinder-grade endpoint extraction regexes
	reQuotedString = regexp.MustCompile(`(?:"|')([a-zA-Z0-9_\-\./~@%#\?&=:]{2,})(?:"|')`)
	reAPIEndpoint  = regexp.MustCompile(`(?i)^(?:\/api\/|\/v[0-9]+\/|\/graphql|\/rest\/|\/auth\/|\/oauth\/|\/admin\/|\/user\/|\/users\/|\/internal\/|\/portal\/|\/ws\/|\/hub\/)`)
	reGenericPath  = regexp.MustCompile(`^(?:\/[a-zA-Z0-9_\-\.]+){1,}\/?(?:\?[a-zA-Z0-9_=&%.-]+)?$`)

	// High precision secret signatures
	builtinJSPatterns = []jsSecretPattern{
		{
			Name:        "GitHub Personal Access Token",
			Regex:       regexp.MustCompile(`gh[pous]_[A-Za-z0-9_]{36,255}`),
			Severity:    "CRITICAL",
			Confidence:  95,
			Remediation: "Revoke token immediately via GitHub Settings -> Developer settings -> Personal access tokens.",
		},
		{
			Name:        "AWS Access Key ID",
			Regex:       regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
			Severity:    "HIGH",
			Confidence:  90,
			Remediation: "Rotate AWS IAM credentials and audit CloudTrail for unauthorized API calls.",
		},
		{
			Name:        "AWS Secret Access Key",
			Regex:       regexp.MustCompile(`(?i)aws_secret_access_key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
			Severity:    "CRITICAL",
			Confidence:  95,
			Remediation: "Revoke and rotate secret access key immediately in AWS IAM console.",
		},
		{
			Name:        "Google API Key",
			Regex:       regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
			Severity:    "HIGH",
			Confidence:  85,
			Remediation: "Restrict API key scope in Google Cloud Console or regenerate.",
		},
		{
			Name:        "Stripe Live API Key",
			Regex:       regexp.MustCompile(`(?:rk|sk)_live_[0-9a-zA-Z]{24}`),
			Severity:    "CRITICAL",
			Confidence:  95,
			Remediation: "Roll Stripe secret keys in the Stripe Developer Dashboard.",
		},
		{
			Name:        "Slack Webhook URL",
			Regex:       regexp.MustCompile(`https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+`),
			Severity:    "HIGH",
			Confidence:  95,
			Remediation: "Revoke incoming webhook URL in Slack App management portal.",
		},
		{
			Name:        "JWT (JSON Web Token)",
			Regex:       regexp.MustCompile(`ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+`),
			Severity:    "MEDIUM",
			Confidence:  80,
			Remediation: "Ensure hardcoded JWTs are not client-baked secrets or long-lived admin credentials.",
		},
		{
			Name:        "RSA/EC Private Key",
			Regex:       regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
			Severity:    "CRITICAL",
			Confidence:  100,
			Remediation: "Rotate compromised cryptographic private key immediately.",
		},
	}
)

// MineJavaScript fetches target HTML, downloads discovered scripts, and extracts endpoints and secrets.
func MineJavaScript(targetURL string, c *client.Client) (*JSMiningReport, []*Finding, error) {
	parsedTarget, err := url.Parse(targetURL)
	if err != nil {
		return nil, nil, err
	}

	targetHost := parsedTarget.Hostname()

	// 1. Fetch initial HTML
	resp, err := c.Request("GET", targetURL, "", nil)
	if err != nil || resp == nil {
		return nil, nil, fmt.Errorf("failed to fetch target HTML: %w", err)
	}

	htmlContent := resp.Body

	// 2. Discover script URLs
	scriptURLs := extractScriptURLs(htmlContent, parsedTarget)

	report := &JSMiningReport{
		TargetURL:    targetURL,
		TotalScripts: len(scriptURLs),
	}

	var (
		findings     []*Finding
		resultsMu    sync.Mutex
		wg           sync.WaitGroup
		endpointSeen = make(map[string]bool)
		secretSeen   = make(map[string]bool)
	)

	// Concurrency limiter for downloading scripts
	sem := make(chan struct{}, 10)

	for _, sURL := range scriptURLs {
		wg.Add(1)
		go func(scriptURL string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			sResp, sErr := c.Request("GET", scriptURL, "", nil)
			if sErr != nil || sResp == nil || len(sResp.Body) == 0 {
				return
			}

			jsBody := sResp.Body
			sRes := &JSScriptResult{
				ScriptURL: scriptURL,
				Size:      len(jsBody),
			}

			// Extract endpoints
			extractedEPs := extractEndpointsFromJS(jsBody)
			for _, ep := range extractedEPs {
				sRes.Endpoints = append(sRes.Endpoints, &JSEndpoint{
					Path:         ep,
					SourceScript: scriptURL,
					Type:         categorizeEndpoint(ep),
				})
			}

			// Extract secrets
			for _, pat := range builtinJSPatterns {
				matches := pat.Regex.FindAllString(jsBody, 5)
				for _, match := range matches {
					match = strings.TrimSpace(match)
					if len(match) < 6 || isGenericFalsePositive(match) {
						continue
					}

					key := pat.Name + ":" + match
					resultsMu.Lock()
					isNew := !secretSeen[key]
					if isNew {
						secretSeen[key] = true
					}
					resultsMu.Unlock()

					if isNew {
						sRes.Secrets = append(sRes.Secrets, &JSSecret{
							Name:         pat.Name,
							Secret:       maskSecret(match),
							Severity:     pat.Severity,
							SourceScript: scriptURL,
						})

						var sev Severity
						switch pat.Severity {
						case "CRITICAL":
							sev = SeverityCritical
						case "HIGH":
							sev = SeverityHigh
						case "MEDIUM":
							sev = SeverityMedium
						default:
							sev = SeverityLow
						}

						finding := &Finding{
							Module:      "jsminer",
							Title:       fmt.Sprintf("Exposed %s in Client-Side JavaScript", pat.Name),
							Severity:    sev,
							Confidence:  pat.Confidence,
							URL:         scriptURL,
							Parameter:   "javascript",
							Payload:     maskSecret(match),
							Detail:      fmt.Sprintf("Discovered exposed %s token in client-side bundle (%s).", pat.Name, scriptURL),
							Evidence:    fmt.Sprintf("Token match: %s", match),
							Remediation: pat.Remediation,
							CWEID:       798,
							CVSS:        7.5,
						}
						resultsMu.Lock()
						findings = append(findings, finding)
						resultsMu.Unlock()
					}
				}
			}

			resultsMu.Lock()
			report.Scripts = append(report.Scripts, sRes)
			for _, ep := range sRes.Endpoints {
				if !endpointSeen[ep.Path] {
					endpointSeen[ep.Path] = true
					report.AllEndpoints = append(report.AllEndpoints, ep.Path)
				}
			}
			resultsMu.Unlock()
		}(sURL)
	}

	wg.Wait()

	// Also parse inline scripts from original HTML
	inlineMatches := reInlineScript.FindAllStringSubmatch(htmlContent, -1)
	if len(inlineMatches) > 0 {
		var inlineEndpoints []*JSEndpoint
		var inlineSecrets []*JSSecret
		for i, match := range inlineMatches {
			if len(match) < 2 {
				continue
			}
			inlineBody := match[1]
			eps := extractEndpointsFromJS(inlineBody)
			for _, ep := range eps {
				inlineEndpoints = append(inlineEndpoints, &JSEndpoint{
					Path:         ep,
					SourceScript: fmt.Sprintf("%s (inline script #%d)", targetURL, i+1),
					Type:         categorizeEndpoint(ep),
				})
				if !endpointSeen[ep] {
					endpointSeen[ep] = true
					report.AllEndpoints = append(report.AllEndpoints, ep)
				}
			}
		}
		if len(inlineEndpoints) > 0 || len(inlineSecrets) > 0 {
			report.Scripts = append(report.Scripts, &JSScriptResult{
				ScriptURL: targetURL + " [Inline Scripts]",
				Size:      len(htmlContent),
				Endpoints: inlineEndpoints,
				Secrets:   inlineSecrets,
			})
		}
	}

	report.TotalEndpoints = len(report.AllEndpoints)
	for _, s := range report.Scripts {
		report.TotalSecrets += len(s.Secrets)
	}

	sort.Strings(report.AllEndpoints)
	_ = targetHost

	return report, findings, nil
}

func extractScriptURLs(htmlContent string, base *url.URL) []string {
	var scripts []string
	seen := make(map[string]bool)

	addURL := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "javascript:") {
			return
		}

		u, err := url.Parse(raw)
		if err != nil {
			return
		}

		resolved := base.ResolveReference(u).String()
		if !seen[resolved] {
			seen[resolved] = true
			scripts = append(scripts, resolved)
		}
	}

	// 1. <script src="...">
	matches := reScriptSrc.FindAllStringSubmatch(htmlContent, -1)
	for _, m := range matches {
		if len(m) > 1 {
			addURL(m[1])
		}
	}

	// 2. <link rel="modulepreload" href="...">
	matchesPreload := reLinkPreload.FindAllStringSubmatch(htmlContent, -1)
	for _, m := range matchesPreload {
		if len(m) > 1 {
			addURL(m[1])
		}
	}

	return scripts
}

func extractEndpointsFromJS(jsBody string) []string {
	var endpoints []string
	seen := make(map[string]bool)

	matches := reQuotedString.FindAllStringSubmatch(jsBody, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		candidate := strings.TrimSpace(m[1])
		if isInterestingEndpoint(candidate) {
			if !seen[candidate] {
				seen[candidate] = true
				endpoints = append(endpoints, candidate)
			}
		}
	}

	return endpoints
}

func isInterestingEndpoint(s string) bool {
	if len(s) < 3 || len(s) > 150 {
		return false
	}

	// Ignore common false positives
	if strings.HasPrefix(s, "http://www.w3.org/") ||
		strings.HasPrefix(s, "application/") ||
		strings.HasPrefix(s, "text/") ||
		strings.HasPrefix(s, "image/") ||
		strings.HasPrefix(s, "font/") {
		return false
	}

	// Ignore common file extensions that are purely assets
	lower := strings.ToLower(s)
	for _, ext := range []string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2", ".ttf", ".eot"} {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}

	// High confidence API endpoints
	if reAPIEndpoint.MatchString(s) {
		return true
	}

	// General relative paths: /users, /dashboard/settings, etc.
	if strings.HasPrefix(s, "/") && reGenericPath.MatchString(s) {
		if strings.Contains(s, "<") || strings.Contains(s, ">") || strings.Contains(s, " ") {
			return false
		}
		return true
	}

	return false
}

func categorizeEndpoint(p string) string {
	lower := strings.ToLower(p)
	switch {
	case strings.Contains(lower, "graphql"):
		return "GraphQL"
	case strings.HasPrefix(lower, "/api/"):
		return "REST API"
	case strings.Contains(lower, "/auth/") || strings.Contains(lower, "oauth") || strings.Contains(lower, "login"):
		return "Auth/SSO"
	case strings.Contains(lower, "admin"):
		return "Admin Portal"
	default:
		return "Route"
	}
}

func isGenericFalsePositive(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "example") ||
		strings.Contains(lower, "placeholder") ||
		strings.Contains(lower, "xxxxxx") ||
		strings.Contains(lower, "000000") ||
		strings.Contains(lower, "test_")
}

func maskSecret(s string) string {
	if len(s) <= 8 {
		return "********"
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

// PrintJSMinerReport renders an executive terminal view of discovered JS endpoints and secrets.
func PrintJSMinerReport(rep *JSMiningReport) {
	fmt.Println("\n\033[1;36m┌──────────────────────────────────────────────────────────────────────────────────┐\033[0m")
	fmt.Printf("\033[1;36m│\033[0m \033[1;37m📜 NightfallLX Client-Side JavaScript Endpoint & Secret Miner\033[0m                    \033[1;36m│\033[0m\n")
	fmt.Printf("\033[1;36m│\033[0m Target:        \033[1;33m%-66s\033[0m \033[1;36m│\033[0m\n", rep.TargetURL)
	fmt.Printf("\033[1;36m│\033[0m Scripts Scanned:\033[1;32m %-65d\033[0m \033[1;36m│\033[0m\n", rep.TotalScripts)
	fmt.Printf("\033[1;36m│\033[0m Unique Routes: \033[1;35m%-66d\033[0m \033[1;36m│\033[0m\n", rep.TotalEndpoints)
	if rep.TotalSecrets > 0 {
		fmt.Printf("\033[1;36m│\033[0m Leaked Secrets:\033[1;31m %-65d\033[0m \033[1;36m│\033[0m\n", rep.TotalSecrets)
	} else {
		fmt.Printf("\033[1;36m│\033[0m Leaked Secrets:\033[1;32m 0 (Clean)\033[0m                                                     \033[1;36m│\033[0m\n")
	}
	fmt.Println("\033[1;36m└──────────────────────────────────────────────────────────────────────────────────┘\033[0m")

	for _, s := range rep.Scripts {
		if len(s.Endpoints) == 0 && len(s.Secrets) == 0 {
			continue
		}
		fmt.Printf("\n\033[1;34m[BUNDLE]\033[0m %s \033[90m(%d bytes)\033[0m\n", s.ScriptURL, s.Size)

		// Print Secrets
		for _, sec := range s.Secrets {
			badge := "\033[1;31m[CRITICAL SECRET]\033[0m"
			if sec.Severity == "HIGH" {
				badge = "\033[1;33m[HIGH SECRET]\033[0m"
			}
			fmt.Printf("  ├── %s \033[1m%s\033[0m: %s\n", badge, sec.Name, sec.Secret)
		}

		// Print top endpoints
		maxShow := 15
		for i, ep := range s.Endpoints {
			if i >= maxShow {
				fmt.Printf("  └── \033[90m... and %d more endpoints\033[0m\n", len(s.Endpoints)-maxShow)
				break
			}
			prefix := "├──"
			if i == len(s.Endpoints)-1 {
				prefix = "└──"
			}
			typeColor := "\033[36m"
			if ep.Type == "GraphQL" {
				typeColor = "\033[35m"
			} else if ep.Type == "Admin Portal" {
				typeColor = "\033[31m"
			} else if ep.Type == "REST API" {
				typeColor = "\033[32m"
			}
			fmt.Printf("  %s %s[%-12s]\033[0m %s\n", prefix, typeColor, ep.Type, ep.Path)
		}
	}
	fmt.Println()
}
