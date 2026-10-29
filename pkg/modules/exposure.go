package modules

import (
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"regexp"
	"strings"
)

type ExposureModule struct{}

func NewExposureModule() *ExposureModule {
	return &ExposureModule{}
}

func (m *ExposureModule) Name() string {
	return "exposure"
}

func (m *ExposureModule) Description() string {
	return "Sensitive File, Backup, Configuration, and API Exposure Detection"
}

var exposureProbes = []struct {
	Path     string
	Method   string
	Body     string
	Headers  map[string]string
	Regex    *regexp.Regexp
	IsHTML   bool
	Title    string
	Severity Severity
	CWEID    int
}{
	{
		Path:     "/.git/HEAD",
		Method:   "GET",
		Regex:    regexp.MustCompile(`(?m)(ref:\s*refs/heads/|^[0-9a-f]{40}$)`),
		IsHTML:   false,
		Title:    "Exposed Git Repository Configuration (/.git/HEAD)",
		Severity: SeverityCritical,
		CWEID:    538,
	},
	{
		Path:     "/.git/config",
		Method:   "GET",
		Regex:    regexp.MustCompile(`(?m)\[(core|remote\s*"origin"|branch\s*"[^"]+")\]`),
		IsHTML:   false,
		Title:    "Exposed Git Repository Configuration (/.git/config)",
		Severity: SeverityCritical,
		CWEID:    538,
	},
	{
		Path:     "/.env",
		Method:   "GET",
		Regex:    regexp.MustCompile(`(?m)^[A-Za-z_][A-Za-z0-9_]{1,64}\s*=\s*.*`),
		IsHTML:   false,
		Title:    "Exposed Environment Credentials File (/.env)",
		Severity: SeverityCritical,
		CWEID:    552,
	},
	{
		Path:     "/.env.local",
		Method:   "GET",
		Regex:    regexp.MustCompile(`(?m)^[A-Za-z_][A-Za-z0-9_]{1,64}\s*=\s*.*`),
		IsHTML:   false,
		Title:    "Exposed Environment Credentials File (/.env.local)",
		Severity: SeverityCritical,
		CWEID:    552,
	},
	{
		Path:     "/.env.production",
		Method:   "GET",
		Regex:    regexp.MustCompile(`(?m)^[A-Za-z_][A-Za-z0-9_]{1,64}\s*=\s*.*`),
		IsHTML:   false,
		Title:    "Exposed Environment Credentials File (/.env.production)",
		Severity: SeverityCritical,
		CWEID:    552,
	},
	{
		Path:     "/.env.backup",
		Method:   "GET",
		Regex:    regexp.MustCompile(`(?m)^[A-Za-z_][A-Za-z0-9_]{1,64}\s*=\s*.*`),
		IsHTML:   false,
		Title:    "Exposed Environment Backup File (/.env.backup)",
		Severity: SeverityCritical,
		CWEID:    552,
	},
	{
		Path:     "/.DS_Store",
		Method:   "GET",
		Regex:    regexp.MustCompile(`Bud1`),
		IsHTML:   false,
		Title:    "Exposed Apple macOS Directory Metadata (/.DS_Store)",
		Severity: SeverityMedium,
		CWEID:    538,
	},
	{
		Path:     "/phpinfo.php",
		Method:   "GET",
		Regex:    regexp.MustCompile(`(?i)(PHP Version <|<h1>PHP Version|<title>phpinfo\(\)</title>)`),
		IsHTML:   true,
		Title:    "Exposed PHP Information Page (/phpinfo.php)",
		Severity: SeverityMedium,
		CWEID:    200,
	},
	{
		Path:     "/server-status",
		Method:   "GET",
		Regex:    regexp.MustCompile(`(?i)(Apache Server Status for|Server Version: Apache)`),
		IsHTML:   true,
		Title:    "Exposed Apache Server Status Page (/server-status)",
		Severity: SeverityMedium,
		CWEID:    200,
	},
	{
		Path:     "/swagger.json",
		Method:   "GET",
		Regex:    regexp.MustCompile(`(?i)("swagger":\s*"2\.|"openapi":\s*"3\.)`),
		IsHTML:   false,
		Title:    "Exposed Swagger / OpenAPI Specification (/swagger.json)",
		Severity: SeverityLow,
		CWEID:    200,
	},
	{
		Path:     "/graphql",
		Method:   "POST",
		Body:     `{"query":"{__schema{types{name}}}"}`,
		Headers:  map[string]string{"Content-Type": "application/json"},
		Regex:    regexp.MustCompile(`"__schema"\s*:\s*\{\s*"types"`),
		IsHTML:   false,
		Title:    "Enabled GraphQL Schema Introspection Query (/graphql)",
		Severity: SeverityLow,
		CWEID:    200,
	},
	{
		Path:     "/docker-compose.yml",
		Method:   "GET",
		Regex:    regexp.MustCompile(`(?i)(version:\s*["'0-9.]+|services:\s*
\s+\w+:)`),
		IsHTML:   false,
		Title:    "Exposed Docker Compose Configuration (/docker-compose.yml)",
		Severity: SeverityCritical,
		CWEID:    552,
	},
	{
		Path:     "/web.config",
		Method:   "GET",
		Regex:    regexp.MustCompile(`(?i)<configuration>\s*<system\.webServer>`),
		IsHTML:   false,
		Title:    "Exposed IIS Web Configuration (/web.config)",
		Severity: SeverityHigh,
		CWEID:    552,
	},
	{
		Path:     "/.bash_history",
		Method:   "GET",
		Regex:    regexp.MustCompile(`(?m)^(sudo |cd |ls |cat |curl |ssh |git |docker )`),
		IsHTML:   false,
		Title:    "Exposed Shell History File (/.bash_history)",
		Severity: SeverityHigh,
		CWEID:    538,
	},
}

func isHTMLDocument(body string) bool {
	lower := strings.ToLower(strings.TrimSpace(body))
	return strings.HasPrefix(lower, "<!doctype") ||
		strings.HasPrefix(lower, "<html") ||
		strings.Contains(lower, "<head>") ||
		strings.Contains(lower, "<body>") ||
		strings.Contains(lower, "__next") ||
		strings.Contains(lower, "<div id=\"root\"")
}

func (m *ExposureModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil, nil
	}
	baseURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)

	for _, probe := range exposureProbes {
		probeURL := baseURL + probe.Path
		method := probe.Method
		if method == "" {
			method = "GET"
		}

		resp, err := c.Request(method, probeURL, probe.Body, probe.Headers)
		if err != nil || resp == nil || resp.Body == "" {
			continue
		}

		// Strictly require 200 OK or 206 Partial Content (eliminates 404/403/500 custom error False Positives)
		if resp.StatusCode != 200 && resp.StatusCode != 206 {
			continue
		}

		// Reject HTML fallback/SPA responses on non-HTML probes
		if !probe.IsHTML && isHTMLDocument(resp.Body) {
			continue
		}

		if probe.Regex.MatchString(resp.Body) {
			evidence := probe.Regex.FindString(resp.Body)
			if len(evidence) > 200 {
				evidence = evidence[:200]
			}
			findings = append(findings, &Finding{
				Module:      m.Name(),
				Title:       probe.Title,
				Severity:    probe.Severity,
				Confidence:  100,
				URL:         probeURL,
				Parameter:   probe.Path,
				Payload:     probeURL,
				Detail:      fmt.Sprintf("Sensitive resource disclosed via deterministic content pattern match: '%s'.", evidence),
				Evidence:    evidence,
				Remediation: "Restrict public access to administrative, metadata, and configuration files via web server directives.",
				CWEID:       probe.CWEID,
			})
		}
	}

	return findings, nil
}
