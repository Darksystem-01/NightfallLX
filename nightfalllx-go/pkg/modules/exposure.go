package modules

import (
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"regexp"
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
	Title    string
	Severity Severity
	CWEID    int
}{
	{
		Path:     "/.git/HEAD",
		Method:   "GET",
		Regex:    regexp.MustCompile(`ref:\s*refs/heads/`),
		Title:    "Exposed Git Repository Configuration (/.git/HEAD)",
		Severity: SeverityCritical,
		CWEID:    538,
	},
	{
		Path:     "/.env",
		Method:   "GET",
		Regex:    regexp.MustCompile(`(?i)(DB_PASSWORD|APP_KEY|AWS_SECRET|DATABASE_URL|SECRET_KEY|REDIS_PASSWORD)`),
		Title:    "Exposed Environment Credentials File (/.env)",
		Severity: SeverityCritical,
		CWEID:    552,
	},
	{
		Path:     "/.DS_Store",
		Method:   "GET",
		Regex:    regexp.MustCompile(`Bud1`),
		Title:    "Exposed Apple macOS Directory Metadata (/.DS_Store)",
		Severity: SeverityMedium,
		CWEID:    538,
	},
	{
		Path:     "/phpinfo.php",
		Method:   "GET",
		Regex:    regexp.MustCompile(`(?i)(PHP Version <|<h1>PHP Version|<title>phpinfo\(\)</title>)`),
		Title:    "Exposed PHP Information Page (/phpinfo.php)",
		Severity: SeverityMedium,
		CWEID:    200,
	},
	{
		Path:     "/server-status",
		Method:   "GET",
		Regex:    regexp.MustCompile(`(?i)(Apache Server Status for|Server Version: Apache)`),
		Title:    "Exposed Apache Server Status Page (/server-status)",
		Severity: SeverityMedium,
		CWEID:    200,
	},
	{
		Path:     "/swagger.json",
		Method:   "GET",
		Regex:    regexp.MustCompile(`(?i)("swagger":\s*"2\.|"openapi":\s*"3\.)`),
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
		Title:    "Enabled GraphQL Schema Introspection Query (/graphql)",
		Severity: SeverityLow,
		CWEID:    200,
	},
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
