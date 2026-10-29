package reporters

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nightfalllx/pkg/modules"
)

func sampleTarget() *modules.Target {
	return &modules.Target{
		URL:    "http://target.lab/app.php?id=1",
		Method: "GET",
		Params: map[string]string{"id": "1"},
		Headers: map[string]string{
			"Cookie": "session=abc123",
		},
	}
}

func sampleFindings() []*modules.Finding {
	return []*modules.Finding{
		{
			Module:      "sqli",
			Title:       "Differential SQL Injection",
			Severity:    modules.SeverityCritical,
			Confidence:  97,
			URL:         "http://target.lab/app.php?id=1",
			Parameter:   "id",
			Payload:     "' OR 1=1--",
			Detail:      "Boolean-based differential response detected.",
			Evidence:    "TRUE response 1420 bytes, FALSE response 980 bytes.",
			Remediation: "Use parameterized queries.",
			CWEID:       89,
		},
		{
			Module:      "xss",
			Title:       "Reflected XSS",
			Severity:    modules.SeverityHigh,
			Confidence:  90,
			URL:         "http://target.lab/app.php?id=1",
			Parameter:   "id",
			Payload:     "<script>alert(1)</script>",
			Detail:      "Payload reflected without encoding.",
			Evidence:    "<script>alert(1)</script>",
			Remediation: "HTML-encode output.",
			CWEID:       79,
		},
		{
			Module:      "sqli",
			Title:       "Time-based SQL Injection",
			Severity:    modules.SeverityMedium,
			Confidence:  80,
			URL:         "http://target.lab/app.php?id=2",
			Parameter:   "id",
			Payload:     "1' AND SLEEP(5)--",
			Detail:      "Response delayed by 5 seconds.",
			Evidence:    "Elapsed: 5.02s",
			Remediation: "Use parameterized queries.",
			CWEID:       89,
		},
		{
			Module:      "headers",
			Title:       "Missing Security Header",
			Severity:    modules.SeverityLow,
			Confidence:  100,
			URL:         "http://target.lab/app.php",
			Parameter:   "Response Header",
			Payload:     "Content-Security-Policy",
			Detail:      "CSP header is absent.",
			Remediation: "Add a restrictive CSP.",
			CWEID:       693,
		},
		{
			Module:      "waf",
			Title:       "WAF Detected (Cloudflare)",
			Severity:    modules.SeverityInfo,
			Confidence:  95,
			URL:         "http://target.lab/",
			Parameter:   "Network Stack",
			Payload:     "Passive fingerprint",
			Detail:      "Cloudflare detected.",
			Remediation: "Information only.",
			CWEID:       200,
		},
	}
}

func testMeta() ReportMeta {
	return ReportMeta{
		Timestamp: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC),
		Duration:  1500 * time.Millisecond,
		Version:   "2.0.0",
		Command:   "nightfalllx -u http://target.lab/app.php?id=1",
	}
}

func TestCVSSForSeverity(t *testing.T) {
	cases := map[modules.Severity]float64{
		modules.SeverityCritical: 9.8,
		modules.SeverityHigh:     8.1,
		modules.SeverityMedium:   5.3,
		modules.SeverityLow:      3.1,
		modules.SeverityInfo:     0,
	}
	for sev, want := range cases {
		if got := CVSSForSeverity(sev); got != want {
			t.Fatalf("CVSSForSeverity(%s) = %v, want %v", sev, got, want)
		}
	}
}

func TestBuildReport(t *testing.T) {
	rep := BuildReport(sampleTarget(), sampleFindings(), testMeta())

	if rep.SchemaVersion != ReportSchemaVersion {
		t.Fatalf("schema = %q", rep.SchemaVersion)
	}
	if rep.Timestamp != "2026-10-25T12:00:00Z" {
		t.Fatalf("timestamp = %q", rep.Timestamp)
	}
	if rep.DurationMS != 1500 {
		t.Fatalf("duration_ms = %d", rep.DurationMS)
	}
	if rep.Summary.Total != 5 || rep.Summary.Critical != 1 || rep.Summary.High != 1 ||
		rep.Summary.Medium != 1 || rep.Summary.Low != 1 || rep.Summary.Info != 1 {
		t.Fatalf("summary = %+v", rep.Summary)
	}
	if rep.Target.Host != "target.lab" || len(rep.Target.Parameters) != 1 {
		t.Fatalf("target = %+v", rep.Target)
	}
	if len(rep.Findings) != 5 {
		t.Fatalf("findings = %d", len(rep.Findings))
	}
	if rep.Findings[0].CVSSScore != 9.8 {
		t.Fatalf("critical CVSS = %v", rep.Findings[0].CVSSScore)
	}
	if !strings.Contains(rep.Findings[0].Curl, "target.lab") {
		t.Fatalf("curl = %q", rep.Findings[0].Curl)
	}
	if rep.Findings[1].CWEURL != "https://cwe.mitre.org/data/definitions/79.html" {
		t.Fatalf("cwe url = %q", rep.Findings[1].CWEURL)
	}
}

func TestJSONReportRoundTrip(t *testing.T) {
	data, err := MarshalJSONReport(sampleTarget(), sampleFindings(), testMeta())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var rep Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rep.Generator != GeneratorName {
		t.Fatalf("generator = %q", rep.Generator)
	}
	if rep.Summary.Total != 5 || len(rep.Findings) != 5 {
		t.Fatalf("unexpected totals: %+v", rep.Summary)
	}
	if rep.Findings[0].Curl == "" || rep.Findings[0].SeverityClass != "critical" {
		t.Fatalf("enriched finding missing: %+v", rep.Findings[0])
	}
	if rep.Findings[0].Finding == nil || rep.Findings[0].CWEID != 89 {
		t.Fatalf("embedded finding not marshalled")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := WriteJSONReport(sampleTarget(), sampleFindings(), testMeta(), path); err != nil {
		t.Fatalf("write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 {
		t.Fatalf("report file missing: %v", err)
	}
}

func TestSARIFReport(t *testing.T) {
	data, err := BuildSARIFJSON(sampleTarget(), sampleFindings(), testMeta())
	if err != nil {
		t.Fatalf("build sarif: %v", err)
	}

	var doc struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID                   string `json:"id"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
						Properties struct {
							SecuritySeverity string   `json:"security-severity"`
							Tags             []string `json:"tags"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Message   struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if doc.Schema != SARIFSchema || doc.Version != "2.1.0" {
		t.Fatalf("bad sarif header: %s %s", doc.Schema, doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != GeneratorName {
		t.Fatalf("driver = %q", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) != 4 {
		t.Fatalf("rules = %d, want 4 unique modules", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 5 {
		t.Fatalf("results = %d", len(run.Results))
	}

	levels := map[string]bool{"error": true, "warning": true, "note": true}
	for i, res := range run.Results {
		if !levels[res.Level] {
			t.Fatalf("result %d has invalid level %q", i, res.Level)
		}
		if res.RuleIndex < 0 || res.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Fatalf("result %d ruleIndex out of range", i)
		}
		if run.Tool.Driver.Rules[res.RuleIndex].ID != res.RuleID {
			t.Fatalf("result %d ruleId/index mismatch", i)
		}
		if res.Message.Text == "" || len(res.Locations) != 1 {
			t.Fatalf("result %d incomplete", i)
		}
		if res.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Fatalf("result %d missing artifact uri", i)
		}
		if res.PartialFingerprints["primaryLocationLineHash"] == "" {
			t.Fatalf("result %d missing fingerprint", i)
		}
	}

	// Critical must be error, info must be note.
	if run.Results[0].Level != "error" {
		t.Fatalf("critical level = %q", run.Results[0].Level)
	}
	if run.Results[4].Level != "note" {
		t.Fatalf("info level = %q", run.Results[4].Level)
	}

	critRule := run.Tool.Driver.Rules[0]
	if critRule.Properties.SecuritySeverity != "9.8" {
		t.Fatalf("security-severity = %q", critRule.Properties.SecuritySeverity)
	}
	if len(critRule.Properties.Tags) < 2 {
		t.Fatalf("rule tags missing: %v", critRule.Properties.Tags)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "report.sarif")
	if err := WriteSARIFReport(sampleTarget(), sampleFindings(), testMeta(), path); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	if info, err := os.Stat(path); err != nil || info.Size() == 0 {
		t.Fatalf("sarif file missing: %v", err)
	}
}

func TestHTMLReport(t *testing.T) {
	out, err := RenderHTML(sampleTarget(), sampleFindings(), testMeta())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	page := string(out)

	for _, want := range []string{
		"<!DOCTYPE html>",
		"NightfallLX Vulnerability Report",
		"http://target.lab/app.php?id=1",
		"data-severity=\"critical\"",
		"data-severity=\"info\"",
		"id=\"search\"",
		"id=\"sev\"",
		"id=\"mod\"",
		"id=\"url\"",
		"CVSS 9.8",
		"CWE-89",
		"https://cwe.mitre.org/data/definitions/89.html",
		"<mark class=\"pl\">",
		"Raw HTTP Request",
		"Raw HTTP Response",
		"Content-Security-Policy",
		"Severity distribution",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("html missing %q", want)
		}
	}

	// Payloads must be escaped, never executed.
	if strings.Contains(page, "<script>alert(1)</script>") {
		t.Fatal("xss payload was not escaped")
	}
	if !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("escaped xss payload missing")
	}

	// Zero external dependencies.
	if strings.Contains(page, "<script src=") || strings.Contains(page, "<link rel=\"stylesheet\"") {
		t.Fatal("html report must not load external assets")
	}
	if strings.Contains(page, "src=\"http") {
		t.Fatal("html report references a remote script")
	}

	// Severity counters.
	for _, want := range []string{">Critical<", ">High<", ">Medium<", ">Low<", ">Info<"} {
		if !strings.Contains(page, want) {
			t.Fatalf("missing KPI label %q", want)
		}
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	if err := WriteHTMLReport(sampleTarget(), sampleFindings(), testMeta(), path); err != nil {
		t.Fatalf("write html: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() < 5000 {
		t.Fatalf("html file too small: %v %d", err, info.Size())
	}
}

func TestHTMLReportEmpty(t *testing.T) {
	out, err := RenderHTML(sampleTarget(), nil, testMeta())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	page := string(out)
	if !strings.Contains(page, "No confirmed findings") {
		t.Fatal("empty state missing")
	}
	if strings.Contains(page, "data-severity=") {
		t.Fatal("unexpected finding rendered")
	}
}

func TestHTMLReportDurationAndMethod(t *testing.T) {
	out, err := RenderHTML(sampleTarget(), sampleFindings(), testMeta())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	page := string(out)
	if !strings.Contains(page, "Duration 1.5s") {
		t.Fatal("duration missing")
	}
	if !strings.Contains(page, ">GET<") {
		t.Fatal("method missing")
	}
}

func TestBuildCurlFinding_GraphQLAndREST(t *testing.T) {
	target := &modules.Target{
		URL:    "http://app.discover.hard/graphql",
		Method: "POST",
	}

	// 1. GraphQL Introspection Finding
	fIntro := &modules.Finding{
		Module:   "graphql",
		Title:    "GraphQL Introspection Schema Publicly Exposed",
		URL:      "http://app.discover.hard/graphql",
		Payload:  `{"query":"query IntrospectionQuery { __schema { types { name } } }"}`,
		Severity: modules.SeverityHigh,
	}
	curlIntro := buildCurlFinding(target, fIntro)
	if !strings.Contains(curlIntro, "-H 'Content-Type: application/json'") || !strings.Contains(curlIntro, "--data-raw") || strings.Contains(curlIntro, "--data '=") {
		t.Fatalf("GraphQL Introspection curl is malformed: %s", curlIntro)
	}

	// 2. GraphQL GET Query Finding
	fGET := &modules.Finding{
		Module:   "graphql",
		Title:    "GraphQL Executable Over HTTP GET Method",
		URL:      "http://app.discover.hard/graphql?query=%7B__typename%7D",
		Severity: modules.SeverityLow,
	}
	curlGET := buildCurlFinding(target, fGET)
	if strings.Contains(curlGET, "-X POST") || strings.Contains(curlGET, "--data") || !strings.Contains(curlGET, "http://app.discover.hard/graphql?query=%7B__typename%7D") {
		t.Fatalf("GraphQL GET curl is malformed: %s", curlGET)
	}
}
