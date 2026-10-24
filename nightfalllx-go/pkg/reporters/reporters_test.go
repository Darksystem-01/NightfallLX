package reporters

import (
	"encoding/json"
	"nightfalllx/pkg/intel"
	"nightfalllx/pkg/modules"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteReportsWithIntel(t *testing.T) {
	tempDir := t.TempDir()
	mdPath := filepath.Join(tempDir, "report.md")
	jsonPath := filepath.Join(tempDir, "report.json")

	target := &modules.Target{
		URL:    "http://127.0.0.1:8080/test",
		Method: "GET",
		Params: map[string]string{"q": "canary"},
	}

	findings := []*modules.Finding{
		{
			Module:          "xss",
			Title:           "Confirmed Reflected XSS",
			Severity:        modules.SeverityHigh,
			Confidence:      100,
			ConfidenceLevel: modules.ConfidenceConfirmed,
			URL:             target.URL,
			Parameter:       "q",
			Payload:         "<svg onload=alert(1)>",
			Detail:          "Confirmed execution in SVG context.",
			Evidence:        "<svg onload=alert(1)>",
			Remediation:     "Encode HTML entities.",
			CWEID:           79,
		},
	}

	intelRep := &intel.IntelReport{
		Target:     target.URL,
		Queries:    []string{"PHP 3.4.5"},
		Disclaimer: "Version detection can be wrong or imprecise.",
		Findings: []*intel.IntelFinding{
			{
				Query:     "PHP 3.4.5",
				Source:    "searchsploit",
				Title:     "PHP 3.x - Remote Buffer Overflow",
				EDBID:     "12345",
				CVEs:      []string{"CVE-2000-0001"},
				LocalPath: "/opt/exploits/12345.txt",
			},
		},
	}

	// 1. Test Markdown Report
	if err := WriteMarkdownReportWithIntel(target, findings, intelRep, mdPath); err != nil {
		t.Fatalf("WriteMarkdownReportWithIntel failed: %v", err)
	}

	mdBytes, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("failed to read markdown file: %v", err)
	}
	mdContent := string(mdBytes)

	if !strings.Contains(mdContent, "Confirmed Reflected XSS") {
		t.Errorf("markdown report missing finding title")
	}
	if !strings.Contains(mdContent, "Version-matched intel (not verified)") {
		t.Errorf("markdown report missing intel section header")
	}
	if !strings.Contains(mdContent, "CVE-2000-0001") {
		t.Errorf("markdown report missing CVE reference")
	}
	if !strings.Contains(mdContent, "Version detection can be wrong") {
		t.Errorf("markdown report missing disclaimer")
	}

	// 2. Test JSON Report
	if err := WriteJSONReportWithIntel(target, findings, intelRep, jsonPath); err != nil {
		t.Fatalf("WriteJSONReportWithIntel failed: %v", err)
	}

	jsonBytes, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed to read json file: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("failed to parse generated JSON report: %v", err)
	}

	if total, ok := parsed["total_findings"].(float64); !ok || total != 1 {
		t.Errorf("expected total_findings 1, got %v", parsed["total_findings"])
	}
	if _, ok := parsed["intel_report"]; !ok {
		t.Errorf("expected intel_report field in JSON output")
	}
}

func TestWriteReportsCleanNegative(t *testing.T) {
	tempDir := t.TempDir()
	mdPath := filepath.Join(tempDir, "clean.md")
	jsonPath := filepath.Join(tempDir, "clean.json")

	target := &modules.Target{
		URL:    "http://127.0.0.1:8080/clean",
		Method: "GET",
	}

	// Zero findings, nil intel
	if err := WriteMarkdownReport(target, nil, mdPath); err != nil {
		t.Fatalf("WriteMarkdownReport failed on clean target: %v", err)
	}
	if err := WriteJSONReport(target, nil, jsonPath); err != nil {
		t.Fatalf("WriteJSONReport failed on clean target: %v", err)
	}

	mdBytes, _ := os.ReadFile(mdPath)
	if !strings.Contains(string(mdBytes), "No confirmed vulnerabilities detected") {
		t.Errorf("expected clean indicator in markdown report")
	}
}

func TestWriteMarkdownStructuredDetail(t *testing.T) {
	tempDir := t.TempDir()
	mdPath := filepath.Join(tempDir, "structured.md")
	jsonPath := filepath.Join(tempDir, "structured.json")

	target := &modules.Target{URL: "http://target.lab/", Method: "GET"}
	findings := []*modules.Finding{
		{
			Module:          "exploit-mapper",
			Title:           "Exploit Mapper Attack Plan: WordPress 6.4.2",
			Severity:        modules.SeverityInfo,
			Confidence:      100,
			ConfidenceLevel: modules.ConfidenceConfirmed,
			URL:             target.URL,
			Parameter:       "Application",
			Payload:         "Passive fingerprint",
			Detail:          "## 🎯 Target Profile\n- **CMS:** WordPress 6.4.2\n\n## 🚀 Metasploit Attack Plan\n1. **Module:** `exploit/multi/http/wp_cf7_file_upload`\n",
			DetailFormat:    "markdown",
			Remediation:     "Patch WordPress.",
		},
	}

	if err := WriteMarkdownReport(target, findings, mdPath); err != nil {
		t.Fatalf("WriteMarkdownReport failed: %v", err)
	}
	mdBytes, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("failed to read markdown: %v", err)
	}
	mdContent := string(mdBytes)
	if !strings.Contains(mdContent, "#### 🎯 Target Profile") {
		t.Errorf("structured heading was not demoted for report hierarchy:\n%s", mdContent)
	}
	if strings.Contains(mdContent, "- **Detail:** ## 🎯") {
		t.Errorf("structured detail was rendered inline instead of as a markdown block")
	}

	if err := WriteJSONReport(target, findings, jsonPath); err != nil {
		t.Fatalf("WriteJSONReport failed: %v", err)
	}
	jsonBytes, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed to read json: %v", err)
	}
	if !strings.Contains(string(jsonBytes), `"detail_format": "markdown"`) {
		t.Errorf("json report missing detail_format field:\n%s", string(jsonBytes))
	}
}

func TestWriteHTMLReport(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "report.html")
	target := &modules.Target{URL: "http://target.lab/app", Method: "GET"}
	findings := []*modules.Finding{
		{
			Module:          "xss",
			Title:           "Confirmed Reflected XSS <script>",
			Severity:        modules.SeverityCritical,
			Confidence:      100,
			ConfidenceLevel: modules.ConfidenceConfirmed,
			URL:             target.URL,
			Parameter:       "q",
			Payload:         "<svg onload=alert(1)>",
			Detail:          "## Finding\nDangerous reflection.",
			DetailFormat:    "markdown",
			Evidence:        "<svg onload=alert(1)>",
			Remediation:     "Encode output.",
			CWEID:           79,
			CurlCmd:         "curl 'http://target.lab/app?q=test'",
		},
		{
			Module:          "headers",
			Title:           "Missing Header",
			Severity:        modules.SeverityMedium,
			Confidence:      100,
			ConfidenceLevel: modules.ConfidenceConfirmed,
			URL:             target.URL,
			Parameter:       "Header",
			Detail:          "Header absent.",
			Remediation:     "Add header.",
		},
	}
	intelRep := &intel.IntelReport{
		Target: target.URL,
		Findings: []*intel.IntelFinding{
			{Query: "WordPress 6.4.2", Source: "nvd", Title: "Core issue", CVEs: []string{"CVE-2023-12345"}, CVSS: 8.8},
		},
	}
	if err := WriteHTMLReportWithIntel(target, findings, intelRep, path); err != nil {
		t.Fatalf("WriteHTMLReportWithIntel failed: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(body)
	for _, want := range []string{
		"Nightfall<span>LX</span>",
		`data-severity="critical"`,
		`data-severity="medium"`,
		"button class=\"filter",
		"Confirmed Reflected XSS &lt;script&gt;",
		"CVE-2023-12345",
		"CVSS 8.8",
		"http://target.lab/app",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
	if strings.Contains(content, "<script>alert") {
		t.Error("HTML report contains unescaped finding content")
	}
}

func TestWriteSARIFReport(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "report.sarif")
	target := &modules.Target{URL: "http://target.lab/app", Method: "GET"}
	findings := []*modules.Finding{
		{
			Module:          "xss",
			Title:           "Confirmed XSS",
			Severity:        modules.SeverityCritical,
			Confidence:      100,
			ConfidenceLevel: modules.ConfidenceConfirmed,
			URL:             target.URL,
			Parameter:       "q",
			Payload:         "<svg>",
			Remediation:     "Encode output.",
			CWEID:           79,
		},
		{
			Module:          "headers",
			Title:           "Missing Header",
			Severity:        modules.SeverityMedium,
			Confidence:      100,
			ConfidenceLevel: modules.ConfidenceConfirmed,
			URL:             target.URL,
			Parameter:       "Header",
		},
	}
	intelRep := &intel.IntelReport{
		Target: target.URL,
		Findings: []*intel.IntelFinding{
			{Query: "WordPress 6.4.2", Source: "nvd", Title: "Core issue", CVEs: []string{"CVE-2023-12345"}, CVSS: 8.8},
		},
	}
	if err := WriteSARIFReportWithIntel(target, findings, intelRep, path); err != nil {
		t.Fatalf("WriteSARIFReportWithIntel failed: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if parsed.Version != "2.1.0" || !strings.Contains(parsed.Schema, "sarif-2.1.0") {
		t.Fatalf("unexpected SARIF header: %+v", parsed)
	}
	if len(parsed.Runs) != 1 || parsed.Runs[0].Tool.Driver.Name != "NightfallLX" {
		t.Fatalf("unexpected SARIF driver: %+v", parsed.Runs)
	}
	if len(parsed.Runs[0].Results) != 3 {
		t.Fatalf("expected 3 SARIF results (2 findings + 1 intel), got %d", len(parsed.Runs[0].Results))
	}
	if parsed.Runs[0].Results[0].Level != "error" {
		t.Errorf("expected critical finding level error, got %q", parsed.Runs[0].Results[0].Level)
	}
	if parsed.Runs[0].Results[1].Level != "warning" {
		t.Errorf("expected medium finding level warning, got %q", parsed.Runs[0].Results[1].Level)
	}
	if parsed.Runs[0].Results[2].Level != "note" {
		t.Errorf("expected intel level note, got %q", parsed.Runs[0].Results[2].Level)
	}
	if got := parsed.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != target.URL {
		t.Errorf("unexpected SARIF location: %q", got)
	}
}
