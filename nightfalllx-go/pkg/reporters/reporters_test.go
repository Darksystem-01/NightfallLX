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
