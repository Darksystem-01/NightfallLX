package main

import (
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/intel"
	"nightfalllx/pkg/modules"
	"nightfalllx/pkg/reporters"
	"nightfalllx/pkg/xss"
	xsslab "nightfalllx/testdata/xss_lab"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestXSSAndIntelIntegrationLab(t *testing.T) {
	mux := xsslab.SetupMux()
	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := client.NewClient("", 5*time.Second, true, "", nil)

	// 1. Reflected HTML-Text
	t.Run("Reflected_HTML_Text", func(t *testing.T) {
		target := &modules.Target{
			URL:    ts.URL + "/reflected/text",
			Method: "GET",
			Params: map[string]string{"q": "initial"},
		}

		engine := xss.NewEngine(&xss.EngineConfig{
			EnableDOM:          false,
			MaxVectorsPerParam: 25,
		})

		findings, err := engine.ScanTarget(target.ToXSSTarget(), c)
		if err != nil {
			t.Fatalf("unexpected error scanning reflected html text: %v", err)
		}
		if len(findings) == 0 {
			t.Fatalf("expected at least one finding for reflected html text, got none")
		}

		hasConfirmed := false
		for _, f := range findings {
			if f.ConfidenceLevel == "confirmed" {
				hasConfirmed = true
				break
			}
		}
		if !hasConfirmed {
			t.Errorf("expected confirmed confidence level for reflected html-text, got %s", findings[0].ConfidenceLevel)
		}
	})

	// 2. Reflected Quoted Attribute
	t.Run("Reflected_Quoted_Attribute", func(t *testing.T) {
		target := &modules.Target{
			URL:    ts.URL + "/reflected/attr-quoted",
			Method: "GET",
			Params: map[string]string{"name": "testuser"},
		}

		engine := xss.NewEngine(&xss.EngineConfig{
			EnableDOM:          false,
			MaxVectorsPerParam: 35,
		})

		findings, err := engine.ScanTarget(target.ToXSSTarget(), c)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(findings) == 0 {
			t.Fatalf("expected finding for quoted attribute injection")
		}

		hasConfirmed := false
		for _, f := range findings {
			if f.ConfidenceLevel == "confirmed" {
				hasConfirmed = true
				break
			}
		}
		if !hasConfirmed {
			t.Errorf("expected confirmed confidence for quoted attribute breakout, got %s", findings[0].ConfidenceLevel)
		}
	})

	// 3. Reflected Unquoted Attribute
	t.Run("Reflected_Unquoted_Attribute", func(t *testing.T) {
		target := &modules.Target{
			URL:    ts.URL + "/reflected/attr-unquoted",
			Method: "GET",
			Params: map[string]string{"theme": "dark"},
		}

		engine := xss.NewEngine(&xss.EngineConfig{
			EnableDOM:          false,
			MaxVectorsPerParam: 25,
		})

		findings, err := engine.ScanTarget(target.ToXSSTarget(), c)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(findings) == 0 {
			t.Fatalf("expected finding for unquoted attribute injection")
		}
		if findings[0].ConfidenceLevel != "confirmed" && findings[0].ConfidenceLevel != "probable" {
			t.Errorf("expected confirmed or probable finding, got %s", findings[0].ConfidenceLevel)
		}
	})

	// 4. Reflected JavaScript String
	t.Run("Reflected_JS_String", func(t *testing.T) {
		target := &modules.Target{
			URL:    ts.URL + "/reflected/js-string",
			Method: "GET",
			Params: map[string]string{"user": "alice"},
		}

		engine := xss.NewEngine(&xss.EngineConfig{
			EnableDOM:          false,
			MaxVectorsPerParam: 35,
		})

		findings, err := engine.ScanTarget(target.ToXSSTarget(), c)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(findings) == 0 {
			t.Fatalf("expected finding for js string reflection")
		}
		hasExec := false
		for _, f := range findings {
			if f.ConfidenceLevel == "confirmed" || f.ConfidenceLevel == "probable" {
				hasExec = true
				break
			}
		}
		if !hasExec {
			t.Errorf("expected confirmed or probable finding, got %s", findings[0].ConfidenceLevel)
		}
	})

	// 5. Reflected JavaScript Template Literal
	t.Run("Reflected_JS_Template", func(t *testing.T) {
		target := &modules.Target{
			URL:    ts.URL + "/reflected/js-template",
			Method: "GET",
			Params: map[string]string{"msg": "hello"},
		}

		engine := xss.NewEngine(&xss.EngineConfig{
			EnableDOM:          false,
			MaxVectorsPerParam: 35,
		})

		findings, err := engine.ScanTarget(target.ToXSSTarget(), c)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(findings) == 0 {
			t.Fatalf("expected finding for js template literal injection")
		}
	})

	// 6. DOM via location.hash (Static Analysis)
	t.Run("DOM_Hash_Static_Analysis", func(t *testing.T) {
		target := &modules.Target{
			URL:    ts.URL + "/dom/hash",
			Method: "GET",
		}

		engine := xss.NewEngine(&xss.EngineConfig{
			EnableDOM:        true,
			EnableDOMBrowser: false,
		})

		findings, err := engine.ScanTarget(target.ToXSSTarget(), c)
		if err != nil {
			t.Fatalf("error: %v", err)
		}

		var domFinding *xss.Finding
		for _, f := range findings {
			if strings.Contains(f.Title, "DOM XSS") {
				domFinding = f
				break
			}
		}

		if domFinding == nil {
			t.Fatalf("expected DOM XSS finding from location.hash -> innerHTML flow, got none")
		}
		if domFinding.ConfidenceLevel != "probable" {
			t.Errorf("expected probable confidence for static DOM finding, got %s", domFinding.ConfidenceLevel)
		}
		if !strings.Contains(domFinding.Detail, "location.hash") || !strings.Contains(domFinding.Detail, "innerHTML") {
			t.Errorf("expected source and sink mentioned in detail: %s", domFinding.Detail)
		}
	})

	// 7. Stored Comment Form with CSRF Protection
	t.Run("Stored_Comment_Form", func(t *testing.T) {
		target := &modules.Target{
			URL:    ts.URL + "/xss/stored",
			Method: "GET",
		}

		engine := xss.NewEngine(&xss.EngineConfig{
			EnableDOM:    false,
			EnableForms:  true,
			EnableStored: true,
		})

		findings, err := engine.ScanTarget(target.ToXSSTarget(), c)
		if err != nil {
			t.Fatalf("error: %v", err)
		}

		var storedFinding *xss.Finding
		for _, f := range findings {
			if strings.Contains(f.Title, "Stored Cross-Site Scripting") {
				storedFinding = f
				break
			}
		}

		if storedFinding == nil {
			t.Fatalf("expected Stored XSS finding, got none")
		}
		if !strings.Contains(storedFinding.Detail, "remains on the target") {
			t.Errorf("expected report to state marker remains on target, got: %s", storedFinding.Detail)
		}
	})

	// 8. Filter: blocks <script> but allows img onerror
	t.Run("Filter_Bypass_Script_Blocked", func(t *testing.T) {
		target := &modules.Target{
			URL:    ts.URL + "/reflected/filter",
			Method: "GET",
			Params: map[string]string{"q": "test"},
		}

		engine := xss.NewEngine(&xss.EngineConfig{
			EnableDOM:          false,
			MaxVectorsPerParam: 35,
		})

		findings, err := engine.ScanTarget(target.ToXSSTarget(), c)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(findings) == 0 {
			t.Fatalf("expected finding on filtered endpoint with non-script vector")
		}
		hasConfirmed := false
		for _, f := range findings {
			if f.ConfidenceLevel == "confirmed" {
				hasConfirmed = true
				break
			}
		}
		if !hasConfirmed {
			t.Errorf("expected confirmed bypass of script filter, got %s", findings[0].ConfidenceLevel)
		}
	})

	// 9. Legacy Banner PHP/3.4.5 & Version-Matched Reference Lookup
	t.Run("Intel_Banner_PHP_3_4_5", func(t *testing.T) {
		bannerURL := ts.URL + "/intel/banner"
		resp, err := c.Get(bannerURL)
		if err != nil {
			t.Fatalf("failed to fetch banner page: %v", err)
		}

		pvList := intel.ExtractProductVersions(nil, resp.Headers, resp.Body, "")
		if len(pvList) == 0 {
			t.Fatalf("expected product version extraction from PHP/3.4.5, got 0")
		}

		hasPHP := false
		for _, b := range pvList {
			if strings.EqualFold(b.Product, "PHP") && strings.HasPrefix(b.Version, "3.4.5") {
				hasPHP = true
				break
			}
		}
		if !hasPHP {
			t.Errorf("expected PHP 3.4.5 banner detected, got %v", pvList)
		}

		// Mock searchsploit binary via PATH
		tmpDir := t.TempDir()
		fakeSearchsploit := filepath.Join(tmpDir, "searchsploit")
		scriptContent := `#!/bin/sh
cat << 'EOF'
{
  "RESULTS_EXPLOIT": [
    {
      "Title": "PHP 3.4.5 - Remote Code Execution (CVE-1999-0001)",
      "EDB-ID": "12345",
      "Date_Published": "1999-01-01",
      "Author": "Security Researcher",
      "Type": "remote",
      "Platform": "multiple",
      "Path": "/opt/exploitdb/exploits/multiple/remote/12345.txt"
    }
  ]
}
EOF
`
		if err := os.WriteFile(fakeSearchsploit, []byte(scriptContent), 0755); err != nil {
			t.Fatalf("failed to write fake searchsploit: %v", err)
		}

		origPath := os.Getenv("PATH")
		defer os.Setenv("PATH", origPath)
		os.Setenv("PATH", tmpDir+string(os.PathListSeparator)+origPath)

		intelReport := intel.RunIntel(bannerURL, pvList, false)
		if intelReport == nil {
			t.Fatalf("expected intel report, got nil")
		}

		if len(intelReport.Findings) == 0 {
			t.Fatalf("expected version-matched intel findings for PHP 3.4.5, got 0")
		}

		finding := intelReport.Findings[0]
		if finding.EDBID != "12345" {
			t.Errorf("expected EDB-ID 12345, got %s", finding.EDBID)
		}
		hasCVE := false
		for _, cve := range finding.CVEs {
			if cve == "CVE-1999-0001" {
				hasCVE = true
				break
			}
		}
		if !hasCVE {
			t.Errorf("expected parsed CVE-1999-0001 in %v", finding.CVEs)
		}

		// Ensure report formatting includes Version-matched Intel section
		dummyTarget := &modules.Target{URL: bannerURL, Method: "GET"}
		tmpReport := filepath.Join(t.TempDir(), "report.md")
		errRep := reporters.WriteMarkdownReportWithIntel(dummyTarget, []*modules.Finding{}, intelReport, tmpReport)
		if errRep != nil {
			t.Fatalf("failed to write markdown report with intel: %v", errRep)
		}

		reportBytes, _ := os.ReadFile(tmpReport)
		reportContent := string(reportBytes)
		if !strings.Contains(reportContent, "Version-matched intel (not verified)") {
			t.Errorf("expected report section 'Version-matched intel (not verified)', got:\n%s", reportContent)
		}
		if !strings.Contains(reportContent, "12345") || !strings.Contains(reportContent, "CVE-1999-0001") {
			t.Errorf("expected exploit metadata in report:\n%s", reportContent)
		}
	})

	// 10. Clean Static Page: Exactly Zero False Positives
	t.Run("Clean_Static_Page_Zero_Findings", func(t *testing.T) {
		cleanURL := ts.URL + "/clean"
		target := &modules.Target{
			URL:    cleanURL,
			Method: "GET",
			Params: map[string]string{
				"id":   "123",
				"name": "corporate",
				"page": "home",
			},
		}

		// Run XSS Module with DOM, Forms, and Parameters enabled
		xssCfg := &xss.EngineConfig{
			EnableDOM:          true,
			EnableForms:        true,
			EnableStored:       true,
			MaxVectorsPerParam: 30,
		}
		xssMod := modules.NewXSSModuleWithConfig(xssCfg)
		xssFindings, err := xssMod.Run(target, c)
		if err != nil {
			t.Fatalf("unexpected error running XSS on clean page: %v", err)
		}
		if len(xssFindings) > 0 {
			t.Fatalf("XSS module produced %d false positives on clean static page: %+v", len(xssFindings), xssFindings[0])
		}

		// Run all standard audit modules
		allMods := []modules.Module{
			modules.NewSQLiModule(),
			modules.NewLFIModule(),
			modules.NewSSTIModule(),
			modules.NewCMDiModule(),
			modules.NewSSRFModule(),
			modules.NewNoSQLiModule(),
			modules.NewXXEModule(),
			modules.NewRedirectModule(),
			modules.NewCRLFModule(),
			modules.NewHostHeaderModule(),
			modules.NewCSRFModule(),
		}

		for _, m := range allMods {
			modFindings, errMod := m.Run(target, c)
			if errMod != nil {
				t.Fatalf("module %s error on clean page: %v", m.Name(), errMod)
			}
			if len(modFindings) > 0 {
				t.Fatalf("module %s falsely flagged clean page with %d findings!", m.Name(), len(modFindings))
			}
		}
	})
}
