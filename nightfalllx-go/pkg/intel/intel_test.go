package intel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestQueryValidation(t *testing.T) {
	valid := []string{"PHP 7.4", "Apache 2.4.49", "wordpress_5.8", "nginx-1.18.0", "drupal"}
	for _, q := range valid {
		res, err := ValidateQuery(q)
		if err != nil {
			t.Errorf("expected %q to be valid, got err: %v", q, err)
		}
		if res != q {
			t.Errorf("expected %q, got %q", q, res)
		}
	}

	invalid := []string{
		"-h",
		"-x",
		"--version",
		"php; id",
		"php;id",
		"apache | whoami",
		"test`cat /etc/passwd`",
		"12345678901234567890123456789012345678901234567890123456789012345",                         // exactly 65 chars
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // > 64 chars
		"",
	}
	for _, q := range invalid {
		_, err := ValidateQuery(q)
		if err == nil {
			t.Errorf("expected %q to be invalid, got nil err", q)
		}
	}
}

func TestSearchsploitWithFakeBinary(t *testing.T) {
	tempDir := t.TempDir()
	fakeBin := filepath.Join(tempDir, "searchsploit")

	fakeScript := `#!/bin/sh
cat << 'EOF'
{
  "SEARCH": "PHP 7.4",
  "DB_PATH_EXPLOIT": "/tmp/db",
  "RESULTS_EXPLOIT": [
    {
      "Title": "PHP 7.4.x - Remote Code Execution (CVE-2019-11043)",
      "EDB-ID": "47553",
      "Date_Published": "2019-10-24",
      "Author": "neex",
      "Type": "remote",
      "Platform": "php",
      "Codes": "CVE-2019-11043",
      "Path": "/opt/exploits/php/remote/47553.py"
    }
  ]
}
EOF
`
	if err := os.WriteFile(fakeBin, []byte(fakeScript), 0755); err != nil {
		t.Fatalf("failed to write fake searchsploit script: %v", err)
	}

	client := &SearchsploitClient{
		BinPath: fakeBin,
	}

	findings, err := client.Lookup("PHP", "7.4")
	if err != nil {
		t.Fatalf("Lookup failed with fake binary: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.EDBID != "47553" {
		t.Errorf("expected EDB-ID 47553, got %s", f.EDBID)
	}
	if len(f.CVEs) == 0 || f.CVEs[0] != "CVE-2019-11043" {
		t.Errorf("expected CVE-2019-11043, got %v", f.CVEs)
	}
	if f.LocalPath != "/opt/exploits/php/remote/47553.py" {
		t.Errorf("expected path /opt/exploits/php/remote/47553.py, got %s", f.LocalPath)
	}
}

func TestSearchsploitMissingBinary(t *testing.T) {
	client := &SearchsploitClient{
		BinPath: "",
	}
	findings, err := client.Lookup("Apache", "2.4.49")
	if err != ErrSearchsploitNotFound {
		t.Errorf("expected ErrSearchsploitNotFound, got %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when binary is missing")
	}
}

func TestNVDClientWithMockServer(t *testing.T) {
	mockJSON := `{
		"vulnerabilities": [
			{
				"cve": {
					"id": "CVE-2021-41773",
					"descriptions": [
						{"lang": "en", "value": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49."}
					],
					"metrics": {
						"cvssMetricV31": [
							{
								"cvssData": {
									"baseScore": 9.8
								}
							}
						]
					}
				}
			}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockJSON))
	}))
	defer server.Close()

	nvd := NewNVDClient()
	nvd.SetBaseURL(server.URL)
	nvd.CacheDir = t.TempDir()

	findings, err := nvd.Lookup("Apache 2.4.49")
	if err != nil {
		t.Fatalf("NVD lookup failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from mock NVD, got %d", len(findings))
	}

	f := findings[0]
	if len(f.CVEs) == 0 || f.CVEs[0] != "CVE-2021-41773" {
		t.Errorf("expected CVE-2021-41773, got %v", f.CVEs)
	}
	if f.CVSS != 9.8 {
		t.Errorf("expected CVSS 9.8, got %f", f.CVSS)
	}

	// Test cache hit: server won't be called second time
	server.Close()
	cachedFindings, errCache := nvd.Lookup("Apache 2.4.49")
	if errCache != nil {
		t.Fatalf("NVD cache read failed: %v", errCache)
	}
	if len(cachedFindings) != 1 {
		t.Errorf("expected 1 cached finding, got %d", len(cachedFindings))
	}
}

func TestExtractProductVersions(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "Apache/2.4.41 (Ubuntu) PHP/3.4.5")
	headers.Set("X-Powered-By", "PHP/7.4.3")

	html := `<!DOCTYPE html><html><head><meta name="generator" content="WordPress 5.8.1"></head><body></body></html>`

	list := ExtractProductVersions(nil, headers, html, "nginx 1.18.0")
	if len(list) < 4 {
		t.Fatalf("expected at least 4 extracted product versions, got %d", len(list))
	}

	foundMap := make(map[string]string)
	for _, pv := range list {
		foundMap[pv.Product] = pv.Version
	}

	if foundMap["Apache"] != "2.4.41" {
		t.Errorf("expected Apache 2.4.41, got %v", foundMap["Apache"])
	}
	if foundMap["PHP"] == "" {
		t.Errorf("expected PHP version to be detected")
	}
	if foundMap["WordPress"] != "5.8.1" {
		t.Errorf("expected WordPress 5.8.1, got %v", foundMap["WordPress"])
	}
	if foundMap["nginx"] != "1.18.0" {
		t.Errorf("expected nginx 1.18.0 from manual query, got %v", foundMap["nginx"])
	}
}

func TestRealSearchsploitOptional(t *testing.T) {
	if os.Getenv("NFLX_REAL_SEARCHSPLOIT") != "1" {
		t.Skip("skipping real searchsploit test; set NFLX_REAL_SEARCHSPLOIT=1 to enable")
	}
	if _, err := exec.LookPath("searchsploit"); err != nil {
		t.Skip("searchsploit binary not found on PATH")
	}

	client := NewSearchsploitClient()
	findings, err := client.Lookup("php", "3.4.5")
	if err != nil {
		t.Fatalf("Lookup failed for php 3.4.5 with real searchsploit: %v", err)
	}

	if len(findings) == 0 {
		t.Logf("real searchsploit returned 0 findings (parseable empty slice)")
	} else {
		for i, f := range findings {
			if f.Title == "" && f.EDBID == "" {
				t.Errorf("finding %d has neither Title nor EDB-ID: %+v", i, f)
			}
		}
		t.Logf("real searchsploit returned %d parseable findings", len(findings))
	}
}

func TestWPScanClientWithMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token test-token" {
			t.Errorf("unexpected authorization header: %q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/wordpresses/6.4.2":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"6.4.2":{"vulnerabilities":[{"id":"abc","title":"Core issue","fixed_in":"6.4.3","references":{"cve":["2023-12345"],"url":["https://example.test/core"]},"cvss":{"score":8.8}}]}}`))
		case "/plugins/contact-form-7":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"contact-form-7":{"vulnerabilities":[{"id":"def","title":"CF7 upload","fixed_in":"5.3.2","references":{"cve":["2020-35489"]},"cvss":{"score":9.8}}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewWPScanClient("test-token")
	client.BaseURL = server.URL
	core, err := client.LookupCore(context.Background(), "6.4.2")
	if err != nil {
		t.Fatalf("core lookup failed: %v", err)
	}
	if len(core) != 1 || len(core[0].CVEs) != 1 || core[0].CVEs[0] != "CVE-2023-12345" {
		t.Fatalf("unexpected core findings: %+v", core)
	}
	plugin, err := client.LookupPlugin(context.Background(), "contact-form-7")
	if err != nil {
		t.Fatalf("plugin lookup failed: %v", err)
	}
	if len(plugin) != 1 || plugin[0].CVSS != 9.8 || plugin[0].FixedIn != "5.3.2" {
		t.Fatalf("unexpected plugin findings: %+v", plugin)
	}
}

func TestNVDLookupCVE(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cveId") != "CVE-2020-35489" {
			t.Errorf("unexpected cveId: %q", r.URL.Query().Get("cveId"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2020-35489","descriptions":[{"lang":"en","value":"Unrestricted file upload in Contact Form 7."}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8}}]}}}]}`))
	}))
	defer server.Close()

	client := NewNVDClient()
	client.SetBaseURL(server.URL)
	client.CacheDir = t.TempDir()
	finding, err := client.LookupCVE(context.Background(), "cve-2020-35489")
	if err != nil {
		t.Fatalf("NVD CVE lookup failed: %v", err)
	}
	if finding == nil || finding.CVSS != 9.8 || len(finding.CVEs) != 1 || finding.CVEs[0] != "CVE-2020-35489" {
		t.Fatalf("unexpected NVD finding: %+v", finding)
	}
	if !strings.Contains(finding.Title, "Unrestricted file upload") {
		t.Errorf("unexpected description: %q", finding.Title)
	}
}

func TestExploitDownloader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/raw/49083" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("#!/usr/bin/env python3\nprint('proof')\n"))
	}))
	defer server.Close()

	dir := t.TempDir()
	downloader := NewExploitDownloader(dir)
	downloader.BaseURL = server.URL
	download, err := downloader.Download(context.Background(), "49083")
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if download.Path != filepath.Join(dir, "edb-49083.txt") {
		t.Fatalf("unexpected download path: %s", download.Path)
	}
	body, err := os.ReadFile(download.Path)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if !strings.Contains(string(body), "print('proof')") {
		t.Errorf("unexpected downloaded body: %q", string(body))
	}
	// Existing files are reused rather than fetched again.
	server.Close()
	if _, err := downloader.Download(context.Background(), "49083"); err != nil {
		t.Fatalf("expected cached download to succeed: %v", err)
	}
	if _, err := downloader.Download(context.Background(), "../etc/passwd"); err == nil {
		t.Fatal("expected invalid EDB-ID to be rejected")
	}
}

func TestRunIntelSkipsVersionlessAutomaticAndCapsResults(t *testing.T) {
	dir := t.TempDir()
	var rows []string
	for i := 0; i < 50; i++ {
		rows = append(rows, fmt.Sprintf(`{"Title":"Test Exploit %d","EDB-ID":"%d","Path":"/tmp/%d.txt"}`, i, i+1, i+1))
	}
	payload := `{"SEARCH":"test","RESULTS_EXPLOIT":[` + strings.Join(rows, ",") + `]}`
	script := "#!/bin/sh\ncat <<'OUT'\n" + payload + "\nOUT\n"
	bin := filepath.Join(dir, "searchsploit")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("NVD_API_KEY", "")

	automatic := RunIntelContext(context.Background(), "http://target.lab", []ProductVersion{
		{Product: "WordPress", Version: "", Source: "detector"},
	}, false)
	if len(automatic.Findings) != 0 {
		t.Fatalf("versionless automatic lookup should be skipped, got %d findings", len(automatic.Findings))
	}

	versioned := RunIntelContext(context.Background(), "http://target.lab", []ProductVersion{
		{Product: "WordPress", Version: "6.4.2", Source: "detector"},
	}, false)
	if len(versioned.Findings) != maxIntelFindingsPerQuery {
		t.Fatalf("expected %d capped findings, got %d", maxIntelFindingsPerQuery, len(versioned.Findings))
	}

	manual := RunIntelContext(context.Background(), "http://target.lab", []ProductVersion{
		{Product: "WordPress", Version: "", Source: "flag"},
	}, false)
	if len(manual.Findings) != maxIntelFindingsPerQuery {
		t.Fatalf("manual versionless query should be capped, got %d findings", len(manual.Findings))
	}
}
