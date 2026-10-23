package intel

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
		"12345678901234567890123456789012345678901234567890123456789012345", // exactly 65 chars
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
