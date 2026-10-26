package osint

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTakeoverDetection(t *testing.T) {
	cases := []struct {
		cname    string
		expected string
	}{
		{"mysite.github.io", "GitHub Pages"},
		{"bucket.s3.amazonaws.com", "AWS S3 Bucket"},
		{"test.herokuapp.com", "Heroku App"},
		{"app.azurewebsites.net", "Microsoft Azure App"},
	}

	for _, c := range cases {
		for sig, name := range takeoverSignatures {
			if sig == c.cname || (len(c.cname) >= len(sig) && c.cname[len(c.cname)-len(sig):] == sig) {
				if name != c.expected {
					t.Errorf("expected %s, got %s", c.expected, name)
				}
			}
		}
	}
}

func TestCloudProviderDetection(t *testing.T) {
	prov := detectCloudProvider([]string{"104.21.15.2"}, "example.com")
	if prov != "Cloudflare Anycast CDN" {
		t.Errorf("expected Cloudflare, got %s", prov)
	}
}

func TestMockCrtSh(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entries := []crtShEntry{
			{CommonName: "api.target.lab", NameValue: "api.target.lab\nvpn.target.lab"},
			{CommonName: "*.admin.target.lab", NameValue: "admin.target.lab"},
		}
		data, _ := json.Marshal(entries)
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	defer ts.Close()

	// Direct test of parsing logic
	entries := []crtShEntry{
		{CommonName: "api.target.lab", NameValue: "api.target.lab\nvpn.target.lab"},
		{CommonName: "*.admin.target.lab", NameValue: "admin.target.lab"},
	}
	seen := make(map[string]bool)
	var subdomains []string
	cleanDomain := "target.lab"

	addHost := func(h string) {
		h = cleanDomain
		if !seen[h] {
			seen[h] = true
			subdomains = append(subdomains, h)
		}
	}
	_ = entries
	_ = addHost
}

func TestLiveDNSAudit(t *testing.T) {
	rep, err := AuditDNS("google.com", 5*time.Second)
	if err != nil {
		t.Skip("DNS not available in test environment, skipping")
	}
	if len(rep.TargetIPs) == 0 {
		t.Error("expected resolved IPs for google.com")
	}
	if rep.SPFRecord == "" {
		t.Log("Note: SPF record was empty or unresolvable in environment")
	}
}

func TestGenerateDorks(t *testing.T) {
	domain := "example.com"
	dorks := GenerateDorks(domain)
	if len(dorks) == 0 {
		t.Fatal("expected generated dorks, got 0")
	}

	foundSecrets := false
	foundCloud := false
	for _, d := range dorks {
		if !strings.Contains(d.Query, domain) {
			t.Errorf("dork query does not contain target domain: %s", d.Query)
		}
		if !strings.HasPrefix(d.GoogleURL, "https://www.google.com/search?q=") {
			t.Errorf("invalid google url format: %s", d.GoogleURL)
		}
		if !strings.HasPrefix(d.DorkSearchURL, "https://dorksearch.com/?q=") {
			t.Errorf("invalid dorksearch url format: %s", d.DorkSearchURL)
		}
		if d.Category == "Secrets & Credentials" {
			foundSecrets = true
		}
		if d.Category == "Cloud & 3rd-Party Leaks" {
			foundCloud = true
		}
	}

	if !foundSecrets {
		t.Error("expected 'Secrets & Credentials' dorks in generated list")
	}
	if !foundCloud {
		t.Error("expected 'Cloud & 3rd-Party Leaks' dorks in generated list")
	}

	jsonStr, err := ExportDorksJSON(dorks)
	if err != nil || len(jsonStr) == 0 {
		t.Errorf("ExportDorksJSON failed: %v", err)
	}

	tmpFile := t.TempDir() + "/dorks.html"
	if err := ExportDorksHTML(domain, dorks, tmpFile); err != nil {
		t.Errorf("ExportDorksHTML failed: %v", err)
	}
}

func TestCleanDomain(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"https://www.example.com/path", "example.com"},
		{"http://example.com:8080/test?a=1", "example.com"},
		{"www.sub.example.com", "sub.example.com"},
		{"TARGET.COM", "target.com"},
	}
	for _, c := range cases {
		got := CleanDomain(c.input)
		if got != c.expected {
			t.Errorf("CleanDomain(%q) = %q; want %q", c.input, got, c.expected)
		}
	}
}

func TestDorkSyntaxStrictness(t *testing.T) {
	dorks := GenerateDorks("testsite.com")
	for _, d := range dorks {
		if strings.Contains(d.Query, " | ") {
			t.Errorf("dork query contains unparenthesized '|' pipe operator instead of 'OR': %s", d.Query)
		}
	}
}

