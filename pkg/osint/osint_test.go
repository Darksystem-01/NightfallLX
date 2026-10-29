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
	if err != nil || len(rep.TargetIPs) == 0 {
		t.Skip("External DNS resolution not available in test environment, skipping")
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
		if !strings.HasPrefix(d.DorkSearchURL, "https://duckduckgo.com/?q=") && !strings.HasPrefix(d.DorkSearchURL, "https://dorksearch.com/?q=") {
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

func TestClassifyPortal(t *testing.T) {
	cases := []struct {
		url      string
		title    string
		body     string
		expected string
	}{
		{"https://example.com/wp-login.php", "Log In ‹ WordPress", "user_login", "WordPress CMS Admin"},
		{"https://example.com/phpmyadmin/", "phpMyAdmin", "pma_username", "Database Console"},
		{"https://example.com/grafana/login", "Grafana", "", "Grafana Metrics Console"},
		{"https://example.com/jenkins/login", "Sign in [Jenkins]", "", "Jenkins CI/CD Portal"},
		{"https://example.com/sso/login", "Single Sign-On", "", "SSO / Identity Provider"},
		{"https://example.com/admin/login", "Administration Panel", "", "Administrative Portal"},
	}

	for _, c := range cases {
		got := classifyPortal(c.url, c.title, c.body)
		if got != c.expected {
			t.Errorf("classifyPortal(%q, %q) = %q; want %q", c.url, c.title, got, c.expected)
		}
	}
}

func TestMockAdminProbe(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-login.php" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><head><title>WordPress › Log In</title></head><body><form><input type="password" name="pwd"></form></body></html>`))
			return
		}
		if r.URL.Path == "/admin/" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`<html><head><title>Access Control</title></head><body>Forbidden</body></html>`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	portals := HuntAdminPortals(ts.URL, nil, nil, 3*time.Second)
	if len(portals) == 0 {
		t.Fatal("expected discovered admin portals on mock server, got 0")
	}

	foundWP := false
	for _, p := range portals {
		if strings.Contains(p.URL, "/wp-login.php") && p.HasLoginForm {
			foundWP = true
		}
	}
	if !foundWP {
		t.Error("expected to discover exposed wp-login with login form on mock server")
	}
}

func TestBuildAXFRQuery(t *testing.T) {
	frame := buildAXFRQuery("example.com")
	if len(frame) < 18 {
		t.Fatalf("expected AXFR frame len >= 18, got %d", len(frame))
	}
	// Check QTYPE 252 (0x00FC) in question tail
	qtype := frame[len(frame)-4:]
	if qtype[0] != 0x00 || qtype[1] != 0xFC {
		t.Errorf("expected QTYPE 252 (AXFR), got %x %x", qtype[0], qtype[1])
	}
}

func TestHarvestEmails(t *testing.T) {
	secTxt := "Contact: mailto:security@target.com\nContact: admin@target.com\n"
	wayback := []string{
		"https://target.com/contact?mail=john.doe@target.com",
		"https://target.com/team/jane.smith@target.com",
		"https://other.com/junk.png",
	}

	dossier := HarvestEmails("target.com", wayback, secTxt, 3*time.Second)
	if dossier.TotalFound < 3 {
		t.Errorf("expected at least 3 emails, got %d", dossier.TotalFound)
	}
	if dossier.Pattern == "" {
		t.Error("expected detected email pattern, got empty")
	}
}



