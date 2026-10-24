package devbuster

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"http://example.com", "http://example.com/"},
		{"http://example.com/api#section", "http://example.com/api"},
		{"https://EXAMPLE.COM:8080/path/test?q=1#frag", "https://example.com:8080/path/test?q=1"},
		{"http://test.lab/a/b/", "http://test.lab/a/b/"},
	}

	for _, c := range cases {
		got := Normalize(c.input)
		if got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestScope(t *testing.T) {
	crawler, err := NewCrawler(&Config{
		TargetURL:         "https://target.com",
		IncludeSubdomains: false,
	})
	if err != nil {
		t.Fatalf("NewCrawler failed: %v", err)
	}

	// Exact host
	if !crawler.InScope("https://target.com/page") {
		t.Errorf("expected target.com to be in scope")
	}

	// Canonical www alias
	if !crawler.InScope("https://www.target.com/page") {
		t.Errorf("expected www.target.com to be in scope via canonical alias")
	}

	// Out of scope subdomain when include_subdomains = false
	if crawler.InScope("https://api.target.com/page") {
		t.Errorf("expected api.target.com to be out of scope")
	}

	// External domain
	if crawler.InScope("https://evil.com/page") {
		t.Errorf("expected evil.com to be out of scope")
	}

	// Subdomain enabled
	crawlerSub, _ := NewCrawler(&Config{
		TargetURL:         "https://target.com",
		IncludeSubdomains: true,
	})
	if !crawlerSub.InScope("https://api.target.com/page") {
		t.Errorf("expected api.target.com to be in scope with include_subdomains=true")
	}
}

func TestExtractJSRoutes(t *testing.T) {
	crawler, err := NewCrawler(&Config{TargetURL: "http://target.lab"})
	if err != nil {
		t.Fatalf("NewCrawler failed: %v", err)
	}

	jsBundle := `
		const routes = [
			{ path: "/dashboard/analytics", component: Analytics },
			{ path: "/users/profile", to: '/admin/settings' },
			{ file: "/assets/banner.png" },
			{ font: "/fonts/inter.woff2" },
			{ api: "/api/v2/orders?status=active" }
		];
		var x = "/valid/route";
		var ignore1 = "/style.css";
		var ignore2 = "/bundle.js";
	`

	extracted := crawler.ExtractRoutes("http://target.lab/static/chunks/app.js", []byte(jsBundle), "application/javascript")

	foundURLs := make(map[string]bool)
	for _, e := range extracted {
		foundURLs[e.URL] = true
	}

	expected := []string{
		"http://target.lab/dashboard/analytics",
		"http://target.lab/users/profile",
		"http://target.lab/admin/settings",
		"http://target.lab/api/v2/orders?status=active",
		"http://target.lab/valid/route",
	}

	for _, exp := range expected {
		if !foundURLs[exp] {
			t.Errorf("expected route %q was not extracted from JS bundle", exp)
		}
	}

	// Ensure asset files are filtered out
	notExpected := []string{
		"http://target.lab/assets/banner.png",
		"http://target.lab/fonts/inter.woff2",
		"http://target.lab/style.css",
		"http://target.lab/bundle.js",
	}

	for _, nexp := range notExpected {
		if foundURLs[nexp] {
			t.Errorf("static asset %q should NOT have been extracted as a route", nexp)
		}
	}
}

func TestExtractHTML(t *testing.T) {
	crawler, _ := NewCrawler(&Config{TargetURL: "http://target.lab"})
	html := `
		<!DOCTYPE html>
		<html>
		<head><link rel="stylesheet" href="/assets/main.css"></head>
		<body>
			<a href="/login">Login</a>
			<a href="https://target.lab/about-us">About</a>
			<form action="/auth/submit" method="POST"></form>
			<script src="/static/bundle.js"></script>
		</body>
		</html>
	`
	extracted := crawler.ExtractRoutes("http://target.lab/", []byte(html), "text/html")
	found := make(map[string]bool)
	for _, e := range extracted {
		found[e.URL] = true
	}

	if !found["http://target.lab/login"] {
		t.Errorf("expected /login from a[href]")
	}
	if !found["https://target.lab/about-us"] {
		t.Errorf("expected /about-us from a[href]")
	}
	if !found["http://target.lab/auth/submit"] {
		t.Errorf("expected /auth/submit from form[action]")
	}
	if !found["http://target.lab/static/bundle.js"] {
		t.Errorf("expected /static/bundle.js from script[src]")
	}
}

func TestStatusFilters(t *testing.T) {
	crawler, _ := NewCrawler(&Config{
		TargetURL:  "http://target.lab",
		HideStatus: map[int]bool{403: true, 404: true},
	})

	if crawler.ShouldShow(403) {
		t.Errorf("expected 403 to be hidden")
	}
	if crawler.ShouldShow(404) {
		t.Errorf("expected 404 to be hidden")
	}
	if !crawler.ShouldShow(200) {
		t.Errorf("expected 200 to be shown")
	}

	crawlerOnly, _ := NewCrawler(&Config{
		TargetURL:  "http://target.lab",
		OnlyStatus: map[int]bool{200: true, 301: true},
	})
	if !crawlerOnly.ShouldShow(200) {
		t.Errorf("expected 200 to be shown")
	}
	if crawlerOnly.ShouldShow(500) {
		t.Errorf("expected 500 to be hidden when only 200,301")
	}
}

func TestEndToEndDevbusterCrawl(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `
				<html>
				<body>
					<h1>Modern App</h1>
					<a href="/public">Public Page</a>
					<script src="%s/app.js"></script>
				</body>
				</html>
			`, ts.URL)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `
				const routes = [
					{ path: "/secret-admin-portal" },
					{ path: "/api/v1/users" }
				];
			`)
		case "/public":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "public page")
		case "/secret-admin-portal":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "admin portal")
		case "/api/v1/users":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `[{"id": 1}]`)
		case "/wordlist-hit":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "wordlist found")
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "not found")
		}
	}))
	defer ts.Close()

	crawler, err := NewCrawler(&Config{
		TargetURL:   ts.URL,
		Depth:       2,
		Concurrency: 5,
		Timeout:     5 * time.Second,
		Wordlist:    []string{"wordlist-hit", "missing-page"},
		HideStatus:  map[int]bool{404: true},
		Quiet:       true,
	})
	if err != nil {
		t.Fatalf("NewCrawler failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findings, err := crawler.Run(ctx)
	if err != nil {
		t.Fatalf("crawler.Run failed: %v", err)
	}

	foundMap := make(map[string]int)
	for _, f := range findings {
		foundMap[f.URL] = f.Status
	}

	// Check discoveries
	if foundMap[ts.URL+"/"] != 200 {
		t.Errorf("seed / not found with 200: %v", foundMap)
	}
	if foundMap[ts.URL+"/public"] != 200 {
		t.Errorf("HTML link /public not found: %v", foundMap)
	}
	if foundMap[ts.URL+"/secret-admin-portal"] != 200 {
		t.Errorf("JS literal route /secret-admin-portal not found: %v", foundMap)
	}
	if foundMap[ts.URL+"/api/v1/users"] != 200 {
		t.Errorf("JS literal route /api/v1/users not found: %v", foundMap)
	}
	if foundMap[ts.URL+"/wordlist-hit"] != 200 {
		t.Errorf("Wordlist candidate /wordlist-hit not found: %v", foundMap)
	}
	if _, exists := foundMap[ts.URL+"/missing-page"]; exists {
		t.Errorf("404 missing-page should have been filtered by HideStatus: %v", foundMap)
	}

	// Verify JSON output
	jsonStr, err := ToJSON(findings)
	if err != nil || !strings.Contains(jsonStr, "secret-admin-portal") {
		t.Errorf("ToJSON failed or missing route: %v", err)
	}
}
