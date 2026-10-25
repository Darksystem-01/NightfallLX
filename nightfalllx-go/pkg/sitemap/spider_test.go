package sitemap

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExtractJSEndpoints(t *testing.T) {
	jsCode := `
		function loadData() {
			fetch('/api/v1/orders?status=active');
			axios.get("/api/v2/products");
			$.post('/graphql');
			let u = '/admin/settings';
			let bad = 'text/html';
			let ignore = '//cdn.example.com/lib.js';
			let internal = '/internal/debug-mode';
		}
	`

	endpoints := ExtractJSEndpoints(jsCode)
	expected := []string{
		"/api/v1/orders?status=active",
		"/api/v2/products",
		"/graphql",
		"/admin/settings",
		"/internal/debug-mode",
	}

	for _, exp := range expected {
		found := false
		for _, ep := range endpoints {
			if ep == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected JS endpoint %s to be extracted, got %v", exp, endpoints)
		}
	}

	for _, ep := range endpoints {
		if ep == "text/html" || strings.HasPrefix(ep, "//") {
			t.Errorf("unexpected invalid endpoint extracted: %s", ep)
		}
	}
}

func TestParseRobotsAndSitemap(t *testing.T) {
	robotsContent := `
User-agent: *
Disallow: /admin/
Disallow: /private/secret.txt
Allow: /public/
Sitemap: https://example.com/sitemap.xml
`
	paths := ParseRobotsTxt(robotsContent)
	if len(paths) < 3 {
		t.Fatalf("expected at least 3 paths from robots.txt, got %d: %v", len(paths), paths)
	}

	sitemapContent := `
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
   <url>
      <loc>http://example.com/page1</loc>
   </url>
   <url>
      <loc>http://example.com/page2</loc>
   </url>
</urlset>
`
	urls := ParseSitemapXML(sitemapContent)
	if len(urls) != 2 {
		t.Fatalf("expected 2 URLs from sitemap.xml, got %d: %v", len(urls), urls)
	}
}

func TestSpiderWithJSAndRobots(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("User-agent: *\nDisallow: /super-secret-admin\n"))
		case "/sitemap.xml":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<urlset><url><loc>" + "http://" + r.Host + "/sitemap-page" + "</loc></url></urlset>"))
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`
				<html>
					<head><link rel="stylesheet" href="/style.css"></head>
					<body>
						<a href="/about.php?user=admin">About</a>
						<form action="/login.php" method="POST">
							<input name="username" type="text">
						</form>
						<script>
							fetch('/api/inline/hidden-endpoint');
						</script>
						<script src="/app.js"></script>
					</body>
				</html>
			`))
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`
				let api = "/api/v1/js-discovered";
			`))
		case "/about.php":
			w.Write([]byte(`<html><body><a href="/">Home</a></body></html>`))
		case "/api/inline/hidden-endpoint":
			w.Write([]byte(`{"ok": true}`))
		case "/api/v1/js-discovered":
			w.Write([]byte(`{"discovered": true}`))
		case "/super-secret-admin":
			w.Write([]byte(`Forbidden`))
		case "/sitemap-page":
			w.Write([]byte(`Sitemap Page`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	spider, err := NewSpider(ts.URL, 2, 25)
	if err != nil {
		t.Fatalf("failed to create spider: %v", err)
	}

	sm := spider.Crawl()
	if sm.TotalURLs == 0 {
		t.Fatalf("expected discovered URLs, got 0")
	}

	foundRobots := false
	foundInlineJS := false
	foundExternalJS := false

	for u := range sm.Endpoints {
		if strings.Contains(u, "super-secret-admin") {
			foundRobots = true
		}
		if strings.Contains(u, "/api/inline/hidden-endpoint") {
			foundInlineJS = true
		}
		if strings.Contains(u, "/api/v1/js-discovered") {
			foundExternalJS = true
		}
	}

	if !foundRobots {
		t.Errorf("expected robots.txt endpoint to be discovered")
	}
	if !foundInlineJS {
		t.Errorf("expected inline JS endpoint to be discovered")
	}
	if !foundExternalJS {
		t.Errorf("expected external JS endpoint to be discovered")
	}
}
