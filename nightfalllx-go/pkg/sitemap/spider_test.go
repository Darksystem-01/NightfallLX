package sitemap

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSpider(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`
				<html>
					<head><link rel="stylesheet" href="/style.css"></head>
					<body>
						<a href="/about.php?user=admin">About</a>
						<a href="/api/v1/users">API</a>
						<form action="/login.php" method="POST">
							<input name="username" type="text">
							<input name="password" type="password">
						</form>
						<script src="/app.js"></script>
					</body>
				</html>
			`))
		case "/about.php":
			w.Write([]byte(`<html><body><a href="/">Home</a></body></html>`))
		case "/api/v1/users":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[]`))
		case "/style.css":
			w.Write([]byte(`body { color: red; }`))
		case "/app.js":
			w.Write([]byte(`console.log("hello");`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	spider, err := NewSpider(ts.URL, 2, 20)
	if err != nil {
		t.Fatalf("failed to create spider: %v", err)
	}

	sm := spider.Crawl()
	if sm.TotalURLs == 0 {
		t.Fatalf("expected discovered URLs, got 0")
	}

	// Verify parameter extraction
	foundUserParam := false
	foundUsernameInput := false
	for _, ep := range sm.Endpoints {
		for _, p := range ep.Parameters {
			if p == "user" {
				foundUserParam = true
			}
		}
		for _, f := range ep.Forms {
			for _, in := range f.Inputs {
				if in == "username" {
					foundUsernameInput = true
				}
			}
		}
	}

	if !foundUserParam {
		t.Errorf("expected 'user' parameter to be discovered")
	}
	if !foundUsernameInput {
		t.Errorf("expected 'username' form input to be discovered")
	}
}
