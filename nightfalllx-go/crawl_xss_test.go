package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/xss"
	"strings"
	"testing"
	"time"
)

func TestCrawlAndScanXSS(t *testing.T) {
	mux := http.NewServeMux()

	// Page 1: Home page links to page 2 (with param) and page 3 (clean static)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Portal Home</title></head>
<body>
  <h1>Welcome to Corporate Portal</h1>
  <a href="/search?q=test">Search Portal</a>
  <a href="/about">About Us</a>
</body>
</html>`)
	})

	// Page 2: Search page reflecting query parameter in active executable context
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Search</title></head>
<body>
  <h1>Search Results</h1>
  <div>You searched for: %s</div>
</body>
</html>`, q)
	})

	// Page 3: About page with no parameters
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>About</title></head>
<body>
  <h1>About Corporate Portal</h1>
  <p>Static clean page with no query parameters or input forms.</p>
</body>
</html>`)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := client.NewClient("", 5*time.Second, true, "", nil)
	xssCfg := &xss.EngineConfig{
		EnableDOM:          false,
		EnableForms:        false,
		EnableStored:       false,
		MaxVectorsPerParam: 15,
	}

	findings, err := RunCrawlAndScanXSS(ts.URL, 2, 10, xssCfg, c, nil)
	if err != nil {
		t.Fatalf("RunCrawlAndScanXSS failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("expected at least one XSS finding on crawled /search endpoint, got none")
	}

	// Verify findings appear for /search ONLY
	for _, f := range findings {
		if !strings.Contains(f.URL, "/search") {
			t.Errorf("expected finding strictly on /search endpoint, got finding on: %s", f.URL)
		}
		if f.Parameter != "q" {
			t.Errorf("expected finding on parameter 'q', got '%s'", f.Parameter)
		}
	}
}
