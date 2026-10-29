package modules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"testing"
	"time"
)

func TestJSMinerModule(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `
<!DOCTYPE html>
<html>
<head>
  <script src="/static/app.bundle.js"></script>
  <link rel="modulepreload" href="/static/chunk-vendor.js">
</head>
<body>
  <h1>Test App</h1>
  <script>
    const inlineRoute = "/internal/metrics";
  </script>
</body>
</html>`)
		case "/static/app.bundle.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `
const apiBase = "/api/v1/users";
const loginUrl = "/auth/v2/login";
const graphQL = "/graphql";
const googleKey = "AIzaSyD9876543210abcdefghij0123456789ab";
`)
		case "/static/chunk-vendor.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `
const exportUrl = "/api/v1/export/database.json";
`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	c := client.NewClient("", 5*time.Second, false, "", nil)
	report, findings, err := MineJavaScript(ts.URL, c)
	if err != nil {
		t.Fatalf("unexpected error mining js: %v", err)
	}

	if report.TotalScripts != 2 {
		t.Errorf("expected 2 scripts discovered, got %d", report.TotalScripts)
	}

	if len(report.AllEndpoints) < 4 {
		t.Errorf("expected at least 4 endpoints discovered, got %d: %v", len(report.AllEndpoints), report.AllEndpoints)
	}

	if len(findings) == 0 {
		t.Errorf("expected finding for exposed Google API Key, got 0")
	} else {
		f := findings[0]
		if f.Module != "jsminer" {
			t.Errorf("expected module 'jsminer', got %s", f.Module)
		}
	}
}
