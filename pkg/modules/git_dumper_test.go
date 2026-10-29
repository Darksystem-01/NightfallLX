package modules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"strings"
	"testing"
	"time"
)

func TestGitDumperModule(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.git/HEAD":
			w.WriteHeader(200)
			fmt.Fprint(w, "ref: refs/heads/main\n")
		case "/.git/config":
			w.WriteHeader(200)
			fmt.Fprint(w, "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n")
		case "/.env":
			w.WriteHeader(200)
			fmt.Fprint(w, "APP_ENV=production\nDB_PASSWORD=super_secret_1234\nAPI_KEY=sk_live_abc123xyz\n")
		default:
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()

	c := client.NewClient("", 5*time.Second, false, "", nil)
	rep, findings, err := AuditGitExposure(ts.URL, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !rep.Exposed {
		t.Errorf("expected .git to be detected as exposed")
	}

	if !strings.Contains(rep.HEADRef, "refs/heads/main") {
		t.Errorf("expected HEAD ref to be 'refs/heads/main', got: %s", rep.HEADRef)
	}

	// Should have at least: .git/HEAD exposure + .git/config + .env
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(findings))
	}

	hasCritical := false
	for _, f := range findings {
		if f.Severity == SeverityCritical {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Errorf("expected at least one CRITICAL finding for .git/ or .env exposure")
	}
}
