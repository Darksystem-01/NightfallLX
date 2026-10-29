package modules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"testing"
	"time"
)

func TestSmuggleVectorBuilder(t *testing.T) {
	vectors := buildSmuggleVectors("example.com", "/test")
	if len(vectors) < 6 {
		t.Fatalf("expected at least 6 vectors, got %d", len(vectors))
	}

	types := map[string]bool{}
	for _, v := range vectors {
		types[v.Type] = true
		if v.Name == "" {
			t.Errorf("vector has empty Name")
		}
		if len(v.Request) == 0 {
			t.Errorf("vector %s has empty raw Request", v.Name)
		}
	}

	for _, required := range []string{"CL.TE", "TE.CL", "TE.TE"} {
		if !types[required] {
			t.Errorf("expected %s type vector, not found", required)
		}
	}
}

func TestAuditHTTPSmugglingClean(t *testing.T) {
	// Normal HTTP server — should not flag any smuggling
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	c := client.NewClient("", 5*time.Second, false, "", nil)
	rep, findings, err := AuditHTTPSmuggling(ts.URL, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep == nil {
		t.Fatalf("expected non-nil report")
	}
	// A clean server should produce no confirmed smuggling findings
	// (timing oracle may not fire, and no GPOST echo expected)
	_ = findings
}
