package osint

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"testing"
	"time"
)

func TestTakeoverFingerprints(t *testing.T) {
	// Verify that all builtin signatures have non-empty services and patterns
	if len(BuiltinTakeoverSignatures) < 15 {
		t.Fatalf("expected at least 15 signatures, got %d", len(BuiltinTakeoverSignatures))
	}

	for _, sig := range BuiltinTakeoverSignatures {
		if sig.Service == "" {
			t.Errorf("empty service name in signature")
		}
		if len(sig.CNAMESuffixes) == 0 {
			t.Errorf("service %s has no CNAME suffixes", sig.Service)
		}
		if len(sig.ResponsePatterns) == 0 {
			t.Errorf("service %s has no response patterns", sig.Service)
		}
	}
}

func TestTakeoverMockDetection(t *testing.T) {
	// Mock a dangling GitHub Pages response
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `<html><body>There isn't a GitHub Pages site here.</body></html>`)
	}))
	defer ts.Close()

	c := client.NewClient("", 5*time.Second, false, "", nil)
	rep, findings, err := CheckSubdomainTakeovers([]string{}, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep == nil || len(findings) != 0 {
		t.Errorf("expected empty results for empty subdomains list")
	}
}
