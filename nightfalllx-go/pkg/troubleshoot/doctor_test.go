package troubleshoot

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDoctor(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	doc := NewDoctor(ts.URL, "", "")
	checks := doc.RunAll()

	if len(checks) == 0 {
		t.Fatalf("expected diagnostic checks, got none")
	}

	foundHTTP := false
	for _, c := range checks {
		if c.Name == "HTTP Responsiveness" {
			foundHTTP = true
			if !c.Passed {
				t.Fatalf("expected HTTP Responsiveness to pass: %s", c.Message)
			}
		}
	}

	if !foundHTTP {
		t.Fatalf("expected HTTP Responsiveness check in report")
	}
}
