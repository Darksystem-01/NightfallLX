package modules

import (
	"net/http"
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"strings"
	"testing"
	"time"
)

func TestSQLiModule_ErrorBased(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") || strings.Contains(id, "\"") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Database error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User Profile: Alice"))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL + "?id=1",
		Method: "GET",
		Params: map[string]string{"id": "1"},
	}

	mod := NewSQLiModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("expected error-based SQLi finding, got 0")
	}

	if !strings.Contains(findings[0].Title, "Error-Based") {
		t.Fatalf("expected Error-Based title, got %s", findings[0].Title)
	}
}

func TestSQLiModule_BooleanBased(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "1=1") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><div class='profile'>Full user details for ID 1: Name=Alice, Role=Admin, Email=alice@example.com, Active=True, Score=100</div></html>"))
			return
		}
		if strings.Contains(id, "1=2") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><div class='error'>User not found</div></html>"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><div class='profile'>Full user details for ID 1: Name=Alice, Role=Admin, Email=alice@example.com, Active=True, Score=100</div></html>"))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL + "?id=1",
		Method: "GET",
		Params: map[string]string{"id": "1"},
	}

	mod := NewSQLiModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("expected boolean-based SQLi finding, got 0")
	}

	if !strings.Contains(findings[0].Title, "Boolean-based") {
		t.Fatalf("expected Boolean-based title, got %s", findings[0].Title)
	}
}

func TestSQLiModule_NegativeControl_BaselineError(t *testing.T) {
	// Baseline already contains an SQL syntax error (e.g. blog post explaining SQL errors)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Article: How to fix 'You have an error in your SQL syntax' in your code."))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL + "?id=1",
		Method: "GET",
		Params: map[string]string{"id": "1"},
	}

	mod := NewSQLiModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when baseline already has SQL error, got %d", len(findings))
	}
}
