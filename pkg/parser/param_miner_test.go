package parser

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParamMinerReflection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		debugVal := r.URL.Query().Get("debug")
		if debugVal != "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("<html><body>Debug Mode Active: %s</body></html>", debugVal)))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Welcome to normal app</body></html>"))
	}))
	defer server.Close()

	miner := NewParamMiner(&MinerConfig{
		URL:       server.URL,
		Method:    "GET",
		BatchSize: 15,
		Timeout:   3 * time.Second,
		Wordlist:  []string{"test", "admin", "debug", "secret", "token", "backup", "mode"},
	})

	params, err := miner.Mine()
	if err != nil {
		t.Fatalf("mining failed: %v", err)
	}

	foundDebug := false
	for _, p := range params {
		if p.Name == "debug" {
			foundDebug = true
			if p.Reason != "reflection" {
				t.Errorf("expected reason 'reflection', got '%s'", p.Reason)
			}
		}
	}

	if !foundDebug {
		t.Errorf("expected 'debug' parameter to be discovered via reflection, got: %+v", params)
	}
}

func TestParamMinerStatusChange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminVal := r.URL.Query().Get("admin")
		if adminVal != "" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Access Denied to Admin"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Regular user landing"))
	}))
	defer server.Close()

	miner := NewParamMiner(&MinerConfig{
		URL:       server.URL,
		Method:    "GET",
		BatchSize: 15,
		Timeout:   3 * time.Second,
		Wordlist:  []string{"view", "show", "admin", "format", "lang"},
	})

	params, err := miner.Mine()
	if err != nil {
		t.Fatalf("mining failed: %v", err)
	}

	foundAdmin := false
	for _, p := range params {
		if p.Name == "admin" {
			foundAdmin = true
			if p.Reason != "status_change" {
				t.Errorf("expected reason 'status_change', got '%s'", p.Reason)
			}
		}
	}

	if !foundAdmin {
		t.Errorf("expected 'admin' parameter to be discovered via status change, got: %+v", params)
	}
}

func TestTop200HiddenParamsCount(t *testing.T) {
	if len(Top200HiddenParams) < 150 {
		t.Errorf("expected at least 150 hidden parameters, got %d", len(Top200HiddenParams))
	}
}
