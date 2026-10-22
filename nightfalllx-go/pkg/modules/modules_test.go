package modules

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"testing"
	"time"
)

func TestSimilarity(t *testing.T) {
	s1 := "Hello World Test"
	s2 := "Hello World Test"
	if sim := Similarity(s1, s2); sim != 1.0 {
		t.Fatalf("expected 1.0, got %f", sim)
	}

	s3 := "Completely Different Content Here"
	if sim := Similarity(s1, s3); sim > 0.5 {
		t.Fatalf("expected low similarity, got %f", sim)
	}
}

func TestSSTIModule(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q == "{{7*7}}" {
			w.Write([]byte("evaluated: 49"))
		} else if q == "{{7*8}}" {
			w.Write([]byte("evaluated: 56"))
		} else {
			w.Write([]byte("normal page content"))
		}
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL,
		Method: "GET",
		Params: map[string]string{"q": "1"},
	}

	mod := NewSSTIModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Confidence != 100 {
		t.Fatalf("expected 100 confidence, got %d", findings[0].Confidence)
	}
}

func TestLFIModule(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("file")
		if q == "php://filter/convert.base64-encode/resource=index.php" {
			b64 := base64.StdEncoding.EncodeToString([]byte("<?php echo 'lab secret'; ?>"))
			w.Write([]byte("stream: " + b64))
		} else {
			w.Write([]byte("file not found"))
		}
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL,
		Method: "GET",
		Params: map[string]string{"file": "home.php"},
	}

	mod := NewLFIModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestXSSModule(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<div>Result: " + q + "</div>"))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL,
		Method: "GET",
		Params: map[string]string{"q": "test"},
	}

	mod := NewXSSModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("expected XSS finding, got none")
	}
}

func TestCORSModule(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Write([]byte("api data"))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL,
		Method: "GET",
	}

	mod := NewCORSModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("expected CORS finding, got none")
	}
}

func TestRedirectModule(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next != "" {
			http.Redirect(w, r, next, http.StatusFound)
			return
		}
		w.Write([]byte("home page"))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL,
		Method: "GET",
		Params: map[string]string{"next": "/login"},
	}

	mod := NewRedirectModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("expected Open Redirect finding, got none")
	}
}

func TestWAFModule(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("cf-ray", "8f382a17682910-IAD")
		w.Header().Set("Server", "cloudflare")
		w.Write([]byte("protected page"))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL,
		Method: "GET",
	}

	mod := NewWAFModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("expected WAF finding, got none")
	}
	if findings[0].Title != "WAF / Reverse Proxy Detected (Cloudflare)" {
		t.Fatalf("expected Cloudflare, got %s", findings[0].Title)
	}
}
