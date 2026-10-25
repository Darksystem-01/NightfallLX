package modules

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"strings"
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

func TestIDORModule(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		cookie := r.Header.Get("Cookie")
		// Identity 1 has session1, Identity 2 has session2
		if id == "101" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"account_id": 101, "name": "Alice User", "balance": 5000, "secret": "alice_data"}`))
			return
		}
		_ = cookie
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "not found"}`))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:      ts.URL,
		Method:   "GET",
		Params:   map[string]string{"id": "101"},
		Cookie2:  "session=user2_cookie",
		Headers2: map[string]string{"X-User": "user2"},
	}

	mod := NewIDORModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected IDOR finding, got none")
	}

	// Negative fixture: clean endpoint
	cleanTarget := &Target{
		URL:    ts.URL,
		Method: "GET",
		Params: map[string]string{"id": "999"},
	}
	cleanFindings, _ := mod.Run(cleanTarget, c)
	if len(cleanFindings) != 0 {
		t.Fatalf("expected 0 findings for non-existent ID, got %d", len(cleanFindings))
	}
}

func TestCSRFModule(t *testing.T) {
	// Vulnerable server: POST without CSRF token and without SameSite
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=abc12345; Path=/")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("updated"))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL,
		Method: "POST",
		Data:   map[string]string{"email": "test@test.com"},
	}

	mod := NewCSRFModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected CSRF finding, got none")
	}

	// Negative fixture: Safe endpoint with CSRF token
	safeTarget := &Target{
		URL:    ts.URL,
		Method: "POST",
		Data:   map[string]string{"email": "test@test.com", "csrf_token": "valid_token"},
	}
	safeFindings, _ := mod.Run(safeTarget, c)
	if len(safeFindings) != 0 {
		t.Fatalf("expected 0 findings for token-protected form, got %d", len(safeFindings))
	}
}

func TestXXEModule(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<nflx><data>root:x:0:0:root:/root:/bin/bash</data></nflx>"))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL,
		Method: "POST",
	}

	mod := NewXXEModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected XXE finding, got none")
	}

	// Negative fixture: Normal XML response
	safeTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte("<nflx><data>safe normal xml content</data></nflx>"))
	}))
	defer safeTs.Close()

	safeTarget := &Target{URL: safeTs.URL, Method: "POST"}
	safeFindings, _ := mod.Run(safeTarget, c)
	if len(safeFindings) != 0 {
		t.Fatalf("expected 0 findings for safe XML, got %d", len(safeFindings))
	}
}

func TestNoSQLiModule(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("user")
		if strings.Contains(q, "$where") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("MongoError: Can't canonicalize query: BadValue unknown operator: $where"))
			return
		}
		w.Write([]byte("user page"))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL,
		Method: "GET",
		Params: map[string]string{"user": "admin"},
	}

	mod := NewNoSQLiModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected NoSQLi finding, got none")
	}

	// Negative fixture: Clean endpoint
	safeTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("clean response"))
	}))
	defer safeTs.Close()

	safeTarget := &Target{URL: safeTs.URL, Method: "GET", Params: map[string]string{"user": "john"}}
	safeFindings, _ := mod.Run(safeTarget, c)
	if len(safeFindings) != 0 {
		t.Fatalf("expected 0 findings for clean endpoint, got %d", len(safeFindings))
	}
}

func TestUploadModule(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Write([]byte(`<html><form method="POST" enctype="multipart/form-data"><input type="file" name="avatar"></form></html>`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "success", "file": "probe.php.png", "message": "file saved"}`))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL,
		Method: "GET",
	}

	mod := NewUploadModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected Upload finding, got none")
	}

	// Negative fixture: No upload form
	safeTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>plain page without upload</body></html>`))
	}))
	defer safeTs.Close()

	safeTarget := &Target{URL: safeTs.URL, Method: "GET"}
	safeFindings, _ := mod.Run(safeTarget, c)
	if len(safeFindings) != 0 {
		t.Fatalf("expected 0 upload findings, got %d", len(safeFindings))
	}
}

func TestHeadersModule(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.Header().Set("Set-Cookie", "session=123; Path=/")
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{URL: ts.URL, Method: "GET"}

	mod := NewHeadersModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected security header findings, got none")
	}

	// Negative fixture: Fully hardened headers
	hardenedTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Server", "webserver")
		w.Header().Set("Set-Cookie", "session=123; Secure; HttpOnly; SameSite=Strict; Path=/")
		w.Write([]byte("hardened"))
	}))
	defer hardenedTs.Close()

	hardenedTarget := &Target{URL: hardenedTs.URL, Method: "GET"}
	hardenedFindings, _ := mod.Run(hardenedTarget, c)
	if len(hardenedFindings) != 0 {
		t.Fatalf("expected 0 findings for hardened headers, got %d", len(hardenedFindings))
	}
}

func TestExposureModule(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/HEAD" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ref: refs/heads/main\n"))
			return
		}
		if r.URL.Path == "/.env" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("DB_PASSWORD=secret_root_pass\nAPP_KEY=base64:123\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{URL: ts.URL, Method: "GET"}

	mod := NewExposureModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 exposure findings (.git and .env), got %d", len(findings))
	}

	// Negative fixture: Clean server returning 404
	cleanTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 page"))
	}))
	defer cleanTs.Close()

	cleanTarget := &Target{URL: cleanTs.URL, Method: "GET"}
	cleanFindings, _ := mod.Run(cleanTarget, c)
	if len(cleanFindings) != 0 {
		t.Fatalf("expected 0 findings on 404 server, got %d", len(cleanFindings))
	}
}

func TestHostHeaderModule(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xfh := r.Header.Get("X-Forwarded-Host")
		if xfh != "" {
			w.Header().Set("Location", fmt.Sprintf("https://%s/reset-password?token=123", xfh))
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Write([]byte("home"))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{URL: ts.URL, Method: "GET"}

	mod := NewHostHeaderModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected Host Header finding, got none")
	}

	// Negative fixture: Safe server that uses fixed domain
	safeTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://fixed-domain.com/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer safeTs.Close()

	safeTarget := &Target{URL: safeTs.URL, Method: "GET"}
	safeFindings, _ := mod.Run(safeTarget, c)
	if len(safeFindings) != 0 {
		t.Fatalf("expected 0 findings for fixed domain redirect, got %d", len(safeFindings))
	}
}

func TestCRLFModule(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("lang")
		if strings.Contains(q, "X-Injected-Header") || strings.Contains(q, "%0d%0a") {
			w.Header().Set("X-Injected-Header", "nflx_crlf")
			w.Header().Set("Set-Cookie", "nflx_crlf=1")
		}
		w.Write([]byte("hello"))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL,
		Method: "GET",
		Params: map[string]string{"lang": "en"},
	}

	mod := NewCRLFModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected CRLF finding, got none")
	}

	// Negative fixture: Clean server
	cleanTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("clean"))
	}))
	defer cleanTs.Close()

	cleanTarget := &Target{URL: cleanTs.URL, Method: "GET", Params: map[string]string{"lang": "en"}}
	cleanFindings, _ := mod.Run(cleanTarget, c)
	if len(cleanFindings) != 0 {
		t.Fatalf("expected 0 CRLF findings on clean server, got %d", len(cleanFindings))
	}
}

