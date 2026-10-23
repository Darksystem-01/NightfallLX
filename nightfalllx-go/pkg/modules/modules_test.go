package modules

import (
	"bytes"
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
	if findings[0].ConfidenceLevel != ConfidenceConfirmed {
		t.Errorf("expected confirmed CORS finding, got %s", findings[0].ConfidenceLevel)
	}

	// Negative test: static page without CORS headers
	cleanTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Static safe page</body></html>"))
	}))
	defer cleanTs.Close()

	cleanTarget := &Target{URL: cleanTs.URL, Method: "GET"}
	cleanFindings, err := mod.Run(cleanTarget, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cleanFindings) != 0 {
		t.Errorf("expected 0 findings on static page, got %d", len(cleanFindings))
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
	if findings[0].ConfidenceLevel != ConfidenceConfirmed {
		t.Errorf("expected confirmed redirect finding, got %s", findings[0].ConfidenceLevel)
	}

	// Negative test: static page with normal 200 response
	cleanTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Safe static page</body></html>"))
	}))
	defer cleanTs.Close()

	cleanTarget := &Target{
		URL:    cleanTs.URL,
		Method: "GET",
		Params: map[string]string{"page": "home"},
	}
	cleanFindings, err := mod.Run(cleanTarget, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cleanFindings) != 0 {
		t.Errorf("expected 0 findings on static clean page, got %d", len(cleanFindings))
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
	var lastUploadedContent string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			if strings.Contains(r.URL.Path, "probe.php.png") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(lastUploadedContent))
				return
			}
			w.Write([]byte(`<html><form method="POST" enctype="multipart/form-data"><input type="file" name="avatar"></form></html>`))
			return
		}
		_ = r.ParseMultipartForm(10 << 20)
		file, _, err := r.FormFile("avatar")
		if err == nil {
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(file)
			lastUploadedContent = buf.String()
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "success", "path": "/uploads/probe.php.png"}`))
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
	if findings[0].ConfidenceLevel != ConfidenceConfirmed {
		t.Fatalf("expected Confirmed confidence level, got %s", findings[0].ConfidenceLevel)
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

	for _, f := range findings {
		if strings.HasPrefix(f.Title, "Missing ") {
			if f.ConfidenceLevel != ConfidencePossible {
				t.Errorf("expected possible confidence for %s, got %s", f.Title, f.ConfidenceLevel)
			}
		} else {
			if f.ConfidenceLevel != ConfidenceProbable {
				t.Errorf("expected probable confidence for %s, got %s", f.Title, f.ConfidenceLevel)
			}
		}
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
	if findings[0].ConfidenceLevel != ConfidenceConfirmed {
		t.Errorf("expected confirmed confidence for hostheader redirect, got %s", findings[0].ConfidenceLevel)
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
		if strings.Contains(q, "\r\n") || strings.Contains(q, "\n") {
			for _, line := range strings.Split(q, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "X-Injected-Header:") {
					w.Header().Set("X-Injected-Header", strings.TrimSpace(strings.TrimPrefix(line, "X-Injected-Header:")))
				}
				if strings.HasPrefix(line, "Set-Cookie:") {
					w.Header().Set("Set-Cookie", strings.TrimSpace(strings.TrimPrefix(line, "Set-Cookie:")))
				}
			}
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

func TestGraphQLModule(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		body := buf.String()

		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(body, "__typename") && strings.Contains(body, "BatchTest") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":{"q1":"Query","q2":"Query","q3":"Query","q4":"Query","q5":"Query","q6":"Query","q7":"Query","q8":"Query","q9":"Query","q10":"Query"}}`))
			return
		}
		if strings.Contains(body, "__schema") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User","kind":"OBJECT"}]}}}`))
			return
		}
		if strings.Contains(body, "__typename") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":{"__typename":"Query"}}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"errors":[{"message":"syntax error"}]}`))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{URL: ts.URL + "/graphql", Method: "POST"}

	mod := NewGraphQLModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings (introspection + batching), got %d", len(findings))
	}

	// Negative fixture: standard REST API
	restTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not found"))
	}))
	defer restTs.Close()

	restFindings, _ := mod.Run(&Target{URL: restTs.URL, Method: "GET"}, c)
	if len(restFindings) != 0 {
		t.Fatalf("expected 0 GraphQL findings for REST API, got %d", len(restFindings))
	}
}

func TestJWTModuleBypass(t *testing.T) {
	validToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized"))
			return
		}
		// Accepts alg:none or weak secret "secret"
		if strings.Contains(auth, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0") || strings.Contains(auth, "Bearer ") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("admin welcome"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:     ts.URL,
		Method:  "GET",
		Headers: map[string]string{"Authorization": "Bearer " + validToken},
	}

	mod := NewJWTModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected JWT bypass finding, got none")
	}

	// Negative fixture: endpoint that strictly rejects unauthenticated and invalid tokens
	strictTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("unauthorized"))
	}))
	defer strictTs.Close()

	strictFindings, _ := mod.Run(&Target{URL: strictTs.URL, Method: "GET", Headers: map[string]string{"Authorization": "Bearer " + validToken}}, c)
	if len(strictFindings) != 0 {
		t.Fatalf("expected 0 JWT findings on strict server, got %d", len(strictFindings))
	}
}

func TestProtoPollutionModule(t *testing.T) {
	polluted := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			buf := new(bytes.Buffer)
			buf.ReadFrom(r.Body)
			if strings.Contains(buf.String(), "__proto__") || strings.Contains(buf.String(), "prototype") {
				polluted = true
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"ok","nflx":"polluted"}`))
				return
			}
		}
		if r.Method == "GET" {
			if polluted {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"ok","user":"admin","nflx":"polluted"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok","user":"guest"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{URL: ts.URL, Method: "POST", IsJSON: true, RawJSON: `{"user":"test"}`}

	mod := NewProtoPollutionModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected prototype pollution finding, got none")
	}

	// Negative fixture: safe server that ignores and does not reflect pollution
	safeTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"clean"}`))
	}))
	defer safeTs.Close()

	safeFindings, _ := mod.Run(&Target{URL: safeTs.URL, Method: "GET"}, c)
	if len(safeFindings) != 0 {
		t.Fatalf("expected 0 findings for safe server, got %d", len(safeFindings))
	}
}

func TestMassAssignModule(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		body := buf.String()

		if strings.Contains(body, "role") && strings.Contains(body, "admin") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success":true,"user":{"name":"john","role":"admin"}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success":true,"user":{"name":"john","role":"user"}}`))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:     ts.URL,
		Method:  "POST",
		IsJSON:  true,
		RawJSON: `{"name":"john"}`,
	}

	mod := NewMassAssignModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected mass assignment finding, got none")
	}

	// Negative fixture: endpoint that ignores extra properties
	strictTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success":true,"user":{"name":"john"}}`))
	}))
	defer strictTs.Close()

	strictFindings, _ := mod.Run(&Target{URL: strictTs.URL, Method: "POST", IsJSON: true, RawJSON: `{"name":"john"}`}, c)
	// Must not be confirmed (could be possible or 0, but not confirmed)
	for _, f := range strictFindings {
		if f.ConfidenceLevel == ConfidenceConfirmed {
			t.Fatalf("did not expect Confirmed finding on strict server")
		}
	}
}

func TestDeserializeModule(t *testing.T) {
	// Vulnerable endpoint passing Java serialized object and Python pickle in cookie
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "remember_me=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==; Path=/")
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL,
		Method: "GET",
		Params: map[string]string{
			"state": "gASVNDAAAAAAAAB9cQAoWA...",
		},
	}

	mod := NewDeserializeModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 deserialize findings (Python pickle in param + Java in response cookie), got %d", len(findings))
	}

	// Negative fixture: Clean standard query parameters and cookies
	cleanTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("clean"))
	}))
	defer cleanTs.Close()

	cleanTarget := &Target{URL: cleanTs.URL, Method: "GET", Params: map[string]string{"page": "1", "sort": "asc"}}
	cleanFindings, _ := mod.Run(cleanTarget, c)
	if len(cleanFindings) != 0 {
		t.Fatalf("expected 0 deserialize findings on clean target, got %d", len(cleanFindings))
	}
}

func TestJSONNestedSQLiAndIDOR(t *testing.T) {
	// JSON endpoint with nested structures
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		body := buf.String()

		// Nested SQL error check
		if strings.Contains(body, "'") || strings.Contains(body, "AND 1=2") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"syntax error near '1=2' in MySQL statement"}`))
			return
		}

		// Nested IDOR check
		if strings.Contains(body, `"id":2`) || strings.Contains(body, `"id": 2`) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"user":{"id":2,"name":"bob_admin","role":"admin"}}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user":{"id":1,"name":"alice","role":"user"}}`))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	jsonTarget := &Target{
		URL:     ts.URL,
		Method:  "POST",
		IsJSON:  true,
		RawJSON: `{"user":{"id":1,"name":"alice"}}`,
	}
	_ = jsonTarget.ParseJSONBody(jsonTarget.RawJSON)

	// Test SQLi on JSON leaf
	sqliMod := NewSQLiModule()
	sqliFindings, err := sqliMod.Run(jsonTarget, c)
	if err != nil {
		t.Fatalf("unexpected sqli error: %v", err)
	}
	if len(sqliFindings) == 0 {
		t.Fatalf("expected SQLi finding on JSON leaf, got none")
	}

	// Test IDOR on JSON leaf
	idorMod := NewIDORModule()
	idorFindings, err2 := idorMod.Run(jsonTarget, c)
	if err2 != nil {
		t.Fatalf("unexpected idor error: %v", err2)
	}
	if len(idorFindings) == 0 {
		t.Fatalf("expected IDOR finding on JSON leaf, got none")
	}
}

