package xss

import (
	"net/http"
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"testing"
	"time"
)

func TestFindReflectionsAndContexts(t *testing.T) {
	marker := "CANARY123"

	tests := []struct {
		name        string
		html        string
		expectedCtx ContextType
	}{
		{
			name:        "HTML Text",
			html:        "<div>Hello CANARY123 World</div>",
			expectedCtx: ContextHTMLText,
		},
		{
			name:        "Quoted Attribute",
			html:        "<input name=\"search\" value=\"CANARY123\">",
			expectedCtx: ContextAttributeQuoted,
		},
		{
			name:        "URL Attribute",
			html:        "<a href=\"/profile?id=CANARY123\">link</a>",
			expectedCtx: ContextURLAttribute,
		},
		{
			name:        "JS Single Quote String",
			html:        "<script>var user = 'CANARY123';</script>",
			expectedCtx: ContextJSStringSingle,
		},
		{
			name:        "JS Double Quote String",
			html:        "<script>var role = \"CANARY123\";</script>",
			expectedCtx: ContextJSStringDouble,
		},
		{
			name:        "JS Template Literal",
			html:        "<script>var greeting = `Hello ${val} CANARY123`;</script>",
			expectedCtx: ContextJSTemplate,
		},
		{
			name:        "HTML Comment",
			html:        "<!-- Debug info: CANARY123 -->",
			expectedCtx: ContextHTMLComment,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			refs := FindReflections(tc.html, marker)
			if len(refs) == 0 {
				t.Fatalf("expected at least 1 reflection for %s, got 0", tc.name)
			}
			if refs[0].Context != tc.expectedCtx {
				t.Errorf("expected context %s, got %s", tc.expectedCtx, refs[0].Context)
			}
		})
	}
}

func TestNegativeCleanPageReflection(t *testing.T) {
	cleanHTML := `<!DOCTYPE html><html><body><h1>Welcome</h1><p>Clean page with no user input.</p></body></html>`
	refs := FindReflections(cleanHTML, "NONEXISTENT_CANARY")
	if len(refs) != 0 {
		t.Errorf("expected 0 reflections on clean page, got %d", len(refs))
	}
}

func TestCheckExecutableNode(t *testing.T) {
	positiveCases := []struct {
		name string
		html string
	}{
		{"Event handler on img", "<img src=x onerror=alert(1)>"},
		{"Event handler on svg", "<svg onload=alert(1)>"},
		{"Executable script tag", "<script>alert(1)</script>"},
		{"Javascript protocol href", "<a href=\"javascript:alert(1)\">click</a>"},
	}

	for _, pc := range positiveCases {
		t.Run(pc.name, func(t *testing.T) {
			exec, proof := CheckExecutableNode(pc.html, "alert(1)")
			if !exec {
				t.Errorf("expected positive executable node for %s", pc.name)
			}
			if proof == "" {
				t.Errorf("expected non-empty proof for %s", pc.name)
			}
		})
	}

	negativeCases := []struct {
		name string
		html string
	}{
		{"Escaped HTML script", "<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>"},
		{"Harmless text alert", "<div>alert(1) in plain text</div>"},
		{"Comment alert", "<!-- alert(1) -->"},
	}

	for _, nc := range negativeCases {
		t.Run(nc.name, func(t *testing.T) {
			exec, _ := CheckExecutableNode(nc.html, "alert(1)")
			if exec {
				t.Errorf("expected false for harmless negative case: %s", nc.name)
			}
		})
	}
}

func TestAnalyzeDOMScript(t *testing.T) {
	jsWithDOM := `
		// Unsafe DOM manipulation
		var hash = window.location.hash.substring(1);
		document.getElementById("content").innerHTML = hash;
	`
	findings := AnalyzeDOMScript(jsWithDOM, "inline")
	if len(findings) == 0 {
		t.Fatalf("expected DOM XSS finding, got 0")
	}
	if findings[0].Source != "window.location" && findings[0].Source != "location.hash" {
		t.Errorf("unexpected source: %s", findings[0].Source)
	}
	if findings[0].Sink != ".innerHTML" {
		t.Errorf("unexpected sink: %s", findings[0].Sink)
	}

	cleanJS := `
		var count = 42;
		console.log("Count is: " + count);
	`
	cleanFindings := AnalyzeDOMScript(cleanJS, "inline")
	if len(cleanFindings) != 0 {
		t.Errorf("expected 0 DOM findings for clean JS, got %d", len(cleanFindings))
	}
}

func TestFormsAndCSRF(t *testing.T) {
	htmlContent := `
		<form action="/login" method="POST">
			<input type="hidden" name="csrf_token" value="sec123456" />
			<input type="text" name="username" value="" />
			<input type="password" name="password" value="" />
			<input type="submit" value="Log In" />
		</form>
	`
	forms := ParseForms(htmlContent, "http://127.0.0.1:8080/login")
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	f := forms[0]
	if f.Method != "POST" {
		t.Errorf("expected method POST, got %s", f.Method)
	}
	if f.CSRFField != "csrf_token" {
		t.Errorf("expected CSRFField csrf_token, got %s", f.CSRFField)
	}
	if f.Inputs["csrf_token"] != "sec123456" {
		t.Errorf("expected csrf_token value sec123456, got %s", f.Inputs["csrf_token"])
	}
}

func TestEngineWithServerFixtures(t *testing.T) {
	// Vulnerable reflected server
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body><h1>Search Results</h1><p>" + q + "</p></body></html>"))
	}))
	defer vulnServer.Close()

	// Clean negative control server
	cleanServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body><h1>Clean Static Page</h1><p>No injection here.</p></body></html>"))
	}))
	defer cleanServer.Close()

	c := client.NewClient("", 5*time.Second, true, "", nil)
	engine := NewEngine(&EngineConfig{
		EnableDOM:          false,
		EnableForms:        false,
		EnableStored:       false,
		MaxVectorsPerParam: 5,
	})

	// Positive test
	vulnTarget := &Target{
		URL:    vulnServer.URL,
		Method: "GET",
		Params: map[string]string{"q": "test"},
	}
	findings, err := engine.ScanTarget(vulnTarget, c)
	if err != nil {
		t.Fatalf("ScanTarget failed: %v", err)
	}
	if len(findings) == 0 {
		t.Errorf("expected at least 1 finding on vulnerable endpoint, got 0")
	}

	// Negative test
	cleanTarget := &Target{
		URL:    cleanServer.URL,
		Method: "GET",
		Params: map[string]string{"page": "home"},
	}
	cleanFindings, err := engine.ScanTarget(cleanTarget, c)
	if err != nil {
		t.Fatalf("ScanTarget failed on clean server: %v", err)
	}
	if len(cleanFindings) != 0 {
		t.Errorf("expected 0 findings on clean server, got %d", len(cleanFindings))
	}
}
