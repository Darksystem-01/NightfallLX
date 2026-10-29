package modules

import (
	"net/http"
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCMDiModule_ArithmeticCanary(t *testing.T) {
	// Vulnerable server that executes shell arithmetic
	mathRegex := regexp.MustCompile(`\$\(\(\s*(\d+)\+(\d+)\s*\)\)`)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmdParam := r.URL.Query().Get("cmd")
		if cmdParam == "" {
			w.Write([]byte("Safe Page"))
			return
		}
		// Simulate shell evaluation of $((n1+n2))
		if matches := mathRegex.FindStringSubmatch(cmdParam); len(matches) == 3 {
			n1, _ := strconv.Atoi(matches[1])
			n2, _ := strconv.Atoi(matches[2])
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Output: nflx_" + strconv.Itoa(n1+n2)))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Received: " + cmdParam))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL + "?cmd=test",
		Method: "GET",
		Params: map[string]string{"cmd": "test"},
	}

	mod := NewCMDiModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("expected arithmetic canary CMDi finding, got 0")
	}

	if !strings.Contains(findings[0].Title, "Deterministic Arithmetic Canary") {
		t.Fatalf("expected canary title, got %s", findings[0].Title)
	}
}

func TestCMDiModule_SystemID(t *testing.T) {
	// Vulnerable server that executes 'id' command
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmdParam := r.URL.Query().Get("host")
		if strings.Contains(cmdParam, "id") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("uid=1001(customuser) gid=1001(customgroup) groups=1001(customgroup)"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Host check OK"))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL + "?host=127.0.0.1",
		Method: "GET",
		Params: map[string]string{"host": "127.0.0.1"},
	}

	mod := NewCMDiModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("expected id-based CMDi finding, got 0")
	}

	if !strings.Contains(findings[0].Evidence, "uid=1001(customuser)") {
		t.Fatalf("expected custom user in evidence, got %s", findings[0].Evidence)
	}
}

func TestCMDiModule_NegativeControl_Reflection(t *testing.T) {
	// Server that merely echoes user input safely without execution (e.g. search box)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html>Search results for: " + q + "</html>"))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL + "?q=searchterm",
		Method: "GET",
		Params: map[string]string{"q": "searchterm"},
	}

	mod := NewCMDiModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for safe reflection page, got %d", len(findings))
	}
}

func TestCMDiModule_NegativeControl_StaticDocumentation(t *testing.T) {
	// Server that already has uid=0(root) in baseline page (e.g. Linux tutorial)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Documentation: standard root prompt is uid=0(root) gid=0(root)"))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL + "?topic=linux",
		Method: "GET",
		Params: map[string]string{"topic": "linux"},
	}

	mod := NewCMDiModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when baseline already has uid pattern, got %d", len(findings))
	}
}
