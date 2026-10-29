package modules

import (
	"net/http"
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"strings"
	"testing"
	"time"
)

func TestSSRFModule_LFIAndLoopback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")

		if strings.Contains(urlParam, "file:///etc/passwd") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:"))
			return
		}

		if strings.Contains(urlParam, "127.0.0.1") || strings.Contains(urlParam, "localhost") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<h1>discover.hard</h1><p>Internal apex host</p>"))
			return
		}

		// Baseline
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Link preview normal page</body></html>"))
	}))
	defer server.Close()

	c := client.NewClient("", 5*time.Second, false, "", nil)
	target := &Target{
		URL:    server.URL + "/?url=https://example.com",
		Method: "GET",
		Params: map[string]string{"url": "https://example.com"},
	}

	mod := NewSSRFModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings (SSRF+LFI and Loopback), got %d", len(findings))
	}

	hasLFI := false
	hasLoopback := false
	for _, f := range findings {
		if strings.Contains(f.Title, "LFI") || strings.Contains(f.Payload, "file://") {
			hasLFI = true
		}
		if strings.Contains(f.Title, "Loopback") || strings.Contains(f.Payload, "127.0.0.1") {
			hasLoopback = true
		}
	}

	if !hasLFI {
		t.Errorf("expected SSRF+LFI finding")
	}
	if !hasLoopback {
		t.Errorf("expected SSRF Loopback finding")
	}
}
