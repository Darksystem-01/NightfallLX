package fuzzer

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSubdomainAndVHostFuzzing(t *testing.T) {
	// Mock HTTP server that responds differently based on Host header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		switch host {
		case "admin.target.lab":
			w.WriteHeader(200)
			w.Write([]byte("Secret Admin Subdomain Portal"))
		case "api.target.lab":
			w.WriteHeader(200)
			w.Write([]byte("API gateway endpoints"))
		case "dev.target.lab":
			w.WriteHeader(403)
			w.Write([]byte("Forbidden internal dev area"))
		default:
			// Default wildcard catch-all page (typical in CTF/labs)
			w.WriteHeader(200)
			w.Write([]byte("Default catch-all landing page for target.lab"))
		}
	}))
	defer server.Close()

	// With Auto-calibration (-ac), default wildcard size/words are automatically detected and filtered
	cfg := &Config{
		URL:           server.URL,
		Wordlist:      []string{"admin", "api", "dev", "wildcard1", "wildcard2", "randomsub"},
		Headers:       map[string]string{"Host": "FUZZ.target.lab"},
		Threads:       4,
		Timeout:       2 * time.Second,
		AutoCalibrate: true,
		IsSubdomain:   true,
	}

	f := NewFuzzer(cfg)
	results, err := f.Run()
	if err != nil {
		t.Fatalf("subdomain fuzzer failed: %v", err)
	}

	foundMap := make(map[string]int)
	for _, res := range results {
		foundMap[res.Word] = res.Status
	}

	fmt.Printf("[+] Subdomain test found: %+v\n", foundMap)

	if foundMap["admin"] != 200 {
		t.Errorf("expected admin=200, got %d", foundMap["admin"])
	}
	if foundMap["api"] != 200 {
		t.Errorf("expected api=200, got %d", foundMap["api"])
	}
	if foundMap["dev"] != 403 {
		t.Errorf("expected dev=403, got %d", foundMap["dev"])
	}

	// Wildcards should have been filtered out by auto-calibration!
	if _, ok := foundMap["wildcard1"]; ok {
		t.Errorf("wildcard1 should have been filtered by auto-calibration")
	}
	if _, ok := foundMap["wildcard2"]; ok {
		t.Errorf("wildcard2 should have been filtered by auto-calibration")
	}
}
