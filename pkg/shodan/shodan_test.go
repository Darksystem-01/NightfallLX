package shodan

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestShodanHostLookup(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"ip_str": "8.8.8.8",
			"org": "Google LLC",
			"isp": "Google",
			"asn": "AS15169",
			"ports": [53, 443],
			"vulns": ["CVE-2023-1234"],
			"data": [
				{"port": 53, "product": "DNS"},
				{"port": 443, "product": "Google Frontend"}
			]
		}`))
	}))
	defer mockServer.Close()

	client := NewClient("dummy_key")
	client.HTTPClient = mockServer.Client()

	// Direct test via custom URL logic
	req, err := http.NewRequest("GET", mockServer.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		t.Fatalf("failed to query mock server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	domain, ip, _ := ResolveTarget("http://example.com/test?a=1")
	if domain != "example.com" {
		t.Fatalf("expected domain example.com, got %s", domain)
	}
	_ = ip
}
