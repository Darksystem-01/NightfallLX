package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"nightfalllx/pkg/version"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		left, right string
		want        int
	}{
		{"v2.1.0", "2.0.0", 1},
		{"2.0.0", "2.1.0", -1},
		{"2.1.0", "2.1", 0},
		{"2.1.0", "2.1.0", 0},
		{"v3.0.0-rc1", "2.9.9", 1},
		{"2.0.10", "2.0.9", 1},
	}
	for _, tc := range cases {
		if got := CompareVersions(tc.left, tc.right); got != tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.left, tc.right, got, tc.want)
		}
	}
}

func TestClientCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/Darksystem-01/NightfallLX/releases/latest" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("User-Agent") != version.UserAgent {
			t.Errorf("unexpected user agent: %q", r.Header.Get("User-Agent"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v99.0.0","html_url":"https://example.test/release"}`))
	}))
	defer server.Close()

	client := NewClient()
	client.BaseURL = server.URL
	result, err := client.Check(context.Background())
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if result.LatestVersion != "v99.0.0" || !result.UpdateAvailable || result.URL != "https://example.test/release" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestClientCheckHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusForbidden)
	}))
	defer server.Close()

	client := NewClient()
	client.BaseURL = server.URL
	if _, err := client.Check(context.Background()); err == nil {
		t.Fatal("expected HTTP error")
	}
}
