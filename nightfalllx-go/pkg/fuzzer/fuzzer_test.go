package fuzzer

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFuzzer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(200)
			w.Write([]byte("admin panel secret"))
		case "/login":
			w.WriteHeader(200)
			w.Write([]byte("login page"))
		case "/redirect":
			w.Header().Set("Location", "/new-path")
			w.WriteHeader(301)
		default:
			w.WriteHeader(404)
			w.Write([]byte("not found"))
		}
	}))
	defer ts.Close()

	cfg := &Config{
		URL:           ts.URL + "/FUZZ",
		Wordlist:      []string{"admin", "login", "nonexistent1", "redirect", "nonexistent2"},
		Threads:       5,
		Timeout:       2 * time.Second,
		AutoCalibrate: false,
	}

	f := NewFuzzer(cfg)
	results, err := f.Run()
	if err != nil {
		t.Fatalf("fuzzer error: %v", err)
	}

	found := make(map[string]int)
	for _, r := range results {
		found[r.Word] = r.Status
	}

	if found["admin"] != 200 {
		t.Fatalf("expected admin=200, got %d", found["admin"])
	}
	if found["login"] != 200 {
		t.Fatalf("expected login=200, got %d", found["login"])
	}
	if found["redirect"] != 301 {
		t.Fatalf("expected redirect=301, got %d", found["redirect"])
	}
	if _, ok := found["nonexistent1"]; ok {
		t.Fatalf("expected nonexistent1 to be filtered")
	}
}

func TestFuzzerRegexFilteringAndAutoRegex(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200) // All return 200, but different body
		switch r.URL.Path {
		case "/secret-portal":
			w.Write([]byte("Access Granted: Super Admin Panel"))
		case "/fake-error":
			w.Write([]byte("Error: Page not found in index"))
		default:
			w.Write([]byte("Standard page does not exist"))
		}
	}))
	defer ts.Close()

	// Test 1: Match Regex
	cfgMR := &Config{
		URL:           ts.URL + "/FUZZ",
		Wordlist:      []string{"secret-portal", "fake-error", "other"},
		Threads:       2,
		Timeout:       2 * time.Second,
		AutoCalibrate: false,
		FilterCodes:   make(map[int]bool),
		MatchRegexStr: `(?i)Super\s+Admin`,
	}
	fMR := NewFuzzer(cfgMR)
	resMR, err := fMR.Run()
	if err != nil {
		t.Fatalf("MR error: %v", err)
	}
	if len(resMR) != 1 || resMR[0].Word != "secret-portal" {
		t.Fatalf("Expected only secret-portal matched by regex, got %d hits", len(resMR))
	}

	// Test 2: Auto-Regex
	cfgAuto := &Config{
		URL:           ts.URL + "/FUZZ",
		Wordlist:      []string{"secret-portal", "fake-error"},
		Threads:       2,
		Timeout:       2 * time.Second,
		AutoCalibrate: true,
		AutoRegex:     true,
		FilterCodes:   make(map[int]bool),
	}
	fAuto := NewFuzzer(cfgAuto)
	resAuto, err := fAuto.Run()
	if err != nil {
		t.Fatalf("AutoRegex error: %v", err)
	}
	if len(resAuto) != 1 || resAuto[0].Word != "secret-portal" {
		t.Fatalf("Expected AutoRegex to filter 'fake-error' and retain 'secret-portal', got %d hits", len(resAuto))
	}
}
