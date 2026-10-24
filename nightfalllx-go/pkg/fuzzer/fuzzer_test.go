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

func TestFuzzerExtensions(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.php":
			w.WriteHeader(200)
			w.Write([]byte("php page"))
		case "/admin.html":
			w.WriteHeader(200)
			w.Write([]byte("admin html"))
		default:
			w.WriteHeader(404)
			w.Write([]byte("not found"))
		}
	}))
	defer ts.Close()

	cfg := &Config{
		URL:           ts.URL + "/",
		Wordlist:      []string{"index", "admin"},
		Extensions:    []string{"php", ".html"},
		Threads:       2,
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

	if found["index.php"] != 200 {
		t.Errorf("expected index.php=200, got %d", found["index.php"])
	}
	if found["admin.html"] != 200 {
		t.Errorf("expected admin.html=200, got %d", found["admin.html"])
	}
}
