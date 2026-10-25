package detector

import (
	"net/http"
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"testing"
	"time"
)

func TestTechDetector(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/8.1.2")
		w.Header().Set("Set-Cookie", "laravel_session=abcd1234efgh; path=/")
		w.WriteHeader(200)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><title>Test App</title></head>
			<body>
				<div data-v-12345 class="container">
					<h1>Welcome to Laravel</h1>
				</div>
				<script src="/js/vue.global.js"></script>
			</body>
			</html>
		`))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	det := NewTechDetector()
	report, err := det.Detect(ts.URL, c)
	if err != nil {
		t.Fatalf("detection failed: %v", err)
	}

	foundTechs := make(map[string]string)
	for _, tech := range report.Technologies {
		foundTechs[tech.Name] = tech.Version
	}

	// Verify PHP exact version
	if v, ok := foundTechs["PHP"]; !ok || v != "8.1.2" {
		t.Errorf("expected PHP 8.1.2, got %v", v)
	}

	// Verify Apache version
	if v, ok := foundTechs["Apache HTTP Server"]; !ok || v != "2.4.41" {
		t.Errorf("expected Apache 2.4.41, got %v", v)
	}

	// Verify OS
	if _, ok := foundTechs["Ubuntu Linux"]; !ok {
		t.Errorf("expected Ubuntu Linux detection")
	}

	// Verify Framework & Template Engine
	if _, ok := foundTechs["Laravel"]; !ok {
		t.Errorf("expected Laravel framework detection")
	}
	if _, ok := foundTechs["Blade"]; !ok {
		t.Errorf("expected Blade template engine detection")
	}

	// Verify Frontend
	if _, ok := foundTechs["Vue.js"]; !ok {
		t.Errorf("expected Vue.js detection")
	}
}
