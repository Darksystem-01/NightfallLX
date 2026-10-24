//go:build !race

package plugins

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func newPluginTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><link href="/wp-content/themes/demo/style.css"></body></html>`))
	}))
}

func TestSamplePluginBuildLoadAndExecute(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Go plugin loading is not supported on Windows")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go binary not available")
	}
	if runtime.GOOS == "darwin" && os.Getenv("CGO_ENABLED") == "0" {
		t.Skip("Go plugins require cgo on macOS")
	}

	out := filepath.Join(t.TempDir(), "sample.so")
	cmd := exec.Command("go", "build", "-buildmode=plugin", "-o", out, "./examples/sample_plugin.go")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building sample plugin failed: %v\n%s", err, output)
	}

	loaded := LoadFile(out)
	if loaded.Error != nil {
		t.Fatalf("loading sample plugin failed: %v", loaded.Error)
	}
	if loaded.Name != "sample-wordpress-check" {
		t.Fatalf("unexpected plugin name %q", loaded.Name)
	}

	server := newPluginTestServer(t)
	client := server.Client()
	result, err := loaded.Plugin.Execute(server.URL, client)
	if err != nil {
		t.Fatalf("plugin execution failed: %v", err)
	}
	if !strings.Contains(result, "WordPress indicators found") {
		t.Errorf("unexpected plugin result: %q", result)
	}
}
