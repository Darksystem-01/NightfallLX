package plugins

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAllEmptyDirectory(t *testing.T) {
	got := LoadAll(t.TempDir())
	if len(got) != 0 {
		t.Fatalf("expected no plugins, got %+v", got)
	}
}

func TestLoadFileRejectsNonPlugin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.so")
	if err := os.WriteFile(path, []byte("not a shared object"), 0600); err != nil {
		t.Fatal(err)
	}
	got := LoadFile(path)
	if got.Error == nil {
		t.Fatal("expected an error for an invalid shared object")
	}
}

func TestDefaultDirEnvironmentOverride(t *testing.T) {
	want := filepath.Join(t.TempDir(), "custom-plugins")
	t.Setenv("NIGHTFALLX_PLUGIN_DIR", want)
	if got := DefaultDir(); got != want {
		t.Fatalf("DefaultDir() = %q, want %q", got, want)
	}
}
