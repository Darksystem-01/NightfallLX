package profile

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func TestProfileSaveLoadAndPathValidation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	path, err := Save("safe-profile_1", map[string][]string{
		"u":     {"https://target.lab"},
		"H":     {"Authorization: Bearer token", "X-Test: 1"},
		"depth": {"3"},
	})
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	want := filepath.Join(dir, ".nightfalllx", "profiles", "safe-profile_1.json")
	if path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("profile permissions = %o, want 0600", info.Mode().Perm())
	}

	loaded, err := Load("safe-profile_1")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.Name != "safe-profile_1" || loaded.Flags["depth"][0] != "3" || len(loaded.Flags["H"]) != 2 {
		t.Fatalf("unexpected profile: %+v", loaded)
	}

	for _, bad := range []string{"", "../escape", "with space", "x/y"} {
		if _, err := Path(bad); err == nil {
			t.Errorf("expected invalid name %q to be rejected", bad)
		}
	}
}

type stringList []string

func (s *stringList) String() string { return "" }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}
func (s *stringList) Values() []string { return []string(*s) }

func TestCaptureAndApplyFlags(t *testing.T) {
	var headers stringList
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	target := fs.String("u", "", "target")
	depth := fs.Int("depth", 1, "depth")
	threads := fs.Int("threads", 10, "threads")
	fs.Var(&headers, "H", "header")
	if err := fs.Parse([]string{"-u", "https://cli.lab", "-H", "X-A: 1", "-H", "X-B: 2"}); err != nil {
		t.Fatal(err)
	}

	captured := Capture(fs, "save-profile")
	if captured["u"][0] != "https://cli.lab" {
		t.Errorf("u not captured: %v", captured)
	}
	if len(captured["H"]) != 2 {
		t.Errorf("headers not captured: %v", captured)
	}
	if _, exists := captured["depth"]; exists {
		t.Errorf("default flag should not be captured: %v", captured)
	}

	already := map[string]bool{"u": true}
	profile := &Profile{Flags: map[string][]string{
		"u":       {"https://profile.lab"},
		"depth":   {"4"},
		"threads": {"25"},
	}}
	if err := Apply(fs, profile, already); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if *target != "https://cli.lab" {
		t.Errorf("explicit flag was overwritten: %q", *target)
	}
	if *depth != 4 || *threads != 25 {
		t.Errorf("profile values not applied: depth=%d threads=%d", *depth, *threads)
	}
}
