package targetlist

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	content := `
# lab targets
http://one.lab
   https://two.lab:8443/path

http://one.lab
# http://ignored.lab
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	want := []string{"http://one.lab", "https://two.lab:8443/path"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestLoadEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte("# only comments\n\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an empty target list")
	}
}

func TestHostAndOutputBase(t *testing.T) {
	tests := []struct {
		target string
		want   string
	}{
		{"http://Example.com:8080/path?q=1", "reports/scan-example.com_8080"},
		{"target.lab/app", "reports/scan-target.lab"},
		{"https://[2001:db8::1]:8443/", "reports/scan-2001_db8_1_8443"},
	}
	for _, test := range tests {
		if got := OutputBase("reports/scan", test.target); got != test.want {
			t.Errorf("OutputBase(%q) = %q, want %q", test.target, got, test.want)
		}
	}
}

func TestSafeName(t *testing.T) {
	if got := SafeName("  "); got != "target" {
		t.Fatalf("got %q", got)
	}
	if got := SafeName("A B:C/D"); got != "a_b_c_d" {
		t.Fatalf("got %q", got)
	}
}
