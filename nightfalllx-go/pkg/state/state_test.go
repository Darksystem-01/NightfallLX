package state

import (
	"os"
	"path/filepath"
	"testing"

	"nightfalllx/pkg/intel"
	"nightfalllx/pkg/modules"
	"nightfalllx/pkg/version"
)

func TestStateSaveLoadRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".nightfalllx", "state.json")
	st := &ScanState{
		TargetURL:        "https://target.lab",
		Method:           "GET",
		ModuleList:       "xss,sqli",
		CompletedModules: []string{"xss"},
		PendingModules:   []string{"sqli"},
		Findings: []*modules.Finding{
			{Module: "xss", Title: "Confirmed XSS", Severity: modules.SeverityHigh, URL: "https://target.lab/?q=1"},
		},
		Intel: &intel.IntelReport{Target: "https://target.lab"},
	}
	if err := Save(path, st); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("state file permissions = %o, want 0600", info.Mode().Perm())
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.TargetURL != st.TargetURL || loaded.Method != st.Method || loaded.ModuleList != st.ModuleList {
		t.Fatalf("state mismatch: %+v", loaded)
	}
	if loaded.Version != version.Version {
		t.Errorf("state version = %q, want %q", loaded.Version, version.Version)
	}
	if len(loaded.Findings) != 1 || loaded.Findings[0].Title != "Confirmed XSS" {
		t.Errorf("findings not restored: %+v", loaded.Findings)
	}
	if loaded.Intel == nil || loaded.Intel.Target != st.TargetURL {
		t.Errorf("intel not restored: %+v", loaded.Intel)
	}

	loaded.MarkCompleted("sqli")
	if !loaded.IsCompleted("sqli") {
		t.Error("expected sqli to be completed")
	}
	if len(loaded.PendingModules) != 0 {
		t.Errorf("expected no pending modules, got %v", loaded.PendingModules)
	}
	loaded.MarkCompleted("sqli")
	if len(loaded.CompletedModules) != 2 {
		t.Errorf("duplicate completion recorded: %v", loaded.CompletedModules)
	}

	if err := Remove(path); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("state file still exists: %v", err)
	}
	if err := Remove(path); err != nil {
		t.Errorf("Remove should ignore missing files: %v", err)
	}
}

func TestStateRejectsNil(t *testing.T) {
	if err := Save(filepath.Join(t.TempDir(), "state.json"), nil); err == nil {
		t.Fatal("expected nil state to be rejected")
	}
}
