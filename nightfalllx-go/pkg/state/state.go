// Package state persists resumable scan progress.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"nightfalllx/pkg/intel"
	"nightfalllx/pkg/modules"
	"nightfalllx/pkg/version"
)

// ScanState is serialized to .nightfalllx/state.json after each completed
// module so an interrupted assessment can be resumed with --resume.
type ScanState struct {
	Version          string             `json:"version"`
	TargetURL        string             `json:"target_url"`
	Method           string             `json:"method"`
	ModuleList       string             `json:"module_list"`
	CompletedModules []string           `json:"completed_modules"`
	PendingModules   []string           `json:"pending_modules"`
	Findings         []*modules.Finding `json:"findings"`
	Intel            *intel.IntelReport `json:"intel,omitempty"`
	UpdatedAt        time.Time          `json:"updated_at"`
}

// DefaultPath returns the default resumable state path.
func DefaultPath() string {
	return filepath.Join(".nightfalllx", "state.json")
}

// Save atomically writes state with owner-only permissions.
func Save(path string, st *ScanState) error {
	if st == nil {
		return fmt.Errorf("state is nil")
	}
	if path == "" {
		path = DefaultPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	st.Version = version.Version
	st.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// Load reads a resumable state file.
func Load(path string) (*ScanState, error) {
	if path == "" {
		path = DefaultPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st ScanState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	st.Version = version.Version
	return &st, nil
}

// Remove deletes the state file after a successful scan.
func Remove(path string) error {
	if path == "" {
		path = DefaultPath()
	}
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// MarkCompleted records a module and removes it from the pending list.
func (s *ScanState) MarkCompleted(module string) {
	if s == nil || module == "" {
		return
	}
	for _, name := range s.CompletedModules {
		if name == module {
			return
		}
	}
	s.CompletedModules = append(s.CompletedModules, module)
	pending := s.PendingModules[:0]
	for _, name := range s.PendingModules {
		if name != module {
			pending = append(pending, name)
		}
	}
	s.PendingModules = pending
}

// IsCompleted reports whether a module has already finished.
func (s *ScanState) IsCompleted(module string) bool {
	if s == nil {
		return false
	}
	for _, name := range s.CompletedModules {
		if name == module {
			return true
		}
	}
	return false
}
