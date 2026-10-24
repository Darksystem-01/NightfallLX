// Package profile stores reusable CLI flag configurations.
package profile

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var validNameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// Profile is a named collection of CLI flag values.
type Profile struct {
	Name    string              `json:"name"`
	Flags   map[string][]string `json:"flags"`
	SavedAt time.Time           `json:"saved_at"`
}

// DefaultDir returns ~/.nightfalllx/profiles.
func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return filepath.Join(".nightfalllx", "profiles")
	}
	return filepath.Join(home, ".nightfalllx", "profiles")
}

// Path validates a profile name and returns its JSON path.
func Path(name string) (string, error) {
	name = strings.TrimSpace(name)
	if !validNameRe.MatchString(name) {
		return "", fmt.Errorf("invalid profile name %q: use 1-64 alphanumeric, dot, underscore, or hyphen characters", name)
	}
	return filepath.Join(DefaultDir(), name+".json"), nil
}

// Save writes a profile with owner-only permissions.
func Save(name string, flags map[string][]string) (string, error) {
	path, err := Path(name)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}
	p := Profile{
		Name:    strings.TrimSpace(name),
		Flags:   flags,
		SavedAt: time.Now().UTC(),
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".profile-*")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return "", err
	}
	return path, nil
}

// Load reads a profile by name.
func Load(name string) (*Profile, error) {
	path, err := Path(name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if p.Flags == nil {
		p.Flags = make(map[string][]string)
	}
	return &p, nil
}

// Capture returns explicitly set flags, excluding profile-control flags.
func Capture(fs *flag.FlagSet, exclude ...string) map[string][]string {
	excluded := make(map[string]bool)
	for _, name := range exclude {
		excluded[name] = true
	}
	out := make(map[string][]string)
	fs.Visit(func(f *flag.Flag) {
		if excluded[f.Name] {
			return
		}
		if values, ok := f.Value.(interface{ Values() []string }); ok {
			out[f.Name] = append([]string(nil), values.Values()...)
			return
		}
		out[f.Name] = []string{f.Value.String()}
	})
	return out
}

// Apply sets profile flags that were not explicitly supplied on the CLI.
func Apply(fs *flag.FlagSet, p *Profile, alreadySet map[string]bool) error {
	if p == nil {
		return nil
	}
	for name, values := range p.Flags {
		if alreadySet[name] || fs.Lookup(name) == nil {
			continue
		}
		for _, value := range values {
			if err := fs.Set(name, value); err != nil {
				return fmt.Errorf("apply profile flag %s=%q: %w", name, value, err)
			}
		}
	}
	return nil
}
