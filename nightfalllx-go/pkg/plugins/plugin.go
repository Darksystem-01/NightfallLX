// Package plugins loads optional NightfallLX extensions at runtime.
//
// The built-in loader uses Go's plugin package, which is supported on Linux,
// FreeBSD, and macOS. Go does not provide runtime .so/.dll loading on Windows;
// Windows users should build a platform-specific plugin host or loader.
package plugins

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"plugin"
	"runtime"
	"strings"
)

// Plugin is the contract implemented by a NightfallLX shared-object plugin.
// A plugin must export a package-level symbol named Plugin whose value
// implements this interface.
type Plugin interface {
	Name() string
	Execute(target string, client *http.Client) (string, error)
}

// Loaded describes one plugin file and any load error.
type Loaded struct {
	Path   string
	Name   string
	Plugin Plugin
	Error  error
}

// DefaultDir returns ~/.nightfalllx/plugins, or NIGHTFALLX_PLUGIN_DIR.
func DefaultDir() string {
	if dir := strings.TrimSpace(os.Getenv("NIGHTFALLX_PLUGIN_DIR")); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ".nightfalllx/plugins"
	}
	return filepath.Join(home, ".nightfalllx", "plugins")
}

// EnsureDir creates the plugin directory with owner-only permissions.
func EnsureDir(dir string) error {
	if strings.TrimSpace(dir) == "" {
		dir = DefaultDir()
	}
	return os.MkdirAll(dir, 0700)
}

// LoadAll loads every compatible plugin in dir. Load errors are reported per
// file so one broken plugin does not prevent the others from running.
func LoadAll(dir string) []Loaded {
	if strings.TrimSpace(dir) == "" {
		dir = DefaultDir()
	}
	pattern := "*.so"
	if runtime.GOOS == "windows" {
		pattern = "*.dll"
	}
	files, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return []Loaded{{Path: dir, Error: err}}
	}
	loaded := make([]Loaded, 0, len(files))
	for _, file := range files {
		loaded = append(loaded, LoadFile(file))
	}
	return loaded
}

// LoadFile opens one shared object and resolves the exported Plugin symbol.
func LoadFile(path string) Loaded {
	result := Loaded{Path: path}
	if runtime.GOOS == "windows" {
		result.Error = fmt.Errorf("Go's plugin package is not supported on Windows; build a Windows-specific .dll loader")
		return result
	}

	shared, err := plugin.Open(path)
	if err != nil {
		result.Error = fmt.Errorf("open plugin: %w", err)
		return result
	}
	symbol, err := shared.Lookup("Plugin")
	if err != nil {
		result.Error = fmt.Errorf("plugin does not export a 'Plugin' symbol: %w", err)
		return result
	}
	instance, ok := symbol.(Plugin)
	if !ok {
		result.Error = fmt.Errorf("exported 'Plugin' symbol does not implement the NightfallLX Plugin interface")
		return result
	}
	result.Plugin = instance
	result.Name = strings.TrimSpace(instance.Name())
	if result.Name == "" {
		result.Name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	return result
}
