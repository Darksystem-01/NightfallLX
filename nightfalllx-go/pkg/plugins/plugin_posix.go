//go:build !windows

package plugins

import (
	"fmt"
	"path/filepath"
	"plugin"
	"strings"
)

// loadFilePlatform loads a Go shared-object (.so) on POSIX platforms.
func loadFilePlatform(path string) Loaded {
	result := Loaded{Path: path}

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
