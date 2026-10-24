// Package targetlist loads and normalizes targets for multi-target scans.
package targetlist

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var unsafeNameChars = regexp.MustCompile(`[^a-z0-9._-]+`)

// Load reads one target per line, ignoring blank lines, comments, and duplicates.
func Load(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open target list: %w", err)
	}
	defer file.Close()

	seen := make(map[string]struct{})
	var targets []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, exists := seen[line]; exists {
			continue
		}
		seen[line] = struct{}{}
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read target list: %w", err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("target list %q contains no targets", path)
	}
	return targets, nil
}

// Host extracts a hostname for per-target report names.
func Host(raw string) string {
	candidate := strings.TrimSpace(raw)
	if !strings.Contains(candidate, "://") {
		candidate = "http://" + candidate
	}
	parsed, err := url.Parse(candidate)
	if err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return strings.TrimSpace(raw)
}

// OutputBase returns a unique report base name for a target.
func OutputBase(base, target string) string {
	base = strings.TrimRight(strings.TrimSpace(base), `/\`)
	if base == "" {
		base = "lab_report"
	}
	return base + "-" + SafeName(Host(target))
}

// SafeName converts a host into a filesystem-friendly name.
func SafeName(value string) string {
	name := strings.ToLower(strings.TrimSpace(value))
	name = unsafeNameChars.ReplaceAllString(name, "_")
	name = strings.Trim(name, "._-")
	if name == "" {
		return "target"
	}
	return name
}
