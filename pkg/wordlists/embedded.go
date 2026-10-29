package wordlists

import (
	_ "embed"
	"os"
	"strings"
	"sync"
)

//go:embed embedded/ssrf.txt
var embeddedSSRF string

//go:embed embedded/sqli.txt
var embeddedSQLi string

//go:embed embedded/ssti.txt
var embeddedSSTI string

//go:embed embedded/xxe.txt
var embeddedXXE string

//go:embed embedded/xss.txt
var embeddedXSS string

//go:embed embedded/parameters.txt
var embeddedParameters string

//go:embed embedded/lfi.txt
var embeddedLFI string

//go:embed embedded/cmdi.txt
var embeddedCMDi string

//go:embed embedded/directories.txt
var embeddedDirectories string

//go:embed embedded/subdomains.txt
var embeddedSubdomains string

var (
	cacheMu sync.RWMutex
	cache   = make(map[string][]string)
)

func splitNonEmptyLines(raw string) []string {
	var res []string
	for _, l := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(l)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			res = append(res, trimmed)
		}
	}
	return res
}

func readLinesFromFile(filePath string) ([]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return splitNonEmptyLines(string(data)), nil
}

// GetWordlist retrieves the best available wordlist for the given category.
// Priority:
// 1. Explicit customPath (if provided and exists)
// 2. Standard filesystem paths (/home/cyborg/Web-Attacks/...)
// 3. Built-in embedded wordlists (compiled into the binary)
func GetWordlist(category string, customPath string) []string {
	if customPath != "" {
		if lines, err := readLinesFromFile(customPath); err == nil && len(lines) > 0 {
			return lines
		}
	}

	normCat := strings.ToLower(strings.TrimSpace(category))
	cacheMu.RLock()
	if cached, ok := cache[normCat]; ok && len(cached) > 0 {
		cacheMu.RUnlock()
		return cached
	}
	cacheMu.RUnlock()

	var result []string
	switch normCat {
	case "ssrf":
		result = splitNonEmptyLines(embeddedSSRF)
	case "sqli":
		result = splitNonEmptyLines(embeddedSQLi)
	case "ssti":
		result = splitNonEmptyLines(embeddedSSTI)
	case "xxe":
		result = splitNonEmptyLines(embeddedXXE)
	case "xss":
		result = splitNonEmptyLines(embeddedXSS)
	case "parameters", "params":
		result = splitNonEmptyLines(embeddedParameters)
	case "lfi":
		result = splitNonEmptyLines(embeddedLFI)
	case "cmdi":
		result = splitNonEmptyLines(embeddedCMDi)
	case "directories", "dirs":
		result = splitNonEmptyLines(embeddedDirectories)
	case "subdomains", "subs":
		result = splitNonEmptyLines(embeddedSubdomains)
	}

	cacheMu.Lock()
	cache[normCat] = result
	cacheMu.Unlock()
	return result
}
