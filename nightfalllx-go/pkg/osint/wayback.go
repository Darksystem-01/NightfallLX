package osint

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

var sensitiveExtensions = []string{
	".sql", ".env", ".bak", ".backup", ".zip", ".tar.gz", ".tar",
	".config", ".conf", ".ini", ".yml", ".yaml", ".xml",
	".json", ".log", ".txt", ".pdf", ".old", ".inc",
}

var interestingKeywords = []string{
	"api", "admin", "login", "auth", "token", "key", "secret",
	"debug", "v1", "v2", "swagger", "graphql", "dashboard",
	"internal", "portal", "user", "payment",
}

// FetchWaybackURLs retrieves archived URLs from web.archive.org CDX API.
func FetchWaybackURLs(domain string, timeout time.Duration) ([]string, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	cleanDomain := strings.TrimSpace(strings.ToLower(domain))
	cleanDomain = strings.TrimPrefix(cleanDomain, "http://")
	cleanDomain = strings.TrimPrefix(cleanDomain, "https://")
	if idx := strings.Index(cleanDomain, "/"); idx != -1 {
		cleanDomain = cleanDomain[:idx]
	}

	reqURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&collapse=urlkey&fl=original&limit=150", cleanDomain)

	client := &http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "NightfallLX-OSINT/2.0 (+https://github.com/Darksystem-01/NightfallLX)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wayback CDX returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}

	if len(rows) <= 1 {
		return nil, nil // First row is header
	}

	seen := make(map[string]bool)
	var sensitiveURLs []string
	var standardURLs []string

	for i := 1; i < len(rows); i++ {
		if len(rows[i]) == 0 {
			continue
		}
		raw := strings.TrimSpace(rows[i][0])
		if raw == "" || seen[raw] {
			continue
		}
		seen[raw] = true

		u, err := url.Parse(raw)
		if err != nil {
			continue
		}

		path := strings.ToLower(u.Path)
		// Skip junk static assets
		if strings.HasSuffix(path, ".png") || strings.HasSuffix(path, ".jpg") ||
			strings.HasSuffix(path, ".jpeg") || strings.HasSuffix(path, ".gif") ||
			strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".svg") ||
			strings.HasSuffix(path, ".ico") || strings.HasSuffix(path, ".woff") ||
			strings.HasSuffix(path, ".woff2") || strings.HasSuffix(path, ".ttf") {
			continue
		}

		isSensitive := false
		for _, ext := range sensitiveExtensions {
			if strings.HasSuffix(path, ext) {
				isSensitive = true
				break
			}
		}
		if !isSensitive {
			for _, kw := range interestingKeywords {
				if strings.Contains(path, kw) || strings.Contains(strings.ToLower(u.RawQuery), kw) {
					isSensitive = true
					break
				}
			}
		}

		if isSensitive {
			sensitiveURLs = append(sensitiveURLs, raw)
		} else {
			standardURLs = append(standardURLs, raw)
		}
	}

	sort.Strings(sensitiveURLs)
	// Return sensitive candidates first, then other unique endpoints up to 40 max
	combined := append(sensitiveURLs, standardURLs...)
	if len(combined) > 40 {
		combined = combined[:40]
	}

	return combined, nil
}
