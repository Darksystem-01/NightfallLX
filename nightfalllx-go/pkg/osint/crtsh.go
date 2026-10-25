package osint

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

type crtShEntry struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

// FetchCertSubdomains queries crt.sh Certificate Transparency logs for passive subdomain discovery.
func FetchCertSubdomains(domain string, timeout time.Duration) ([]string, error) {
	if timeout <= 0 {
		timeout = 12 * time.Second
	}

	cleanDomain := strings.TrimSpace(strings.ToLower(domain))
	cleanDomain = strings.TrimPrefix(cleanDomain, "http://")
	cleanDomain = strings.TrimPrefix(cleanDomain, "https://")
	if idx := strings.Index(cleanDomain, "/"); idx != -1 {
		cleanDomain = cleanDomain[:idx]
	}

	reqURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", cleanDomain)

	client := &http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "NightfallLX-OSINT/2.0 (+https://github.com/Darksystem-01/NightfallLX)")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned non-200 status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var entries []crtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt.sh response unmarshal failed: %w", err)
	}

	seen := make(map[string]bool)
	var subdomains []string

	addHost := func(h string) {
		h = strings.TrimSpace(strings.ToLower(h))
		h = strings.TrimPrefix(h, "*.")
		h = strings.TrimPrefix(h, ".")
		if h == "" {
			return
		}
		// Must belong to target domain
		if (strings.HasSuffix(h, "."+cleanDomain) || h == cleanDomain) && !seen[h] {
			seen[h] = true
			subdomains = append(subdomains, h)
		}
	}

	for _, entry := range entries {
		addHost(entry.CommonName)
		// name_value may contain multiple names separated by newlines
		for _, line := range strings.Split(entry.NameValue, "\n") {
			addHost(line)
		}
	}

	sort.Strings(subdomains)
	return subdomains, nil
}
