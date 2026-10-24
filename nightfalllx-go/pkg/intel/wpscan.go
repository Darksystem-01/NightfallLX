package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"nightfalllx/pkg/version"
)

var (
	wpscanSlugRe    = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,120}$`)
	wpscanVersionRe = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,3}(?:[-a-zA-Z0-9._]*)?$`)
)

// WPScanVulnerability is a normalized vulnerability entry from the WPScan API.
type WPScanVulnerability struct {
	ID      string
	Title   string
	FixedIn string
	CVEs    []string
	CVSS    float64
	URL     string
	Type    string
}

// WPScanClient queries the WPScan vulnerability database for WordPress core,
// plugins, and themes. A token is required by the upstream API.
type WPScanClient struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// NewWPScanClient creates a WPScan API client.
func NewWPScanClient(token string) *WPScanClient {
	return &WPScanClient{
		BaseURL: "https://wpscan.com/api/v3",
		Token:   strings.TrimSpace(token),
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Enabled reports whether an API token is configured.
func (c *WPScanClient) Enabled() bool {
	return c != nil && strings.TrimSpace(c.Token) != ""
}

// LookupCore fetches vulnerabilities for a WordPress core version.
func (c *WPScanClient) LookupCore(ctx context.Context, version string) ([]*WPScanVulnerability, error) {
	version = strings.TrimSpace(version)
	if !wpscanVersionRe.MatchString(version) {
		return nil, fmt.Errorf("invalid WordPress version %q", version)
	}
	return c.lookup(ctx, "wordpresses", version, "")
}

// LookupPlugin fetches vulnerabilities for a plugin slug.
func (c *WPScanClient) LookupPlugin(ctx context.Context, slug string) ([]*WPScanVulnerability, error) {
	return c.lookup(ctx, "plugins", slug, "")
}

// LookupTheme fetches vulnerabilities for a theme slug.
func (c *WPScanClient) LookupTheme(ctx context.Context, slug string) ([]*WPScanVulnerability, error) {
	return c.lookup(ctx, "themes", slug, "")
}

type wpscanEntry struct {
	Vulnerabilities []struct {
		ID      string `json:"id"`
		Title   string `json:"title"`
		FixedIn string `json:"fixed_in"`
		Type    string `json:"vuln_type"`
		CVSS    struct {
			Score float64 `json:"score"`
		} `json:"cvss"`
		References struct {
			CVE []string `json:"cve"`
			URL []string `json:"url"`
		} `json:"references"`
	} `json:"vulnerabilities"`
}

func (c *WPScanClient) lookup(ctx context.Context, kind, name, _ string) ([]*WPScanVulnerability, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("WPScan API token is not configured")
	}
	name = strings.TrimSpace(name)
	if !wpscanSlugRe.MatchString(name) {
		return nil, fmt.Errorf("invalid WPScan %s identifier %q", kind, name)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	base := strings.TrimRight(c.BaseURL, "/")
	reqURL := base + "/" + kind + "/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Token "+c.Token)
	req.Header.Set("User-Agent", version.UserAgent)
	req.Header.Set("Accept", "application/json")

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("WPScan API returned HTTP %d", resp.StatusCode)
	}

	var payload map[string]wpscanEntry
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("failed to parse WPScan response: %w", err)
	}

	var findings []*WPScanVulnerability
	for _, entry := range payload {
		for _, v := range entry.Vulnerabilities {
			cves := normalizeWPScanCVEs(v.References.CVE)
			refURL := ""
			if len(v.References.URL) > 0 {
				refURL = v.References.URL[0]
			}
			findings = append(findings, &WPScanVulnerability{
				ID:      strings.TrimSpace(v.ID),
				Title:   strings.TrimSpace(v.Title),
				FixedIn: cleanWPScanVersion(v.FixedIn),
				CVEs:    cves,
				CVSS:    v.CVSS.Score,
				URL:     refURL,
				Type:    v.Type,
			})
		}
	}
	return findings, nil
}

func normalizeWPScanCVEs(raw []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		upper := strings.ToUpper(item)
		if !strings.HasPrefix(upper, "CVE-") {
			upper = "CVE-" + upper
		}
		if !seen[upper] {
			seen[upper] = true
			out = append(out, upper)
		}
	}
	return out
}

func cleanWPScanVersion(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return ""
	}
	return strings.Trim(fields[0], ".,;")
}
