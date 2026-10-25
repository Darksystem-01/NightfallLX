package portscan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CVEEntry holds vulnerability data.
type CVEEntry struct {
	ID       string  `json:"id"`
	CVSS     float64 `json:"cvss"`
	Severity string  `json:"severity"`
	Summary  string  `json:"summary"`
}

// CVECache caches NVD lookups in memory.
type CVECache struct {
	mu    sync.Mutex
	store map[string][]CVEEntry
}

func NewCVECache() *CVECache {
	return &CVECache{store: make(map[string][]CVEEntry)}
}

// Lookup queries NIST NVD CVE API v2.
func (c *CVECache) Lookup(keyword string) ([]CVEEntry, error) {
	key := strings.ToLower(strings.TrimSpace(keyword))
	if key == "" {
		return nil, nil
	}

	c.mu.Lock()
	if cached, ok := c.store[key]; ok {
		c.mu.Unlock()
		return cached, nil
	}
	c.mu.Unlock()

	apiURL := fmt.Sprintf(
		"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=5",
		url.QueryEscape(keyword),
	)

	httpClient := &http.Client{Timeout: 6 * time.Second}
	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvd api returned status: %d", resp.StatusCode)
	}

	var result struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CvssMetricV31 []struct {
						CvssData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CvssMetricV2 []struct {
						CvssData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
						BaseSeverity string `json:"baseSeverity"`
					} `json:"cvssMetricV2"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var entries []CVEEntry
	for _, v := range result.Vulnerabilities {
		entry := CVEEntry{ID: v.CVE.ID}
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				entry.Summary = d.Value
				if len(entry.Summary) > 120 {
					entry.Summary = entry.Summary[:120] + "..."
				}
				break
			}
		}
		if len(v.CVE.Metrics.CvssMetricV31) > 0 {
			entry.CVSS = v.CVE.Metrics.CvssMetricV31[0].CvssData.BaseScore
			entry.Severity = v.CVE.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
		} else if len(v.CVE.Metrics.CvssMetricV2) > 0 {
			entry.CVSS = v.CVE.Metrics.CvssMetricV2[0].CvssData.BaseScore
			entry.Severity = v.CVE.Metrics.CvssMetricV2[0].BaseSeverity
		}
		entries = append(entries, entry)
	}

	c.mu.Lock()
	c.store[key] = entries
	c.mu.Unlock()

	return entries, nil
}
