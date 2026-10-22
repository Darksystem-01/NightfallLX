package intel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// NVDClient queries the NIST National Vulnerability Database REST API 2.0.
type NVDClient struct {
	BaseURL    string
	APIKey     string
	CacheDir   string
	HTTPClient *http.Client
	mu         sync.Mutex
	lastReq    time.Time
}

// NewNVDClient creates an NVDClient with rate limiting and local disk caching.
func NewNVDClient() *NVDClient {
	apiKey := os.Getenv("NVD_API_KEY")
	return &NVDClient{
		BaseURL:  "https://services.nvd.nist.gov/rest/json/cves/2.0",
		APIKey:   apiKey,
		CacheDir: ".intel_cache",
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// SetBaseURL overrides the API endpoint (useful for mock testing).
func (c *NVDClient) SetBaseURL(urlStr string) {
	c.BaseURL = urlStr
}

// waitRateLimit enforces the NVD API rate limits (5 req / 30s without key, 50 req / 30s with key).
func (c *NVDClient) waitRateLimit() {
	c.mu.Lock()
	defer c.mu.Unlock()

	delay := 6 * time.Second
	if c.APIKey != "" {
		delay = 650 * time.Millisecond
	}

	elapsed := time.Since(c.lastReq)
	if elapsed < delay {
		time.Sleep(delay - elapsed)
	}
	c.lastReq = time.Now()
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CVSSMetricV30 []struct {
					CVSSData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
				CVSSMetricV2 []struct {
					CVSSData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// Lookup queries NVD by keyword, utilizing cached entries when available.
func (c *NVDClient) Lookup(keyword string) ([]*IntelFinding, error) {
	validKeyword, err := ValidateQuery(keyword)
	if err != nil {
		return nil, err
	}

	// 1. Check local disk cache
	cached, errCache := c.readCache(validKeyword)
	if errCache == nil && cached != nil {
		return cached, nil
	}

	// 2. Enforce rate limit
	c.waitRateLimit()

	// 3. Make HTTP request
	reqURL := fmt.Sprintf("%s?keywordSearch=%s", c.BaseURL, url.QueryEscape(validKeyword))
	req, errReq := http.NewRequest("GET", reqURL, nil)
	if errReq != nil {
		return nil, errReq
	}

	req.Header.Set("User-Agent", "NightfallLX-Intel/2.0")
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}

	resp, errDo := c.HTTPClient.Do(req)
	if errDo != nil {
		return nil, fmt.Errorf("NVD request failed: %w", errDo)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned HTTP %d", resp.StatusCode)
	}

	bodyBytes, errRead := io.ReadAll(resp.Body)
	if errRead != nil {
		return nil, errRead
	}

	var nvdResp nvdResponse
	if err := json.Unmarshal(bodyBytes, &nvdResp); err != nil {
		return nil, fmt.Errorf("failed to parse NVD response: %w", err)
	}

	var findings []*IntelFinding
	for _, v := range nvdResp.Vulnerabilities {
		cveID := v.CVE.ID
		desc := ""
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}
		if desc == "" && len(v.CVE.Descriptions) > 0 {
			desc = v.CVE.Descriptions[0].Value
		}

		var cvss float64
		if len(v.CVE.Metrics.CVSSMetricV31) > 0 {
			cvss = v.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
		} else if len(v.CVE.Metrics.CVSSMetricV30) > 0 {
			cvss = v.CVE.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
		} else if len(v.CVE.Metrics.CVSSMetricV2) > 0 {
			cvss = v.CVE.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
		}

		findings = append(findings, &IntelFinding{
			Query:  validKeyword,
			Source: "nvd",
			Title:  desc,
			CVEs:   []string{cveID},
			CVSS:   cvss,
		})
	}

	// Write to cache
	_ = c.writeCache(validKeyword, findings)

	return findings, nil
}

func (c *NVDClient) cacheFilePath(query string) string {
	h := sha256.Sum256([]byte(query))
	filename := fmt.Sprintf("nvd_%s.json", hex.EncodeToString(h[:8]))
	return filepath.Join(c.CacheDir, filename)
}

func (c *NVDClient) readCache(query string) ([]*IntelFinding, error) {
	path := c.cacheFilePath(query)
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	// Expire cache after 24 hours
	if time.Since(fi.ModTime()) > 24*time.Hour {
		return nil, os.ErrNotExist
	}
	bytes, errRead := os.ReadFile(path)
	if errRead != nil {
		return nil, errRead
	}
	var findings []*IntelFinding
	if err := json.Unmarshal(bytes, &findings); err != nil {
		return nil, err
	}
	return findings, nil
}

func (c *NVDClient) writeCache(query string, findings []*IntelFinding) error {
	_ = os.MkdirAll(c.CacheDir, 0755)
	path := c.cacheFilePath(query)
	bytes, err := json.Marshal(findings)
	if err != nil {
		return err
	}
	return os.WriteFile(path, bytes, 0644)
}
