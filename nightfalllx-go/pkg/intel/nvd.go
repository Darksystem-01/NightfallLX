package intel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var nvdCVEIDRe = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

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
	_ = c.waitRateLimitContext(context.Background())
}

func (c *NVDClient) waitRateLimitContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	delay := 6 * time.Second
	if c.APIKey != "" {
		delay = 650 * time.Millisecond
	}

	elapsed := time.Since(c.lastReq)
	if elapsed < delay {
		timer := time.NewTimer(delay - elapsed)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	c.lastReq = time.Now()
	return nil
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
	return c.LookupContext(context.Background(), keyword)
}

// LookupContext queries NVD by keyword with caller-controlled cancellation.
func (c *NVDClient) LookupContext(ctx context.Context, keyword string) ([]*IntelFinding, error) {
	validKeyword, err := ValidateQuery(keyword)
	if err != nil {
		return nil, err
	}
	params := url.Values{}
	params.Set("keywordSearch", validKeyword)
	return c.lookup(ctx, "keyword:"+validKeyword, params)
}

// LookupCVE fetches the CVSS score and English description for one CVE.
func (c *NVDClient) LookupCVE(ctx context.Context, cveID string) (*IntelFinding, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if !nvdCVEIDRe.MatchString(cveID) {
		return nil, fmt.Errorf("invalid CVE identifier %q", cveID)
	}
	params := url.Values{}
	params.Set("cveId", cveID)
	findings, err := c.lookup(ctx, "cve:"+cveID, params)
	if err != nil {
		return nil, err
	}
	for _, finding := range findings {
		for _, candidate := range finding.CVEs {
			if strings.EqualFold(candidate, cveID) {
				return finding, nil
			}
		}
	}
	return nil, nil
}

func (c *NVDClient) lookup(ctx context.Context, cacheKey string, params url.Values) ([]*IntelFinding, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 1. Check local disk cache
	cached, errCache := c.readCache(cacheKey)
	if errCache == nil && cached != nil {
		return cached, nil
	}

	// 2. Enforce rate limit
	if err := c.waitRateLimitContext(ctx); err != nil {
		return nil, err
	}

	// 3. Make HTTP request
	reqURL := c.BaseURL
	separator := "?"
	if strings.Contains(reqURL, "?") {
		separator = "&"
	}
	reqURL += separator + params.Encode()
	req, errReq := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if errReq != nil {
		return nil, errReq
	}

	req.Header.Set("User-Agent", "NightfallLX-Intel/2.1")
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	resp, errDo := httpClient.Do(req)
	if errDo != nil {
		return nil, fmt.Errorf("NVD request failed: %w", errDo)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned HTTP %d", resp.StatusCode)
	}

	bodyBytes, errRead := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if errRead != nil {
		return nil, errRead
	}

	var nvdResp nvdResponse
	if err := json.Unmarshal(bodyBytes, &nvdResp); err != nil {
		return nil, fmt.Errorf("failed to parse NVD response: %w", err)
	}

	findings := nvdFindings(&nvdResp, params.Get("keywordSearch"))
	_ = c.writeCache(cacheKey, findings)
	return findings, nil
}

func nvdFindings(resp *nvdResponse, query string) []*IntelFinding {
	var findings []*IntelFinding
	for _, v := range resp.Vulnerabilities {
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
			Query:  query,
			Source: "nvd",
			Title:  desc,
			CVEs:   []string{cveID},
			CVSS:   cvss,
		})
	}
	return findings
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
