package client

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Response wraps HTTP response details with pre-computed statistics.
type Response struct {
	URL        string
	StatusCode int
	Body       string
	Bytes      int
	Words      int
	Lines      int
	Duration   time.Duration
	Headers    http.Header
	Location   string
}

// RateLimiter controls maximum requests per second.
type RateLimiter struct {
	interval time.Duration
	mu       sync.Mutex
	lastReq  time.Time
}

func NewRateLimiter(rate int) *RateLimiter {
	if rate <= 0 {
		return nil
	}
	return &RateLimiter{
		interval: time.Second / time.Duration(rate),
	}
}

func (r *RateLimiter) Wait() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(r.lastReq)
	if elapsed < r.interval {
		time.Sleep(r.interval - elapsed)
	}
	r.lastReq = time.Now()
}

// Client wraps an optimized http.Client with connection reuse, cookie jar, proxy, and auth management.
type Client struct {
	httpClient *http.Client
	ProxyURL   string
	Timeout    time.Duration
	Insecure   bool
	Headers    map[string]string
	Cookie     string
	ScopeHosts []string
	ScopeOff   bool
	Limiter    *RateLimiter

	// Authenticated Scanning
	LoginURL           string
	LoginData          string
	LoginUser          string
	LoginPass          string
	LoginSuccessRegex  *regexp.Regexp
	LoginSuccessStatus int
	LogoutRegex        *regexp.Regexp
	BearerToken        string
	RefreshURL         string
	RefreshJSONPath    string

	reloginMu   sync.Mutex
	lastRelogin time.Time
}

// NewClient creates a new high-performance HTTP client.
func NewClient(proxyURL string, timeout time.Duration, insecure bool, cookie string, headers map[string]string) *Client {
	transport := &http.Transport{
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 200,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
	}

	if proxyURL != "" {
		if pURL, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(pURL)
		}
	}

	jar, _ := cookiejar.New(nil)

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Client{
		httpClient: httpClient,
		ProxyURL:   proxyURL,
		Timeout:    timeout,
		Insecure:   insecure,
		Headers:    headers,
		Cookie:     cookie,
		ScopeOff:   false,
	}
}

// SetRateLimit sets the rate limit in requests per second.
func (c *Client) SetRateLimit(reqPerSec int) {
	c.Limiter = NewRateLimiter(reqPerSec)
}

// IsInScope checks whether a host is permitted by the scope configuration.
func (c *Client) IsInScope(host string) bool {
	if c.ScopeOff || len(c.ScopeHosts) == 0 {
		return true
	}
	cleanHost := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		cleanHost = h
	}
	cleanHost = strings.ToLower(cleanHost)

	for _, s := range c.ScopeHosts {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if s == cleanHost {
			return true
		}
		if strings.HasPrefix(s, "*.") && strings.HasSuffix(cleanHost, s[1:]) {
			return true
		}
		if strings.HasPrefix(s, ".") && strings.HasSuffix(cleanHost, s) {
			return true
		}
	}
	return false
}

// PerformLogin executes the configured login sequence and saves session cookies in the jar.
func (c *Client) PerformLogin() error {
	if c.LoginURL == "" {
		return fmt.Errorf("login URL not configured")
	}

	bodyData := c.LoginData
	bodyData = strings.ReplaceAll(bodyData, "{{user}}", c.LoginUser)
	bodyData = strings.ReplaceAll(bodyData, "{{pass}}", c.LoginPass)

	reqMethod := "POST"
	if bodyData == "" {
		reqMethod = "GET"
	}

	headers := map[string]string{}
	if strings.HasPrefix(strings.TrimSpace(bodyData), "{") {
		headers["Content-Type"] = "application/json"
	} else if bodyData != "" {
		headers["Content-Type"] = "application/x-www-form-urlencoded"
	}

	resp, err := c.rawRequest(reqMethod, c.LoginURL, bodyData, headers)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}

	// Verify login success
	if c.LoginSuccessStatus != 0 && resp.StatusCode != c.LoginSuccessStatus {
		return fmt.Errorf("login failed: expected status %d, got %d", c.LoginSuccessStatus, resp.StatusCode)
	}
	if c.LoginSuccessRegex != nil && !c.LoginSuccessRegex.MatchString(resp.Body) {
		return fmt.Errorf("login failed: success regex did not match response")
	}

	return nil
}

// RefreshToken queries the refresh URL and extracts a new bearer token using JSON path.
func (c *Client) RefreshToken() error {
	if c.RefreshURL == "" {
		return nil
	}
	resp, err := c.rawRequest("POST", c.RefreshURL, "", nil)
	if err != nil {
		return err
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(resp.Body), &data); err != nil {
		return err
	}

	pathParts := strings.Split(c.RefreshJSONPath, ".")
	var cur interface{} = data
	for _, p := range pathParts {
		if m, ok := cur.(map[string]interface{}); ok {
			cur = m[p]
		}
	}
	if str, ok := cur.(string); ok && str != "" {
		c.BearerToken = str
		return nil
	}
	return fmt.Errorf("failed to extract token from path %s", c.RefreshJSONPath)
}

// Request sends an HTTP request, checks scope, applies rate limiting, and handles auto-relogin.
func (c *Client) Request(method, reqURL, data string, customHeaders map[string]string) (*Response, error) {
	if c.Limiter != nil {
		c.Limiter.Wait()
	}

	resp, err := c.rawRequest(method, reqURL, data, customHeaders)
	if err != nil {
		return nil, err
	}

	// Check if re-login is required due to session expiry
	needsRelogin := false
	if c.LoginURL != "" {
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			needsRelogin = true
		} else if c.LogoutRegex != nil && c.LogoutRegex.MatchString(resp.Body) {
			needsRelogin = true
		}
	}

	if needsRelogin {
		c.reloginMu.Lock()
		if time.Since(c.lastRelogin) > 2*time.Second {
			_ = c.PerformLogin()
			c.lastRelogin = time.Now()
		}
		c.reloginMu.Unlock()

		// Retry request once with renewed session
		return c.rawRequest(method, reqURL, data, customHeaders)
	}

	return resp, nil
}

func (c *Client) rawRequest(method, reqURL, data string, customHeaders map[string]string) (*Response, error) {
	u, parseErr := url.Parse(reqURL)
	if parseErr == nil && u.Host != "" {
		if !c.IsInScope(u.Host) {
			return nil, fmt.Errorf("scope guard refusal: host '%s' is not in authorized scope (use -scope or -scope-off)", u.Host)
		}
	}

	var bodyReader io.Reader
	if data != "" {
		bodyReader = strings.NewReader(data)
	}

	req, err := http.NewRequest(method, reqURL, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "NightfallLX/2.0 (+https://github.com/Darksystem-01/NightfallLX)")

	if c.Cookie != "" {
		req.Header.Set("Cookie", c.Cookie)
	}

	if c.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}

	for k, v := range c.Headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	for k, v := range customHeaders {
		if strings.EqualFold(k, "Host") {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}

	start := time.Now()
	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	bodyStr := string(bodyBytes)
	words := len(strings.Fields(bodyStr))
	lines := strings.Count(bodyStr, "\n")

	return &Response{
		URL:        reqURL,
		StatusCode: resp.StatusCode,
		Body:       bodyStr,
		Bytes:      len(bodyBytes),
		Words:      words,
		Lines:      lines,
		Duration:   duration,
		Headers:    resp.Header,
		Location:   resp.Header.Get("Location"),
	}, nil
}
