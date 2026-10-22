package client

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
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

// Client wraps an optimized http.Client with connection reuse and proxy support.
type Client struct {
	httpClient *http.Client
	ProxyURL   string
	Timeout    time.Duration
	Insecure   bool
	Headers    map[string]string
	Cookie     string
	ScopeHosts []string
	ScopeOff   bool
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

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't auto-follow redirects, like ffuf/curl
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

// Request sends an HTTP request and measures its duration.
func (c *Client) Request(method, reqURL, data string, customHeaders map[string]string) (*Response, error) {
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

	// Set default User-Agent
	req.Header.Set("User-Agent", "NightfallLX/1.0 (+https://github.com/Darksystem-01/NightfallLX)")

	if c.Cookie != "" {
		req.Header.Set("Cookie", c.Cookie)
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
