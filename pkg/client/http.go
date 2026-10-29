package client

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
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
	Proto      string // e.g. "HTTP/1.1", "HTTP/2.0"
}

// Client wraps an optimized http.Client with connection reuse, proxy support,
// rate limiting, automatic smart retry/backoff, and raw TCP/TLS socket capabilities.
type Client struct {
	httpClient  *http.Client
	ProxyURL    string
	Timeout     time.Duration
	Insecure    bool
	Headers     map[string]string
	Cookie      string
	ScopeHosts  []string
	ScopeOff    bool
	RateLimiter *RateLimiter
	MaxRetries  int
	RetryDelay  time.Duration
	// HeaderTampering injects WAF bypass headers on every request.
	HeaderTampering bool
	// ChunkedEncoding sends request bodies with Transfer-Encoding: chunked.
	ChunkedEncoding bool
}

// NewClient creates a new high-performance HTTP client.
func NewClient(proxyURL string, timeout time.Duration, insecure bool, cookie string, headers map[string]string) *Client {
	transport := &http.Transport{
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 200,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
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
		RetryDelay: 500 * time.Millisecond,
	}
}

// SetRateLimit sets the maximum requests per second.
func (c *Client) SetRateLimit(rps int) *Client {
	if c.RateLimiter != nil {
		c.RateLimiter.Stop()
	}
	c.RateLimiter = NewRateLimiter(rps)
	return c
}

// SetRetry configures the client to retry requests on 429/503 status or dropped connections.
func (c *Client) SetRetry(maxRetries int, delay time.Duration) *Client {
	c.MaxRetries = maxRetries
	if delay > 0 {
		c.RetryDelay = delay
	}
	return c
}

// SetHTTP2 toggles HTTP/2 support on the underlying transport.
func (c *Client) SetHTTP2(enabled bool) *Client {
	if tr, ok := c.httpClient.Transport.(*http.Transport); ok {
		tr.ForceAttemptHTTP2 = enabled
		if !enabled {
			tr.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)
		} else {
			tr.TLSNextProto = nil
		}
	}
	return c
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

func (c *Client) calculateBackoff(attempt int, retryAfterHeader string) time.Duration {
	if retryAfterHeader != "" {
		if secs, err := strconv.Atoi(strings.TrimSpace(retryAfterHeader)); err == nil && secs > 0 && secs <= 60 {
			return time.Duration(secs) * time.Second
		}
	}
	base := c.RetryDelay
	if base <= 0 {
		base = 500 * time.Millisecond
	}
	multiplier := 1 << uint(attempt-1)
	delay := base * time.Duration(multiplier)
	if delay > 10*time.Second {
		delay = 10 * time.Second
	}
	return delay
}

// Request sends an HTTP request with automatic rate limiting and exponential backoff retry.
func (c *Client) Request(method, reqURL, data string, customHeaders map[string]string) (*Response, error) {
	u, parseErr := url.Parse(reqURL)
	if parseErr == nil && u.Host != "" {
		if !c.IsInScope(u.Host) {
			return nil, fmt.Errorf("scope guard refusal: host '%s' is not in authorized scope (use -scope or -scope-off)", u.Host)
		}
	}

	maxAttempts := 1 + c.MaxRetries
	var resp *Response
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if c.RateLimiter != nil {
			c.RateLimiter.Wait()
		}

		resp, lastErr = c.doSingleRequest(method, reqURL, data, customHeaders)
		if lastErr == nil && resp != nil {
			if (resp.StatusCode == 429 || resp.StatusCode == 503) && attempt < maxAttempts {
				retryAfter := resp.Headers.Get("Retry-After")
				backoff := c.calculateBackoff(attempt, retryAfter)
				time.Sleep(backoff)
				continue
			}
			return resp, nil
		}

		if attempt < maxAttempts {
			backoff := c.calculateBackoff(attempt, "")
			time.Sleep(backoff)
			continue
		}
	}

	return resp, lastErr
}

func (c *Client) doSingleRequest(method, reqURL, data string, customHeaders map[string]string) (*Response, error) {
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

	// Ensure POST/PUT request bodies have appropriate Content-Type header so web frameworks parse fields
	if req.Header.Get("Content-Type") == "" && data != "" {
		trimmed := strings.TrimSpace(data)
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			req.Header.Set("Content-Type", "application/json")
		} else {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	if c.HeaderTampering {
		ApplyBypassHeaders(req)
	}
	if c.ChunkedEncoding && data != "" {
		ApplyChunkedEncoding(req)
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
		Proto:      resp.Proto,
	}, nil
}

// RawRequest sends verbatim bytes over a direct TCP/TLS socket, bypassing Go's HTTP header normalization.
func (c *Client) RawRequest(targetURL string, rawPayload []byte) (*Response, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	if !c.IsInScope(u.Host) {
		return nil, fmt.Errorf("scope guard refusal: host '%s' is not in authorized scope", u.Host)
	}

	if c.RateLimiter != nil {
		c.RateLimiter.Wait()
	}

	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}

	targetAddr := net.JoinHostPort(u.Hostname(), port)
	start := time.Now()

	var conn net.Conn
	if strings.EqualFold(u.Scheme, "https") {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: c.Insecure,
			ServerName:         u.Hostname(),
		}
		dialer := &net.Dialer{Timeout: c.Timeout}
		conn, err = tls.DialWithDialer(dialer, "tcp", targetAddr, tlsConfig)
	} else {
		conn, err = net.DialTimeout("tcp", targetAddr, c.Timeout)
	}

	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(c.Timeout))

	if _, err := conn.Write(rawPayload); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	httpResp, err := http.ReadResponse(reader, nil)
	duration := time.Since(start)

	if err == nil && httpResp != nil {
		defer httpResp.Body.Close()
		bodyBytes, _ := io.ReadAll(httpResp.Body)
		bodyStr := string(bodyBytes)
		return &Response{
			URL:        targetURL,
			StatusCode: httpResp.StatusCode,
			Body:       bodyStr,
			Bytes:      len(bodyBytes),
			Words:      len(strings.Fields(bodyStr)),
			Lines:      strings.Count(bodyStr, "\n"),
			Duration:   duration,
			Headers:    httpResp.Header,
			Location:   httpResp.Header.Get("Location"),
			Proto:      httpResp.Proto,
		}, nil
	}

	// Fallback if raw response could not be parsed by standard http parser
	var rawBuf [8192]byte
	n, readErr := conn.Read(rawBuf[:])
	if readErr != nil && n == 0 {
		return nil, readErr
	}
	rawStr := string(rawBuf[:n])
	return &Response{
		URL:        targetURL,
		StatusCode: 200,
		Body:       rawStr,
		Bytes:      n,
		Words:      len(strings.Fields(rawStr)),
		Lines:      strings.Count(rawStr, "\n"),
		Duration:   duration,
		Headers:    make(http.Header),
		Proto:      "RAW",
	}, nil
}

// ResolveRedirect follows HTTP redirects (up to maxHops) and returns the final destination URL.
func (c *Client) ResolveRedirect(startURL string, maxHops int) (string, error) {
	current := startURL
	for hop := 0; hop < maxHops; hop++ {
		resp, err := c.Request("GET", current, "", nil)
		if err != nil || resp == nil {
			break
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Location
			if loc == "" {
				loc = resp.Headers.Get("Location")
			}
			if loc == "" {
				break
			}
			parsedLoc, err := url.Parse(loc)
			if err != nil {
				break
			}
			parsedCurrent, err := url.Parse(current)
			if err != nil {
				break
			}
			resolved := parsedCurrent.ResolveReference(parsedLoc).String()
			if resolved == current {
				break
			}
			current = resolved
			continue
		}
		break
	}
	return current, nil
}
