package devbuster

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nightfalllx/pkg/client"
)

// Finding represents an identified route/endpoint.
type Finding struct {
	URL         string `json:"url"`
	Status      int    `json:"status"`
	Size        int    `json:"size"`
	ContentType string `json:"content_type"`
	Depth       int    `json:"depth"`
	Source      string `json:"source"`
	Parent      string `json:"parent,omitempty"`
	Error       string `json:"error,omitempty"`
}

// Config configures the Devbuster modern web crawler and route discovery engine.
type Config struct {
	TargetURL         string
	Depth             int
	Concurrency       int
	Delay             time.Duration
	Timeout           time.Duration
	Headers           map[string]string
	IncludeSubdomains bool
	Wordlist          []string
	WordlistPath      string
	OnlyStatus        map[int]bool
	HideStatus        map[int]bool
	Browser           bool
	ChromePath        string
	Proxy             string
	Insecure          bool
	Context           context.Context
	Limiter           *client.RateLimiter
	Quiet             bool
}

// Crawler executes scope-aware modern web route discovery.
type Crawler struct {
	cfg        *Config
	startURL   string
	baseHost   string
	httpClient *http.Client
	chromeBin  string

	seenLock  sync.Mutex
	seen      map[string]bool
	finalSeen map[string]bool

	findingsLock sync.Mutex
	findings     []*Finding

	total     int64
	completed int64
	errors    int64
	startedAt time.Time
}

var (
	htmlAttrRegex = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'>\s#]+)["']`)
	scriptTagSrc  = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	formTagAction = regexp.MustCompile(`(?i)<form[^>]+action\s*=\s*["']([^"']*)["']`)
	linkTagHref   = regexp.MustCompile(`(?i)<(?:a|link)[^>]+href\s*=\s*["']([^"'>\s#]+)["']`)

	// jsRouteRegex matches route literals inside JS bundles, e.g. "/dashboard/users", "/api/v1/orders?status=active"
	jsRouteRegex = regexp.MustCompile(`(?:['"` + "`" + `])(/[\w\-\.~:@%!$&'\(\)\*\+,;=\/]+(?:\?[\w\-\.~:@%!$&'\(\)\*\+,;=\/]*)?)(?:['"` + "`" + `])`)

	// nonRouteAssetRegex filters out media, fonts, and source maps
	nonRouteAssetRegex = regexp.MustCompile(`(?i)\.(?:png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|otf|map|css|js)(?:$|[?#])`)
)

// NewCrawler initializes a Devbuster modern route discovery crawler.
func NewCrawler(cfg *Config) (*Crawler, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	raw := strings.TrimSpace(cfg.TargetURL)
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("invalid target URL: %q", cfg.TargetURL)
	}

	if cfg.Depth <= 0 {
		cfg.Depth = 2
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Headers == nil {
		cfg.Headers = make(map[string]string)
	}
	if _, ok := cfg.Headers["User-Agent"]; !ok {
		cfg.Headers["User-Agent"] = "devbuster/0.1 (authorized security testing)"
	}

	chromePath := cfg.ChromePath
	if chromePath == "" {
		chromePath = findChromeBinary()
	}

	// Setup HTTP transport with proxy and TLS config
	tlsConfig := &tls.Config{InsecureSkipVerify: cfg.Insecure}
	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   30,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   cfg.Timeout,
		ResponseHeaderTimeout: cfg.Timeout,
		DialContext: (&net.Dialer{
			Timeout:   cfg.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	if cfg.Proxy != "" {
		if proxyURL, err := url.Parse(cfg.Proxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return &Crawler{
		cfg:        cfg,
		startURL:   normalizeURL(raw),
		baseHost:   strings.ToLower(parsed.Hostname()),
		httpClient: httpClient,
		chromeBin:  chromePath,
		seen:       make(map[string]bool),
		finalSeen:  make(map[string]bool),
		findings:   make([]*Finding, 0),
		startedAt:  time.Now(),
	}, nil
}

// Normalize cleans and normalizes a URL by stripping fragments and standardizing host/scheme.
func Normalize(raw string) string {
	return normalizeURL(raw)
}

func normalizeURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return raw
	}
	u.Fragment = ""
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	host := strings.ToLower(u.Host)
	path := u.Path
	if path == "" {
		path = "/"
	}
	u.Scheme = scheme
	u.Host = host
	u.Path = path
	return u.String()
}

// InScope determines if a URL belongs to the target scope.
func (c *Crawler) InScope(target string) bool {
	p, err := url.Parse(target)
	if err != nil {
		return false
	}
	if p.Scheme != "http" && p.Scheme != "https" {
		return false
	}
	host := strings.ToLower(p.Hostname())
	if host == "" {
		return false
	}
	if c.cfg.IncludeSubdomains {
		if host == c.baseHost || strings.HasSuffix(host, "."+c.baseHost) {
			return true
		}
	}
	// Support www <-> non-www canonical alias
	if host == c.baseHost || host == "www."+c.baseHost || c.baseHost == "www."+host {
		return true
	}
	return false
}

// ResolveCanonicalOrigin checks for root redirects (e.g. http->https, apex->www, / -> /login).
func (c *Crawler) ResolveCanonicalOrigin(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.startURL, nil)
	if err != nil {
		return
	}
	for k, v := range c.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.Request != nil && resp.Request.URL != nil {
		finalURL := normalizeURL(resp.Request.URL.String())
		if p, err := url.Parse(finalURL); err == nil && p.Hostname() != "" {
			c.startURL = finalURL
			c.baseHost = strings.ToLower(p.Hostname())
		}
	}
}

// LoadWordlist loads candidates from slice or file.
func (c *Crawler) LoadWordlist() ([]string, error) {
	var words []string
	if len(c.cfg.Wordlist) > 0 {
		words = append(words, c.cfg.Wordlist...)
	}
	if c.cfg.WordlistPath != "" {
		f, err := os.Open(c.cfg.WordlistPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				words = append(words, line)
			}
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}

	// Clean paths: strip leading slashes
	seen := make(map[string]bool)
	var cleaned []string
	for _, w := range words {
		w = strings.TrimSpace(w)
		w = strings.TrimPrefix(w, "/")
		if w != "" && !seen[w] {
			seen[w] = true
			cleaned = append(cleaned, w)
		}
	}
	return cleaned, nil
}

// ShouldShow checks if a status code should be reported according to status filters.
func (c *Crawler) ShouldShow(status int) bool {
	if status <= 0 {
		return false
	}
	if c.cfg.HideStatus != nil && c.cfg.HideStatus[status] {
		return false
	}
	if c.cfg.OnlyStatus != nil && len(c.cfg.OnlyStatus) > 0 {
		return c.cfg.OnlyStatus[status]
	}
	return true
}

// ExtractRoutes finds HTML links and JS bundle route literals.
func (c *Crawler) ExtractRoutes(baseURL string, body []byte, contentType string) []struct {
	URL    string
	Source string
} {
	var results []struct {
		URL    string
		Source string
	}
	seen := make(map[string]bool)

	baseParsed, err := url.Parse(baseURL)
	if err != nil {
		return results
	}

	bodyStr := string(body)
	cTypeLower := strings.ToLower(contentType)

	// 1. HTML link & form extraction
	if strings.Contains(cTypeLower, "html") || strings.Contains(cTypeLower, "xml") {
		for _, m := range htmlAttrRegex.FindAllStringSubmatch(bodyStr, -1) {
			if len(m) > 1 {
				val := strings.TrimSpace(m[1])
				if strings.HasPrefix(val, "javascript:") || strings.HasPrefix(val, "mailto:") || strings.HasPrefix(val, "tel:") {
					continue
				}
				resolved := resolveReference(baseParsed, val)
				if resolved != "" && !seen[resolved] {
					seen[resolved] = true
					results = append(results, struct {
						URL    string
						Source string
					}{URL: resolved, Source: "html:link"})
				}
			}
		}
	}

	// 2. JS Bundle Route Extraction (Next.js, React, Angular, Vue chunk inspection)
	isJS := strings.Contains(cTypeLower, "javascript") || strings.Contains(cTypeLower, "json") ||
		strings.HasSuffix(strings.ToLower(baseParsed.Path), ".js")

	if isJS {
		for _, m := range jsRouteRegex.FindAllStringSubmatch(bodyStr, -1) {
			if len(m) > 1 {
				candidate := strings.TrimSpace(m[1])
				// Ensure it starts with / and is not a static asset
				if !strings.HasPrefix(candidate, "/") || nonRouteAssetRegex.MatchString(candidate) {
					continue
				}
				// Filter common noise/operators
				if candidate == "/" || strings.HasPrefix(candidate, "//") {
					continue
				}

				resolved := resolveReference(baseParsed, candidate)
				if resolved != "" && !seen[resolved] {
					seen[resolved] = true
					results = append(results, struct {
						URL    string
						Source string
					}{URL: resolved, Source: "js:literal"})
				}
			}
		}
	}

	return results
}

func resolveReference(base *url.URL, ref string) string {
	refURL, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(refURL)
	return normalizeURL(resolved.String())
}

type queueItem struct {
	URL    string
	Depth  int
	Parent string
	Source string
}

// Run executes the complete modern crawling and route discovery workflow.
func (c *Crawler) Run(ctx context.Context) ([]*Finding, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	// 1. Resolve canonical origin (handling www, https, root redirects)
	c.ResolveCanonicalOrigin(ctx)

	// 2. Prepare wordlist
	words, err := c.LoadWordlist()
	if err != nil {
		return nil, fmt.Errorf("load wordlist: %w", err)
	}

	if !c.cfg.Quiet {
		fmt.Printf("\033[1;36m[*] Devbuster Modern Route Discovery Engine\033[0m\n")
		fmt.Printf("    Target origin : %s (Host: %s)\n", c.startURL, c.baseHost)
		fmt.Printf("    Concurrency   : %d workers | Depth: %d\n", c.cfg.Concurrency, c.cfg.Depth)
		fmt.Printf("    Wordlist size : %d items\n", len(words))
		if c.cfg.Browser {
			if c.chromeBin != "" {
				fmt.Printf("    SPA Browser   : Enabled (%s)\n", c.chromeBin)
			} else {
				fmt.Printf("    SPA Browser   : Requested but Chrome not found (falling back to HTTP)\n")
			}
		}
	}

	c.startedAt = time.Now()

	// Task queue with concurrency control
	workQueue := make(chan queueItem, 100000)
	var wg sync.WaitGroup

	// Push seed
	workQueue <- queueItem{URL: c.startURL, Depth: 0, Parent: "", Source: "seed"}
	atomic.AddInt64(&c.total, 1)

	// Push wordlist URLs
	basePrefix := strings.TrimRight(c.startURL, "/")
	for _, w := range words {
		targetURL := normalizeURL(basePrefix + "/" + w)
		workQueue <- queueItem{URL: targetURL, Depth: 1, Parent: c.startURL, Source: "wordlist"}
		atomic.AddInt64(&c.total, 1)
	}

	// Start worker pool
	workerCount := c.cfg.Concurrency
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case item, ok := <-workQueue:
					if !ok {
						return
					}
					c.processItem(ctx, item, workQueue)
				}
			}
		}()
	}

	// Wait for queue drain with dynamic idle detection
	idleTicker := time.NewTicker(50 * time.Millisecond)
	defer idleTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			close(workQueue)
			wg.Wait()
			return c.GetFindings(), ctx.Err()
		case <-idleTicker.C:
			done := atomic.LoadInt64(&c.completed)
			tot := atomic.LoadInt64(&c.total)
			if done >= tot && len(workQueue) == 0 {
				close(workQueue)
				wg.Wait()
				return c.GetFindings(), nil
			}
		}
	}
}

func (c *Crawler) processItem(ctx context.Context, item queueItem, queue chan<- queueItem) {
	defer atomic.AddInt64(&c.completed, 1)

	norm := normalizeURL(item.URL)

	c.seenLock.Lock()
	if c.seen[norm] || !c.InScope(norm) || item.Depth > c.cfg.Depth {
		c.seenLock.Unlock()
		return
	}
	c.seen[norm] = true
	c.seenLock.Unlock()

	// Rate limiter & delay
	if c.cfg.Limiter != nil {
		if err := c.cfg.Limiter.WaitContext(ctx); err != nil {
			return
		}
	}
	if c.cfg.Delay > 0 {
		select {
		case <-time.After(c.cfg.Delay):
		case <-ctx.Done():
			return
		}
	}

	// If browser mode is enabled and Chrome exists, render page for deep SPA discovery
	if c.cfg.Browser && c.chromeBin != "" && item.Depth < c.cfg.Depth {
		c.renderBrowserDOM(ctx, norm, item.Depth, queue)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, norm, nil)
	if err != nil {
		atomic.AddInt64(&c.errors, 1)
		return
	}
	for k, v := range c.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		atomic.AddInt64(&c.errors, 1)
		c.findingsLock.Lock()
		c.findings = append(c.findings, &Finding{
			URL:    norm,
			Status: 0,
			Depth:  item.Depth,
			Source: item.Source,
			Parent: item.Parent,
			Error:  err.Error(),
		})
		c.findingsLock.Unlock()
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // Read up to 512KB
	cType := resp.Header.Get("Content-Type")

	// Final destination check (after redirects)
	var finalURL string
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = normalizeURL(resp.Request.URL.String())
	} else {
		finalURL = norm
	}

	c.seenLock.Lock()
	if c.finalSeen[finalURL] && finalURL != norm {
		c.seenLock.Unlock()
		return
	}
	c.finalSeen[finalURL] = true
	c.seenLock.Unlock()

	finding := &Finding{
		URL:         finalURL,
		Status:      resp.StatusCode,
		Size:        len(bodyBytes),
		ContentType: strings.Split(cType, ";")[0],
		Depth:       item.Depth,
		Source:      item.Source,
		Parent:      item.Parent,
	}

	shouldShow := c.ShouldShow(resp.StatusCode)
	if shouldShow {
		c.findingsLock.Lock()
		c.findings = append(c.findings, finding)
		c.findingsLock.Unlock()
	}

	// Live console output matching devbuster's UI
	if !c.cfg.Quiet {
		c.printProgress(finding, shouldShow)
	}

	// Extract recursive links & JS route literals if within max depth
	if item.Depth < c.cfg.Depth {
		extracted := c.ExtractRoutes(finalURL, bodyBytes, cType)
		for _, child := range extracted {
			childNorm := normalizeURL(child.URL)
			if c.InScope(childNorm) {
				c.seenLock.Lock()
				if !c.seen[childNorm] {
					atomic.AddInt64(&c.total, 1)
					select {
					case queue <- queueItem{
						URL:    childNorm,
						Depth:  item.Depth + 1,
						Parent: finalURL,
						Source: child.Source,
					}:
					default:
					}
				}
				c.seenLock.Unlock()
			}
		}
	}
}

func (c *Crawler) renderBrowserDOM(ctx context.Context, target string, depth int, queue chan<- queueItem) {
	cmdCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, c.chromeBin,
		"--headless",
		"--disable-gpu",
		"--no-sandbox",
		"--disable-dev-shm-usage",
		"--virtual-time-budget=1500",
		"--dump-dom",
		target,
	)
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return
	}

	baseParsed, err := url.Parse(target)
	if err != nil {
		return
	}

	for _, m := range htmlAttrRegex.FindAllStringSubmatch(string(out), -1) {
		if len(m) > 1 {
			val := strings.TrimSpace(m[1])
			if strings.HasPrefix(val, "javascript:") || strings.HasPrefix(val, "mailto:") {
				continue
			}
			resolved := resolveReference(baseParsed, val)
			if resolved != "" && c.InScope(resolved) {
				c.seenLock.Lock()
				if !c.seen[resolved] {
					atomic.AddInt64(&c.total, 1)
					select {
					case queue <- queueItem{
						URL:    resolved,
						Depth:  depth + 1,
						Parent: target,
						Source: "browser:dom",
					}:
					default:
					}
				}
				c.seenLock.Unlock()
			}
		}
	}
}

func (c *Crawler) printProgress(f *Finding, shown bool) {
	comp := atomic.LoadInt64(&c.completed) + 1
	tot := atomic.LoadInt64(&c.total)
	elapsed := time.Since(c.startedAt).Seconds()
	if elapsed <= 0 {
		elapsed = 0.001
	}
	rate := float64(comp) / elapsed

	if shown {
		statusColor := "\033[32m" // green
		if f.Status >= 300 && f.Status < 400 {
			statusColor = "\033[34m" // blue
		} else if f.Status >= 400 && f.Status < 500 {
			statusColor = "\033[33m" // yellow
		} else if f.Status >= 500 {
			statusColor = "\033[31m" // red
		}

		fmt.Printf("\n[%d/%d] %6.1f/s \033[1mFOUND\033[0m %s%3d\033[0m %8d bytes [%s] %s",
			comp, tot, rate, statusColor, f.Status, f.Size, f.Source, f.URL)
	} else {
		c.findingsLock.Lock()
		foundCount := len(c.findings)
		c.findingsLock.Unlock()
		errs := atomic.LoadInt64(&c.errors)
		fmt.Printf("\r[%d/%d] %6.1f/s found:%d errors:%d", comp, tot, rate, foundCount, errs)
	}
}

// GetFindings returns a copy of discovered findings sorted by status and URL.
func (c *Crawler) GetFindings() []*Finding {
	c.findingsLock.Lock()
	defer c.findingsLock.Unlock()

	out := make([]*Finding, len(c.findings))
	copy(out, c.findings)

	sort.Slice(out, func(i, j int) bool {
		if out[i].Status != out[j].Status {
			return out[i].Status < out[j].Status
		}
		return out[i].URL < out[j].URL
	})
	return out
}

// ToJSON serializes findings into indented JSON format.
func ToJSON(findings []*Finding) (string, error) {
	bytes, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func findChromeBinary() string {
	for _, bin := range []string{"chromium", "chromium-browser", "google-chrome", "chrome"} {
		if path, err := exec.LookPath(bin); err == nil {
			return path
		}
	}
	return ""
}
