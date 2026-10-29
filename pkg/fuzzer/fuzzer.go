package fuzzer

import (
	"bufio"
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/wordlists"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Result represents a single hit from fuzzing.
type Result struct {
	Word        string        `json:"word"`
	URL         string        `json:"url"`
	Status      int           `json:"status"`
	Bytes       int           `json:"bytes"`
	Words       int           `json:"words"`
	Lines       int           `json:"lines"`
	Duration    time.Duration `json:"duration"`
	RedirectURL string        `json:"redirect_url,omitempty"`
}

// Config controls fuzzer execution.
type Config struct {
	URL             string
	WordlistPath    string
	Wordlist        []string
	Method          string
	Data            string
	Headers         map[string]string
	Threads         int
	Timeout         time.Duration
	Proxy           string
	Insecure        bool
	AutoCalibrate   bool
	IsSubdomain     bool
	MatchCodes      map[int]bool
	FilterCodes     map[int]bool
	MatchSizes      map[int]bool
	FilterSizes     map[int]bool
	MatchWords      map[int]bool
	FilterWords     map[int]bool
	MatchLines      map[int]bool
	FilterLines     map[int]bool
	RateLimit       int
	MaxRetries      int
	RetryDelay      time.Duration
	HTTP2           bool
	RawHTTP         bool
	HeaderTampering bool
	Chunked         bool
	MatchRegexStr   string
	FilterRegexStr  string
	MatchRegex      *regexp.Regexp
	FilterRegex     *regexp.Regexp
	AutoRegex       bool

	// Adaptive enables WAF-aware throttling: exponential backoff on 429 /
	// repeated 403 responses, dynamic thread reduction, jitter and rotated
	// browser User-Agent fingerprints.
	Adaptive             bool
	AdaptiveMinThreads   int
	AdaptiveJitter       time.Duration
	AdaptiveBackoffBase  time.Duration
	AdaptiveMaxBackoff   time.Duration
	AdaptiveForbiddenMax int
	RotateUserAgent      bool
}

// DefaultLabWordlist is a general web discovery wordlist.
var DefaultLabWordlist = []string{
	"admin", "login", "api", "dashboard", "panel", "robots.txt", ".git", ".env",
	"config", "backup", "db", "upload", "uploads", "shell", "test", "dev",
	"portal", "console", "server-status", "phpmyadmin", "actuator", "swagger",
	"graphql", "v1", "v2", "debug", "secret", "private", "users", "user",
	"manage", "manager", "app", "cgi-bin", "internal", "auth", "token",
	"register", "signup", "view", "edit", "create", "delete", "file", "download",
	"logs", "error.log", "access.log", "info.php", "phpinfo.php", "index.php",
	"home", "search", "query", "status", "health", "metrics", "root",
}

// DefaultSubdomainWordlist contains top subdomains for DNS & VHost fuzzing.
var DefaultSubdomainWordlist = []string{
	"www", "mail", "dev", "api", "admin", "vpn", "staging", "portal", "test",
	"beta", "corp", "internal", "remote", "gateway", "gitlab", "git", "jenkins",
	"auth", "sso", "id", "cloud", "db", "stage", "monitor", "grafana", "kibana",
	"vault", "k8s", "docker", "registry", "prod", "production", "uat", "qa",
	"backup", "old", "new", "v1", "v2", "docs", "help", "billing", "pay",
	"payment", "static", "assets", "cdn", "media", "img", "images", "download",
	"files", "storage", "ws", "socket", "chat", "bot", "ops", "dns", "mx",
	"crm", "erp", "hr", "intra", "extranet", "partner", "client", "customer",
	"member", "members", "account", "accounts", "manage", "management", "panel",
	"secure", "shop", "checkout", "app", "support", "status", "jira", "confluence",
	"login", "cpanel", "web", "office", "database", "mysql", "postgres", "redis",
	"elastic", "prometheus", "monitoring", "ci", "cd", "lab", "labs", "order",
	"drive", "share", "node", "ai", "sys", "pop", "imap", "exchange", "owa",
	"autodiscover", "mobile", "mobi", "affiliate", "reseller",
}

// Fuzzer performs high-speed concurrent fuzzing using goroutines.
type Fuzzer struct {
	cfg         *Config
	client      *client.Client
	results     []*Result
	completed   int64
	total       int
	resLock     sync.Mutex
	startTime   time.Time
	adaptive      *AdaptiveController
	hasBaseline   bool
	inferredRegex *regexp.Regexp
	baseline      struct {
		StatusCode int
		Bytes      int
		Words      int
		Lines      int
	}
}

// NewFuzzer initializes the Fuzzer with defaults.
func NewFuzzer(cfg *Config) *Fuzzer {
	if cfg.Threads <= 0 {
		cfg.Threads = 40
	}
	if cfg.Method == "" {
		cfg.Method = "GET"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 7 * time.Second
	}
	if cfg.MatchCodes == nil {
		cfg.MatchCodes = map[int]bool{200: true, 204: true, 301: true, 302: true, 307: true, 308: true, 401: true, 403: true, 405: true}
	}
	if cfg.FilterCodes == nil {
		cfg.FilterCodes = map[int]bool{404: true}
	}
	if cfg.MatchSizes == nil {
		cfg.MatchSizes = make(map[int]bool)
	}
	if cfg.FilterSizes == nil {
		cfg.FilterSizes = make(map[int]bool)
	}
	if cfg.MatchWords == nil {
		cfg.MatchWords = make(map[int]bool)
	}
	if cfg.FilterWords == nil {
		cfg.FilterWords = make(map[int]bool)
	}
	if cfg.MatchLines == nil {
		cfg.MatchLines = make(map[int]bool)
	}
	if cfg.FilterLines == nil {
		cfg.FilterLines = make(map[int]bool)
	}

	// Check if FUZZ is present in data or headers
	hasFuzzElsewhere := strings.Contains(cfg.Data, "FUZZ") || strings.Contains(cfg.Data, "*")
	for _, v := range cfg.Headers {
		if strings.Contains(v, "FUZZ") || strings.Contains(v, "*") {
			hasFuzzElsewhere = true
			break
		}
	}

	if !strings.Contains(cfg.URL, "FUZZ") && !strings.Contains(cfg.URL, "*") && !cfg.IsSubdomain && !hasFuzzElsewhere {
		if strings.HasSuffix(cfg.URL, "/") {
			cfg.URL += "FUZZ"
		} else {
			cfg.URL += "/FUZZ"
		}
	}

	c := client.NewClient(cfg.Proxy, cfg.Timeout, cfg.Insecure, "", nil)
	if cfg.RateLimit > 0 {
		c.SetRateLimit(cfg.RateLimit)
	}
	if cfg.MaxRetries > 0 {
		c.SetRetry(cfg.MaxRetries, cfg.RetryDelay)
	}
	c.SetHTTP2(cfg.HTTP2)
	c.SetHeaderTampering(cfg.HeaderTampering)
	c.SetChunkedEncoding(cfg.Chunked)

	if cfg.MatchRegexStr != "" && cfg.MatchRegex == nil {
		if re, err := regexp.Compile(cfg.MatchRegexStr); err == nil {
			cfg.MatchRegex = re
		}
	}
	if cfg.FilterRegexStr != "" && cfg.FilterRegex == nil {
		if re, err := regexp.Compile(cfg.FilterRegexStr); err == nil {
			cfg.FilterRegex = re
		}
	}

	f := &Fuzzer{
		cfg:    cfg,
		client: c,
	}
	if cfg.Adaptive {
		f.adaptive = NewAdaptiveController(AdaptiveConfig{
			MaxConcurrency:     cfg.Threads,
			MinConcurrency:     cfg.AdaptiveMinThreads,
			BackoffBase:        cfg.AdaptiveBackoffBase,
			MaxBackoff:         cfg.AdaptiveMaxBackoff,
			Jitter:             cfg.AdaptiveJitter,
			ForbiddenThreshold: cfg.AdaptiveForbiddenMax,
			RotateUserAgents:   cfg.RotateUserAgent,
		})
	}
	return f
}

func (f *Fuzzer) loadWords() ([]string, error) {
	if len(f.cfg.Wordlist) > 0 {
		return f.cfg.Wordlist, nil
	}
	if f.cfg.WordlistPath != "" {
		file, err := os.Open(f.cfg.WordlistPath)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		var words []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				words = append(words, line)
			}
		}
		return words, scanner.Err()
	}

	if f.cfg.IsSubdomain {
		embedded := wordlists.GetWordlist("subdomains", "")
		if len(embedded) > 0 {
			return embedded, nil
		}
		return DefaultSubdomainWordlist, nil
	}
	embedded := wordlists.GetWordlist("directories", "")
	if len(embedded) > 0 {
		return embedded, nil
	}
	return DefaultLabWordlist, nil
}

func (f *Fuzzer) replaceKeyword(template, payload string) string {
	if template == "" {
		return ""
	}
	if strings.Contains(template, "FUZZ") {
		return strings.ReplaceAll(template, "FUZZ", payload)
	}
	if strings.Contains(template, "*") {
		return strings.ReplaceAll(template, "*", payload)
	}
	return template
}

func (f *Fuzzer) calibrate() {
	if !f.cfg.AutoCalibrate {
		return
	}

	canary := fmt.Sprintf("nflx-%d", time.Now().UnixNano()%1000000)
	testURL := f.replaceKeyword(f.cfg.URL, canary)
	testData := ""
	if f.cfg.Data != "" {
		testData = f.replaceKeyword(f.cfg.Data, canary)
	}

	customHeaders := make(map[string]string)
	for k, v := range f.cfg.Headers {
		customHeaders[f.replaceKeyword(k, canary)] = f.replaceKeyword(v, canary)
	}

	resp, err := f.client.Request(f.cfg.Method, testURL, testData, customHeaders)
	if err == nil && resp != nil {
		f.hasBaseline = true
		f.baseline.StatusCode = resp.StatusCode
		f.baseline.Bytes = resp.Bytes
		f.baseline.Words = resp.Words
		f.baseline.Lines = resp.Lines
		fmt.Printf("\033[33m[::] Auto-calibration (-ac): baseline wildcard detected (status %d, %d bytes, %d words, %d lines) -> auto-filtered\033[0m\n",
			resp.StatusCode, resp.Bytes, resp.Words, resp.Lines)

		if f.cfg.AutoRegex && resp.Body != "" {
			patterns := []string{
				`(?i)(not\s+found|404\s+not\s+found|page\s+not\s+found|does\s+not\s+exist)`,
				`(?i)(invalid\s+(?:user|username|request|parameter|token|key|credentials)|user(?:name)?\s+not\s+found)`,
				`(?i)(no\s+results?\s+found|nothing\s+found)`,
			}
			for _, pat := range patterns {
				if re, err := regexp.Compile(pat); err == nil && re.MatchString(resp.Body) {
					f.inferredRegex = re
					fmt.Printf("\033[1;35m[::] Auto-Regex (-auto-regex): Inferred differential filter regex: '%s' -> auto-filtered\033[0m\n", pat)
					break
				}
			}
		}
	}
}

// Run executes the fuzzer concurrently.
func (f *Fuzzer) Run() ([]*Result, error) {
	words, err := f.loadWords()
	if err != nil {
		return nil, err
	}

	f.total = len(words)
	f.startTime = time.Now()
	f.calibrate()

	f.printBanner()

	jobs := make(chan string, f.cfg.Threads*4)
	var wg sync.WaitGroup

	// Launch worker goroutines
	for i := 0; i < f.cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range jobs {
				f.processWord(word)
			}
		}()
	}

	// Live progress printer goroutine
	doneProgress := make(chan struct{})
	go f.progressLoop(doneProgress)

	// Feed words to channel
	for _, word := range words {
		jobs <- word
	}
	close(jobs)

	// Wait for workers to finish
	wg.Wait()
	close(doneProgress)

	duration := time.Since(f.startTime)
	rps := float64(f.total) / duration.Seconds()
	if duration.Seconds() == 0 {
		rps = 0
	}

	fmt.Printf("\r%s\r", strings.Repeat(" ", 80))
	fmt.Printf("\n\033[1mFuzzing Complete!\033[0m Processed \033[1m%d\033[0m requests in %v (%.1f req/sec). Hits: \033[1;32m%d\033[0m\n\n",
		f.total, duration.Round(time.Millisecond), rps, len(f.results))

	return f.results, nil
}

func (f *Fuzzer) processWord(word string) {
	defer atomic.AddInt64(&f.completed, 1)

	reqURL := f.replaceKeyword(f.cfg.URL, word)
	reqData := ""
	if f.cfg.Data != "" {
		reqData = f.replaceKeyword(f.cfg.Data, word)
	}

	customHeaders := make(map[string]string)
	for k, v := range f.cfg.Headers {
		customHeaders[f.replaceKeyword(k, word)] = f.replaceKeyword(v, word)
	}

	if f.adaptive != nil {
		f.adaptive.Acquire()
		defer f.adaptive.Release()
		if ua := f.adaptive.UserAgent(); ua != "" {
			customHeaders["User-Agent"] = ua
		}
	}

	if f.cfg.HeaderTampering {
		for k, v := range client.BypassHeaders() {
			if _, ok := customHeaders[k]; !ok {
				customHeaders[k] = v
			}
		}
	}

	var resp *client.Response
	var err error
	if f.cfg.RawHTTP {
		u, _ := url.Parse(reqURL)
		path := u.RequestURI()
		if path == "" {
			path = "/"
		}
		var rawBuf strings.Builder
		rawBuf.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", f.cfg.Method, path))
		rawBuf.WriteString(fmt.Sprintf("Host: %s\r\n", u.Host))
		for k, v := range customHeaders {
			if !strings.EqualFold(k, "Host") {
				rawBuf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
			}
		}
		if reqData != "" {
			if f.cfg.Chunked {
				rawBuf.WriteString("Transfer-Encoding: chunked\r\n")
			} else {
				rawBuf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(reqData)))
			}
		}
		rawBuf.WriteString("Connection: close\r\n\r\n")
		if reqData != "" {
			if f.cfg.Chunked {
				rawBuf.Write(client.ChunkedBody([]byte(reqData)))
			} else {
				rawBuf.WriteString(reqData)
			}
		}
		resp, err = f.client.RawRequest(reqURL, []byte(rawBuf.String()))
	} else {
		resp, err = f.client.Request(f.cfg.Method, reqURL, reqData, customHeaders)
	}
	if err != nil || resp == nil {
		return
	}
	if f.adaptive != nil {
		f.adaptive.Observe(resp.StatusCode)
	}

	// Auto-calibration baseline filtering (compound check: status AND size AND words/lines)
	if f.hasBaseline && resp.StatusCode == f.baseline.StatusCode &&
		resp.Bytes == f.baseline.Bytes &&
		resp.Words == f.baseline.Words &&
		resp.Lines == f.baseline.Lines {
		return
	}

	// 1. Status Code filtering & matching
	if f.cfg.FilterCodes[resp.StatusCode] {
		return
	}
	if len(f.cfg.MatchCodes) > 0 && !f.cfg.MatchCodes[resp.StatusCode] {
		return
	}

	// 2. Response Size (Bytes) filtering & matching
	if f.cfg.FilterSizes[resp.Bytes] {
		return
	}
	if len(f.cfg.MatchSizes) > 0 && !f.cfg.MatchSizes[resp.Bytes] {
		return
	}

	// 3. Response Words filtering & matching
	if f.cfg.FilterWords[resp.Words] {
		return
	}
	if len(f.cfg.MatchWords) > 0 && !f.cfg.MatchWords[resp.Words] {
		return
	}

	// 4. Response Lines filtering & matching
	if f.cfg.FilterLines[resp.Lines] {
		return
	}
	if len(f.cfg.MatchLines) > 0 && !f.cfg.MatchLines[resp.Lines] {
		return
	}

	// 5. Inferred Auto-Regex filtering
	if f.inferredRegex != nil && f.inferredRegex.MatchString(resp.Body) {
		return
	}

	// 6. User-specified Regex matching & filtering
	if f.cfg.FilterRegex != nil && f.cfg.FilterRegex.MatchString(resp.Body) {
		return
	}
	if f.cfg.MatchRegex != nil && !f.cfg.MatchRegex.MatchString(resp.Body) {
		return
	}

	res := &Result{
		Word:        word,
		URL:         reqURL,
		Status:      resp.StatusCode,
		Bytes:       resp.Bytes,
		Words:       resp.Words,
		Lines:       resp.Lines,
		Duration:    resp.Duration,
		RedirectURL: resp.Location,
	}

	f.resLock.Lock()
	f.results = append(f.results, res)
	f.printHit(res, customHeaders)
	f.resLock.Unlock()
}

func (f *Fuzzer) printHit(res *Result, headers map[string]string) {
	color := "\033[32m" // Green
	if res.Status >= 300 && res.Status < 400 {
		color = "\033[36m" // Cyan
	} else if res.Status >= 400 {
		color = "\033[33m" // Yellow
	}

	redirect := ""
	if res.RedirectURL != "" {
		redirect = fmt.Sprintf(" -> \033[36m%s\033[0m", res.RedirectURL)
	}

	vhostExtra := ""
	if h, ok := headers["Host"]; ok && strings.Contains(h, res.Word) {
		vhostExtra = fmt.Sprintf(" [VHost: \033[1;35m%s\033[0m]", h)
	}

	fmt.Printf("\r\033[1m%-24s\033[0m [%sStatus: %d\033[0m, Size: %-6d, Words: %-5d, Lines: %-4d, Time: %v]%s%s\n",
		res.Word, color, res.Status, res.Bytes, res.Words, res.Lines, res.Duration.Round(time.Millisecond), vhostExtra, redirect)
}

func (f *Fuzzer) printBanner() {
	modeStr := "Mega Fast Go Fuzzer"
	if f.cfg.IsSubdomain {
		modeStr = "Subdomain & VHost Discovery (ffuf-compatible)"
	}

	fmt.Printf("\n\033[1;36m:: NightfallLX %s ::\033[0m\n", modeStr)
	fmt.Printf("   :: Method        : \033[33m%s\033[0m\n", f.cfg.Method)
	fmt.Printf("   :: Target URL    : \033[1m%s\033[0m\n", f.cfg.URL)
	if h, ok := f.cfg.Headers["Host"]; ok {
		fmt.Printf("   :: Target VHost  : \033[1;35m%s\033[0m\n", h)
	}
	fmt.Printf("   :: Wordlist size : \033[32m%d words\033[0m\n", f.total)
	fmt.Printf("   :: Threads       : \033[1m%d goroutines\033[0m\n", f.cfg.Threads)
	if f.cfg.Proxy != "" {
		fmt.Printf("   :: Proxy         : %s\n", f.cfg.Proxy)
	}
	if f.adaptive != nil {
		fmt.Printf("   :: Adaptive WAF  : \033[33mON\033[0m (jitter %v, UA rotation %v)\n", f.cfg.AdaptiveJitter, f.cfg.RotateUserAgent)
	}
	fmt.Printf("\033[36m________________________________________________\033[0m\n\n")
}

func (f *Fuzzer) progressLoop(done chan struct{}) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			doneCount := atomic.LoadInt64(&f.completed)
			elapsed := time.Since(f.startTime).Seconds()
			rps := float64(doneCount) / elapsed
			if elapsed == 0 {
				rps = 0
			}
			pct := float64(doneCount) / float64(f.total) * 100
			f.resLock.Lock()
			hits := len(f.results)
			f.resLock.Unlock()

			fmt.Printf("\r:: Progress: [%d/%d] %.1f%% :: %.1f req/sec :: Hits: %d",
				doneCount, f.total, pct, rps, hits)
		}
	}
}

func parseURL(raw string) *url.URL {
	u, _ := url.Parse(raw)
	return u
}
