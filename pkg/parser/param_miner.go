package parser

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"net/url"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/wordlists"
	"sort"
	"strings"
	"sync"
	"time"
)

// DiscoveredParam represents a discovered hidden parameter with diagnostic evidence.
type DiscoveredParam struct {
	Name       string `json:"name"`
	Location   string `json:"location"` // "query" or "body"
	Reason     string `json:"reason"`   // "reflection", "status_change", "length_diff", "body_diff"
	StatusCode int    `json:"status_code"`
	LengthDiff int    `json:"length_diff"`
	Evidence   string `json:"evidence"`
}

// MinerConfig defines configuration options for the hidden parameter miner.
type MinerConfig struct {
	URL         string
	Method      string // "GET" or "POST"
	Headers     map[string]string
	Cookie      string
	Proxy       string
	Timeout     time.Duration
	Insecure    bool
	BatchSize   int      // Group candidates (15-30 per request, default: 25)
	Concurrency int      // Worker count (default: 5)
	Wordlist    []string // Parameter candidates (defaults to Top200HiddenParams)
}

// Top200HiddenParams represents the top 200 hidden parameter candidates for web audits.
var Top200HiddenParams = []string{
	"debug", "admin", "internal", "test", "redirect", "secret", "enable", "dev",
	"root", "config", "show", "view", "source", "cmd", "exec", "eval", "token",
	"key", "api_key", "mode", "access", "preview", "hidden", "beta", "role",
	"auth", "env", "backup", "log", "format", "callback", "jsonp", "url",
	"uri", "dest", "next", "return", "goto", "file", "path", "page",
	"include", "document", "doc", "load", "read", "action", "do", "run",
	"filter", "query", "search", "q", "id", "user", "username", "email",
	"account", "pass", "password", "hash", "salt", "pin", "code", "otp",
	"session", "cookie", "jwt", "ticket", "csrf", "xsrf", "nonce", "state",
	"scope", "grant", "client_id", "client_secret", "app_id", "app_secret",
	"signature", "sig", "timestamp", "time", "date", "expires", "version",
	"v", "api_version", "lang", "locale", "translate", "msg", "message",
	"error", "warn", "info", "alert", "prompt", "confirm", "popup", "modal",
	"dialog", "window", "frame", "iframe", "tab", "panel", "layout",
	"template", "theme", "skin", "style", "css", "js", "script", "asset",
	"static", "media", "image", "img", "avatar", "icon", "logo", "banner",
	"header", "footer", "menu", "nav", "sidebar", "widget", "plugin",
	"module", "component", "element", "node", "item", "data", "payload",
	"body", "raw", "content", "text", "html", "xml", "json", "yaml",
	"csv", "output", "response", "result", "status", "flag", "bool",
	"toggle", "switch", "opt", "option", "param", "arg", "value", "val",
	"key_val", "input", "out", "in", "dump", "trace", "verbose", "quiet",
	"silent", "dry_run", "simulate", "fake", "mock", "stub", "override",
	"impersonate", "su", "sudo", "elevate", "privilege", "bypass", "skip",
	"ignore", "disable", "allow", "deny", "whitelist", "blacklist", "trust",
	"safe", "secure", "vuln", "exploit", "probe", "ping", "health",
	"alive", "ready", "metrics", "stat", "counter", "gauge", "timer",
	"profiler", "heap", "cpu", "mem", "gc", "stack", "thread", "worker",
	"pool", "queue", "job", "task", "cron", "batch", "limit", "offset",
}

// ParamMiner discovers hidden HTTP parameters via batch testing and heuristic differential analysis.
type ParamMiner struct {
	cfg        *MinerConfig
	client     *client.Client
	baseline   *client.Response
	discovered []DiscoveredParam
	mu         sync.Mutex
}

// NewParamMiner initializes a ParamMiner with sensible defaults.
func NewParamMiner(cfg *MinerConfig) *ParamMiner {
	if cfg.Method == "" {
		cfg.Method = "GET"
	}
	cfg.Method = strings.ToUpper(cfg.Method)
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 25
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}
	if len(cfg.Wordlist) == 0 {
		embedded := wordlists.GetWordlist("parameters", "")
		if len(embedded) > 0 {
			cfg.Wordlist = embedded
		} else {
			cfg.Wordlist = Top200HiddenParams
		}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	c := client.NewClient(cfg.Proxy, cfg.Timeout, cfg.Insecure, cfg.Cookie, cfg.Headers)
	return &ParamMiner{
		cfg:    cfg,
		client: c,
	}
}

// randomCanary produces a short unique identifier for testing reflection and diffs.
func randomCanary(prefix string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("nflx_%s_%s", prefix, hex.EncodeToString(b))
}

// Mine runs hidden parameter mining and returns all identified parameters.
func (pm *ParamMiner) Mine() ([]DiscoveredParam, error) {
	// Step 1: Capture Baseline
	baseResp, err := pm.client.Request(pm.cfg.Method, pm.cfg.URL, "", nil)
	if err != nil {
		return nil, fmt.Errorf("baseline request failed: %w", err)
	}
	pm.baseline = baseResp

	// Step 2: Slice wordlist into batches
	var batches [][]string
	for i := 0; i < len(pm.cfg.Wordlist); i += pm.cfg.BatchSize {
		end := i + pm.cfg.BatchSize
		if end > len(pm.cfg.Wordlist) {
			end = len(pm.cfg.Wordlist)
		}
		batches = append(batches, pm.cfg.Wordlist[i:end])
	}

	batchChan := make(chan []string, len(batches))
	for _, b := range batches {
		batchChan <- b
	}
	close(batchChan)

	var wg sync.WaitGroup
	for i := 0; i < pm.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for batch := range batchChan {
				pm.processBatch(batch)
			}
		}()
	}

	wg.Wait()

	// Sort results deterministically by param name
	sort.Slice(pm.discovered, func(i, j int) bool {
		return pm.discovered[i].Name < pm.discovered[j].Name
	})

	return pm.discovered, nil
}

func (pm *ParamMiner) processBatch(batch []string) {
	canaryMap := make(map[string]string)
	for _, p := range batch {
		canaryMap[p] = randomCanary(p)
	}

	resp, reqURL, reqData := pm.sendCandidateRequest(canaryMap)
	if resp == nil {
		return
	}

	// 1. Check for Canary Reflection in response body
	var reflectedParams []string
	for p, canary := range canaryMap {
		if strings.Contains(resp.Body, canary) && !strings.Contains(pm.baseline.Body, canary) {
			reflectedParams = append(reflectedParams, p)
		}
	}

	if len(reflectedParams) > 0 {
		for _, p := range reflectedParams {
			pm.addDiscovered(DiscoveredParam{
				Name:       p,
				Location:   pm.locationString(),
				Reason:     "reflection",
				StatusCode: resp.StatusCode,
				LengthDiff: resp.Bytes - pm.baseline.Bytes,
				Evidence:   fmt.Sprintf("Canary value '%s' was directly reflected in response body", canaryMap[p]),
			})
		}
		return
	}

	// 2. Check for Status Code change
	statusAnomaly := resp.StatusCode != pm.baseline.StatusCode

	// 3. Check for Response Body size difference (ignoring expected parameter injection bytes)
	injectedLen := len(reqData)
	if pm.cfg.Method == "GET" {
		injectedLen = len(reqURL) - len(pm.cfg.URL)
	}
	lenDiff := math.Abs(float64((resp.Bytes - pm.baseline.Bytes) - injectedLen))
	sizeAnomaly := lenDiff > 60

	// 4. Narrow down candidates if batch triggered an anomaly
	if statusAnomaly || sizeAnomaly {
		pm.narrowDownBatch(batch)
	}
}

// narrowDownBatch tests parameters individually to confirm which one triggered the anomaly.
func (pm *ParamMiner) narrowDownBatch(candidates []string) {
	for _, p := range candidates {
		canary := randomCanary(p)
		singleMap := map[string]string{p: canary}
		resp, _, _ := pm.sendCandidateRequest(singleMap)
		if resp == nil {
			continue
		}

		// Reflection confirmation
		if strings.Contains(resp.Body, canary) && !strings.Contains(pm.baseline.Body, canary) {
			pm.addDiscovered(DiscoveredParam{
				Name:       p,
				Location:   pm.locationString(),
				Reason:     "reflection",
				StatusCode: resp.StatusCode,
				LengthDiff: resp.Bytes - pm.baseline.Bytes,
				Evidence:   fmt.Sprintf("Canary '%s' reflected in response body", canary),
			})
			continue
		}

		// Status Code confirmation
		if resp.StatusCode != pm.baseline.StatusCode {
			pm.addDiscovered(DiscoveredParam{
				Name:       p,
				Location:   pm.locationString(),
				Reason:     "status_change",
				StatusCode: resp.StatusCode,
				LengthDiff: resp.Bytes - pm.baseline.Bytes,
				Evidence:   fmt.Sprintf("Status code shifted from %d to %d when '%s' was supplied", pm.baseline.StatusCode, resp.StatusCode, p),
			})
			continue
		}

		// Significant body difference
		diffLen := int(math.Abs(float64(resp.Bytes - pm.baseline.Bytes)))
		if diffLen > 80 {
			pm.addDiscovered(DiscoveredParam{
				Name:       p,
				Location:   pm.locationString(),
				Reason:     "body_diff",
				StatusCode: resp.StatusCode,
				LengthDiff: resp.Bytes - pm.baseline.Bytes,
				Evidence:   fmt.Sprintf("Response size deviated by %d bytes compared to baseline", diffLen),
			})
		}
	}
}

func (pm *ParamMiner) sendCandidateRequest(params map[string]string) (*client.Response, string, string) {
	reqURL := pm.cfg.URL
	reqData := ""

	if pm.cfg.Method == "GET" {
		u, err := url.Parse(reqURL)
		if err != nil {
			return nil, "", ""
		}
		q := u.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
		reqURL = u.String()
	} else {
		// POST application/x-www-form-urlencoded
		values := url.Values{}
		for k, v := range params {
			values.Set(k, v)
		}
		reqData = values.Encode()
	}

	headers := make(map[string]string)
	for k, v := range pm.cfg.Headers {
		headers[k] = v
	}
	if pm.cfg.Method != "GET" && headers["Content-Type"] == "" {
		headers["Content-Type"] = "application/x-www-form-urlencoded"
	}

	resp, _ := pm.client.Request(pm.cfg.Method, reqURL, reqData, headers)
	return resp, reqURL, reqData
}

func (pm *ParamMiner) addDiscovered(dp DiscoveredParam) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, existing := range pm.discovered {
		if existing.Name == dp.Name && existing.Location == dp.Location {
			return // already discovered
		}
	}
	pm.discovered = append(pm.discovered, dp)
}

func (pm *ParamMiner) locationString() string {
	if pm.cfg.Method == "GET" {
		return "query"
	}
	return "body"
}
