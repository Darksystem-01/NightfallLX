package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/detector"
	"nightfalllx/pkg/discovery"
	"nightfalllx/pkg/fuzzer"
	"nightfalllx/pkg/modules"
	"nightfalllx/pkg/oast"
	"nightfalllx/pkg/parser"
	"nightfalllx/pkg/reporters"
	"nightfalllx/pkg/shodan"
	"nightfalllx/pkg/sitemap"
	"nightfalllx/pkg/troubleshoot"
	"nightfalllx/pkg/tui"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return strings.Join(*i, ", ")
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func parseCodes(raw string) map[int]bool {
	res := make(map[int]bool)
	if raw == "" {
		return res
	}
	parts := strings.Split(raw, ",")
	for _, p := range parts {
		if c, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			res[c] = true
		}
	}
	return res
}

func main() {
	var (
		rawURL             string
		rawReqFile         string
		domain             string
		moduleList         string
		method             string
		data               string
		cookie             string
		proxy              string
		insecure           bool
		isHTTPS            bool
		output             string
		wordlist           string
		threads            int
		matchCodesRaw      string
		filterCodeRaw      string
		matchSizesRaw      string
		filterSizeRaw      string
		matchWordsRaw      string
		filterWordsRaw     string
		matchLinesRaw      string
		filterLinesRaw     string
		isFuzz             bool
		isSubdomain        bool
		autoCalibrate      bool
		timeoutSec         int
		isDoctor           bool
		isTech             bool
		isShodan           bool
		shodanKey          string
		isSiteMap          bool
		spiderDepth        int
		spiderMaxURLs      int
		isInteractive      bool
		headersFlag        arrayFlags
		headers2Flag       arrayFlags
		cookie2            string
		scope              string
		scopeOff           bool

		// OAST Out-of-band listener
		oastListen         string
		oastHost           string
		oastWaitSec        int

		// Time-based SQLi
		sqliDelaySec       int

		// Parameter discovery
		discoverParams     bool

		// Authenticated scanning
		loginURL           string
		loginData          string
		loginUser          string
		loginPass          string
		loginSuccessRegex  string
		loginSuccessStatus int
		logoutRegex        string
		bearerToken        string
		refreshURL         string
		refreshJSONPath    string

		// JSON & Rate Limiting
		isJSON             bool
		rateLimit          int
	)

	// Target & Input
	flag.StringVar(&rawURL, "u", "", "Target URL or template (e.g. http://10.129.x.x/FUZZ or http://target.lab/?id=1)")
	flag.StringVar(&rawReqFile, "r", "", "Burp Suite raw HTTP request file (e.g. -r request.txt)")
	flag.StringVar(&domain, "domain", "", "Domain for subdomain discovery / VHost fuzzing (e.g. -domain target.lab)")
	flag.BoolVar(&isHTTPS, "https", false, "Force HTTPS scheme (useful with -r or raw domain)")
	flag.BoolVar(&isHTTPS, "ssl", false, "Alias for --https")

	// Scope Guard & Secondary Identity
	flag.StringVar(&scope, "scope", "", "Scope domains or path to scope.txt (e.g. -scope target.lab,*.target.lab)")
	flag.BoolVar(&scopeOff, "scope-off", false, "Explicitly disable scope guard checking")
	flag.StringVar(&cookie2, "b2", "", "Secondary cookie value for IDOR / authorization testing")
	flag.Var(&headers2Flag, "H2", "Secondary custom header (repeatable, e.g. -H2 'Authorization: Bearer user2')")

	// Out-Of-Band (OAST) Listener
	flag.StringVar(&oastListen, "oast-listen", "", "Local IP:Port to listen for OAST HTTP callbacks (e.g. 0.0.0.0:8888 or 127.0.0.1:8888)")
	flag.StringVar(&oastHost, "oast-host", "", "Public IP/hostname for OAST callback payloads (e.g. 10.10.14.x or tunnel.domain.com)")
	flag.IntVar(&oastWaitSec, "oast-wait", 10, "Seconds to wait for OAST interaction callback (default: 10)")

	// SQLi Time Delay
	flag.IntVar(&sqliDelaySec, "sqli-delay", 3, "Delay in seconds for time-based SQL injection tests (default: 3)")

	// Parameter Discovery (Arjun-style)
	flag.BoolVar(&discoverParams, "discover-params", false, "Discover hidden HTTP parameters via response bisection (-w required)")

	// Authenticated Scanning
	flag.StringVar(&loginURL, "login-url", "", "URL to submit authentication credentials for authenticated scanning")
	flag.StringVar(&loginData, "login-data", "", "Login body payload template with {{user}} and {{pass}} placeholders (form or JSON)")
	flag.StringVar(&loginUser, "login-user", "", "Username for login (or env var LOGIN_USER)")
	flag.StringVar(&loginPass, "login-pass", "", "Password for login (or env var LOGIN_PASS)")
	flag.StringVar(&loginSuccessRegex, "login-success-regex", "", "Regex to confirm successful login response")
	flag.IntVar(&loginSuccessStatus, "login-success-status", 0, "Expected HTTP status code for successful login (e.g. 200 or 302)")
	flag.StringVar(&logoutRegex, "logout-regex", "", "Regex indicating session logout to trigger automatic re-login")
	flag.StringVar(&bearerToken, "bearer", "", "Bearer token for Authorization header")
	flag.StringVar(&refreshURL, "refresh-url", "", "URL to refresh expired authentication tokens")
	flag.StringVar(&refreshJSONPath, "refresh-json-path", "access_token", "JSON path to extract new token from refresh response")

	// Rate Limiting & JSON Mode
	flag.BoolVar(&isJSON, "json", false, "Force treat request body as application/json")
	flag.IntVar(&rateLimit, "rate", 0, "Rate limit in requests per second (default: 0 = unlimited)")

	// Interactive Mouse Dashboard, Tech Detector, Sitemap & Shodan
	flag.BoolVar(&isInteractive, "i", false, "Launch interactive mouse-controllable TUI dashboard")
	flag.BoolVar(&isInteractive, "ui", false, "Alias for -i (Interactive Mouse TUI)")
	flag.BoolVar(&isInteractive, "tui", false, "Alias for -i (Interactive Mouse TUI)")
	flag.BoolVar(&isTech, "tech", false, "Run Wappalyzer-grade technology & exact version detector")
	flag.BoolVar(&isSiteMap, "map", false, "Spider and generate full web application architecture site map")
	flag.BoolVar(&isSiteMap, "spider", false, "Alias for --map")
	flag.BoolVar(&isSiteMap, "crawl", false, "Alias for --map")
	flag.IntVar(&spiderDepth, "depth", 3, "Web crawler recursion depth (default: 3)")
	flag.IntVar(&spiderMaxURLs, "max-urls", 50, "Max URLs to discover during spidering (default: 50)")
	flag.BoolVar(&isShodan, "shodan", false, "Run Shodan OSINT intelligence reconnaissance on target IP/domain")
	flag.StringVar(&shodanKey, "shodan-key", "", "Shodan API Key (optional, defaults to SHODAN_API_KEY env)")

	// Vulnerability Assessment Modules
	flag.StringVar(&moduleList, "m", "all", "Comma-separated modules: sqli, ssti, lfi, cmdi, xss, cors, redirect, ssrf, jwt, waf, idor, csrf, xxe, nosqli, upload (opt-in), headers, exposure, hostheader, crlf, graphql, protopollution, massassign, deserialize (or 'all')")

	// HTTP Options
	flag.StringVar(&method, "X", "GET", "HTTP Method: GET, POST, PUT, etc.")
	flag.StringVar(&data, "d", "", "POST data body (e.g. 'user=FUZZ&pass=123' or '{\"id\":1}')")
	flag.Var(&headersFlag, "H", "Custom HTTP Header (can repeat, e.g. -H 'Host: FUZZ.target.lab')")
	flag.StringVar(&cookie, "b", "", "Cookie header value")
	flag.StringVar(&proxy, "p", "", "HTTP proxy URL (e.g. http://127.0.0.1:8080 for Burp Suite)")
	flag.BoolVar(&insecure, "k", true, "Disable TLS certificate verification (default: true for labs)")
	flag.IntVar(&timeoutSec, "timeout", 15, "Request timeout in seconds (default: 15)")

	// Reporting
	flag.StringVar(&output, "o", "lab_report", "Output report base name")

	// Fast Fuzzing & Subdomain Discovery (ffuf-compatible)
	flag.StringVar(&wordlist, "w", "", "Wordlist file path for high-speed fuzzing / subdomain discovery")
	flag.IntVar(&threads, "t", 40, "Number of concurrent goroutine workers (default: 40)")
	flag.BoolVar(&isFuzz, "fuzz", false, "Explicitly enable fast fuzzing mode")
	flag.BoolVar(&isSubdomain, "subdomain", false, "Enable Subdomain / VHost discovery mode (ffuf-style)")
	flag.BoolVar(&isSubdomain, "sub", false, "Alias for --subdomain")
	flag.BoolVar(&autoCalibrate, "ac", true, "Auto-calibrate baseline wildcard responses (default: true)")

	// Matchers & Filters
	flag.StringVar(&matchCodesRaw, "mc", "", "Match HTTP status codes (comma-separated, e.g. 200,204,301,302,403)")
	flag.StringVar(&filterCodeRaw, "fc", "404", "Filter HTTP status codes (comma-separated, default: 404)")
	flag.StringVar(&matchSizesRaw, "ms", "", "Match response sizes in bytes (comma-separated)")
	flag.StringVar(&filterSizeRaw, "fs", "", "Filter response sizes in bytes (comma-separated, e.g. 0,404)")
	flag.StringVar(&matchWordsRaw, "mw", "", "Match response word counts (comma-separated)")
	flag.StringVar(&filterWordsRaw, "fw", "", "Filter response word counts (comma-separated)")
	flag.StringVar(&matchLinesRaw, "ml", "", "Match response line counts (comma-separated)")
	flag.StringVar(&filterLinesRaw, "fl", "", "Filter response line counts (comma-separated)")

	// Diagnostics & Version
	flag.BoolVar(&isDoctor, "doctor", false, "Run diagnostic checks and troubleshooting")
	flag.BoolVar(&isDoctor, "troubleshoot", false, "Alias for --doctor")
	var isVersion bool
	flag.BoolVar(&isVersion, "version", false, "Show program version")
	flag.BoolVar(&isVersion, "V", false, "Alias for --version")

	flag.Usage = func() {
		fmt.Println(`
  ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗ █████╗ ██╗     ██╗     ██╗   ██╗
  ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔══██╗██║     ██║     ╚██╗ ██╔╝
  ██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ███████║██║     ██║      ╚████╔╝ 
  ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██╔══██║██║     ██║       ██╔═██╗ 
  ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║     ██║  ██║███████╗███████╗ ██╔╝ ██╗
  ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═╝  ╚═╝
              NightfallLX (Go Edition v2.0) - Offensive Assessment Engine`)
		fmt.Println("\nUsage:")
		fmt.Println("  nightfalllx -u <URL> [options]")
		fmt.Println("  nightfalllx -r <request.txt> [options]")
		fmt.Println("  nightfalllx -u <URL>/FUZZ -w <wordlist.txt> [fuzzing options]")
		fmt.Println("  nightfalllx -domain <target.lab> -w <subdomains.txt> [subdomain options]")
		fmt.Println("\nExamples:")
		fmt.Println("  nightfalllx -u http://target.lab/?id=1 -m sqli,lfi -scope target.lab")
		fmt.Println("  nightfalllx -u http://target.lab/api/user -d '{\"id\":1}' -json -m sqli,idor")
		fmt.Println("  nightfalllx -u http://target.lab/ -discover-params -w /path/to/params.txt")
		fmt.Println("  nightfalllx -u http://target.lab/ -oast-listen 0.0.0.0:8888 -oast-host 10.10.14.5:8888 -m ssrf,cmdi,xxe")
		fmt.Println("  nightfalllx -u http://target.lab/admin -login-url http://target.lab/login -login-data 'user={{user}}&pass={{pass}}' -login-user admin -login-pass secret")
		fmt.Println()
		flag.PrintDefaults()
		os.Exit(0)
	}

	flag.Parse()

	if isVersion {
		fmt.Println("NightfallLX v2.0.0 (Go Edition) - High-Performance Web Assessment & Recon Suite")
		return
	}

	// 0. Authorization Warning Notice
	fmt.Println("\033[33m⚠️  Authorization Notice: Ensure you have explicit authorization to test target host(s).\033[0m")

	// 1. Process Scope Guard List
	var scopeHosts []string
	if scope != "" {
		if fileBytes, err := os.ReadFile(scope); err == nil {
			lines := strings.Split(string(fileBytes), "\n")
			for _, l := range lines {
				l = strings.TrimSpace(l)
				if l != "" && !strings.HasPrefix(l, "#") {
					scopeHosts = append(scopeHosts, l)
				}
			}
		} else {
			for _, part := range strings.Split(scope, ",") {
				part = strings.TrimSpace(part)
				if part != "" {
					scopeHosts = append(scopeHosts, part)
				}
			}
		}
	}

	// 2. Doctor Diagnostics Mode
	if isDoctor {
		diagTarget := rawURL
		if diagTarget == "" && rawReqFile != "" {
			diagTarget = "Burp Request: " + rawReqFile
		}
		doc := troubleshoot.NewDoctor(diagTarget, proxy, wordlist)
		checks := doc.RunAll()
		code := troubleshoot.PrintDoctorReport(checks)
		os.Exit(code)
	}

	// 3. Interactive Mouse Dashboard Mode
	if isInteractive {
		dashboardURL := rawURL
		if dashboardURL == "" {
			dashboardURL = "http://127.0.0.1:8080"
		}
		dashboard := tui.NewInteractiveTUI(dashboardURL)
		dashboard.Proxy = proxy
		dashboard.Threads = threads
		dashboard.Wordlist = wordlist
		dashboard.RunLoop()
		return
	}

	// 4. Header Parsing
	parsedHeaders := make(map[string]string)
	for _, h := range headersFlag {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			parsedHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	parsedHeaders2 := make(map[string]string)
	for _, h := range headers2Flag {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			parsedHeaders2[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// 5. Raw Request Parser Mode (-r)
	var queryParams = make(map[string]string)
	var postData = make(map[string]string)
	var urlWithoutQuery string

	if rawReqFile != "" {
		rawBytes, err := os.ReadFile(rawReqFile)
		if err != nil {
			fmt.Printf("\033[31m[!] Error reading raw request file: %v\033[0m\n", err)
			os.Exit(1)
		}
		rawParsed, err := parser.ParseRawRequest(rawBytes, isHTTPS)
		if err != nil {
			fmt.Printf("\033[31m[!] Error parsing raw request: %v\033[0m\n", err)
			os.Exit(1)
		}

		rawURL = rawParsed.FullURL
		method = rawParsed.Method
		data = rawParsed.Body
		if cookie == "" && rawParsed.Cookie != "" {
			cookie = rawParsed.Cookie
		}
		for k, v := range rawParsed.Headers {
			if _, exists := parsedHeaders[k]; !exists {
				parsedHeaders[k] = v
			}
		}
		for k, v := range rawParsed.QueryParams {
			queryParams[k] = v
		}
		for k, v := range rawParsed.PostParams {
			postData[k] = v
		}

		u, err := url.Parse(rawURL)
		if err == nil {
			urlWithoutQuery = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
		}
	}

	// Validation
	if rawURL == "" && domain == "" {
		flag.Usage()
		return
	}

	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		if isHTTPS {
			rawURL = "https://" + rawURL
		} else {
			rawURL = "http://" + rawURL
		}
	}

	// 6. Standalone Tech Detector Mode
	if isTech {
		techTimeout := time.Duration(timeoutSec) * time.Second
		if techTimeout < 15*time.Second {
			techTimeout = 15 * time.Second
		}
		httpClient := client.NewClient(proxy, techTimeout, insecure, cookie, parsedHeaders)
		det := detector.NewTechDetector()
		fmt.Printf("\n\033[1;36m[*] Fingerprinting Technologies & Exact Versions on:\033[0m %s ...\n", rawURL)
		rep, err := det.Detect(rawURL, httpClient)
		if err != nil {
			fmt.Printf("\033[31m[!] Detection failed: %v\033[0m\n", err)
			os.Exit(1)
		}
		detector.PrintReport(rep)
		return
	}

	// 6b. Standalone Full Site Map & Web Crawler
	if isSiteMap {
		sp, err := sitemap.NewSpider(rawURL, spiderDepth, spiderMaxURLs)
		if err != nil {
			fmt.Printf("\033[31m[!] Spider init failed: %v\033[0m\n", err)
			os.Exit(1)
		}
		sm := sp.Crawl()
		sitemap.PrintSiteMap(sm)
		return
	}

	// 6c. Standalone Shodan OSINT Intelligence Reconnaissance
	if isShodan {
		shodanClient := shodan.NewClient(shodanKey)
		domainTarget, ipTarget, err := shodan.ResolveTarget(rawURL)
		if err != nil && domainTarget == "" && ipTarget == "" {
			fmt.Printf("\033[31m[!] Could not resolve target: %v\033[0m\n", err)
			os.Exit(1)
		}
		var hostInfo *shodan.HostInfo
		var dnsInfo *shodan.DomainInfo
		if ipTarget != "" {
			hostInfo, _ = shodanClient.LookupHost(ipTarget)
		}
		if domainTarget != "" {
			dnsInfo, _ = shodanClient.LookupDomain(domainTarget)
		}
		if hostInfo != nil || dnsInfo != nil {
			shodan.PrintReport(domainTarget, hostInfo, dnsInfo)
		} else {
			fmt.Println("\033[33m[!] No Shodan OSINT data found or API limit reached.\033[0m")
		}
		return
	}

	// 7. Fast Fuzzer / Subdomain Mode Check
	hasFuzzKeyword := strings.Contains(rawURL, "FUZZ") || strings.Contains(rawURL, "*") ||
		strings.Contains(data, "FUZZ") || strings.Contains(data, "*")
	for _, v := range parsedHeaders {
		if strings.Contains(v, "FUZZ") || strings.Contains(v, "*") {
			hasFuzzKeyword = true
			break
		}
	}

	if isFuzz || hasFuzzKeyword || (wordlist != "" && len(parsedHeaders["Host"]) > 0 && strings.Contains(parsedHeaders["Host"], "FUZZ")) {
		if cookie != "" && parsedHeaders["Cookie"] == "" {
			parsedHeaders["Cookie"] = cookie
		}
		if isSubdomain && domain != "" && parsedHeaders["Host"] == "" {
			parsedHeaders["Host"] = "FUZZ." + domain
		}
		fuzzCfg := &fuzzer.Config{
			Method:        strings.ToUpper(method),
			URL:           rawURL,
			Data:          data,
			Headers:       parsedHeaders,
			Proxy:         proxy,
			Insecure:      insecure,
			Timeout:       time.Duration(timeoutSec) * time.Second,
			Threads:       threads,
			WordlistPath:  wordlist,
			AutoCalibrate: autoCalibrate,
			MatchCodes:    parseCodes(matchCodesRaw),
			FilterCodes:   parseCodes(filterCodeRaw),
			MatchSizes:    parseCodes(matchSizesRaw),
			FilterSizes:   parseCodes(filterSizeRaw),
			MatchWords:    parseCodes(matchWordsRaw),
			FilterWords:   parseCodes(filterWordsRaw),
			MatchLines:    parseCodes(matchLinesRaw),
			FilterLines:   parseCodes(filterLinesRaw),
			IsSubdomain:   isSubdomain,
		}

		if len(fuzzCfg.MatchCodes) == 0 && len(fuzzCfg.FilterCodes) == 0 {
			fuzzCfg.FilterCodes = map[int]bool{404: true}
		}

		f := fuzzer.NewFuzzer(fuzzCfg)
		if _, err := f.Run(); err != nil {
			fmt.Printf("\033[31m[!] Fuzzer error: %v\033[0m\n", err)
			os.Exit(1)
		}
		return
	}

	// 8. Vulnerability Assessment Engine
	if urlWithoutQuery == "" {
		u, err := url.Parse(rawURL)
		if err != nil {
			fmt.Printf("\033[31m[!] Invalid target URL: %v\033[0m\n", err)
			os.Exit(1)
		}
		urlWithoutQuery = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
		for k, v := range u.Query() {
			if len(v) > 0 {
				queryParams[k] = v[0]
			}
		}
	}

	trimmedData := strings.TrimSpace(data)
	if !isJSON && (strings.HasPrefix(trimmedData, "{") || strings.HasPrefix(trimmedData, "[")) {
		isJSON = true
	}

	if data != "" && len(postData) == 0 && !isJSON {
		vals, err := url.ParseQuery(data)
		if err == nil {
			for k, v := range vals {
				if len(v) > 0 {
					postData[k] = v[0]
				}
			}
		}
	}

	target := &modules.Target{
		URL:      urlWithoutQuery,
		Method:   strings.ToUpper(method),
		Params:   queryParams,
		Data:     postData,
		Headers:  parsedHeaders,
		Cookie2:  cookie2,
		Headers2: parsedHeaders2,
	}

	if isJSON {
		target.IsJSON = true
		if trimmedData != "" {
			_ = target.ParseJSONBody(trimmedData)
		}
		if _, hasCT := parsedHeaders["Content-Type"]; !hasCT {
			parsedHeaders["Content-Type"] = "application/json"
		}
	}

	httpClient := client.NewClient(proxy, time.Duration(timeoutSec)*time.Second, insecure, cookie, parsedHeaders)
	httpClient.ScopeHosts = scopeHosts
	httpClient.ScopeOff = scopeOff
	if rateLimit > 0 {
		httpClient.SetRateLimit(rateLimit)
	}

	// Environment variable fallback for login credentials
	if loginUser == "" {
		loginUser = os.Getenv("LOGIN_USER")
	}
	if loginPass == "" {
		loginPass = os.Getenv("LOGIN_PASS")
	}

	// Authenticated Scanning Setup
	if loginURL != "" {
		httpClient.LoginURL = loginURL
		httpClient.LoginData = loginData
		httpClient.LoginUser = loginUser
		httpClient.LoginPass = loginPass
		httpClient.LoginSuccessStatus = loginSuccessStatus
		if loginSuccessRegex != "" {
			httpClient.LoginSuccessRegex = regexp.MustCompile(loginSuccessRegex)
		}
		if logoutRegex != "" {
			httpClient.LogoutRegex = regexp.MustCompile(logoutRegex)
		}
		httpClient.BearerToken = bearerToken
		httpClient.RefreshURL = refreshURL
		httpClient.RefreshJSONPath = refreshJSONPath

		fmt.Println("\033[36m[*] Authenticating session on login endpoint...\033[0m")
		if err := httpClient.PerformLogin(); err != nil {
			fmt.Printf("\033[31m[!] Login failed: %v\033[0m\n", err)
		} else {
			fmt.Println("\033[32m[+] Authentication succeeded! Session cookies cached in jar.\033[0m")
		}
	}

	// OAST Listener Initialization
	if oastListen != "" || oastHost != "" {
		if oastListen == "" {
			oastListen = "0.0.0.0:8888"
		}
		oastServer := oast.NewServer(oastListen, oastHost, time.Duration(oastWaitSec)*time.Second)
		if err := oastServer.Start(); err != nil {
			fmt.Printf("\033[31m[!] Warning: Failed to start OAST listener on %s: %v\033[0m\n", oastListen, err)
		} else {
			defer oastServer.Close()
			target.OAST = oastServer
			fmt.Printf("\033[32m[+] Built-in OAST Callback Server started on %s (Public: %s)\033[0m\n", oastServer.ListenAddr, oastServer.PublicHost)
		}
	}

	// Parameter Discovery (Arjun-style)
	if discoverParams {
		if wordlist == "" {
			fmt.Println("\033[33m[!] -discover-params specified without -w wordlist. Using built-in common parameter list...\033[0m")
		}
		var words []string
		if wordlist != "" {
			if fBytes, err := os.ReadFile(wordlist); err == nil {
				sc := bufio.NewScanner(strings.NewReader(string(fBytes)))
				for sc.Scan() {
					txt := strings.TrimSpace(sc.Text())
					if txt != "" && !strings.HasPrefix(txt, "#") {
						words = append(words, txt)
					}
				}
			}
		}
		if len(words) == 0 {
			words = []string{
				"id", "user", "username", "email", "pass", "password", "token", "key", "admin", "debug",
				"file", "path", "url", "redirect", "dest", "view", "show", "cat", "page", "role", "cmd",
				"exec", "action", "query", "search", "lang", "type", "filter", "sort", "data", "callback",
			}
		}

		fmt.Printf("\033[36m[*] Discovering hidden parameters using %d candidates...\033[0m\n", len(words))
		pd := discovery.NewParameterDiscovery(50)
		foundParams, err := pd.Discover(target, httpClient, words)
		if err != nil {
			fmt.Printf("\033[31m[!] Parameter discovery error: %v\033[0m\n", err)
		} else if len(foundParams) > 0 {
			fmt.Printf("\033[1;32m[+] Discovered %d hidden parameter(s): %v\033[0m\n", len(foundParams), foundParams)
			for _, p := range foundParams {
				if target.Params == nil {
					target.Params = make(map[string]string)
				}
				target.Params[p] = "1"
			}
		} else {
			fmt.Println("\033[33m[-] No anomalous parameters discovered.\033[0m")
		}
	}

	// Step 1: Deep Technology & Version Fingerprint
	det := detector.NewTechDetector()
	techRep, err := det.Detect(rawURL, httpClient)
	if err == nil && techRep != nil {
		detector.PrintReport(techRep)
	}

	fmt.Printf("\n\033[1;36mNightfallLX (Go Edition v2.0)\033[0m - Web Assessment Framework\n")
	fmt.Printf("Target:     \033[1m%s\033[0m [%s]\n", target.URL, target.Method)
	fmt.Printf("Parameters: %v\n", target.Parameters())
	if target.IsJSON {
		fmt.Printf("Payload:    \033[35mJSON Body (%d leaves)\033[0m\n", len(target.JSONLeaves))
	}
	if proxy != "" {
		fmt.Printf("Proxy:      \033[33m%s\033[0m\n", proxy)
	}
	fmt.Println()

	if len(target.Parameters()) == 0 {
		fmt.Println("\033[33m[!] Notice: No query or body parameters detected in target URL.\033[0m")
		fmt.Println("    Running passive / host modules. To test injection, add parameters: -u 'http://site/?id=1' or -d 'param=1'")
	}

	sqliModule := modules.NewSQLiModule()
	if sqliDelaySec > 0 {
		sqliModule.DefaultDelay = sqliDelaySec
	}

	availableModules := map[string]modules.Module{
		"sqli":           sqliModule,
		"ssti":           modules.NewSSTIModule(),
		"lfi":            modules.NewLFIModule(),
		"cmdi":           modules.NewCMDiModule(),
		"xss":            modules.NewXSSModule(),
		"cors":           modules.NewCORSModule(),
		"redirect":       modules.NewRedirectModule(),
		"ssrf":           modules.NewSSRFModule(),
		"jwt":            modules.NewJWTModule(),
		"waf":            modules.NewWAFModule(),
		"idor":           modules.NewIDORModule(),
		"csrf":           modules.NewCSRFModule(),
		"xxe":            modules.NewXXEModule(),
		"nosqli":         modules.NewNoSQLiModule(),
		"upload":         modules.NewUploadModule(), // Opt-in only
		"headers":        modules.NewHeadersModule(),
		"exposure":       modules.NewExposureModule(),
		"hostheader":     modules.NewHostHeaderModule(),
		"crlf":           modules.NewCRLFModule(),
		"graphql":        modules.NewGraphQLModule(),
		"protopollution": modules.NewProtoPollutionModule(),
		"massassign":     modules.NewMassAssignModule(),
		"deserialize":    modules.NewDeserializeModule(),
	}

	var activeModules []modules.Module
	if moduleList == "all" {
		order := []string{
			"waf", "headers", "exposure", "sqli", "ssti", "lfi", "cmdi",
			"xss", "cors", "redirect", "ssrf", "jwt", "idor", "csrf",
			"xxe", "nosqli", "hostheader", "crlf", "graphql",
			"protopollution", "massassign", "deserialize",
		}
		for _, name := range order {
			activeModules = append(activeModules, availableModules[name])
		}
	} else {
		for _, mName := range strings.Split(moduleList, ",") {
			name := strings.TrimSpace(strings.ToLower(mName))
			if mod, ok := availableModules[name]; ok {
				activeModules = append(activeModules, mod)
			}
		}
	}

	var allFindings []*modules.Finding
	for _, mod := range activeModules {
		fmt.Printf("\033[36m[*] Running module: \033[1m%-14s\033[0m (%s) ...\n", mod.Name(), mod.Description())
		findings, err := mod.Run(target, httpClient)
		if err != nil {
			fmt.Printf("    \033[31m[!] Error running %s: %v\033[0m\n", mod.Name(), err)
			continue
		}
		for _, f := range findings {
			status := "\033[1;32m[CONFIRMED]\033[0m"
			if f.ConfidenceLevel == modules.ConfidencePossible {
				status = "\033[1;33m[POSSIBLE]\033[0m"
			} else if f.ConfidenceLevel == modules.ConfidenceProbable {
				status = "\033[1;34m[PROBABLE]\033[0m"
			} else if f.Severity == modules.SeverityInfo {
				status = "\033[1;36m[INFO]\033[0m"
			}
			fmt.Printf("    %s \033[1m%s\033[0m (param=%s, confidence=%s)\n", status, f.Title, f.Parameter, f.ConfidenceLevel)
		}
		allFindings = append(allFindings, findings...)
	}

	mdFile := output + ".md"
	jsonFile := output + ".json"
	reporters.WriteMarkdownReport(target, allFindings, mdFile)
	reporters.WriteJSONReport(target, allFindings, jsonFile)

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Printf("\033[1mScan Finished!\033[0m Total Findings: \033[1;32m%d\033[0m\n", len(allFindings))
	fmt.Printf("Reports saved to:\n  Markdown: \033[32m%s\033[0m\n  JSON:     \033[32m%s\033[0m\n", mdFile, jsonFile)
	fmt.Println(strings.Repeat("=", 60))
}
