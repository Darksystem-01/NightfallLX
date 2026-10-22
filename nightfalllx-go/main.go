package main

import (
	"flag"
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/detector"
	"nightfalllx/pkg/fuzzer"
	"nightfalllx/pkg/modules"
	"nightfalllx/pkg/parser"
	"nightfalllx/pkg/reporters"
	"nightfalllx/pkg/troubleshoot"
	"nightfalllx/pkg/tui"
	"os"
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
		rawURL         string
		rawReqFile     string
		domain         string
		moduleList     string
		method         string
		data           string
		cookie         string
		proxy          string
		insecure       bool
		isHTTPS        bool
		output         string
		wordlist       string
		threads        int
		matchCodesRaw  string
		filterCodeRaw  string
		matchSizesRaw  string
		filterSizeRaw  string
		matchWordsRaw  string
		filterWordsRaw string
		matchLinesRaw  string
		filterLinesRaw string
		isFuzz         bool
		isSubdomain    bool
		autoCalibrate  bool
		timeoutSec     int
		isDoctor       bool
		isTech         bool
		isInteractive  bool
		headersFlag    arrayFlags
	)

	// Target & Input
	flag.StringVar(&rawURL, "u", "", "Target URL or template (e.g. http://10.129.x.x/FUZZ or http://target.lab/?id=1)")
	flag.StringVar(&rawReqFile, "r", "", "Burp Suite raw HTTP request file (e.g. -r request.txt)")
	flag.StringVar(&domain, "domain", "", "Domain for subdomain discovery / VHost fuzzing (e.g. -domain target.lab)")
	flag.BoolVar(&isHTTPS, "https", false, "Force HTTPS scheme (useful with -r or raw domain)")
	flag.BoolVar(&isHTTPS, "ssl", false, "Alias for --https")

	// Interactive Mouse Dashboard & Tech Detector
	flag.BoolVar(&isInteractive, "i", false, "Launch interactive mouse-controllable TUI dashboard")
	flag.BoolVar(&isInteractive, "ui", false, "Alias for -i (Interactive Mouse TUI)")
	flag.BoolVar(&isInteractive, "tui", false, "Alias for -i (Interactive Mouse TUI)")
	flag.BoolVar(&isTech, "tech", false, "Run Wappalyzer-grade technology & exact version detector")

	// Vulnerability Assessment Modules
	flag.StringVar(&moduleList, "m", "all", "Comma-separated modules: sqli, ssti, lfi, cmdi, xss, cors, redirect, ssrf, jwt, waf (or 'all')")

	// HTTP Options
	flag.StringVar(&method, "X", "GET", "HTTP Method: GET, POST, PUT, etc.")
	flag.StringVar(&data, "d", "", "POST data body (e.g. 'user=FUZZ&pass=123')")
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

	flag.Parse()

	if isVersion {
		fmt.Println("NightfallLX v2.0.0 (Go Edition) - High-Performance Web Assessment & Recon Suite")
		return
	}

	// 0. Interactive Mouse-Controllable TUI Mode
	if isInteractive || (len(os.Args) == 1 && rawURL == "" && rawReqFile == "") {
		dash := tui.NewInteractiveTUI(rawURL)
		dash.Proxy = proxy
		dash.Wordlist = wordlist
		dash.RunLoop()
		return
	}

	// 1. Troubleshooting / Doctor Mode
	if isDoctor {
		doc := troubleshoot.NewDoctor(rawURL, proxy, wordlist)
		checks := doc.RunAll()
		exitCode := troubleshoot.PrintDoctorReport(checks)
		os.Exit(exitCode)
	}

	// 2. Parse Custom Headers
	parsedHeaders := make(map[string]string)
	for _, h := range headersFlag {
		if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
			parsedHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// 3. Handle Burp Suite Raw Request (-r)
	var parsedRawReq *parser.RawRequest
	if rawReqFile != "" {
		var err error
		parsedRawReq, err = parser.ParseRawRequestFile(rawReqFile, isHTTPS)
		if err != nil {
			fmt.Printf("\033[31m[!] Error parsing raw request file %s: %v\033[0m\n", rawReqFile, err)
			os.Exit(1)
		}

		if rawURL == "" {
			rawURL = parsedRawReq.FullURL
		}
		if method == "GET" && parsedRawReq.Method != "" {
			method = parsedRawReq.Method
		}
		if data == "" && parsedRawReq.Body != "" {
			data = parsedRawReq.Body
		}
		if cookie == "" && parsedRawReq.Cookie != "" {
			cookie = parsedRawReq.Cookie
		}
		for k, v := range parsedRawReq.Headers {
			if _, exists := parsedHeaders[k]; !exists {
				parsedHeaders[k] = v
			}
		}
		if parsedRawReq.HasFuzzPoint {
			isFuzz = true
		}
		fmt.Printf("\033[32m[+] Loaded Burp Suite Raw Request from:\033[0m %s [%s %s]\n", rawReqFile, method, rawURL)
	}

	// 4. Subdomain Discovery Mode setup
	if isSubdomain {
		isFuzz = true
		if rawURL == "" && domain != "" {
			scheme := "http"
			if isHTTPS {
				scheme = "https"
			}
			rawURL = fmt.Sprintf("%s://%s", scheme, domain)
		}
		if domain != "" && rawURL != "" {
			// If target is an IP or base URL, set Host: FUZZ.<domain>
			parsedHeaders["Host"] = fmt.Sprintf("FUZZ.%s", domain)
		} else if rawURL != "" {
			// Extract host from rawURL and configure VHost fuzzing if not present
			cleanHost := strings.TrimPrefix(strings.TrimPrefix(rawURL, "http://"), "https://")
			cleanHost = strings.TrimSuffix(cleanHost, "/")
			if qIdx := strings.Index(cleanHost, "/"); qIdx != -1 {
				cleanHost = cleanHost[:qIdx]
			}
			if _, hasHost := parsedHeaders["Host"]; !hasHost && !strings.Contains(rawURL, "FUZZ") {
				parsedHeaders["Host"] = fmt.Sprintf("FUZZ.%s", cleanHost)
			}
		}
	}

	// 5. Validation Check
	if rawURL == "" {
		fmt.Println("\033[1;36mNightfallLX (Go Edition)\033[0m - High-Performance Web Assessment & Fuzzer")
		fmt.Println("Usage:")
		fmt.Println("  nightfalllx -i                                               # Launch interactive Mouse-controlled Dashboard")
		fmt.Println("  nightfalllx --tech -u http://target.lab                      # Wappalyzer-grade technology & version detector")
		fmt.Println("  nightfalllx -r request.txt                                   # Scan Burp Suite request")
		fmt.Println("  nightfalllx -sub -u http://10.129.x.x -domain target.htb     # ffuf-style VHost/Subdomain finder")
		fmt.Println("  nightfalllx -u http://10.129.x.x/FUZZ -w wordlist.txt -t 50  # Directory/Param fuzzer")
		fmt.Println("  nightfalllx -u http://target.lab/?id=1 -m all -p http://127.0.0.1:8080")
		fmt.Println("  nightfalllx --doctor -u http://target.lab/ -p http://127.0.0.1:8080")
		fmt.Println()
		flag.PrintDefaults()
		os.Exit(1)
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
		fuzzCfg := &fuzzer.Config{
			URL:           rawURL,
			WordlistPath:  wordlist,
			Method:        strings.ToUpper(method),
			Data:          data,
			Headers:       parsedHeaders,
			Threads:       threads,
			Timeout:       time.Duration(timeoutSec) * time.Second,
			Proxy:         proxy,
			Insecure:      insecure,
			AutoCalibrate: autoCalibrate,
			IsSubdomain:   isSubdomain,
			FilterCodes:   parseCodes(filterCodeRaw),
			FilterSizes:   parseCodes(filterSizeRaw),
			FilterWords:   parseCodes(filterWordsRaw),
			FilterLines:   parseCodes(filterLinesRaw),
			MatchSizes:    parseCodes(matchSizesRaw),
			MatchWords:    parseCodes(matchWordsRaw),
			MatchLines:    parseCodes(matchLinesRaw),
		}
		if matchCodesRaw != "" {
			fuzzCfg.MatchCodes = parseCodes(matchCodesRaw)
		}

		f := fuzzer.NewFuzzer(fuzzCfg)
		_, err := f.Run()
		if err != nil {
			fmt.Printf("\033[31m[!] Fuzzer error: %v\033[0m\n", err)
			os.Exit(1)
		}
		return
	}

	// 8. Vulnerability Assessment Mode
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		fmt.Printf("\033[31m[!] Invalid URL: %v\033[0m\n", err)
		os.Exit(1)
	}

	urlWithoutQuery := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)
	queryParams := make(map[string]string)
	for k, v := range parsedURL.Query() {
		if len(v) > 0 {
			queryParams[k] = v[0]
		}
	}

	postData := make(map[string]string)
	if data != "" {
		vals, err := url.ParseQuery(data)
		if err == nil {
			for k, v := range vals {
				if len(v) > 0 {
					postData[k] = v[0]
				}
			}
		}
	}

	if parsedRawReq != nil {
		for k, v := range parsedRawReq.QueryParams {
			if _, exists := queryParams[k]; !exists {
				queryParams[k] = v
			}
		}
		for k, v := range parsedRawReq.PostParams {
			if _, exists := postData[k]; !exists {
				postData[k] = v
			}
		}
	}

	target := &modules.Target{
		URL:     urlWithoutQuery,
		Method:  strings.ToUpper(method),
		Params:  queryParams,
		Data:    postData,
		Headers: parsedHeaders,
	}

	httpClient := client.NewClient(proxy, time.Duration(timeoutSec)*time.Second, insecure, cookie, parsedHeaders)

	// Step 1: Deep Technology & Version Fingerprint
	det := detector.NewTechDetector()
	techRep, err := det.Detect(rawURL, httpClient)
	if err == nil && techRep != nil {
		detector.PrintReport(techRep)
	}

	fmt.Printf("\n\033[1;36mNightfallLX (Go Edition)\033[0m - Web Assessment Framework\n")
	fmt.Printf("Target:     \033[1m%s\033[0m [%s]\n", target.URL, target.Method)
	fmt.Printf("Parameters: %v\n", target.Parameters())
	if proxy != "" {
		fmt.Printf("Proxy:      \033[33m%s\033[0m\n", proxy)
	}
	fmt.Println()

	if len(target.Parameters()) == 0 {
		fmt.Println("\033[33m[!] Notice: No query or body parameters detected in target URL.\033[0m")
		fmt.Println("    Running passive / host modules (WAF, CORS). To test injection, add parameters: -u 'http://site/?id=1' or -d 'param=1'")
	}

	availableModules := map[string]modules.Module{
		"sqli":     modules.NewSQLiModule(),
		"ssti":     modules.NewSSTIModule(),
		"lfi":      modules.NewLFIModule(),
		"cmdi":     modules.NewCMDiModule(),
		"xss":      modules.NewXSSModule(),
		"cors":     modules.NewCORSModule(),
		"redirect": modules.NewRedirectModule(),
		"ssrf":     modules.NewSSRFModule(),
		"jwt":      modules.NewJWTModule(),
		"waf":      modules.NewWAFModule(),
	}

	var activeModules []modules.Module
	if moduleList == "all" {
		order := []string{"waf", "sqli", "ssti", "lfi", "cmdi", "xss", "cors", "redirect", "ssrf", "jwt"}
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
		fmt.Printf("\033[36m[*] Running module: \033[1m%-10s\033[0m (%s) ...\n", mod.Name(), mod.Description())
		findings, err := mod.Run(target, httpClient)
		if err != nil {
			fmt.Printf("    \033[31m[!] Error running %s: %v\033[0m\n", mod.Name(), err)
			continue
		}
		for _, f := range findings {
			status := "\033[1;32m[CONFIRMED]\033[0m"
			if f.Severity == modules.SeverityInfo {
				status = "\033[1;36m[INFO]\033[0m"
			}
			fmt.Printf("    %s \033[1m%s\033[0m (param=%s, confidence=%d%%)\n", status, f.Title, f.Parameter, f.Confidence)
		}
		allFindings = append(allFindings, findings...)
	}

	mdFile := output + ".md"
	jsonFile := output + ".json"
	reporters.WriteMarkdownReport(target, allFindings, mdFile)
	reporters.WriteJSONReport(target, allFindings, jsonFile)

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Printf("\033[1mScan Finished!\033[0m Confirmed Vulnerabilities: \033[1;32m%d\033[0m\n", len(allFindings))
	fmt.Printf("Reports saved to:\n  Markdown: \033[32m%s\033[0m\n  JSON:     \033[32m%s\033[0m\n", mdFile, jsonFile)
	fmt.Println(strings.Repeat("=", 60))
}
