package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/detector"
	"nightfalllx/pkg/devbuster"
	"nightfalllx/pkg/discovery"
	"nightfalllx/pkg/fuzzer"
	"nightfalllx/pkg/intel"
	"nightfalllx/pkg/modules"
	"nightfalllx/pkg/oast"
	"nightfalllx/pkg/parser"
	"nightfalllx/pkg/plugins"
	"nightfalllx/pkg/profile"
	"nightfalllx/pkg/reporters"
	"nightfalllx/pkg/shodan"
	"nightfalllx/pkg/sitemap"
	"nightfalllx/pkg/state"
	"nightfalllx/pkg/troubleshoot"
	"nightfalllx/pkg/tui"
	"nightfalllx/pkg/update"
	"nightfalllx/pkg/version"
	"nightfalllx/pkg/wordlists"
	"nightfalllx/pkg/xss"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
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

func (i *arrayFlags) Values() []string {
	return []string(*i)
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

var bloodyBannerLines = []string{
	"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
	"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@**@@@@@@@@@@@@",
	"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*@@@@@@@@@@* -*@@@@@@@@@@@@@@@**@@@@@@@@@@@@@@@@@@@@*@@@@@@@@@@*@@@-@@@@@@@@@@@@@@@@@@",
	"@@@@@@@@@@*@@@@@@**@@@@@@@@@@* *@@@@@@@@@  --**@@@*-**-@@@@@    -@@@@@@@@* -**  *- *@@@@*--*---@* --@@@@@@@@@@@@@@@@",
	"@@@@@@@@@@@@@@@@@@@* *@@*@@-     *@@@@@@@-   *@@@@@    *@@@     @@@@@@@@-   -   *   *@@@@*    @*   *@@@@@@@@@@*@@@@@",
	"@@@@@@@@@@@@@@@@*-   -     *@@*-@@*   -  -   -  --       --   --**              -   *@@@@@*-      *@@@@@@@@@@@@@@@@@",
	"@@@@@@@@@@@@@@@@*           -   *-       *       -      -       *-      *   *   @   *@@@@@@@-    @@@@@@@@@@--@@@@@@@",
	"@@@@@@@@@-***@@@@@@    --   *   *   *@   *   **   **  *@@@@   *@*-      *   *   @   *@@@@@@*     -@@@@*----*@@@@@@@@",
	"@@@@@@@@@@@*-    *@   *@*  -@   @@       *  -@@   @@  ***@@   @*    -   *- -@-  @-  --*--*-   *    @@@@@@*@@@@@@@@@@",
	"@@@@@@@@@@@@@@**@**   @@-  -@*-*@@@-     *-  @@ --@@@   -@@   @@*       -*  *   @        *   @@-*   *@@@@@@@@@@@@@@@",
	"@@@@@@@@@@@@@@@@@   @*@@**@@@@*@@*  *   -@@  @@@ @@@@@ @@@@ -@@@@* -*@-@@@-@@@@- - --    @- @@@ @@-*  **-@@@@@@@@@@@",
	"@@@@@@@@@@@@@@*@*@@-@@@@@@@@@@@@@*      @@@ @@@@@@@@@@*@@@@ *@@@@@-@@@@@@@@@@@*-@@ @@ -@@@@*@@@@@@*@@@@@**@@@@@@@@@@",
	"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@**  @@@@@-@@@@@@@@@@@@@@* -@@@@@@@@@@@@@*@@@**@@ @@@-@@@@-@@@@@@@@@@@@@*@@@@@@@@@@",
	"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@**@@@@@@@@@@@@@@@@@@@@@*@@@@@@@@@@@@@@@@@@@*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
}

func printBloodyBanner() {
	shades := []string{
		"\033[38;2;160;0;0m",
		"\033[38;2;190;0;0m",
		"\033[38;2;220;0;0m",
		"\033[38;2;255;0;0m",
		"\033[38;2;255;0;0m",
		"\033[38;2;255;30;30m",
		"\033[38;2;255;20;20m",
		"\033[38;2;255;0;0m",
		"\033[38;2;235;0;0m",
		"\033[38;2;205;0;0m",
		"\033[38;2;175;0;0m",
		"\033[38;2;150;0;0m",
		"\033[38;2;130;0;0m",
		"\033[38;2;110;0;0m",
	}
	fmt.Println()
	for i, line := range bloodyBannerLines {
		color := "\033[38;2;255;0;0m"
		if i < len(shades) {
			color = shades[i]
		}
		fmt.Printf("%s%s\033[0m\n", color, line)
	}
	fmt.Printf("\033[38;2;220;20;60m%s\033[0m\n\n", "              [ NightfallLX (Go Edition v2.1) - Offensive Assessment Engine ]")
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
		isShodan       bool
		shodanKey      string
		isSiteMap      bool
		isCrawlXSS     bool
		spiderDepth       int
		spiderMaxURLs     int
		isInteractive     bool
		targetListFile    string
		enableSPA         bool
		isDevbuster       bool
		includeSubdomains bool
		hideStatusRaw     string
		statusRaw         string
		delaySec          float64
		headersFlag       arrayFlags
		headers2Flag   arrayFlags
		cookie2        string
		scope          string
		scopeOff       bool

		// OAST Out-of-band listener
		oastListen  string
		oastHost    string
		oastWaitSec int

		// Time-based SQLi
		sqliDelaySec int

		// Parameter discovery
		discoverParams bool

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
		isJSON    bool
		rateLimit int

		// Native XSS Engine & Flag Mapping
		enableDOM        bool
		noDOM            bool
		enableDOMBrowser bool
		enableForms      bool
		enableParamBrute bool
		xssFuzz          bool
		logFile          string
		headerLongFlag   arrayFlags
		enableStored     bool

		// Version-Matched Intel Flags
		intelQuery       string
		noIntel          bool
		enableNVD        bool
		enableMSFSearch  bool
		wpscanToken      string
		downloadExploits bool
		lootDir          string

		// Extensibility & reporting
		runPlugins bool
		pluginDir  string
		writeHTML  bool
		writeSARIF bool

		// Resume, profiles, and updates
		resumeScan    bool
		profileName   string
		saveProfile   string
		noUpdateCheck bool
	)

	// Target & Input
	flag.StringVar(&rawURL, "u", "", "Target URL or template (e.g. http://10.129.x.x/FUZZ or http://target.lab/?id=1)")
	flag.StringVar(&targetListFile, "l", "", "Path to file containing list of target URLs for batch scanning (one URL per line)")
	flag.StringVar(&targetListFile, "list", "", "Alias for -l")
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

	// Parameter Discovery (Arjun-style & XSStrike style)
	flag.BoolVar(&discoverParams, "discover-params", false, "Discover hidden HTTP parameters via response bisection (-w required)")
	flag.BoolVar(&enableParamBrute, "param-brute", false, "Brute-force hidden parameters (-w wordlist)")

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

	// Native XSS Engine & XSStrike Compatibility Flags
	flag.BoolVar(&enableDOM, "dom", true, "Enable static DOM XSS source-to-sink analysis (default: true; disable with -dom=false or --no-dom)")
	flag.BoolVar(&noDOM, "no-dom", false, "Disable static DOM XSS source-to-sink analysis")
	flag.BoolVar(&enableDOMBrowser, "dom-browser", false, "Validate DOM XSS with headless Chrome/Chromium if installed")
	flag.BoolVar(&enableForms, "forms", false, "Automatically extract and test HTML forms with CSRF refresh")
	flag.BoolVar(&xssFuzz, "xss-fuzz", false, "Fuzz parameters with filter survival probing")
	flag.StringVar(&logFile, "log", "", "Log assessment results to specified file")
	flag.Var(&headerLongFlag, "header", "Custom HTTP Header (repeatable alias for -H)")
	flag.BoolVar(&enableStored, "stored", false, "Test for stored XSS via form submission and re-crawling")

	// Version-Matched Reference Lookup (Searchsploit & NVD)
	flag.StringVar(&intelQuery, "intel-query", "", "Manual product and version query for searchsploit / NVD reference lookup (e.g. 'Apache 2.4.49')")
	flag.BoolVar(&noIntel, "no-intel", false, "Disable automatic version-matched reference lookup")
	flag.BoolVar(&enableNVD, "nvd", false, "Query NIST NVD 2.0 REST API for CVEs and CVSS scores")
	flag.BoolVar(&enableMSFSearch, "msf-search", true, "Use dynamic msfconsole module search in exploit-mapper (default: true)")
	flag.StringVar(&wpscanToken, "wpscan-token", os.Getenv("WPSCAN_API_TOKEN"), "WPScan API token for WordPress core/plugin/theme CVEs (or WPSCAN_API_TOKEN)")
	flag.BoolVar(&downloadExploits, "download-exploits", false, "Download raw Exploit-DB entries for mapped EDB-IDs into --loot-dir for manual review")
	flag.StringVar(&lootDir, "loot-dir", "loot", "Directory for downloaded Exploit-DB references (default: loot)")

	// Plugins, reporting, resume, profiles, and updates
	flag.BoolVar(&runPlugins, "plugins", false, "Load and execute .so plugins from --plugin-dir")
	flag.StringVar(&pluginDir, "plugin-dir", plugins.DefaultDir(), "Directory containing NightfallLX plugins (default: ~/.nightfalllx/plugins)")
	flag.BoolVar(&writeHTML, "html", false, "Write a dark-themed interactive HTML report (<output>.html)")
	flag.BoolVar(&writeSARIF, "sarif", false, "Write a SARIF 2.1.0 report (<output>.sarif)")
	flag.BoolVar(&resumeScan, "resume", false, "Resume an interrupted scan from .nightfalllx/state.json")
	flag.StringVar(&profileName, "profile", "", "Load a saved CLI profile from ~/.nightfalllx/profiles/<name>.json")
	flag.StringVar(&saveProfile, "save-profile", "", "Save the current CLI configuration as a named profile and exit")
	flag.BoolVar(&noUpdateCheck, "no-update-check", os.Getenv("NIGHTFALLX_NO_UPDATE_CHECK") == "1", "Disable the startup GitHub release update check")

	// Interactive Mouse Dashboard, Tech Detector, Sitemap & Shodan
	flag.BoolVar(&isInteractive, "i", false, "Launch interactive mouse-controllable TUI dashboard")
	flag.BoolVar(&isInteractive, "ui", false, "Alias for -i (Interactive Mouse TUI)")
	flag.BoolVar(&isInteractive, "tui", false, "Alias for -i (Interactive Mouse TUI)")
	flag.BoolVar(&isTech, "tech", false, "Run Wappalyzer-grade technology & exact version detector")
	flag.BoolVar(&isSiteMap, "map", false, "Spider and generate full web application architecture site map")
	flag.BoolVar(&isSiteMap, "spider", false, "Alias for --map")
	flag.BoolVar(&isCrawlXSS, "crawl", false, "Spider web application and run XSS engine on endpoints with parameters/forms")
	flag.IntVar(&spiderDepth, "depth", 3, "Web crawler recursion depth (default: 3)")
	flag.IntVar(&spiderMaxURLs, "max-urls", 50, "Max URLs to discover during spidering (default: 50)")
	flag.BoolVar(&enableSPA, "spa", false, "Enable headless Chrome SPA rendering & client-side route discovery in crawler")
	flag.BoolVar(&isDevbuster, "devbuster", false, "Modern web application scope-aware crawler & JS bundle route fuzzer (devbuster)")
	flag.BoolVar(&isDevbuster, "dbuster", false, "Alias for --devbuster")
	flag.BoolVar(&includeSubdomains, "include-subdomains", false, "Include subdomains in scope during devbuster crawl")
	flag.StringVar(&hideStatusRaw, "hide-status", "", "Hide status codes in devbuster/crawler (comma-separated, e.g. 403,404)")
	flag.StringVar(&statusRaw, "status", "", "Only show status codes in devbuster/crawler (comma-separated, e.g. 200,301,302)")
	flag.Float64Var(&delaySec, "delay", 0, "Delay between requests in seconds (e.g. 0.5)")
	flag.BoolVar(&isShodan, "shodan", false, "Run Shodan OSINT intelligence reconnaissance on target IP/domain")
	flag.StringVar(&shodanKey, "shodan-key", "", "Shodan API Key (optional, defaults to SHODAN_API_KEY env)")

	// Vulnerability Assessment Modules
	flag.StringVar(&moduleList, "m", "all", "Comma-separated modules: sqli, ssti, lfi, cmdi, xss, cors, redirect, ssrf, jwt, waf, idor, csrf, xxe, nosqli, upload (opt-in), headers, exposure, hostheader, crlf, graphql, protopollution, massassign, deserialize, exploit-mapper (or 'all')")

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
	flag.StringVar(&wordlist, "w", "", "Wordlist file path or auto-keyword (common, lfi, params, rockyou, 4digit, colors, cities, pins, users; default: auto-resolved)")
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
		printBloodyBanner()
		fmt.Println("Usage:")
		fmt.Println("  nightfalllx -u <URL> [options]")
		fmt.Println("  nightfalllx -u <URL> -devbuster [-w routes.txt] [options]")
		fmt.Println("  nightfalllx -l <targets.txt> [options]")
		fmt.Println("  nightfalllx -r <request.txt> [options]")
		fmt.Println("  nightfalllx -u <URL>/FUZZ -w <wordlist.txt> [fuzzing options]")
		fmt.Println("  nightfalllx -domain <target.lab> -w <subdomains.txt> [subdomain options]")
		fmt.Println("\nExamples:")
		fmt.Println("  nightfalllx -l targets.txt -m sqli,xss -o batch_report")
		fmt.Println("  nightfalllx -u http://target.lab/ -devbuster -w routes.txt --hide-status 403,404")
		fmt.Println("  nightfalllx -u http://target.lab/ -map -spa")
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

	explicitFlags := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		explicitFlags[f.Name] = true
	})

	if profileName != "" {
		saved, err := profile.Load(profileName)
		if err != nil {
			fmt.Printf("\033[31m[!] Could not load profile %q: %v\033[0m\n", profileName, err)
			os.Exit(1)
		}
		if err := profile.Apply(flag.CommandLine, saved, explicitFlags); err != nil {
			fmt.Printf("\033[31m[!] Could not apply profile %q: %v\033[0m\n", profileName, err)
			os.Exit(1)
		}
		fmt.Printf("\033[32m[+] Loaded profile: %s\033[0m\n", saved.Name)
	}

	if saveProfile != "" {
		captured := profile.Capture(flag.CommandLine, "profile", "save-profile")
		path, err := profile.Save(saveProfile, captured)
		if err != nil {
			fmt.Printf("\033[31m[!] Could not save profile: %v\033[0m\n", err)
			os.Exit(1)
		}
		fmt.Printf("\033[32m[+] Profile saved to %s\033[0m\n", path)
		return
	}

	if targetListFile != "" {
		code := runTargetList(ctx, multiTargetOptions{
			Path:          targetListFile,
			BaseOutput:    output,
			LogFile:       logFile,
			NoUpdateCheck: noUpdateCheck,
			Args:          os.Args[1:],
		})
		os.Exit(code)
	}

	if noDOM {
		enableDOM = false
	}

	// Merge --header into headersFlag
	for _, h := range headerLongFlag {
		_ = headersFlag.Set(h)
	}

	var globalLimiter *client.RateLimiter
	if rateLimit > 0 {
		globalLimiter = client.NewRateLimiter(rateLimit)
	}

	// Handle XSStrike habit: -m POST maps to -X POST
	if strings.EqualFold(moduleList, "POST") {
		method = "POST"
		moduleList = "all"
	} else if strings.HasPrefix(strings.ToUpper(moduleList), "POST,") {
		method = "POST"
		moduleList = strings.TrimPrefix(moduleList, "POST,")
	}

	if enableParamBrute {
		discoverParams = true
	}

	if isVersion {
		fmt.Printf("NightfallLX v%s (Go Edition) - High-Performance Web Assessment & Recon Suite\n", version.Version)
		return
	}

	printBloodyBanner()

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

	if !noUpdateCheck && ctx.Err() == nil {
		updateCtx, cancelUpdate := context.WithTimeout(ctx, 3*time.Second)
		check, err := update.NewClient().Check(updateCtx)
		cancelUpdate()
		if err == nil && check != nil && check.UpdateAvailable {
			fmt.Printf("\033[33m[!] NightfallLX %s is available (current %s). %s\033[0m\n",
				check.LatestVersion, check.CurrentVersion, check.URL)
		}
	}

	// 6. Standalone Tech Detector Mode
	if isTech {
		techTimeout := time.Duration(timeoutSec) * time.Second
		if techTimeout < 15*time.Second {
			techTimeout = 15 * time.Second
		}
		httpClient := client.NewClient(proxy, techTimeout, insecure, cookie, parsedHeaders)
		httpClient.SetContext(ctx)
		httpClient.Limiter = globalLimiter
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
		sp.EnableSPA = enableSPA
		sp.SetContext(ctx)
		sp.Limiter = globalLimiter
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

	// 6d. Devbuster Modern Route Discovery & Scope-Aware Fuzzer Mode
	if isDevbuster {
		dbCfg := &devbuster.Config{
			TargetURL:         rawURL,
			Depth:             spiderDepth,
			Concurrency:       threads,
			Delay:             time.Duration(delaySec * float64(time.Second)),
			Timeout:           time.Duration(timeoutSec) * time.Second,
			Headers:           parsedHeaders,
			IncludeSubdomains: includeSubdomains,
			WordlistPath:      wordlist,
			Browser:           enableSPA,
			Proxy:             proxy,
			Insecure:          insecure,
			Context:           ctx,
			Limiter:           globalLimiter,
		}
		if statusRaw != "" {
			dbCfg.OnlyStatus = parseCodes(statusRaw)
		}
		if hideStatusRaw != "" {
			dbCfg.HideStatus = parseCodes(hideStatusRaw)
		}

		words, srcName, errWords := wordlists.Resolve(wordlists.CategoryCommon, wordlist)
		if errWords == nil && len(words) > 0 {
			dbCfg.Wordlist = words
			if wordlist == "" {
				fmt.Printf("\033[36m[*] Devbuster: Auto-selected default wordlist: %s (%d candidates)\033[0m\n", srcName, len(words))
			} else {
				fmt.Printf("\033[36m[*] Devbuster using %s (%d candidates)\033[0m\n", srcName, len(words))
			}
		}

		crawler, err := devbuster.NewCrawler(dbCfg)
		if err != nil {
			fmt.Printf("\033[31m[!] Devbuster init failed: %v\033[0m\n", err)
			os.Exit(1)
		}

		findings, err := crawler.Run(ctx)
		if err != nil && ctx.Err() == nil {
			fmt.Printf("\033[31m[!] Devbuster error: %v\033[0m\n", err)
		}

		fmt.Printf("\n\n\033[1;32m[+] Devbuster completed! Total routes discovered: %d\033[0m\n", len(findings))

		if output != "" {
			jsonStr, errJSON := devbuster.ToJSON(findings)
			if errJSON == nil {
				jsonPath := output + ".json"
				_ = os.WriteFile(jsonPath, []byte(jsonStr), 0644)
				fmt.Printf("\033[36m[*] Devbuster findings saved to: %s\033[0m\n", jsonPath)
			}
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
		if !isSubdomain {
			words, srcName, errWords := wordlists.Resolve(wordlists.CategoryCommon, wordlist)
			if errWords == nil && len(words) > 0 {
				if wordlist == "" {
					fmt.Printf("\033[36m[*] No -w provided. Auto-selected default wordlist: %s (%d candidates)\033[0m\n", srcName, len(words))
				} else {
					fmt.Printf("\033[36m[*] Fuzzing using %s (%d candidates)\033[0m\n", srcName, len(words))
				}
			}
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
			Context:       ctx,
			Limiter:       globalLimiter,
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
	httpClient.SetContext(ctx)
	httpClient.ScopeHosts = scopeHosts
	httpClient.ScopeOff = scopeOff
	httpClient.Limiter = globalLimiter

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

	xssCfg := xss.DefaultEngineConfig()
	xssCfg.EnableDOM = enableDOM
	xssCfg.EnableDOMBrowser = enableDOMBrowser
	xssCfg.EnableForms = enableForms
	xssCfg.EnableStored = enableStored
	xssCfg.FuzzMode = xssFuzz

	// Crawl & Scan XSS Engine (--crawl)
	if isCrawlXSS {
		fmt.Printf("\033[36m[*] Spidering %s (depth=%d, max-urls=%d) to discover endpoints for XSS engine...\033[0m\n", rawURL, spiderDepth, spiderMaxURLs)
		crawlFindings, err := RunCrawlAndScanXSSWithContextAndSPA(ctx, rawURL, spiderDepth, spiderMaxURLs, enableSPA, xssCfg, httpClient, parsedHeaders)
		if err != nil {
			fmt.Printf("\033[31m[!] Crawl error: %v\033[0m\n", err)
			os.Exit(1)
		}
		if len(crawlFindings) == 0 {
			fmt.Println("\033[32m[+] Crawl and XSS scan completed with 0 findings.\033[0m")
		} else {
			fmt.Printf("\033[32m[+] Crawl and XSS scan completed with %d finding(s)!\033[0m\n", len(crawlFindings))
			for _, f := range crawlFindings {
				fmt.Printf("    [%s] %s on %s (param: %s)\n", f.ConfidenceLevel, f.Title, f.URL, f.Parameter)
			}
			if output != "" {
				crawlTarget := &modules.Target{URL: rawURL, Method: "GET"}
				_ = reporters.WriteMarkdownReport(crawlTarget, crawlFindings, output+".md")
				_ = reporters.WriteJSONReport(crawlTarget, crawlFindings, output+".json")
				if writeHTML {
					_ = reporters.WriteHTMLReport(crawlTarget, crawlFindings, output+".html")
				}
				if writeSARIF {
					_ = reporters.WriteSARIFReport(crawlTarget, crawlFindings, output+".sarif")
				}
			}
		}
		return
	}

	// Parameter Discovery (Arjun-style)
	if discoverParams {
		words, srcName, errWords := wordlists.Resolve(wordlists.CategoryParams, wordlist)
		if errWords != nil || len(words) == 0 {
			words = wordlists.LoadParams()
			srcName = "SecLists burp-parameter-names.txt"
		}
		if wordlist == "" {
			fmt.Printf("\033[36m[*] -discover-params: Auto-selected default wordlist: %s (%d parameters)\033[0m\n", srcName, len(words))
		} else {
			fmt.Printf("\033[36m[*] -discover-params using %s (%d parameters)...\033[0m\n", srcName, len(words))
		}

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

	// Step 1.4: Load resumable scan state.
	statePath := state.DefaultPath()
	var resumeState *state.ScanState
	if resumeScan {
		saved, errState := state.Load(statePath)
		if errState != nil {
			fmt.Printf("\033[31m[!] Could not load resume state from %s: %v\033[0m\n", statePath, errState)
			os.Exit(1)
		}
		if saved.TargetURL != "" && !strings.EqualFold(strings.TrimRight(saved.TargetURL, "/"), strings.TrimRight(target.URL, "/")) {
			fmt.Printf("\033[31m[!] Resume state belongs to %s, not %s\033[0m\n", saved.TargetURL, target.URL)
			os.Exit(1)
		}
		if saved.Method != "" && !strings.EqualFold(saved.Method, target.Method) {
			fmt.Printf("\033[31m[!] Resume state uses method %s, not %s\033[0m\n", saved.Method, target.Method)
			os.Exit(1)
		}
		resumeState = saved
		fmt.Printf("\033[36m[*] Resuming scan: %d module(s) already complete, %d finding(s) restored\033[0m\n",
			len(saved.CompletedModules), len(saved.Findings))
	}

	// Step 1.5: Version-Matched Reference Lookup (Searchsploit & NVD)
	var intelRep *intel.IntelReport
	if resumeState != nil && resumeState.Intel != nil {
		intelRep = resumeState.Intel
	} else if !noIntel {
		var respHeaders http.Header
		var landingBody string
		if baseResp, errBase := httpClient.Get(rawURL); errBase == nil && baseResp != nil {
			respHeaders = baseResp.Headers
			landingBody = baseResp.Body
		}

		var techs []*detector.Technology
		if techRep != nil {
			techs = techRep.Technologies
		}
		pvList := intel.ExtractProductVersions(techs, respHeaders, landingBody, intelQuery)
		if len(pvList) > 0 {
			fmt.Printf("\n\033[36m[*] Running Version-Matched Reference Lookup for %d detected component(s)...\033[0m\n", len(pvList))
			intelRep = intel.RunIntelContext(ctx, rawURL, pvList, enableNVD)
			if intelRep != nil && len(intelRep.Findings) > 0 {
				fmt.Println("\n\033[1;33m[!] Version-matched intel (not verified)\033[0m")
				fmt.Printf("    \033[90m%s\033[0m\n", intelRep.Disclaimer)
				for _, f := range intelRep.Findings {
					cveStr := strings.Join(f.CVEs, ", ")
					if cveStr == "" {
						cveStr = f.EDBID
					}
					metaRef := f.LocalPath
					if metaRef == "" && f.CVSS > 0 {
						metaRef = fmt.Sprintf("CVSS: %.1f", f.CVSS)
					}
					fmt.Printf("    \033[33m[%s]\033[0m \033[1m%s\033[0m (%s) -> %s\n", f.Source, f.Title, cveStr, metaRef)
				}
			} else {
				fmt.Println("\033[32m[-] No version-matched public CVE/exploit references matched for detected versions.\033[0m")
			}
		}
	}

	fmt.Printf("\n\033[1;36mNightfallLX (Go Edition v%s)\033[0m - Web Assessment Framework\n", version.Version)
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

	availableModules := modules.Registry(xssCfg)
	availableModules["sqli"] = sqliModule
	if exploitMapper, ok := availableModules["exploit-mapper"].(*modules.ExploitMapperModule); ok {
		exploitMapper.EnableMSFSearch = enableMSFSearch
		exploitMapper.WPScanToken = strings.TrimSpace(wpscanToken)
		exploitMapper.NVDAPIKey = strings.TrimSpace(os.Getenv("NVD_API_KEY"))
		exploitMapper.DownloadExploits = downloadExploits
		exploitMapper.LootDir = lootDir
	}

	var activeModules []modules.Module
	if moduleList == "all" {
		for _, name := range modules.DefaultOrder() {
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
	scanState := &state.ScanState{
		TargetURL:  target.URL,
		Method:     target.Method,
		ModuleList: moduleList,
		Findings:   allFindings,
		Intel:      intelRep,
	}
	if resumeState != nil {
		allFindings = append(allFindings, resumeState.Findings...)
		scanState.Findings = allFindings
		scanState.CompletedModules = append(scanState.CompletedModules, resumeState.CompletedModules...)
	}
	for _, mod := range activeModules {
		if resumeState != nil && resumeState.IsCompleted(mod.Name()) {
			continue
		}
		scanState.PendingModules = append(scanState.PendingModules, mod.Name())
	}
	if err := state.Save(statePath, scanState); err != nil {
		fmt.Printf("\033[33m[!] Warning: could not save resume state: %v\033[0m\n", err)
	}

	for _, mod := range activeModules {
		if resumeState != nil && resumeState.IsCompleted(mod.Name()) {
			fmt.Printf("\033[90m[*] Skipping completed module: %s\033[0m\n", mod.Name())
			continue
		}
		if ctx.Err() != nil {
			saveInterruptedState(statePath, scanState)
			os.Exit(130)
		}
		fmt.Printf("\033[36m[*] Running module: \033[1m%-14s\033[0m (%s) ...\n", mod.Name(), mod.Description())
		findings, err := mod.Run(target, httpClient)
		if err != nil {
			fmt.Printf("    \033[31m[!] Error running %s: %v\033[0m\n", mod.Name(), err)
			if ctx.Err() != nil {
				saveInterruptedState(statePath, scanState)
				os.Exit(130)
			}
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
		scanState.Findings = allFindings
		scanState.MarkCompleted(mod.Name())
		if err := state.Save(statePath, scanState); err != nil {
			fmt.Printf("\033[33m[!] Warning: could not save resume state: %v\033[0m\n", err)
		}
		if ctx.Err() != nil {
			saveInterruptedState(statePath, scanState)
			os.Exit(130)
		}
	}

	// Optional runtime plugins.
	if runPlugins {
		loadedPlugins := plugins.LoadAll(pluginDir)
		if len(loadedPlugins) == 0 {
			fmt.Printf("\033[33m[!] No compatible plugins found in %s\033[0m\n", pluginDir)
		}
		for _, loaded := range loadedPlugins {
			if loaded.Error != nil {
				fmt.Printf("    \033[31m[!] Plugin %s: %v\033[0m\n", loaded.Path, loaded.Error)
				continue
			}
			if ctx.Err() != nil {
				saveInterruptedState(statePath, scanState)
				os.Exit(130)
			}
			fmt.Printf("\033[36m[*] Running plugin: \033[1m%s\033[0m ...\n", loaded.Name)
			result, err := loaded.Plugin.Execute(target.URL, httpClient.HTTPClient())
			if err != nil {
				fmt.Printf("    \033[31m[!] Plugin %s failed: %v\033[0m\n", loaded.Name, err)
				continue
			}
			allFindings = append(allFindings, &modules.Finding{
				Module:          "plugin:" + loaded.Name,
				Title:           "Plugin result: " + loaded.Name,
				Severity:        modules.SeverityInfo,
				Confidence:      100,
				ConfidenceLevel: modules.ConfidenceConfirmed,
				URL:             target.URL,
				Parameter:       "plugin",
				Detail:          result,
				DetailFormat:    "text",
				Evidence:        loaded.Path,
				Remediation:     "Review the plugin output and validate any observations manually.",
			})
			scanState.Findings = allFindings
			if err := state.Save(statePath, scanState); err != nil {
				fmt.Printf("\033[33m[!] Warning: could not save resume state: %v\033[0m\n", err)
			}
		}
	}

	if ctx.Err() != nil {
		saveInterruptedState(statePath, scanState)
		os.Exit(130)
	}

	mdFile := output + ".md"
	jsonFile := output + ".json"
	reporters.WriteMarkdownReportWithIntel(target, allFindings, intelRep, mdFile)
	reporters.WriteJSONReportWithIntel(target, allFindings, intelRep, jsonFile)
	if logFile != "" {
		_ = reporters.WriteMarkdownReportWithIntel(target, allFindings, intelRep, logFile)
	}
	htmlFile := output + ".html"
	sarifFile := output + ".sarif"
	if writeHTML {
		if err := reporters.WriteHTMLReportWithIntel(target, allFindings, intelRep, htmlFile); err != nil {
			fmt.Printf("\033[33m[!] Could not write HTML report: %v\033[0m\n", err)
		}
	}
	if writeSARIF {
		if err := reporters.WriteSARIFReportWithIntel(target, allFindings, intelRep, sarifFile); err != nil {
			fmt.Printf("\033[33m[!] Could not write SARIF report: %v\033[0m\n", err)
		}
	}
	_ = state.Remove(statePath)

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Printf("\033[1mScan Finished!\033[0m Total Findings: \033[1;32m%d\033[0m\n", len(allFindings))
	fmt.Printf("Reports saved to:\n  Markdown: \033[32m%s\033[0m\n  JSON:     \033[32m%s\033[0m\n", mdFile, jsonFile)
	if writeHTML {
		fmt.Printf("  HTML:     \033[32m%s\033[0m\n", htmlFile)
	}
	if writeSARIF {
		fmt.Printf("  SARIF:    \033[32m%s\033[0m\n", sarifFile)
	}
	if logFile != "" {
		fmt.Printf("  Log:      \033[32m%s\033[0m\n", logFile)
	}
	fmt.Println(strings.Repeat("=", 60))
}

func saveInterruptedState(path string, st *state.ScanState) {
	if err := state.Save(path, st); err != nil {
		fmt.Printf("\033[31m[!] Could not save interrupted state: %v\033[0m\n", err)
		return
	}
	fmt.Printf("\n\033[33m[!] Scan interrupted. Progress saved to %s. Resume with --resume.\033[0m\n", path)
}

// RunCrawlAndScanXSS spiders the target application and executes the XSS module on discovered URLs with parameters or forms.
func RunCrawlAndScanXSS(targetURL string, depth, maxURLs int, xssCfg *xss.EngineConfig, c *client.Client, customHeaders map[string]string) ([]*modules.Finding, error) {
	return RunCrawlAndScanXSSWithContext(context.Background(), targetURL, depth, maxURLs, xssCfg, c, customHeaders)
}

// RunCrawlAndScanXSSWithContext is the cancellable crawl-and-scan entry point.
func RunCrawlAndScanXSSWithContext(ctx context.Context, targetURL string, depth, maxURLs int, xssCfg *xss.EngineConfig, c *client.Client, customHeaders map[string]string) ([]*modules.Finding, error) {
	return RunCrawlAndScanXSSWithContextAndSPA(ctx, targetURL, depth, maxURLs, false, xssCfg, c, customHeaders)
}

// RunCrawlAndScanXSSWithContextAndSPA spiders the target application with optional SPA headless rendering and scans discovered endpoints.
func RunCrawlAndScanXSSWithContextAndSPA(ctx context.Context, targetURL string, depth, maxURLs int, enableSPA bool, xssCfg *xss.EngineConfig, c *client.Client, customHeaders map[string]string) ([]*modules.Finding, error) {
	sp, err := sitemap.NewSpider(targetURL, depth, maxURLs)
	if err != nil {
		return nil, fmt.Errorf("spider init failed: %w", err)
	}
	sp.EnableSPA = enableSPA
	sp.SetContext(ctx)
	if c != nil && c.Limiter != nil {
		sp.Limiter = c.Limiter
	}
	sm := sp.Crawl()

	var targets []*modules.Target
	seenURLs := make(map[string]bool)

	for _, ep := range sm.Endpoints {
		u, errParse := url.Parse(ep.URL)
		if errParse != nil {
			continue
		}

		// 1. Query parameters
		q := u.Query()
		if len(q) > 0 {
			params := make(map[string]string)
			for k, v := range q {
				if len(v) > 0 {
					params[k] = v[0]
				} else {
					params[k] = "test"
				}
			}
			cleanURL := fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
			tKey := "GET:" + cleanURL + "?" + u.RawQuery
			if !seenURLs[tKey] {
				seenURLs[tKey] = true
				targets = append(targets, &modules.Target{
					URL:     cleanURL,
					Method:  "GET",
					Params:  params,
					Headers: customHeaders,
				})
			}
		}

		// 2. Forms
		for _, form := range ep.Forms {
			formAction := form.Action
			if formAction == "" {
				formAction = ep.URL
			} else if strings.HasPrefix(formAction, "/") {
				base, _ := url.Parse(ep.URL)
				if base != nil {
					formAction = fmt.Sprintf("%s://%s%s", base.Scheme, base.Host, formAction)
				}
			}
			fMethod := "POST"
			if strings.EqualFold(form.Method, "GET") {
				fMethod = "GET"
			}
			inputs := make(map[string]string)
			for _, inp := range form.Inputs {
				inputs[inp] = "test"
			}
			if len(inputs) > 0 {
				tKey := fMethod + ":" + formAction
				if !seenURLs[tKey] {
					seenURLs[tKey] = true
					if fMethod == "POST" {
						targets = append(targets, &modules.Target{
							URL:     formAction,
							Method:  "POST",
							Data:    inputs,
							Headers: customHeaders,
						})
					} else {
						targets = append(targets, &modules.Target{
							URL:     formAction,
							Method:  "GET",
							Params:  inputs,
							Headers: customHeaders,
						})
					}
				}
			}
		}
	}

	if len(targets) == 0 {
		fmt.Println("[*] Notice: No URLs with parameters or forms found during crawl.")
		return nil, nil
	}

	fmt.Printf("[+] Crawl discovered %d testable target endpoint(s) with parameters/forms. Running XSS engine...\n", len(targets))

	xssMod := modules.NewXSSModuleWithConfig(xssCfg)
	var allFindings []*modules.Finding

	for _, t := range targets {
		if ctx.Err() != nil {
			return allFindings, ctx.Err()
		}
		fList, errScan := xssMod.Run(t, c)
		if errScan == nil && len(fList) > 0 {
			allFindings = append(allFindings, fList...)
		}
	}

	if ctx.Err() != nil {
		return allFindings, ctx.Err()
	}
	return allFindings, nil
}
