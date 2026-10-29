package main

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/cvss"
	"nightfalllx/pkg/detector"
	"nightfalllx/pkg/fuzzer"
	"nightfalllx/pkg/modules"
	"nightfalllx/pkg/nuclei_engine"
	"nightfalllx/pkg/osint"
	"nightfalllx/pkg/parser"
	"nightfalllx/pkg/portscan"
	"nightfalllx/pkg/race"
	"nightfalllx/pkg/reporters"
	"nightfalllx/pkg/secrets"
	"nightfalllx/pkg/shodan"
	"nightfalllx/pkg/sitemap"
	"nightfalllx/pkg/troubleshoot"
	"nightfalllx/pkg/tui"
	"nightfalllx/pkg/webgui"
	"os"
	"os/exec"
	"regexp"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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


func getReportOutputBase(userOutput, domain, rawURL, suffix string) string {
	cleanName := ""
	if domain != "" {
		cleanName = osint.CleanDomain(domain)
	} else if rawURL != "" {
		if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
			cleanName = osint.CleanDomain(u.Hostname())
		} else {
			cleanName = osint.CleanDomain(rawURL)
		}
	}
	if cleanName == "" {
		cleanName = "target"
	}

	if userOutput != "" && userOutput != "lab_report" {
		return userOutput
	}

	if suffix != "" {
		return fmt.Sprintf("/tmp/%s_%s", cleanName, suffix)
	}
	return fmt.Sprintf("/tmp/%s_report", cleanName)
}


func syncToDownloadsIfTmp(htmlPath string) {
	if strings.HasPrefix(htmlPath, "/tmp/") {
		if homeDir, err := os.UserHomeDir(); err == nil && homeDir != "" {
			dlDir := filepath.Join(homeDir, "Downloads")
			_ = os.MkdirAll(dlDir, 0755)
			dlPath := filepath.Join(dlDir, filepath.Base(htmlPath))
			if data, err := os.ReadFile(htmlPath); err == nil {
				_ = os.WriteFile(dlPath, data, 0644)
			}
		}
	}
}

func printViewCommand(filePath string) {
	syncToDownloadsIfTmp(filePath)
	fmt.Printf("\033[1;32m[+] Interactive HTML Dashboard saved to: %s\033[0m\n", filePath)
	browserCmd := "brave-browser"
	if _, err := exec.LookPath("brave-browser"); err != nil {
		if _, err := exec.LookPath("brave"); err == nil {
			browserCmd = "brave"
		} else if _, err := exec.LookPath("google-chrome"); err == nil {
			browserCmd = "google-chrome"
		} else if _, err := exec.LookPath("firefox"); err == nil {
			browserCmd = "firefox"
		} else {
			browserCmd = "xdg-open"
		}
	}
	fmt.Printf("\033[1;33m[*] To view the report in your browser, run:\033[0m\n")
	fmt.Printf("    \033[1;36m%s %s\033[0m\n\n", browserCmd, filePath)
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
		reportHTML     string
		reportSARIF    string
		reportJSON     string
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
		spiderDepth    int
		spiderMaxURLs  int
		isMineParams   bool
		isInteractive  bool
		headersFlag    arrayFlags
		headers2Flag   arrayFlags
		cookie2        string
		scope          string
		scopeOff       bool
		rateLimit      int
		maxRetries     int
		retryDelayMs   int
		enableHTTP2    bool
		rawHTTP        bool
		tamperHeaders  bool
		chunkedBody    bool
		adaptive       bool
		jitterMs       int
		rotateUA       bool
		adaptiveMin    int
		isScan         bool
		scanPorts      string
		scanCVE        bool
		isRace         bool
		raceThreads    int
		raceRounds     int
		isNuclei       bool
		templatesPath  string
		templateTags   string
		nucleiSeverity string
		nucleiC        int
		nucleiEngine   string
		nucleiArgs     string
		isAuto         bool
		isWeb          bool
		webPort        int
		matchRegexStr  string
		filterRegexStr string
		autoRegex      bool
		isOSINT        bool
		isDorks        bool
		isAdmin        bool
		isEmails       bool
		is403Bypass    bool
		isGraphQL      bool
		isJSMiner      bool
		isTakeover     bool
		isGitAudit     bool
		isSmuggling    bool
		isDNSEnum      bool
		dnsServer      string
		dnsThreads     int
		dnsTimeout     int
		dnsWordlist    string
		dnsNoReverse   bool
		dnsWhois       bool
		dnsScrap       int
		dnsSubfile     string
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
	flag.BoolVar(&isMineParams, "mine-params", false, "Run hidden parameter miner to discover undocumented parameters")
	flag.BoolVar(&isMineParams, "param-miner", false, "Alias for --mine-params")
	flag.BoolVar(&isShodan, "shodan", false, "Run Shodan OSINT intelligence reconnaissance on target IP/domain")
	flag.StringVar(&shodanKey, "shodan-key", "", "Shodan API Key (optional, reads from SHODAN_API_KEY environment variable)")
	flag.BoolVar(&isOSINT, "osint", false, "Run comprehensive passive OSINT reconnaissance (crt.sh, DNS, SPF/DMARC, Wayback, GHDB, Admin Hunter)")
	flag.BoolVar(&isDorks, "dorks", false, "Generate Exploit-DB GHDB & DorkSearch intelligence queries for the target domain")
	flag.BoolVar(&isDorks, "ghdb", false, "Alias for --dorks")
	flag.BoolVar(&isAdmin, "admin", false, "Hunt and fingerprint exposed admin panels, dashboards, and login portals")
	flag.BoolVar(&isAdmin, "admin-hunter", false, "Alias for --admin")
	flag.BoolVar(&isEmails, "emails", false, "Harvest corporate email addresses and detect corporate email naming pattern")
	flag.BoolVar(&is403Bypass, "bypass-403", false, "Test 30+ authorization bypass vectors on 403 Forbidden / 401 Unauthorized endpoints")
	flag.BoolVar(&is403Bypass, "bypass", false, "Alias for --bypass-403")
	flag.BoolVar(&isGraphQL, "graphql", false, "Audit GraphQL instances for exposed introspection, query batching, and schema leaks")
	flag.BoolVar(&isGraphQL, "api-audit", false, "Alias for --graphql")
	flag.BoolVar(&isJSMiner, "mine-js", false, "Extract API routes, endpoints, and credentials from discovered JavaScript files")
	flag.BoolVar(&isJSMiner, "js-links", false, "Alias for --mine-js")
	flag.BoolVar(&isTakeover, "takeover", false, "Audit subdomains for dangling cloud CNAME DNS takeovers (AWS, GitHub, Heroku, etc.)")
	flag.BoolVar(&isTakeover, "sub-takeover", false, "Alias for --takeover")
	flag.BoolVar(&isGitAudit, "dump-git", false, "Audit and inspect exposed .git/ directories and repository metadata")
	flag.BoolVar(&isGitAudit, "git-audit", false, "Alias for --dump-git")
	flag.BoolVar(&isSmuggling, "smuggling", false, "Audit HTTP Request Smuggling desync vulnerabilities (CL.TE, TE.CL, TE.TE)")
	flag.BoolVar(&isSmuggling, "http-smuggle", false, "Alias for --smuggling")

	// Automated DNS Intelligence & Enum Engine (dnsenum)
	flag.BoolVar(&isDNSEnum, "dnsenum", false, "Run automated DNS enumeration & intelligence (dnsenum integration)")
	flag.BoolVar(&isDNSEnum, "dns", false, "Alias for --dnsenum")
	flag.BoolVar(&isDNSEnum, "dns-enum", false, "Alias for --dnsenum")
	flag.StringVar(&dnsServer, "dns-server", "", "Custom DNS server for queries (e.g. 8.8.8.8)")
	flag.IntVar(&dnsThreads, "dns-threads", 15, "Number of concurrent threads for DNS queries (default: 15)")
	flag.IntVar(&dnsTimeout, "dns-timeout", 5, "TCP/UDP timeout for DNS queries in seconds (default: 5)")
	flag.StringVar(&dnsWordlist, "dns-wordlist", "", "Custom wordlist for subdomain brute force in dnsenum")
	flag.BoolVar(&dnsNoReverse, "dns-noreverse", true, "Skip reverse lookup operations in dnsenum (default: true)")
	flag.BoolVar(&dnsWhois, "dns-whois", false, "Perform WHOIS queries on C class network ranges (dnsenum -w)")
	flag.IntVar(&dnsScrap, "dns-scrap", 0, "Max subdomains to scrape from Google (default: 0)")
	flag.StringVar(&dnsSubfile, "dns-subfile", "", "Write valid discovered subdomains to this file")


	// Vulnerability Assessment Modules
	flag.StringVar(&moduleList, "m", "all", "Comma-separated modules: sqli, ssti, lfi, cmdi, xss, cors, redirect, ssrf, jwt, waf, idor, csrf, xxe, nosqli, upload, headers, exposure, hostheader, crlf, secrets, race, userenum (or 'all')")

	// Network Port Scanning
	flag.BoolVar(&isScan, "scan", false, "Enable fast TCP port scanning mode")
	flag.StringVar(&scanPorts, "scan-ports", "top100", "Port range or profile: 'top100', '1-1024', or '80,443,8080'")
	flag.BoolVar(&scanCVE, "scan-cve", false, "Enrich open ports with live NIST NVD CVE lookup")

	// Race Condition Testing
	flag.BoolVar(&isRace, "race", false, "Run nanosecond-synchronized race condition & limit bypass attack")
	flag.IntVar(&raceThreads, "race-threads", 20, "Number of concurrent burst requests for race attack (default: 20)")
	flag.IntVar(&raceRounds, "race-rounds", 2, "Number of burst rounds to execute (default: 2)")

	// Nuclei Template DSL Engine
	flag.BoolVar(&isNuclei, "nuclei", false, "Execute high-speed concurrent Nuclei vulnerability engine")
	flag.StringVar(&templatesPath, "templates", "", "Path to Nuclei YAML template file or directory to execute (auto-discovered if omitted)")
	flag.StringVar(&templateTags, "template-tags", "", "Comma-separated tag filter for Nuclei templates (e.g. 'cve,misconfig')")
	flag.StringVar(&templateTags, "tags", "", "Alias for -template-tags")
	flag.StringVar(&nucleiSeverity, "sev", "", "Filter Nuclei templates by severity: 'critical,high,medium,low,info'")
	flag.StringVar(&nucleiSeverity, "severity", "", "Alias for -sev")
	flag.IntVar(&nucleiC, "nuclei-c", 35, "Concurrency for Nuclei execution (default: 35)")
	flag.StringVar(&nucleiEngine, "nuclei-engine", "auto", "Nuclei engine mode: 'auto' (preferred), 'official', or 'internal'")
	flag.StringVar(&nucleiArgs, "nuclei-args", "", "Additional custom CLI flags passed directly to official Nuclei binary")
	flag.BoolVar(&isAuto, "auto", false, "Autonomous full-scope scan: Recon, Tech, Crawler, Web Injections, Nuclei & Report")
	flag.BoolVar(&isWeb, "web", false, "Launch persistent Web Command Center & Generator dashboard (default: http://127.0.0.1:8888)")
	flag.BoolVar(&isWeb, "gui", false, "Alias for --web")
	flag.IntVar(&webPort, "web-port", 8888, "Port for Web Command Center dashboard (default: 8888)")
	flag.BoolVar(&isAuto, "full", false, "Alias for -auto")

	// HTTP Options
	flag.StringVar(&method, "X", "GET", "HTTP Method: GET, POST, PUT, etc.")
	flag.StringVar(&data, "d", "", "POST data body (e.g. 'user=FUZZ&pass=123')")
	flag.Var(&headersFlag, "H", "Custom HTTP Header (can repeat, e.g. -H 'Host: FUZZ.target.lab')")
	flag.StringVar(&cookie, "b", "", "Cookie header value")
	flag.StringVar(&proxy, "p", "", "HTTP proxy URL (e.g. http://127.0.0.1:8080 for Burp Suite)")
	flag.IntVar(&rateLimit, "rate", 0, "Max requests per second rate limit (default: 0 unlimited)")
	flag.IntVar(&maxRetries, "retry", 0, "Max retry attempts on 429/503 or dropped connection (default: 0)")
	flag.IntVar(&retryDelayMs, "retry-delay", 500, "Base retry delay in ms for exponential backoff (default: 500)")
	flag.BoolVar(&enableHTTP2, "http2", true, "Enable HTTP/2 support (default: true)")
	flag.BoolVar(&rawHTTP, "raw", false, "Use raw TCP/TLS socket HTTP mode")
	flag.BoolVar(&tamperHeaders, "tamper-headers", false, "Inject WAF bypass headers (X-Originating-IP, X-Forwarded-Host, X-Custom-IP-Authorization, ...)")
	flag.BoolVar(&chunkedBody, "chunked", false, "Send request bodies with Transfer-Encoding: chunked")
	flag.BoolVar(&adaptive, "adaptive", false, "Adaptive WAF throttling: 429/403 backoff, dynamic threads, jitter, UA rotation")
	flag.IntVar(&jitterMs, "jitter", 0, "Random delay between adaptive fuzz requests in ms (default: 0)")
	flag.BoolVar(&rotateUA, "rotate-ua", false, "Rotate realistic browser User-Agent fingerprints (adaptive mode)")
	flag.IntVar(&adaptiveMin, "adaptive-min", 1, "Minimum concurrency floor for adaptive throttling (default: 1)")
	flag.BoolVar(&insecure, "k", true, "Disable TLS certificate verification (default: true for labs)")
	flag.IntVar(&timeoutSec, "timeout", 15, "Request timeout in seconds (default: 15)")

	// Reporting
	flag.StringVar(&output, "o", "lab_report", "Output report base name")
	flag.StringVar(&reportHTML, "report-html", "", "Write interactive offline HTML dashboard to this path")
	flag.StringVar(&reportSARIF, "report-sarif", "", "Write SARIF v2.1.0 report to this path (GitHub / GitLab / DefectDojo)")
	flag.StringVar(&reportJSON, "report-json", "", "Write structured JSON report to this path")

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
	flag.StringVar(&matchRegexStr, "mr", "", "Match response body regular expression (e.g. -mr 'admin|dashboard')")
	flag.StringVar(&filterRegexStr, "fr", "", "Filter response body regular expression (e.g. -fr 'error|not found')")
	flag.BoolVar(&autoRegex, "auto-regex", false, "Automatically infer differential regex filter from baseline response")

	// Diagnostics & Version
	flag.BoolVar(&isDoctor, "doctor", false, "Run diagnostic checks and troubleshooting")
	flag.BoolVar(&isDoctor, "troubleshoot", false, "Alias for --doctor")
	var cvssVectorFlag string
	flag.StringVar(&cvssVectorFlag, "cvss", "", "Calculate and verify official CVSS v3.1 vector string (e.g. -cvss 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')")
	var isVersion bool
	flag.BoolVar(&isVersion, "version", false, "Show program version")
	flag.BoolVar(&isVersion, "V", false, "Alias for --version")

	flag.Usage = func() {
		fmt.Println(`
  ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗ █████╗ ██╗     ██╗     ██╗   ██╗
  ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔══██╗██║     ██║     ╚██╗ ██╔╝
  ██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ███████║██║     ██║      ╚████╔╝ 
  ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██╔══██║██║     ██║      ██╔═██╗ 
  ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║     ██║  ██║███████╗███████╗██╔╝ ██╗
  ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
  :: Next-Gen Web Assessment & Recon Suite :: [ Go Edition v2.0 ] ::

USAGE:
  nightfalllx -u <target-url> [options]
  nightfalllx -tech -u <target-url>
  nightfalllx -map -u <target-url>
  nightfalllx -shodan -u <target-url>
  nightfalllx -domain <target.com> -dorks
  nightfalllx -r <burp-request.txt> [options]
  nightfalllx -u "http://target.lab/FUZZ" -w wordlist.txt
  nightfalllx -i   (Launch Interactive Mouse-Controllable Dashboard)

TARGET SPECIFICATION:
  -u string        Target URL (e.g. http://10.129.x.x/index.php?id=1 or .../FUZZ)
  -r string        Burp Suite raw HTTP request file (e.g. -r request.txt)
  -domain string   Target domain for Subdomain & VHost discovery
  -https, -ssl     Force HTTPS scheme

ASSESSMENT, OSINT & RECON:
  -tech            Deep technology & exact version discovery (Wappalyzer-grade)
  -map, -spider    Spider target architecture & generate full sitemap
  -depth int       Crawler recursion depth (default: 3)
  -max-urls int    Max URLs to discover during spidering (default: 50)
  -shodan          Run Shodan OSINT reconnaissance (subdomains, ports, CVEs)
  -osint           Comprehensive passive OSINT (crt.sh, DNS, SPF/DMARC, Wayback, GHDB)
  -dorks, -ghdb    Generate Exploit-DB GHDB & DorkSearch intelligence dossier & clickable links
  -dnsenum, -dns   Automated DNS enumeration (Host A, NS, MX, AXFR zone transfer, Subdomains, Netranges)
  -dns-server str  Custom DNS server for queries (e.g. 8.8.8.8)
  -dns-threads int Threads for DNS queries (default: 15)
  -dns-timeout int Query timeout in seconds (default: 5)
  -dns-wordlist str Wordlist for subdomain brute-force (default: SecLists 5000 / dns.txt)
  -dns-whois       Perform WHOIS queries on C class network ranges (-w)
  -dns-noreverse   Skip reverse lookup operations (default: true)
  -dns-subfile str Save discovered subdomains to file
  -mine-params     Run automated hidden parameter miner (reflection/diff analysis)
  -shodan-key str  Shodan API Key (optional, reads from SHODAN_API_KEY env)
  -m string        Modules to run: sqli, ssti, lfi, cmdi, xss, cors, redirect, ssrf, jwt, waf, jsminer, gitdumper, smuggling, graphql, nuclei (default: "all")
  -mine-js         Extract hidden API routes, endpoints, and secrets from JavaScript (-js-links)
  -takeover        Audit subdomains for dangling cloud CNAME takeovers (-sub-takeover)
  -dump-git        Audit exposed .git/ directory and extract repo metadata (-git-audit)
  -smuggling       Audit HTTP Request Smuggling desync (CL.TE, TE.CL, TE.TE)

HIGH-SPEED FUZZING & VHOSTS (ffuf-style):
  -w string        Wordlist path for directory, parameter, or VHost fuzzing
  -t int           Concurrent Goroutines (default: 40)
  -sub, -subdomain Enable Subdomain & Virtual Host discovery mode
  -ac              Auto-calibrate baseline wildcard responses (default: true)
  -mc, -fc string  Match / Filter HTTP status codes (e.g. -mc 200,302 -fc 404)
  -ms, -fs string  Match / Filter response sizes in bytes
  -mw, -fw string  Match / Filter response word counts
  -ml, -fl string  Match / Filter response line counts
  -mr, -fr regex   Match / Filter response body regular expression (e.g. -mr 'admin|success')
  -auto-regex      Infer & apply differential regex filter automatically from baseline canary

INTERACTIVE & WEB DASHBOARD:
  -web, -gui       Launch persistent Web Command Center & Generator (http://127.0.0.1:8888)
  -web-port n      Port for Web Command Center (default: 8888)
  -i, -ui, -tui    Launch interactive mouse-controllable TUI dashboard
  -doctor          Run connectivity, DNS, TLS, and proxy diagnostics
  -version, -V     Show program version

HTTP & PROXY CONFIGURATION:
  -X string        HTTP Method: GET, POST, PUT, etc. (default: "GET")
  -d string        POST request data body
  -H value         Custom HTTP header (repeatable, e.g. -H "Authorization: Bearer ...")
  -b string        Cookie string
  -p string        Proxy URL (e.g. http://127.0.0.1:8080)
  -k               Insecure / Ignore TLS verification (default: true)
  -timeout int     Request timeout in seconds (default: 15)
  -rate int        Max requests per second (rate limit, default: 0 unlimited)
  -retry int       Retry attempts on 429/503 status (default: 0)
  -retry-delay ms  Base retry backoff delay in ms (default: 500)
  -http2           Enable HTTP/2 support (default: true)
  -raw             Use raw TCP/TLS socket HTTP mode
  -tamper-headers  Inject WAF bypass headers (X-Originating-IP, X-Forwarded-Host, ...)
  -chunked         Send request bodies with Transfer-Encoding: chunked
  -adaptive        Adaptive WAF throttling (429/403 backoff, jitter, UA rotation)
  -jitter ms       Random delay between adaptive requests (default: 0)
  -rotate-ua       Rotate realistic browser User-Agent fingerprints
  -adaptive-min n  Minimum concurrency floor for adaptive throttling (default: 1)
  -o string        Output report filename prefix (default: "lab_report")
  -report-html p   Write interactive offline HTML dashboard to path p
  -report-sarif p  Write SARIF v2.1.0 report to path p (GitHub/GitLab/DefectDojo)
  -report-json p   Write structured JSON report to path p

ADVANCED EXPLOITATION & EXPANSION:
  -scan            Enable fast TCP port scanning mode
  -scan-ports str  Port range or profile: 'top100', '1-1024', or '80,443' (default: 'top100')
  -scan-cve        Enrich open ports with live NIST NVD CVE lookup
  -race            Run nanosecond-synchronized race condition & limit bypass attack
  -race-threads n  Concurrent burst requests for race attack (default: 20)
  -race-rounds n   Number of burst rounds to execute (default: 2)
  -nuclei          Execute high-speed concurrent Nuclei vulnerability engine
  -templates path  Path to Nuclei YAML template file or directory (auto-discovered)
  -tags s          Filter Nuclei templates by tag (e.g. 'cve,misconfig,exposure')
  -sev s           Filter Nuclei templates by severity (e.g. 'critical,high,medium')
  -nuclei-c n      Concurrency for Nuclei execution (default: 35)
  -nuclei-engine s Engine mode: 'auto' (preferred), 'official', or 'internal' (default: 'auto')
  -nuclei-args s   Additional raw arguments passed directly to official Nuclei (e.g. '-dast -as')
  -auto, -full     Autonomous full-scope scan: Recon, Tech, Crawler, Web Injections, Nuclei & Report

CVSS v3.1 SCORING ENGINE:
  -cvss str        Calculate and verify official CVSS v3.1 vector string (e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')`)
	}

	flag.Parse()

	if rawURL == "" && len(flag.Args()) > 0 {
		for _, arg := range flag.Args() {
			trimmed := strings.TrimSpace(arg)
			if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") || strings.Contains(trimmed, ".") || strings.Contains(trimmed, ":") {
				rawURL = trimmed
				break
			}
		}
	}

	if rawURL != "" && !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		if isHTTPS {
			rawURL = "https://" + rawURL
		} else {
			rawURL = "http://" + rawURL
		}
	}

	if isVersion {
		fmt.Println("NightfallLX v2.0.0 (Go Edition) - High-Performance Web Assessment & Recon Suite")
		return
	}

	// Standalone CVSS v3.1 Calculation & Verification Engine
	if cvssVectorFlag != "" {
		res, err := cvss.CalculateVector(cvssVectorFlag)
		if err != nil {
			fmt.Printf("\033[31m[!] CVSS v3.1 Calculation Error: %v\033[0m\n", err)
			os.Exit(1)
		}
		var color string
		switch res.Severity {
		case "CRITICAL":
			color = "\033[35m"
		case "HIGH":
			color = "\033[31m"
		case "MEDIUM":
			color = "\033[33m"
		case "LOW":
			color = "\033[34m"
		default:
			color = "\033[37m"
		}
		fmt.Printf("\n\033[1m=== NightfallLX CVSS v3.1 Scoring Engine ===\033[0m\n")
		fmt.Printf("  Canonical Vector: \033[36m%s\033[0m\n", res.VectorString)
		fmt.Printf("  Base Score:       %s\033[1m%.1f\033[0m\n", color, res.BaseScore)
		fmt.Printf("  Severity Rating:  %s\033[1m%s\033[0m\n", color, res.Severity)
		fmt.Printf("  Impact Sub-Score: %.4f\n", res.ISS)
		fmt.Printf("  Impact Score:     %.4f\n", res.Impact)
		fmt.Printf("  Exploitability:   %.4f\n", res.Exploitability)
		fmt.Printf("  Specification:    FIRST.ORG CVSS v3.1 Specification Compliant\n\n")
		return
	}

	// Web Command Center & Generator Dashboard
	if isWeb {
		if err := webgui.StartServer("127.0.0.1", webPort); err != nil {
			fmt.Printf("\033[31m[!] Web server error: %v\033[0m\n", err)
			os.Exit(1)
		}
		return
	}

	// 0. Interactive Mouse-Controllable TUI Mode (only on explicit -i / -ui / -tui flag)
	if isInteractive {
		dash := tui.NewInteractiveTUI(rawURL)
		dash.Proxy = proxy
		dash.Wordlist = wordlist
		dash.RunLoop()
		return
	}

	// If no arguments or target given, show standard usage
	if len(os.Args) == 1 || (rawURL == "" && rawReqFile == "" && domain == "" && !isDoctor && !isScan && !isOSINT && !isDorks && !isTakeover && !isDNSEnum && !isAdmin && !isEmails && !isWeb) {
		flag.Usage()
		return
	}

	// 1. Troubleshooting / Doctor Mode
	if isDoctor {
		doc := troubleshoot.NewDoctor(rawURL, proxy, wordlist)
		checks := doc.RunAll()
		exitCode := troubleshoot.PrintDoctorReport(checks)
		os.Exit(exitCode)
	}

	// 2. Parse Custom Headers & Secondary Identity
	parsedHeaders := make(map[string]string)
	for _, h := range headersFlag {
		if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
			parsedHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	parsedHeaders2 := make(map[string]string)
	for _, h := range headers2Flag {
		if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
			parsedHeaders2[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Scope parsing
	var scopeHosts []string
	if scope != "" {
		if fileBytes, err := os.ReadFile(scope); err == nil {
			for _, line := range strings.Split(string(fileBytes), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					scopeHosts = append(scopeHosts, line)
				}
			}
		} else {
			for _, s := range strings.Split(scope, ",") {
				if s = strings.TrimSpace(s); s != "" {
					scopeHosts = append(scopeHosts, s)
				}
			}
		}
	}

	fmt.Println("\033[1;33m⚠️  Authorization Notice: Ensure you have explicit authorization to test target host(s).\033[0m")

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
	if rawURL == "" && domain != "" {
		rawURL = domain
	}

	if rawURL == "" && !isScan && !isOSINT && !isDorks && !isNuclei && !isDNSEnum && !isAdmin && !isEmails && !isTakeover {
		fmt.Println("\033[1;36mNightfallLX (Go Edition)\033[0m - High-Performance Web Assessment & Fuzzer")
		fmt.Println("Usage:")
		fmt.Println("  nightfalllx -i                                               # Launch interactive Mouse-controlled Dashboard")
		fmt.Println("  nightfalllx --tech -u http://target.lab                      # Wappalyzer-grade technology & version detector")
		fmt.Println("  nightfalllx -r request.txt                                   # Scan Burp Suite request")
		fmt.Println("  nightfalllx -sub -u http://10.129.x.x -domain target.htb     # ffuf-style VHost/Subdomain finder")
		fmt.Println("  nightfalllx -u http://10.129.x.x/FUZZ -w wordlist.txt -t 50  # Directory/Param fuzzer")
		fmt.Println("  nightfalllx -u http://target.lab -nuclei                     # High-speed auto-discovered Nuclei scan")
		fmt.Println("  nightfalllx -u http://target.lab -nuclei -tags cve,misconfig # Tagged CVE & misconfig scan")
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

	// 6b. Standalone Full Site Map & Web Crawler
	if isSiteMap {
		sp, err := sitemap.NewSpider(rawURL, spiderDepth, spiderMaxURLs)
		if err != nil {
			fmt.Printf("\033[31m[!] Spider init failed: %v\033[0m\n", err)
			os.Exit(1)
		}
		sm := sp.Crawl()
		sitemap.PrintSiteMap(sm)

		schemaClient := client.NewClient(proxy, time.Duration(timeoutSec)*time.Second, insecure, cookie, parsedHeaders)
		if schemas, err := parser.DetectAndParseAPISchemas(rawURL, schemaClient); err == nil && len(schemas) > 0 {
			fmt.Printf("\033[1;32m[+] Discovered %d API Routes from OpenAPI/GraphQL Schemas:\033[0m\n", len(schemas))
			for _, ep := range schemas {
				fmt.Printf("    ├── [%s] %-30s (%s)\n", ep.Method, ep.Path, ep.Summary)
			}
			fmt.Println()
		}
		return
	}

	// 6d. Standalone Hidden Parameter Miner
	if isMineParams {
		fmt.Printf("\n\033[1;35m[*] Launching Hidden Parameter Miner on: %s (%s)\033[0m\n", rawURL, method)
		miner := parser.NewParamMiner(&parser.MinerConfig{
			URL:       rawURL,
			Method:    method,
			Proxy:     proxy,
			Timeout:   time.Duration(timeoutSec) * time.Second,
			Insecure:  insecure,
			Cookie:    cookie,
			Headers:   parsedHeaders,
			BatchSize: 25,
		})
		discovered, err := miner.Mine()
		if err != nil {
			fmt.Printf("\033[31m[!] Parameter mining failed: %v\033[0m\n", err)
			os.Exit(1)
		}
		if len(discovered) == 0 {
			fmt.Println("\033[33m[-] No hidden parameters identified from wordlist.\033[0m")
		} else {
			fmt.Printf("\n\033[1;32m[+] Discovered %d Hidden Parameter(s):\033[0m\n", len(discovered))
			for _, dp := range discovered {
				fmt.Printf("    ├── \033[1;36m%-16s\033[0m [%s] Reason: %s (Status: %d, Diff: %+d bytes)\n",
					dp.Name, dp.Location, dp.Reason, dp.StatusCode, dp.LengthDiff)
				if dp.Evidence != "" {
					fmt.Printf("    │   └── Evidence: %s\n", dp.Evidence)
				}
			}
			fmt.Println()
		}
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

	// 6c-2. Standalone Passive OSINT Intelligence Engine
	if isOSINT {
		targetDomain := domain
		if targetDomain == "" {
			if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
				targetDomain = u.Hostname()
			} else {
				targetDomain = rawURL
			}
		}
		targetDomain = strings.TrimPrefix(targetDomain, "http://")
		targetDomain = strings.TrimPrefix(targetDomain, "https://")
		if idx := strings.Index(targetDomain, "/"); idx != -1 {
			targetDomain = targetDomain[:idx]
		}
		if idx := strings.Index(targetDomain, ":"); idx != -1 {
			targetDomain = targetDomain[:idx]
		}

		fmt.Printf("\n\033[1;35m[*] Launching Passive OSINT Reconnaissance on:\033[0m %s ...\n", targetDomain)
		rep, err := osint.RunOSINT(osint.Config{
			Domain:        targetDomain,
			Timeout:       time.Duration(timeoutSec) * time.Second,
			FetchArchive:  true,
			CheckTakeover: true,
			IncludeDorks:  true,
			CheckAdmin:    true,
			CheckAXFR:     true,
			CheckEmails:     true,
			CheckASN:        true,
			CheckDNSEnum:    true,
			DNSEnumWordlist: dnsWordlist,
		})
		if err != nil {
			fmt.Printf("\033[31m[!] OSINT failed: %v\033[0m\n", err)
			os.Exit(1)
		}
		osint.PrintOSINTReport(rep)

		basePath := getReportOutputBase(output, targetDomain, rawURL, "osint")
		htmlPath := basePath + ".html"
		if err := osint.ExportOSINTHTML(rep, htmlPath); err == nil {
			printViewCommand(htmlPath)
		}
		jsonPath := basePath + ".json"
		if jsonStr, err := osint.ExportOSINTJSON(rep); err == nil {
			_ = os.WriteFile(jsonPath, []byte(jsonStr), 0644)
			fmt.Printf("\033[1;32m[+] JSON OSINT Dossier saved to: %s\033[0m\n", jsonPath)
		}
		return
	}

	// 6c-3. Standalone Exploit-DB GHDB & DorkSearch OSINT Engine
	if isDorks {
		targetDomain := domain
		if targetDomain == "" {
			if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
				targetDomain = u.Hostname()
			} else {
				targetDomain = rawURL
			}
		}
		targetDomain = strings.TrimPrefix(targetDomain, "http://")
		targetDomain = strings.TrimPrefix(targetDomain, "https://")
		if idx := strings.Index(targetDomain, "/"); idx != -1 {
			targetDomain = targetDomain[:idx]
		}
		if idx := strings.Index(targetDomain, ":"); idx != -1 {
			targetDomain = targetDomain[:idx]
		}

		fmt.Printf("\n\033[1;31m[*] Generating Exploit-DB GHDB & DorkSearch Intelligence for:\033[0m %s ...\n", targetDomain)
		dorks := osint.GenerateDorks(targetDomain)
		osint.PrintDorksReport(targetDomain, dorks)

		basePath := getReportOutputBase(output, targetDomain, rawURL, "dorks")
		htmlPath := basePath + ".html"
		if err := osint.ExportDorksHTML(targetDomain, dorks, htmlPath); err == nil {
			printViewCommand(htmlPath)
		}
		jsonPath := basePath + ".json"
		if jsonStr, err := osint.ExportDorksJSON(dorks); err == nil {
			_ = os.WriteFile(jsonPath, []byte(jsonStr), 0644)
			fmt.Printf("\033[1;32m[+] JSON Dork Dossier saved to: %s\033[0m\n", jsonPath)
		}
		return
	}


	// 6c-8. Standalone Automated DNS Intelligence & Enum Engine (dnsenum)
	if isDNSEnum {
		targetDomain := domain
		if targetDomain == "" {
			if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
				targetDomain = u.Hostname()
			} else {
				targetDomain = rawURL
			}
		}
		targetDomain = osint.CleanDomain(targetDomain)
		if targetDomain == "" {
			fmt.Println("\033[31m[!] Please specify a target domain using -domain or -u (e.g. -domain target.com -dnsenum)\033[0m")
			os.Exit(1)
		}

		fmt.Printf("\n\033[1;36m[*] Launching Automated DNS Intelligence & Enumeration on:\033[0m %s ...\n", targetDomain)
		wl := dnsWordlist
		if wl == "" && wordlist != "" {
			wl = wordlist
		}

		res, err := osint.RunDNSEnum(osint.DNSEnumConfig{
			Domain:       targetDomain,
			DNSServer:    dnsServer,
			Wordlist:     wl,
			Threads:      dnsThreads,
			TimeoutSec:   dnsTimeout,
			NoReverse:    dnsNoReverse,
			Whois:        dnsWhois,
			ScrapGoogle:  dnsScrap,
			Subfile:      dnsSubfile,
			LiveOutput:   true,
		})
		if err != nil {
			fmt.Printf("\033[31m[!] DNS enumeration error: %v\033[0m\n", err)
			os.Exit(1)
		}

		osint.PrintDNSEnumReport(res)
		return
	}

	// 6c-4. Standalone Admin Panel & Login Portal Hunter
	if isAdmin {
		targetDomain := domain
		if targetDomain == "" {
			if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
				targetDomain = u.Hostname()
			} else {
				targetDomain = rawURL
			}
		}
		targetDomain = osint.CleanDomain(targetDomain)
		if targetDomain == "" {
			fmt.Println("\033[31m[!] Please specify a target domain using -domain or -u (e.g. -domain target.lab -admin)\033[0m")
			os.Exit(1)
		}

		fmt.Printf("\n\033[1;31m[*] Launching High-Precision Admin Panel & Login Portal Hunter on:\033[0m %s ...\n", targetDomain)
		var certSubs []string
		var waybackURLs []string
		if net.ParseIP(targetDomain) == nil {
			var subWg sync.WaitGroup
			subWg.Add(2)
			go func() {
				defer subWg.Done()
				subs, _ := osint.FetchCertSubdomains(targetDomain, 4*time.Second)
				certSubs = subs
			}()
			go func() {
				defer subWg.Done()
				urls, _ := osint.FetchWaybackURLs(targetDomain, 4*time.Second)
				waybackURLs = urls
			}()
			subWg.Wait()
		}
		portals := osint.HuntAdminPortals(targetDomain, certSubs, waybackURLs, time.Duration(timeoutSec)*time.Second)
		osint.PrintAdminReport(portals, targetDomain)
		return
	}

	// 6c-5. Standalone Corporate Email & Pattern Hunter
	if isEmails {
		targetDomain := domain
		if targetDomain == "" {
			if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
				targetDomain = u.Hostname()
			} else {
				targetDomain = rawURL
			}
		}
		targetDomain = osint.CleanDomain(targetDomain)
		if targetDomain == "" {
			fmt.Println("\033[31m[!] Please specify a target domain using -domain or -u (e.g. -domain target.com -emails)\033[0m")
			os.Exit(1)
		}

		fmt.Printf("\n\033[1;36m[*] Harvesting Corporate Email Addresses on:\033[0m %s ...\n", targetDomain)
		waybackURLs, _ := osint.FetchWaybackURLs(targetDomain, 5*time.Second)
		dossier := osint.HarvestEmails(targetDomain, waybackURLs, "", time.Duration(timeoutSec)*time.Second)
		osint.PrintEmailReport(dossier)
		return
	}

	// 6c-6. Standalone 403/401 Authorization Bypass Engine
	if is403Bypass {
		if rawURL == "" {
			fmt.Println("\033[31m[!] Please specify a target URL using -u (e.g. -u https://target.com/admin -bypass-403)\033[0m")
			os.Exit(1)
		}
		httpClient := client.NewClient(proxy, time.Duration(timeoutSec)*time.Second, insecure, cookie, parsedHeaders)
		fmt.Printf("\n\033[1;31m[*] Launching 403/401 Authorization Bypass Sweep on:\033[0m %s ...\n", rawURL)
		rep := modules.Run403Bypass(rawURL, httpClient)
		modules.PrintBypassReport(rep)
		return
	}

	// 6c-7. Standalone GraphQL & Modern API Security Auditing Engine
	if isGraphQL {
		if rawURL == "" {
			fmt.Println("\033[31m[!] Please specify a target URL using -u (e.g. -u https://target.com/graphql -graphql)\033[0m")
			os.Exit(1)
		}
		httpClient := client.NewClient(proxy, time.Duration(timeoutSec)*time.Second, insecure, cookie, parsedHeaders)
		fmt.Printf("\n\033[1;35m[*] Launching GraphQL & Modern API Security Auditing on:\033[0m %s ...\n", rawURL)
		rep := modules.RunGraphQLAudit(rawURL, httpClient)
		modules.PrintGraphQLReport(rep)
		if len(rep.Findings) > 0 {
			var findings []*modules.Finding
			for i := range rep.Findings {
				findings = append(findings, &rep.Findings[i])
			}
			meta := reporters.ReportMeta{
				Timestamp: time.Now().UTC(),
				Duration:  rep.Duration,
				Version:   "2.0.0",
				Command:   strings.Join(os.Args, " "),
			}
			endpointURL := rep.Endpoint
			if endpointURL == "" {
				endpointURL = rawURL
			}
			dummyTarget := &modules.Target{URL: endpointURL, Method: "POST"}
			_ = reporters.WriteJSONReport(dummyTarget, findings, meta, output+".json")
			_ = reporters.WriteHTMLReport(dummyTarget, findings, meta, output+".html")
			_ = reporters.WriteMarkdownReport(dummyTarget, findings, output+".md")
			fmt.Printf("\033[1;32m[+] Reports generated: %s.html | %s.md | %s.json\033[0m\n", output, output, output)
			fmt.Printf("\033[1;36m[*] View HTML Report in Browser:\033[0m brave-browser %s.html\n\n", output)
		}
		return
	}

	// 6c-8. Standalone JavaScript Endpoint & Secret Miner
	if isJSMiner {
		if rawURL == "" {
			fmt.Println("\033[31m[!] Please specify a target URL using -u (e.g. -u https://target.com -mine-js)\033[0m")
			os.Exit(1)
		}
		httpClient := client.NewClient(proxy, time.Duration(timeoutSec)*time.Second, insecure, cookie, parsedHeaders)
		fmt.Printf("\n\033[1;36m[*] Launching JavaScript Endpoint & Secret Miner on:\033[0m %s ...\n", rawURL)
		rep, findings, err := modules.MineJavaScript(rawURL, httpClient)
		if err != nil {
			fmt.Printf("\033[31m[!] JS mining failed: %v\033[0m\n", err)
			os.Exit(1)
		}
		modules.PrintJSMinerReport(rep)
		if len(findings) > 0 && (reportJSON != "" || reportHTML != "" || reportSARIF != "" || output != "lab_report") {
			meta := reporters.ReportMeta{Timestamp: time.Now().UTC(), Duration: 1 * time.Second, Version: "2.0.0", Command: strings.Join(os.Args, " ")}
			dummyTarget := &modules.Target{URL: rawURL, Method: "GET"}
			_ = reporters.WriteJSONReport(dummyTarget, findings, meta, output+".json")
			_ = reporters.WriteHTMLReport(dummyTarget, findings, meta, output+".html")
		}
		return
	}

	// 6c-9. Standalone Subdomain Takeover Auditor
	if isTakeover {
		targetDomain := domain
		if targetDomain == "" {
			if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
				targetDomain = u.Hostname()
			} else {
				targetDomain = rawURL
			}
		}
		targetDomain = osint.CleanDomain(targetDomain)
		if targetDomain == "" {
			fmt.Println("\033[31m[!] Please specify a target domain using -domain or -u (e.g. -domain target.com -takeover)\033[0m")
			os.Exit(1)
		}
		fmt.Printf("\n\033[1;35m[*] Discovering subdomains and auditing for dangling CNAME takeovers on:\033[0m %s ...\n", targetDomain)
		subs, err := osint.FetchCertSubdomains(targetDomain, 10*time.Second)
		if err != nil || len(subs) == 0 {
			subs = []string{targetDomain}
		}
		httpClient := client.NewClient(proxy, time.Duration(timeoutSec)*time.Second, insecure, cookie, parsedHeaders)
		rep, findings, err := osint.CheckSubdomainTakeovers(subs, httpClient)
		if err != nil {
			fmt.Printf("\033[31m[!] Takeover audit failed: %v\033[0m\n", err)
			os.Exit(1)
		}
		osint.PrintTakeoverReport(rep)
		if len(findings) > 0 && (reportJSON != "" || reportHTML != "" || reportSARIF != "" || output != "lab_report") {
			meta := reporters.ReportMeta{Timestamp: time.Now().UTC(), Duration: 1 * time.Second, Version: "2.0.0", Command: strings.Join(os.Args, " ")}
			dummyTarget := &modules.Target{URL: "https://" + targetDomain, Method: "GET"}
			_ = reporters.WriteJSONReport(dummyTarget, findings, meta, output+".json")
			_ = reporters.WriteHTMLReport(dummyTarget, findings, meta, output+".html")
		}
		return
	}

	// 6c-10. Standalone Exposed .git/ Repository Auditor
	if isGitAudit {
		if rawURL == "" {
			fmt.Println("\033[31m[!] Please specify a target URL using -u (e.g. -u https://target.com -dump-git)\033[0m")
			os.Exit(1)
		}
		httpClient := client.NewClient(proxy, time.Duration(timeoutSec)*time.Second, insecure, cookie, parsedHeaders)
		fmt.Printf("\n\033[1;33m[*] Auditing for exposed .git/ directory on:\033[0m %s ...\n", rawURL)
		rep, findings, err := modules.AuditGitExposure(rawURL, httpClient)
		if err != nil {
			fmt.Printf("\033[31m[!] Git audit failed: %v\033[0m\n", err)
			os.Exit(1)
		}
		modules.PrintGitDumpReport(rep)
		if len(findings) > 0 && (reportJSON != "" || reportHTML != "" || reportSARIF != "" || output != "lab_report") {
			meta := reporters.ReportMeta{Timestamp: time.Now().UTC(), Duration: 1 * time.Second, Version: "2.0.0", Command: strings.Join(os.Args, " ")}
			dummyTarget := &modules.Target{URL: rawURL, Method: "GET"}
			_ = reporters.WriteJSONReport(dummyTarget, findings, meta, output+".json")
			_ = reporters.WriteHTMLReport(dummyTarget, findings, meta, output+".html")
		}
		return
	}

	// 6c-11. Standalone HTTP Request Smuggling Engine
	if isSmuggling {
		if rawURL == "" {
			fmt.Println("\033[31m[!] Please specify a target URL using -u (e.g. -u https://target.com -smuggling)\033[0m")
			os.Exit(1)
		}
		httpClient := client.NewClient(proxy, time.Duration(timeoutSec)*time.Second, insecure, cookie, parsedHeaders)
		fmt.Printf("\n\033[1;31m[*] Auditing HTTP Request Smuggling desync vectors on:\033[0m %s ...\n", rawURL)
		rep, findings, err := modules.AuditHTTPSmuggling(rawURL, httpClient)
		if err != nil {
			fmt.Printf("\033[31m[!] Smuggling audit failed: %v\033[0m\n", err)
			os.Exit(1)
		}
		modules.PrintSmuggleReport(rep)
		if len(findings) > 0 && (reportJSON != "" || reportHTML != "" || reportSARIF != "" || output != "lab_report") {
			meta := reporters.ReportMeta{Timestamp: time.Now().UTC(), Duration: 1 * time.Second, Version: "2.0.0", Command: strings.Join(os.Args, " ")}
			dummyTarget := &modules.Target{URL: rawURL, Method: "GET"}
			_ = reporters.WriteJSONReport(dummyTarget, findings, meta, output+".json")
			_ = reporters.WriteHTMLReport(dummyTarget, findings, meta, output+".html")
		}
		return
	}

	// 6e. Standalone Port Scanning Mode
	if isScan {
		targetHost := domain
		if targetHost == "" {
			if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
				targetHost = u.Hostname()
			} else {
				targetHost = rawURL
			}
		}
		targetHost = strings.TrimPrefix(targetHost, "http://")
		targetHost = strings.TrimPrefix(targetHost, "https://")
		if idx := strings.Index(targetHost, "/"); idx != -1 {
			targetHost = targetHost[:idx]
		}
		if idx := strings.Index(targetHost, ":"); idx != -1 {
			targetHost = targetHost[:idx]
		}

		fmt.Printf("\n\033[1;36m[*] Launching High-Speed Port Scanner on:\033[0m %s (Profile: %s)\n", targetHost, scanPorts)
		scanner := portscan.NewScanner(targetHost)
		scanner.FetchCVEs = scanCVE

		var results []portscan.PortResult
		var scanErr error
		if scanPorts == "top100" || scanPorts == "" {
			results, scanErr = scanner.ScanCommon()
		} else if strings.Contains(scanPorts, "-") {
			parts := strings.Split(scanPorts, "-")
			start, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
			results, scanErr = scanner.ScanRange(start, end)
		} else if strings.Contains(scanPorts, ",") {
			var customPorts []int
			for _, pStr := range strings.Split(scanPorts, ",") {
				if p, err := strconv.Atoi(strings.TrimSpace(pStr)); err == nil && p > 0 && p <= 65535 {
					customPorts = append(customPorts, p)
				}
			}
			results, scanErr = scanner.ScanPorts(customPorts)
		} else if p, err := strconv.Atoi(strings.TrimSpace(scanPorts)); err == nil && p > 0 && p <= 65535 {
			results, scanErr = scanner.ScanPorts([]int{p})
		} else {
			results, scanErr = scanner.ScanCommon()
		}

		if scanErr != nil {
			fmt.Printf("\033[31m[!] Port scan failed: %v\033[0m\n", scanErr)
			os.Exit(1)
		}

		fmt.Printf("\n\033[1;32m[+] Open Ports Discovered (%d total):\033[0m\n", len(results))
		fmt.Printf("    %-8s %-16s %-30s %s\n", "PORT", "SERVICE", "VERSION/BANNER", "CVE DETAILS")
		fmt.Printf("    %s\n", strings.Repeat("-", 75))
		for _, r := range results {
			bannerText := r.Version
			if bannerText == "" {
				bannerText = r.Banner
			}
			if len(bannerText) > 28 {
				bannerText = bannerText[:28] + "..."
			}
			cveStr := ""
			if len(r.CVEs) > 0 {
				cveStr = fmt.Sprintf("[%s (CVSS %.1f)]", r.CVEs[0].ID, r.CVEs[0].CVSS)
			}
			fmt.Printf("    %-8s %-16s %-30s %s\n", fmt.Sprintf("%d/tcp", r.Port), r.Service, bannerText, cveStr)
		}
		fmt.Println()
		return
	}

	// 6f. Standalone Race Condition Testing Mode
	if isRace {
		fmt.Printf("\n\033[1;31m[*] Launching Race Condition Attack (Burst Threads: %d, Rounds: %d) on: %s\033[0m\n", raceThreads, raceRounds, rawURL)
		raceCfg := race.RaceConfig{
			URL:      rawURL,
			Method:   method,
			Body:     data,
			Headers:  parsedHeaders,
			Threads:  raceThreads,
			Rounds:   raceRounds,
			Insecure: insecure,
		}
		rep, err := race.Run(raceCfg)
		if err != nil {
			fmt.Printf("\033[31m[!] Race attack failed: %v\033[0m\n", err)
			os.Exit(1)
		}
		fmt.Printf("\n\033[1;36m[+] Race Attack Results:\033[0m Total Dispatched: %d\n", rep.TotalRequests)
		fmt.Printf("    ├── Status Distributions: %v\n", rep.UniqueStatuses)
		fmt.Printf("    ├── Unique Body Variants: %d\n", len(rep.UniqueBodyHashes))
		if rep.AnomalyDetected {
			fmt.Printf("    └── \033[1;31m[VULNERABLE] Race Condition Confirmed!\033[0m %s\n", rep.AnomalyReason)
		} else {
			fmt.Printf("    └── \033[1;32m[SAFE]\033[0m Endpoints responded deterministically. No concurrency anomaly.\n")
		}
		fmt.Println()
		return
	}

	// 6g. High-Speed Concurrent Nuclei Vulnerability & Misconfiguration Execution Engine
	var standaloneNucleiFindings []*modules.Finding
	if isNuclei || templatesPath != "" {
		fmt.Println("\n\033[1;36m┌──────────────────────────────────────────────────────────────────────────────────┐\033[0m")
		fmt.Println("\033[1;36m│\033[0m \033[1;37m⚡ NightfallLX High-Speed Nuclei Vulnerability & Misconfig Engine\033[0m               \033[1;36m│\033[0m")
		fmt.Printf("\033[1;36m│\033[0m Target:      \033[1;33m%-67s\033[0m \033[1;36m│\033[0m\n", rawURL)
		if templatesPath != "" {
			fmt.Printf("\033[1;36m│\033[0m Templates:   \033[1;32m%-67s\033[0m \033[1;36m│\033[0m\n", templatesPath)
		} else {
			fmt.Printf("\033[1;36m│\033[0m Templates:   \033[1;32m%-67s\033[0m \033[1;36m│\033[0m\n", "Auto-Discover (Full Official Suite)")
		}
		if templateTags != "" {
			fmt.Printf("\033[1;36m│\033[0m Tags:        \033[1;35m%-67s\033[0m \033[1;36m│\033[0m\n", templateTags)
		}
		if nucleiSeverity != "" {
			fmt.Printf("\033[1;36m│\033[0m Severity:    \033[1;31m%-67s\033[0m \033[1;36m│\033[0m\n", nucleiSeverity)
		}
		if nucleiArgs != "" {
			fmt.Printf("\033[1;36m│\033[0m Custom Args: \033[1;36m%-67s\033[0m \033[1;36m│\033[0m\n", nucleiArgs)
		}
		fmt.Println("\033[1;36m└──────────────────────────────────────────────────────────────────────────────────┘\033[0m")

		effectiveTags := templateTags
		if effectiveTags == "" {
			// Quick non-invasive technology detection to prioritize relevant tags
			detClient := client.NewClient(proxy, time.Duration(timeoutSec)*time.Second, insecure, cookie, parsedHeaders)
			det := detector.NewTechDetector()
			if rep, err := det.Detect(rawURL, detClient); err == nil && rep != nil && len(rep.Technologies) > 0 {
				var techNames []string
				for _, t := range rep.Technologies {
					techNames = append(techNames, t.Name)
				}
				inferred := nuclei_engine.InferTagsFromTech(techNames)
				if inferred != "" {
					effectiveTags = inferred + ",misconfig,exposure"
					fmt.Printf("\033[1;34m[*] Smart Technology Filtering:\033[0m Detected %s -> Prioritizing tags '%s'\n", strings.Join(techNames, ", "), effectiveTags)
				}
			}
			if effectiveTags == "" && templatesPath == "" && nucleiArgs == "" {
				effectiveTags = "cve,misconfig,exposure"
				fmt.Printf("\033[1;34m[*] Default Targeted Tags:\033[0m Applying '%s' for fast high-impact coverage (use -tags all to scan entire library)\n", effectiveTags)
			}
		}

		tClient := client.NewClient(proxy, time.Duration(timeoutSec)*time.Second, insecure, cookie, parsedHeaders)
		nucleiCfg := nuclei_engine.NucleiRunnerConfig{
			TargetURL:     rawURL,
			TemplatesPath: templatesPath,
			Tags:          effectiveTags,
			Severity:      nucleiSeverity,
			Concurrency:   nucleiC,
			TimeoutSec:    timeoutSec,
			Engine:        nucleiEngine,
			CustomArgs:    nucleiArgs,
			Proxy:         proxy,
			Headers:       parsedHeaders,
			Client:        tClient,
		}

		nFindings, nErr := nuclei_engine.RunSmartNuclei(nucleiCfg)
		if nErr != nil {
			fmt.Printf("\033[31m[!] Nuclei execution error: %v\033[0m\n", nErr)
		} else {
			standaloneNucleiFindings = nFindings
			fmt.Printf("\n\033[1;32m[+] Nuclei Scan Finished:\033[0m \033[1m%d\033[0m vulnerability/misconfiguration findings matched.\n\n", len(nFindings))
		}

		// If user called standalone nuclei mode without standard web assessment, generate reports and return
		hasFuzz := strings.Contains(rawURL, "FUZZ") || strings.Contains(rawURL, "*") || strings.Contains(data, "FUZZ")
		if !isScan && !isOSINT && !isDorks && !isAdmin && !isEmails && !is403Bypass && !isGraphQL && !isSiteMap && !isMineParams && !isRace && !isJSMiner && !isTakeover && !isGitAudit && !isSmuggling && !hasFuzz {
			if len(nFindings) > 0 {
				meta := reporters.ReportMeta{
					Timestamp: time.Now().UTC(),
					Duration:  1 * time.Second,
					Version:   "2.0.0",
					Command:   strings.Join(os.Args, " "),
				}
				dummyTarget := &modules.Target{
					URL:    rawURL,
					Method: "GET",
				}
				basePath := getReportOutputBase(output, domain, rawURL, "nuclei_report")
				mdFile := basePath + ".md"
				jsonFile := basePath + ".json"
				if reportJSON != "" {
					jsonFile = reportJSON
				}
				htmlFile := basePath + ".html"
				if reportHTML != "" {
					htmlFile = reportHTML
				}

				_ = reporters.WriteMarkdownReport(dummyTarget, nFindings, mdFile)
				_ = reporters.WriteJSONReport(dummyTarget, nFindings, meta, jsonFile)
				_ = reporters.WriteHTMLReport(dummyTarget, nFindings, meta, htmlFile)
				saved := []string{
					fmt.Sprintf("  Markdown: \033[32m%s\033[0m", mdFile),
					fmt.Sprintf("  JSON:     \033[32m%s\033[0m", jsonFile),
					fmt.Sprintf("  HTML:     \033[32m%s\033[0m", htmlFile),
				}
				if reportSARIF != "" {
					_ = reporters.WriteSARIFReport(dummyTarget, nFindings, meta, reportSARIF)
					saved = append(saved, fmt.Sprintf("  SARIF:    \033[32m%s\033[0m", reportSARIF))
				}
				fmt.Println(strings.Repeat("=", 60))
				fmt.Printf("\033[1mNuclei Scan Finished!\033[0m Confirmed Findings: \033[1;32m%d\033[0m\n", len(nFindings))
				fmt.Printf("Reports saved to:\n%s\n", strings.Join(saved, "\n"))
				fmt.Println(strings.Repeat("=", 60))
				printViewCommand(htmlFile)
			}
			return
		}
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
			URL:                rawURL,
			WordlistPath:       wordlist,
			Method:             strings.ToUpper(method),
			Data:               data,
			Headers:            parsedHeaders,
			Threads:            threads,
			Timeout:            time.Duration(timeoutSec) * time.Second,
			Proxy:              proxy,
			Insecure:           insecure,
			AutoCalibrate:      autoCalibrate,
			IsSubdomain:        isSubdomain,
			FilterCodes:        parseCodes(filterCodeRaw),
			FilterSizes:        parseCodes(filterSizeRaw),
			FilterWords:        parseCodes(filterWordsRaw),
			FilterLines:        parseCodes(filterLinesRaw),
			MatchSizes:         parseCodes(matchSizesRaw),
			MatchWords:         parseCodes(matchWordsRaw),
			MatchLines:         parseCodes(matchLinesRaw),
			RateLimit:          rateLimit,
			MaxRetries:         maxRetries,
			RetryDelay:         time.Duration(retryDelayMs) * time.Millisecond,
			HTTP2:              enableHTTP2,
			RawHTTP:            rawHTTP,
			HeaderTampering:    tamperHeaders,
			Chunked:            chunkedBody,
			Adaptive:           adaptive,
			AdaptiveMinThreads: adaptiveMin,
			AdaptiveJitter:     time.Duration(jitterMs) * time.Millisecond,
			RotateUserAgent:    rotateUA,
			MatchRegexStr:      matchRegexStr,
			FilterRegexStr:     filterRegexStr,
			AutoRegex:          autoRegex,
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
	// RESTful Path Parameter Extraction (e.g. /ticket/4211 or /order/500)
	restPathRegex := regexp.MustCompile(`(?i)/([a-zA-Z0-9_\-]+)/(\d+)(?:/|$)`)
	if restMatches := restPathRegex.FindAllStringSubmatch(parsedURL.Path, -1); len(restMatches) > 0 {
		for _, m := range restMatches {
			if len(m) >= 3 {
				rName, rID := m[1], m[2]
				if _, exists := queryParams[rName]; !exists {
					queryParams[rName] = rID
				}
			}
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

	httpClient := client.NewClient(proxy, time.Duration(timeoutSec)*time.Second, insecure, cookie, parsedHeaders)

	// Canonical Redirect Resolution:
	// Automatically follow initial redirects (e.g. http -> https or / -> /uz) so the scanner tests the real application!
	if !strings.Contains(rawURL, "FUZZ") {
		resolvedURL, rErr := httpClient.ResolveRedirect(rawURL, 5)
		if rErr == nil && resolvedURL != "" && resolvedURL != rawURL {
			fmt.Printf("\033[1;34m[*] Followed initial redirect to canonical application endpoint:\033[0m %s\n", resolvedURL)
			rawURL = resolvedURL
			if pU, err := url.Parse(rawURL); err == nil {
				parsedURL = pU
				urlWithoutQuery = fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)
				for k, v := range parsedURL.Query() {
					if len(v) > 0 {
						queryParams[k] = v[0]
					}
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
		Wordlist: wordlist,
	}

	httpClient.ScopeHosts = scopeHosts
	httpClient.ScopeOff = scopeOff
	if rateLimit > 0 {
		httpClient.SetRateLimit(rateLimit)
	}
	if maxRetries > 0 {
		httpClient.SetRetry(maxRetries, time.Duration(retryDelayMs)*time.Millisecond)
	}
	httpClient.SetHTTP2(enableHTTP2)
	httpClient.SetHeaderTampering(tamperHeaders)
	httpClient.SetChunkedEncoding(chunkedBody)

	// Step 1: Deep Technology & Version Fingerprint
	det := detector.NewTechDetector()
	techRep, err := det.Detect(rawURL, httpClient)
	if err == nil && techRep != nil {
		detector.PrintReport(techRep)
	}

	// Automated HTML Form & Parameter Discovery
	if len(target.Parameters()) == 0 {
		if pageResp, err := httpClient.Request("GET", target.URL, "", nil); err == nil && pageResp != nil {
			forms := modules.ExtractFormsFromHTML(target.URL, pageResp.Body)
			if len(forms) > 0 {
				form := forms[0]
				var fieldNames []string
				for k, v := range form.Fields {
					target.Params[k] = v
					target.Data[k] = v
					fieldNames = append(fieldNames, k)
				}
				target.Method = form.Method
				target.URL = form.Action
				fmt.Printf("\033[1;32m[+] Discovered HTML Form [%s %s]:\033[0m %v\n", form.Method, form.Action, fieldNames)
			} else {
				discoveredParams := modules.ExtractParametersFromHTML(pageResp.Body)
				if len(discoveredParams) > 0 {
					fmt.Printf("\033[1;32m[+] Discovered %d Form / URL Parameter(s) from Landing Page:\033[0m %v\n", len(discoveredParams), discoveredParams)
					for _, p := range discoveredParams {
						target.Params[p] = "test"
						target.Data[p] = "test"
					}
				}
			}
		}
	}

	if len(target.Parameters()) == 0 {
		if sp, spErr := sitemap.NewSpider(target.URL, 2, 10); spErr == nil {
			sm := sp.Crawl()
			if sm != nil && len(sm.Endpoints) > 0 {
				for _, ep := range sm.Endpoints {
					if len(ep.Forms) > 0 {
						form := ep.Forms[0]
						for _, inp := range form.Inputs {
							target.Params[inp] = "test"
							target.Data[inp] = "test"
						}
						target.Method = form.Method
						if form.Action != "" {
							target.URL = form.Action
						}
						fmt.Printf("\033[1;32m[+] Discovered Form via Crawler [%s %s]:\033[0m %v\n", target.Method, target.URL, form.Inputs)
						break
					}
					if len(ep.Parameters) > 0 {
						for _, p := range ep.Parameters {
							target.Params[p] = "test"
							target.Data[p] = "test"
						}
						target.URL = ep.URL
						fmt.Printf("\033[1;32m[+] Discovered Parameters via Crawler [%s]:\033[0m %v\n", target.URL, ep.Parameters)
						break
					}
				}
			}
		}
	}

	fmt.Printf("\n\033[1;36mNightfallLX (Go Edition)\033[0m - Web Assessment Framework\n")
	fmt.Printf("Target:     \033[1m%s\033[0m [%s]\n", target.URL, target.Method)
	fmt.Printf("Parameters: %v\n", target.Parameters())
	if proxy != "" {
		fmt.Printf("Proxy:      \033[33m%s\033[0m\n", proxy)
	}
	fmt.Println()

	if len(target.Parameters()) == 0 {
		fmt.Println("[33m[!] Notice: No query or body parameters detected in target URL or landing page forms.[0m")
		fmt.Println("    Running passive / host modules (WAF, Headers, Exposure, CORS, Secrets, JSMiner, GitDumper, Smuggling).")
		fmt.Println("    To test injection with specific parameters, specify: -u 'http://site/?id=1' or -d 'param=1'")
	}

	nucleiMod := nuclei_engine.NewNucleiModule()
	nucleiMod.TemplatesPath = templatesPath
	nucleiMod.Tags = templateTags
	if nucleiMod.Tags == "" && techRep != nil && len(techRep.Technologies) > 0 {
		var techNames []string
		for _, t := range techRep.Technologies {
			techNames = append(techNames, t.Name)
		}
		inferred := nuclei_engine.InferTagsFromTech(techNames)
		if inferred != "" {
			nucleiMod.Tags = inferred + ",misconfig,exposure"
		}
	}
	nucleiMod.Severity = nucleiSeverity
	nucleiMod.Concurrency = nucleiC
	nucleiMod.TimeoutSec = timeoutSec
	nucleiMod.CustomArgs = nucleiArgs

	availableModules := map[string]modules.Module{
		"nuclei":     nucleiMod,
		"sqli":       modules.NewSQLiModule(),
		"ssti":       modules.NewSSTIModule(),
		"lfi":        modules.NewLFIModule(),
		"cmdi":       modules.NewCMDiModule(),
		"xss":        modules.NewXSSModule(),
		"cors":       modules.NewCORSModule(),
		"redirect":   modules.NewRedirectModule(),
		"ssrf":       modules.NewSSRFModule(),
		"jwt":        modules.NewJWTModule(),
		"waf":        modules.NewWAFModule(),
		"idor":       modules.NewIDORModule(),
		"csrf":       modules.NewCSRFModule(),
		"xxe":        modules.NewXXEModule(),
		"nosqli":     modules.NewNoSQLiModule(),
		"upload":     modules.NewUploadModule(),
		"headers":    modules.NewHeadersModule(),
		"exposure":   modules.NewExposureModule(),
		"hostheader": modules.NewHostHeaderModule(),
		"crlf":       modules.NewCRLFModule(),
		"secrets":    secrets.NewModule(),
		"race":       race.NewModule(),
		"userenum":   modules.NewUserEnumModule(),
		"jsminer":    modules.NewJSMinerModule(),
		"gitdumper":  modules.NewGitDumperModule(),
		"smuggling":  modules.NewSmugglingModule(),
		"graphql":    modules.NewGraphQLModule(),
	}

	var activeModules []modules.Module
	if moduleList == "all" {
		order := []string{
			"waf", "headers", "exposure", "secrets", "sqli", "ssti", "lfi", "cmdi",
			"xss", "cors", "redirect", "ssrf", "jwt", "idor", "csrf",
			"xxe", "nosqli", "upload", "hostheader", "crlf", "race", "userenum", "jsminer", "gitdumper", "smuggling", "graphql", "nuclei",
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

	// Pre-flight host reachability check
	checkResp, checkErr := httpClient.Request("GET", target.URL, "", nil)
	if checkErr != nil && checkResp == nil {
		fmt.Printf("\n\033[1;31m[!] TARGET OFFLINE / UNREACHABLE: Cannot connect to %s (%v)\033[0m\n", target.URL, checkErr)
		fmt.Printf("\033[33m[*] Please verify the lab machine / Docker container is running and IP is reachable.\033[0m\n\n")
	}

	var allFindings []*modules.Finding
	if len(standaloneNucleiFindings) > 0 {
		allFindings = append(allFindings, standaloneNucleiFindings...)
	}
	scanStart := time.Now()
	for _, mod := range activeModules {
		fmt.Printf("\033[36m[*] Running module: \033[1m%-10s\033[0m (%s) ...\n", mod.Name(), mod.Description())
		findings, err := mod.Run(target, httpClient)
		if err != nil {
			fmt.Printf("    \033[31m[!] Error running %s: %v\033[0m\n", mod.Name(), err)
			continue
		}
		for _, f := range findings {
			f.AlignSeverityToCVSS()
			status := "\033[1;32m[CONFIRMED]\033[0m"
			if f.Severity == modules.SeverityInfo {
				status = "\033[1;36m[INFO]\033[0m"
			}
			cvssInfo := ""
			if f.CVSS > 0 {
				var sevColor string
				switch f.Severity {
				case modules.SeverityCritical:
					sevColor = "\033[1;35m"
				case modules.SeverityHigh:
					sevColor = "\033[1;31m"
				case modules.SeverityMedium:
					sevColor = "\033[1;33m"
				case modules.SeverityLow:
					sevColor = "\033[1;34m"
				default:
					sevColor = "\033[1;36m"
				}
				cvssInfo = fmt.Sprintf(" | %sCVSS %.1f %s\033[0m", sevColor, f.CVSS, f.Severity)
			}
			fmt.Printf("    %s \033[1m%s\033[0m (param=%s, confidence=%d%%%s)\n", status, f.Title, f.Parameter, f.Confidence, cvssInfo)
		}
		allFindings = append(allFindings, findings...)
	}

	meta := reporters.ReportMeta{
		Timestamp: time.Now().UTC(),
		Duration:  time.Since(scanStart),
		Version:   "2.0.0",
		Command:   strings.Join(os.Args, " "),
	}

	basePath := getReportOutputBase(output, domain, rawURL, "report")
	mdFile := basePath + ".md"
	jsonFile := basePath + ".json"
	if reportJSON != "" {
		jsonFile = reportJSON
	}
	htmlFile := basePath + ".html"
	if reportHTML != "" {
		htmlFile = reportHTML
	}

	_ = reporters.WriteMarkdownReport(target, allFindings, mdFile)
	if err := reporters.WriteJSONReport(target, allFindings, meta, jsonFile); err != nil {
		fmt.Printf("\033[31m[!] JSON report error: %v\033[0m\n", err)
	}
	if err := reporters.WriteHTMLReport(target, allFindings, meta, htmlFile); err != nil {
		fmt.Printf("\033[31m[!] HTML report error: %v\033[0m\n", err)
	}

	saved := []string{
		fmt.Sprintf("  Markdown: \033[32m%s\033[0m", mdFile),
		fmt.Sprintf("  JSON:     \033[32m%s\033[0m", jsonFile),
		fmt.Sprintf("  HTML:     \033[32m%s\033[0m", htmlFile),
	}
	if reportSARIF != "" {
		if err := reporters.WriteSARIFReport(target, allFindings, meta, reportSARIF); err != nil {
			fmt.Printf("\033[31m[!] SARIF report error: %v\033[0m\n", err)
		} else {
			saved = append(saved, fmt.Sprintf("  SARIF:    \033[32m%s\033[0m", reportSARIF))
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Printf("\033[1mScan Finished!\033[0m Confirmed Vulnerabilities: \033[1;32m%d\033[0m\n", len(allFindings))
	fmt.Printf("Reports saved to:\n%s\n", strings.Join(saved, "\n"))
	fmt.Println(strings.Repeat("=", 60))
	printViewCommand(htmlFile)
}
