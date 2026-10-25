# NightfallLX (v2.0) — Complete Technical Manual & Property Reference

**Comprehensive Offensive & Defensive Security Assessment Suite**  
*Document Version: 2.0.0 | Runtime: Go 1.21+ | Architecture: Standalone Cross-Platform Binary*

---

## 1. Executive Overview

**NightfallLX** is an evidence-first, high-performance web application vulnerability scanner, deep OSINT reconnaissance suite, and high-speed fuzzing platform. Built in pure Go without external dependencies, it consolidates reconnaissance, discovery, exploitation, and reporting into a single high-throughput binary.

### Core Architecture Capabilities
- **Deep Passive OSINT Engine:** Non-intrusive reconnaissance via Certificate Transparency (crt.sh), DNS, SPF/DMARC email spoofing audit, CNAME Subdomain Takeover verification, and Wayback Machine archive discovery.
- **Intelligent User Enumeration & Auto-Regex:** Heuristic differential baseline analysis that automatically infers error patterns and detects registered users via status, body divergence, and password hashing execution latency.
- **Nanosecond Gate-Synchronized Race Engine:** Turbo Intruder-style simultaneous goroutine release for limit bypass and concurrency testing.
- **TruffleHog-Grade Secret Scanner:** Identifies 14+ credential and token types in responses and linked JavaScript with Shannon entropy validation.
- **Nuclei YAML DSL Engine:** Runs community or custom Nuclei v3 YAML rules without external dependencies.
- **High-Speed Network Port Scanner:** Concurrent TCP port scanning with banner grabbing and NIST NVD CVE correlation.
- **WAF Adaptive Throttling & Evasion:** Automatic exponential backoff, jitter, User-Agent fingerprint rotation, chunked transfer encoding, and raw TLS socket transmission.
- **Multi-Format Reporting:** Interactive Cyber Dark Mode HTML Dashboard, SARIF v2.1.0 for CI/CD integration, JSON, and Markdown.

---

## 2. Exhaustive Properties & CLI Flags Reference

The following table documents **every single CLI flag and configuration property** available in NightfallLX (Go Edition v2.0).

| Property / Flag | Description / Purpose | Example Usage |
| :--- | :--- | :--- |
| `-u <string>` | Target base URL or URL template containing injection markers (`FUZZ` or `*`). Required for most scanning modes unless `-r`, `-domain`, or `-scan` is used. | `nightfalllx -u "http://target.lab/view.php?id=1"`<br>`nightfalllx -u "http://target.lab/FUZZ"` |
| `-r <file>` | Path to a raw Burp Suite HTTP request export file. Automatically parses HTTP method, headers, cookies, query/POST parameters, and injection points (`*`). | `nightfalllx -r request.txt -m all` |
| `-domain <string>` | Target root domain for Subdomain/VHost discovery, OSINT intelligence, or port scanning. | `nightfalllx -domain target.com -osint`<br>`nightfalllx -sub -domain target.htb -u http://10.129.20.10` |
| `-https` | Forces the HTTPS protocol scheme for the target URL when not explicitly specified. | `nightfalllx -u target.lab -https` |
| `-ssl` | Alias for `-https`. Enforces TLS encrypted communication. | `nightfalllx -u target.lab -ssl` |
| `-scope <string>` | Restricts all outbound requests strictly to authorized domains. Accepts comma-separated list or path to `scope.txt`. Blocks off-scope interactions. | `nightfalllx -u http://target.lab -scope "target.lab,*.target.lab"`<br>`nightfalllx -r req.txt -scope scope.txt` |
| `-scope-off` | Explicitly disables scope checking. Bypasses domain validation (use with caution). | `nightfalllx -u http://target.lab -scope-off` |
| `-b2 <string>` | Secondary cookie session string for automated Privilege Escalation, BOLA, and IDOR vulnerability verification. | `nightfalllx -u "http://target.lab/account" -b "session=user1" -b2 "session=user2" -m idor` |
| `-H2 <string>` | Secondary custom authorization header for IDOR/RBAC testing (repeatable for multiple headers). | `nightfalllx -u "http://target.lab/api" -H "Auth: Bearer tok1" -H2 "Auth: Bearer tok2" -m idor` |
| `-osint` | Runs comprehensive passive OSINT reconnaissance: crt.sh Certificate Transparency, DNS records, SPF/DMARC email spoofing audit, CNAME takeover, and Wayback Machine archive discovery. | `nightfalllx -osint -domain example.com`<br>`nightfalllx -osint -u https://target.lab -timeout 25` |
| `-shodan` | Executes Shodan OSINT intelligence lookup: retrieves public IP allocations, open ports, software banners, hostnames, and known CVEs. | `nightfalllx -shodan -u http://target.lab` |
| `-shodan-key <str>` | Custom Shodan API key. Overrides built-in defaults or the `SHODAN_API_KEY` environment variable. | `nightfalllx -shodan -u http://target.lab -shodan-key "API_KEY_HERE"` |
| `-tech` | Deep Wappalyzer-grade technology stack and exact version fingerprinting (Web Server, PHP, Frameworks, Template Engines, Security Headers). | `nightfalllx -tech -u http://target.lab` |
| `-map` | Spiders the target web architecture recursively and produces a structured sitemap. Extracts embedded endpoints from JavaScript files and parses `robots.txt` / `sitemap.xml`. | `nightfalllx -map -u http://target.lab -depth 3 -max-urls 100` |
| `-spider` | Alias for `-map`. Executes recursive web crawler. | `nightfalllx -spider -u http://target.lab` |
| `-crawl` | Alias for `-map`. Executes recursive web crawler. | `nightfalllx -crawl -u http://target.lab` |
| `-depth <int>` | Maximum recursion depth for the web crawler (default: `3`). | `nightfalllx -map -u http://target.lab -depth 4` |
| `-max-urls <int>` | Maximum number of unique URLs to discover during spidering before termination (default: `50`). | `nightfalllx -map -u http://target.lab -max-urls 150` |
| `-mine-params` | Runs PortSwigger-style hidden parameter miner. Batches candidates (25/req) with canary tokens to identify unlinked query/body parameters via reflection, status, and length anomalies. | `nightfalllx -mine-params -u "http://target.lab/index.php" -X POST` |
| `-param-miner` | Alias for `-mine-params`. | `nightfalllx -param-miner -u http://target.lab/search` |
| `-m <string>` | Comma-separated list of vulnerability testing modules to execute, or `'all'` (default: `'all'`). Available: `sqli`, `ssti`, `lfi`, `cmdi`, `xss`, `cors`, `redirect`, `ssrf`, `jwt`, `waf`, `idor`, `csrf`, `xxe`, `nosqli`, `upload`, `headers`, `exposure`, `hostheader`, `crlf`, `secrets`, `race`, `userenum`. | `nightfalllx -u "http://target.lab/?id=1" -m "sqli,xss,lfi"`<br>`nightfalllx -u "http://target.lab/login" -m userenum`<br>`nightfalllx -u "http://target.lab" -m secrets` |
| `-scan` | Enables multi-threaded TCP network port scanning mode. Probes target host ports, extracts service banners, and queries vulnerabilities. | `nightfalllx -scan -domain target.lab -scan-ports "80,443,8080"` |
| `-scan-ports <str>` | Port range or profile for network scanner: `'top100'` (default), ranges like `'1-1024'`, or comma-delimited lists like `'80,443,135,445'`. | `nightfalllx -scan -domain 192.168.1.10 -scan-ports "1-1000"`<br>`nightfalllx -scan -domain target.com -scan-ports "80,443"` |
| `-scan-cve` | Enriches discovered open ports and service version banners with live queries against the NIST NVD CVE vulnerability database. | `nightfalllx -scan -domain target.lab -scan-ports "top100" -scan-cve` |
| `-race` | Executes nanosecond gate-synchronized race condition and limit bypass attack (Turbo Intruder style). Releases burst requests simultaneously. | `nightfalllx -u "http://target.lab/api/redeem" -X POST -d '{"code":"VIP"}' -race -race-threads 30` |
| `-race-threads <n>` | Number of concurrent parallel burst requests dispatched per round during race condition attack (default: `20`). | `nightfalllx -u "http://target.lab/cart/checkout" -race -race-threads 40` |
| `-race-rounds <n>` | Number of burst rounds to repeat during race testing (default: `2`). | `nightfalllx -u "http://target.lab/vote" -race -race-rounds 3` |
| `-templates <path>` | Path to a single Nuclei YAML template file or directory of templates to parse and execute against the target. | `nightfalllx -u "http://target.lab" -templates ./cves/CVE-2023-1234.yaml`<br>`nightfalllx -u "http://target.lab" -templates ./templates/` |
| `-template-tags <s>`| Comma-separated tag filter for Nuclei templates when loading from a directory (e.g. `'cve,misconfig,auth'`). | `nightfalllx -u "http://target.lab" -templates ./templates -template-tags "cve,critical"` |
| `-X <string>` | HTTP Request Method: `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`, `HEAD` (default: `'GET'`). | `nightfalllx -u "http://target.lab/api" -X POST -d "action=test"` |
| `-d <string>` | POST / PUT body data string. Supports urlencoded parameters, JSON payloads, or injection marker `FUZZ`. | `nightfalllx -u "http://target.lab/login" -X POST -d "user=admin&pass=FUZZ"` |
| `-H <string>` | Custom HTTP Header to include in requests. Repeatable flag for passing multiple headers. | `nightfalllx -u http://target.lab -H "Authorization: Bearer SECRET" -H "X-Custom: 1"` |
| `-b <string>` | HTTP Cookie header value to attach to all requests. | `nightfalllx -u http://target.lab -b "PHPSESSID=d92j10dj12; role=admin"` |
| `-p <string>` | HTTP proxy URL for forwarding outbound scanner traffic (e.g. Burp Suite, OWASP ZAP, or Caido). | `nightfalllx -u http://target.lab -p http://127.0.0.1:8080` |
| `-rate <int>` | Token-bucket rate limiter specifying maximum requests per second. Default `0` (unlimited). Prevents server overload or DoS. | `nightfalllx -u http://target.lab/FUZZ -w wordlist.txt -rate 50` |
| `-retry <int>` | Maximum automatic retry attempts when encountering HTTP 429 (Too Many Requests), HTTP 503, or connection dropouts (default: `0`). | `nightfalllx -u http://target.lab/FUZZ -w list.txt -retry 3` |
| `-retry-delay <ms>` | Base exponential backoff delay in milliseconds between retries (default: `500`). Dynamically respects `Retry-After` headers. | `nightfalllx -u http://target.lab -retry 3 -retry-delay 1000` |
| `-http2` | Enables or disables HTTP/2 transport protocol support over TLS (default: `true`). | `nightfalllx -u https://target.lab -http2=false` |
| `-raw` | Bypasses Go's HTTP client and header normalization by transmitting verbatim bytes over direct raw TCP/TLS socket connections. | `nightfalllx -u http://target.lab/FUZZ -w list.txt -raw` |
| `-tamper-headers` | Injects WAF bypass headers (`X-Originating-IP`, `X-Forwarded-For`, `X-Remote-IP`, `X-Custom-IP-Authorization`) to circumvent IP-based access controls. | `nightfalllx -u http://target.lab/admin -tamper-headers` |
| `-chunked` | Transmits request body payloads using `Transfer-Encoding: chunked` to evade payload inspection firewalls. | `nightfalllx -u http://target.lab/upload -X POST -d "payload" -chunked` |
| `-adaptive` | Activates intelligent WAF throttling: automatically slows concurrency upon 429/403 responses, injects jitter, and rotates browser fingerprints. | `nightfalllx -u http://target.lab/FUZZ -w list.txt -adaptive -rotate-ua` |
| `-jitter <ms>` | Adds a randomized sleep delay between 0 and N milliseconds between adaptive fuzz requests to randomize traffic cadence (default: `0`). | `nightfalllx -u http://target.lab/FUZZ -w list.txt -adaptive -jitter 200` |
| `-rotate-ua` | Dynamically cycles through realistic browser User-Agent fingerprints (Chrome, Firefox, Safari, Edge across Windows, macOS, Linux). | `nightfalllx -u http://target.lab/FUZZ -w list.txt -rotate-ua` |
| `-adaptive-min <n>`| Concurrency floor for adaptive rate throttling; prevents worker thread starvation (default: `1`). | `nightfalllx -u http://target.lab/FUZZ -w list.txt -adaptive -adaptive-min 2` |
| `-k` | Insecure TLS verification bypass (default: `true`). Allows auditing laboratory targets with self-signed, untrusted, or expired certificates. | `nightfalllx -u https://192.168.1.50 -k` |
| `-timeout <int>` | HTTP network timeout duration in seconds per request (default: `15`). | `nightfalllx -u http://target.lab -timeout 30` |
| `-o <string>` | Output filename base prefix for generated reports (default: `'lab_report'`). Generates `<prefix>.md`, `<prefix>.json`, etc. | `nightfalllx -u http://target.lab -m all -o audit_q3` |
| `-report-html <p>` | Path to generate an interactive offline Cyber Dark Mode HTML Dashboard report with filterable tables and ready-to-run curl reproduction commands. | `nightfalllx -u http://target.lab -m all -report-html ./reports/dashboard.html` |
| `-report-sarif <p>`| Path to output a standardized SARIF v2.1.0 vulnerability report suitable for direct ingestion into GitHub Code Scanning, GitLab CI, or DefectDojo. | `nightfalllx -u http://target.lab -m all -report-sarif ./reports/results.sarif` |
| `-report-json <p>` | Path to output a structured JSON report containing findings, CVSS scores, remediation guidance, and evidence payloads. | `nightfalllx -u http://target.lab -m all -report-json ./reports/report.json` |
| `-w <string>` | Path to a wordlist file on disk for directory, parameter, or virtual host fuzzing. | `nightfalllx -u http://target.lab/FUZZ -w /usr/share/wordlists/dirb/common.txt` |
| `-t <int>` | Number of concurrent worker goroutines for fuzzing, spidering, or crawling (default: `40`). | `nightfalllx -u http://target.lab/FUZZ -w wordlist.txt -t 80` |
| `-fuzz` | Explicitly enables high-speed fuzzing mode without requiring the `FUZZ` keyword in the URL. | `nightfalllx -u http://target.lab/ -w wordlist.txt -fuzz` |
| `-sub` | Enables virtual host (VHost) and subdomain discovery mode (`ffuf`-compatible). Fuzzes HTTP `Host` headers against target IP. | `nightfalllx -sub -domain target.lab -u http://10.129.20.10 -w subdomains.txt` |
| `-subdomain` | Alias for `-sub`. Activates VHost discovery mode. | `nightfalllx -subdomain -domain target.lab -u http://10.129.20.10` |
| `-ac` | Auto-calibrates baseline wildcard / catch-all responses before fuzzing (default: `true`). Eliminates false positives by discarding baseline signatures. | `nightfalllx -u http://target.lab/FUZZ -w wordlist.txt -ac=true` |
| `-mc <string>` | Match HTTP status codes (comma-separated). Only responses with these codes are reported. | `nightfalllx -u http://target.lab/FUZZ -w list.txt -mc "200,204,301,302,403"` |
| `-fc <string>` | Filter HTTP status codes (comma-separated, default: `'404'`). Responses matching these codes are discarded. | `nightfalllx -u http://target.lab/FUZZ -w list.txt -fc "404,500"` |
| `-ms <string>` | Match response sizes in bytes (comma-separated). | `nightfalllx -u http://target.lab/FUZZ -w list.txt -ms "1024,2048"` |
| `-fs <string>` | Filter response sizes in bytes (comma-separated). Discards fixed-length error responses. | `nightfalllx -u http://target.lab/FUZZ -w list.txt -fs "0,421"` |
| `-mw <string>` | Match response word counts (comma-separated). | `nightfalllx -u http://target.lab/FUZZ -w list.txt -mw "15,22"` |
| `-fw <string>` | Filter response word counts (comma-separated). | `nightfalllx -u http://target.lab/FUZZ -w list.txt -fw "45"` |
| `-ml <string>` | Match response line counts (comma-separated). | `nightfalllx -u http://target.lab/FUZZ -w list.txt -ml "10,20"` |
| `-fl <string>` | Filter response line counts (comma-separated). | `nightfalllx -u http://target.lab/FUZZ -w list.txt -fl "2"` |
| `-mr <string>` | Match response body regular expression. Only responses matching the regex pattern are recorded. | `nightfalllx -u http://target.lab/FUZZ -w list.txt -mr "(?i)admin|dashboard"` |
| `-fr <string>` | Filter response body regular expression. Discards responses matching the regex pattern (e.g. custom error messages). | `nightfalllx -u http://target.lab/FUZZ -w list.txt -fr "(?i)page not found|access denied"` |
| `-auto-regex` | Automatically infers differential error regexes from baseline canary responses and applies them as dynamic filters to eliminate soft-404 false positives. | `nightfalllx -u http://target.lab/FUZZ -w list.txt -auto-regex` |
| `-i` | Launches the interactive mouse-controlled Terminal User Interface (TUI) dashboard with full ANSI SGR mouse navigation and neon cyber visualizers. | `nightfalllx -i` |
| `-ui` | Alias for `-i`. Launches interactive mouse TUI dashboard. | `nightfalllx -ui` |
| `-tui` | Alias for `-i`. Launches interactive mouse TUI dashboard. | `nightfalllx -tui` |
| `-doctor` | Pre-flight connectivity diagnostic suite: verifies DNS resolution, TCP handshakes, TLS 1.3 protocol versions, cipher suites, proxy routing, and system CPU health. | `nightfalllx -doctor -u https://target.lab -p http://127.0.0.1:8080` |
| `-troubleshoot` | Alias for `-doctor`. Runs pre-flight diagnostics. | `nightfalllx -troubleshoot -u http://target.lab` |
| `-version` | Displays current program version, build timestamp, and runtime architecture. | `nightfalllx -version` |
| `-V` | Alias for `-version`. | `nightfalllx -V` |

---

## 3. Operational Workflows & Scenarios

### Workflow A: Zero-Knowledge Passive OSINT
Engage a target domain without emitting intrusive traffic:
```bash
nightfalllx -osint -domain example.com -timeout 20
```
**Intelligence Harvested:**
1. **Certificate Transparency:** Every subdomain ever issued an SSL certificate via crt.sh.
2. **DNS & Email Security:** SPF policy enforcement, `_dmarc.<domain>` verification (spoofing detection).
3. **Subdomain Takeover:** CNAME pointer inspection against dangling cloud services.
4. **Wayback Machine:** Unindexed `.env`, `.sql`, `.bak`, `.config` historical URLs.
5. **Infrastructure:** Cloud provider detection (Cloudflare, AWS, GCP, Azure, Linode).

### Workflow B: High-Speed Fuzzing with Auto-Regex Filtering
Eliminate soft-404 responses that return HTTP 200 with custom error pages:
```bash
nightfalllx -u "http://target.lab/FUZZ" -w /usr/share/wordlists/dirb/common.txt -t 50 -auto-regex
```

### Workflow C: User Enumeration on Login Endpoints
Discover valid accounts on authentication surfaces:
```bash
nightfalllx -u "http://target.lab/login" -X POST -d "username=admin&password=Password123" -m userenum
```

### Workflow D: Limit Bypass via Turbo Race Condition
Test race condition vulnerabilities in financial transactions or promotional coupons:
```bash
nightfalllx -u "http://target.lab/api/apply-coupon" -X POST -d '{"coupon":"PROMO50"}' -race -race-threads 30 -race-rounds 2
```

### Workflow E: Complete Assessment with Multi-Format Reporting
Execute all 22 assessment modules and generate HTML and SARIF dashboards:
```bash
nightfalllx -u "http://target.lab/app.php?id=1" -m all -p http://127.0.0.1:8080 -report-html ./reports/audit.html -report-sarif ./reports/audit.sarif
```

---

## 4. Troubleshooting & Diagnostic Reference

Run the diagnostic subsystem to isolate connectivity and environment bottlenecks:
```bash
nightfalllx -doctor -u https://target.lab -p http://127.0.0.1:8080
```
- **DNS Resolution:** Validates local and upstream nameservers.
- **TCP Handshake:** Measures round-trip time (RTT) to port 80/443.
- **TLS Handshake:** Identifies negotiated TLS version (e.g. `TLS 1.3 - 0x0304`) and CipherSuite.
- **Proxy Verification:** Confirms whether the specified HTTP proxy is reachable and responding.

---

## 5. Security & Legal Disclaimer

NightfallLX is engineered exclusively for authorized security audits, sanctioned penetration tests, and educational vulnerability research. Executing security testing against target infrastructures without prior explicit written authorization is illegal. Operators must maintain compliance with all applicable laws and rules of engagement.
