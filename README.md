# NightfallLX (v2.0)

[![Go](https://img.shields.io/badge/go-1.21%2B-blue.svg)](https://golang.org/)
[![Version](https://img.shields.io/badge/version-2.0.0-purple.svg)](https://github.com/Darksystem-01/NightfallLX)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/Darksystem-01/NightfallLX/actions)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Next-Generation High-Performance Web Assessment, Vulnerability Scanner, Web Command Center & Deep OSINT Recon Suite**

NightfallLX is an evidence-first, multi-threaded offensive and defensive security platform written in pure **Go (Golang)**. Designed for penetration testers, bug bounty hunters, red teams, and security researchers, it consolidates web vulnerability discovery, passive OSINT reconnaissance, high-speed fuzzing, race condition testing, secret detection, and an interactive **Web Command Center** into a single, dependency-free binary.

---

## ⚡ Key Capabilities & Modules

### 1. 🌐 Web Command Center & Live Generator (`-web`)
- **Zero-Dependency Web UI:** Embedded directly inside the binary via `//go:embed` — requires no external files, Node.js, or internet access.
- **Smart Target Auto-Detection:** Automatically detects target format (IPv4, CIDR, Domain, or full URL) and tailors relevant scan modules.
- **Interactive Strategy Presets:**
  - ⚡ **Quick Recon:** Fast port scanning, technology profiling, security headers.
  - 🛡️ **Web Core:** SQLi, XSS, SSRF, SSTI, LFI, CMDi, IDOR.
  - 🧬 **Nuclei Deep:** Targeted Nuclei templates by severity (Critical, High, Medium) and tags.
  - 💀 **Full Penetration:** All 16+ modules, fuzzing, wordlists, and parameter mining.
  - 🛠️ **Custom:** Granular module-by-module interactive chips.
- **Real-Time Live Command Generator:** Dynamically creates the exact, 100% syntactically correct CLI command as you toggle modules.
- **Live Terminal & SSE Streaming:** Execute scans directly from the browser with real-time Server-Sent Events output streaming and 1-click HTML report viewing.
- **24/7 Host Persistence:** Ready-to-use systemd user daemon for running continuously in the background on your host.

### 2. 🔍 Deep Passive OSINT Reconnaissance (`-osint`)
- **Certificate Transparency (crt.sh):** Passively discovers hidden subdomains and historical SSL certificates without sending a single packet to the target.
- **DNS & Email Spoofing Auditing:** Automatic verification of `SPF` and `_dmarc.<domain>` records; flags **Missing DMARC (CEO Fraud / Phishing risk)** and permissive `+all` SPF policies.
- **Subdomain Takeover Detection (`-takeover`):** Resolves CNAME records against signatures for abandoned third-party services (GitHub Pages, AWS S3, Heroku, Azure, Ghost, Surge, Fastly, etc.).
- **Wayback Machine Integration:** Fetches historical URLs and extracts sensitive files (`.sql`, `.env`, `.bak`, `.config`, `.json`, unlisted `/api/` routes) from web.archive.org.
- **Cloud & Network Intelligence:** Reverse DNS, BGP ASN, and Anycast CDN identification (Cloudflare, AWS, Google Cloud, Azure, DigitalOcean, Linode).

### 3. 🛡️ Advanced Web Vulnerability Engines
- **HTTP Request Smuggling / Desync (`-m smuggling`):** Tests for CL.TE and TE.CL desynchronization flaws using low-level socket chunking and malformed headers.
- **Git Dumper & Source Extractor (`-m git`):** Identifies exposed `/.git/` directories, downloads `HEAD` / `index`, and maps repository objects.
- **JS Secrets & Route Miner (`-m js`):** Scrapes loaded JavaScript bundles, extracts internal API routes, and audits for high-entropy secrets and auth keys.
- **Hidden Parameter Miner (`-param-mine`):** Discovers unlinked query/body parameters via differential response analysis.
- **SQL Injection (`-m sqli`):** Error-based, boolean-blind, and time-based heuristic injection detection.
- **Cross-Site Scripting (`-m xss`):** Context-aware reflection analysis (HTML, attribute, script tag, DOM-sinks).
- **SSRF & Cloud Metadata (`-m ssrf`):** Probes for AWS, GCP, Azure, DigitalOcean instance metadata endpoints and local loopback redirects.
- **SSTI, LFI, CMDi, IDOR, CORS, CSRF, GraphQL:** Comprehensive detection modules with differential false-positive reduction filters.

### 4. 🧬 Native Nuclei YAML DSL Engine (`-templates`)
- Native parser and runner for Nuclei v3 YAML templates (`status`, `word`, `regex` matchers with `and`/`or` conditions).
- Run custom community exploit templates directly with zero external tool dependencies.
- Tunable concurrency, rate-limits, and severity filters (`info,low,medium,high,critical`).

### 5. 🧠 Differential User Enumeration (`-m userenum`)
- **Canary Baseline Calibration:** Dispatches non-existent canary usernames to establish baseline error responses.
- **Auto-Regex Inference:** Automatically identifies failure patterns and synthesizes differential regexes without manual tuning.
- **Timing Discrepancy Detection:** Flags existing users via response divergence and password-hashing execution latency (>180ms).

### 6. ⚡ Nanosecond-Synchronized Race Condition Engine (`-race`)
- **Turbo Intruder Gate-Sync:** Pre-builds HTTP requests in memory and releases 20–50 concurrent goroutines simultaneously via channel gate closure.
- **Limit Bypass & Collision Detection:** Detects concurrency flaws (coupon duplication, balance deduction, double redeem) with false-positive filtering for dynamic tokens and timestamps.

### 7. 🔑 Secrets & Credential Leak Detection (`-m secrets`)
- **TruffleHog-Grade Detection:** Real-time scanning of HTML responses and linked JavaScript bundles.
- **14+ Signatures:** GitHub PATs, AWS Access Keys, Google Cloud APIs, Stripe Keys, Slack/Telegram Bot Tokens, JWTs, RSA/EC Private Keys, and Database URIs with automatic Shannon entropy analysis.

### 8. 🔌 High-Speed TCP Port Scanner & CVE Lookup (`-scan`)
- Concurrent TCP port scanner (`top100`, port ranges like `1-1024`, or comma-separated lists like `80,443,135,445`).
- Banner grabbing and automatic query against NIST NVD CVE databases.

### 9. 📐 Official CVSS v3.1 Calculator & Severity Classifier
- Fully compliant with the FIRST CVSS v3.1 specification for accurate score calculation and vulnerability severity ratings.

### 10. 📊 Professional Multi-Format Reporting
- **Cyber HTML Dashboard (`-report-html`):** Standalone offline interactive dark-mode dashboard.
- **SARIF v2.1.0 (`-report-sarif`):** Standard SARIF output for GitHub Code Scanning, GitLab CI, and DefectDojo.
- **Structured JSON & Markdown:** Machine-readable logs and ready-to-run `curl` reproduction commands.

---

## 🚀 Global One-Command Installation

NightfallLX compiles into a single, dependency-free binary that can be run globally from any terminal.

### 🐧 Linux / macOS / WSL (Auto-Installer)
```bash
git clone https://github.com/Darksystem-01/NightfallLX.git
cd NightfallLX
chmod +x install.sh
./install.sh
```

### 🪟 Windows (PowerShell Auto-Installer)
Open PowerShell and run:
```powershell
git clone https://github.com/Darksystem-01/NightfallLX.git
cd NightfallLX
.\install.ps1
```

### ⚡ Manual Compilation (Go 1.21+)
```bash
git clone https://github.com/Darksystem-01/NightfallLX.git
cd NightfallLX
go build -ldflags="-s -w" -o nightfalllx .
```

---

## 🖥️ Running the Web Command Center

Start the Web Command Center on port 8888:
```bash
nightfalllx -web -web-port 8888
```
Then open your browser at `http://127.0.0.1:8888`.

### 🔄 Running Continuously as a Systemd Service (Host Persistence)
Create `~/.config/systemd/user/nightfalllx-web.service`:
```ini
[Unit]
Description=NightfallLX Web Command Center & Generator Daemon
After=network.target

[Service]
Type=simple
ExecStart=%h/.local/bin/nightfalllx -web -web-port 8888
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
```
Enable and start the service:
```bash
systemctl --user daemon-reload
systemctl --user enable --now nightfalllx-web.service
```

---

## 🎮 CLI Usage Examples

### 1. Launch Web Command Center
```bash
nightfalllx -web
```

### 2. Full Vulnerability & Secrets Audit
```bash
nightfalllx -u "http://target.lab/?id=1" -m all -report-html report.html -report-sarif report.sarif
```

### 3. Passive OSINT Reconnaissance & Subdomain Takeover
```bash
nightfalllx -osint -domain target.com -takeover
```

### 4. HTTP Request Smuggling & Git Repository Extraction
```bash
nightfalllx -u "http://target.lab" -m smuggling,git,js
```

### 5. High-Speed Web Fuzzing with Auto-Regex Filtering
```bash
nightfalllx -u "http://target.lab/FUZZ" -w wordlist.txt -auto-regex -t 40
```

### 6. Differential User Enumeration
```bash
nightfalllx -u "http://target.lab/login" -X POST -d "username=admin&password=123" -m userenum
```

### 7. Turbo Race Condition Attack (Limit Bypass)
```bash
nightfalllx -u "http://target.lab/api/redeem" -X POST -d '{"coupon":"FREE2026"}' -race -race-threads 25 -race-rounds 2
```

### 8. Run Nuclei Community Templates
```bash
nightfalllx -u "http://target.lab" -templates ./nuclei-templates/http/cves/
```

### 9. Fast Port Scan with CVE Enrichment
```bash
nightfalllx -scan -domain target.lab -scan-ports "80,443,8080,8443" -scan-cve
```

---

## 🧪 Verification & Tests

To execute the entire 17-package unit and integration test suite:

```bash
go test -v -count=1 ./pkg/...
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

NightfallLX is developed for authorized penetration testing, security research, and vulnerability assessments only. Testing target systems without explicit prior mutual consent is illegal.
