# NightfallLX (v2.0)

[![Go](https://img.shields.io/badge/go-1.21%2B-blue.svg)](https://golang.org/)
[![Version](https://img.shields.io/badge/version-2.0.0-purple.svg)](https://github.com/Darksystem-01/NightfallLX)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/Darksystem-01/NightfallLX/actions)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Next-Generation High-Performance Web Assessment, Vulnerability Scanner & Deep OSINT Recon Suite**

NightfallLX is an evidence-first, multi-threaded offensive and defensive security platform written in pure **Go (Golang)**. Designed for penetration testers, bug bounty hunters, red teams, and security researchers, it consolidates web vulnerability discovery, passive OSINT reconnaissance, high-speed fuzzing, race condition testing, and secret detection into a single, dependency-free binary.

---

## ⚡ Key Capabilities & Modules

### 1. 🔍 Deep Passive OSINT Reconnaissance (`-osint`)
- **Certificate Transparency (crt.sh):** Passively discovers hidden subdomains and historical SSL certificates without sending a single packet to the target.
- **DNS & Email Spoofing Auditing:** Automatic verification of `SPF` and `_dmarc.<domain>` records; flags **Missing DMARC (CEO Fraud / Phishing risk)** and permissive `+all` SPF policies.
- **Subdomain Takeover Detection:** Resolves CNAME records against signatures for abandoned third-party services (GitHub Pages, AWS S3, Heroku, Azure, Ghost, Surge, Fastly, etc.).
- **Wayback Machine Integration:** Fetches historical URLs and extracts sensitive files (`.sql`, `.env`, `.bak`, `.config`, `.json`, unlisted `/api/` routes) from web.archive.org.
- **Cloud & Network Intelligence:** Reverse DNS, BGP ASN, and Anycast CDN identification (Cloudflare, AWS, Google Cloud, Azure, DigitalOcean, Linode).

### 2. 🧠 Intelligent User Enumeration with Differential Auto-Regex (`-m userenum`)
- **Canary Baseline Calibration:** Dispatches non-existent canary usernames to establish baseline error responses.
- **Auto-Regex Inference:** Automatically identifies the failure pattern and synthesizes differential regexes (e.g. `(?i)user.*not\s*found`) without manual regex configuration.
- **Timing & Discrepancy Detection:** Flags existing users (`admin`, `root`, `support`) via response divergence, HTTP status shifts, and password-hashing execution latency (>180ms).

### 3. ⚡ Nanosecond-Synchronized Race Condition Engine (`-race`)
- **Turbo Intruder Gate-Sync:** Pre-builds HTTP requests in memory and releases 20–50 concurrent goroutines simultaneously via channel gate closure.
- **Limit Bypass & Collision Detection:** Detects concurrency flaws (coupon duplication, balance deduction, double redeem) with false-positive filtering for dynamic tokens and timestamps.

### 4. 🔑 Secrets & Credential Leak Detection (`-m secrets`)
- **TruffleHog-Grade Detection:** Real-time scanning of HTML responses and linked JavaScript bundles.
- **14+ Signatures:** GitHub PATs, AWS Access Keys, Google Cloud APIs, Stripe Keys, Slack/Telegram Bot Tokens, JWTs, RSA/EC Private Keys, and Database URIs with automatic Shannon entropy analysis.

### 5. 🧬 Nuclei YAML DSL Engine (`-templates`)
- Native parser and runner for Nuclei v3 YAML templates (`status`, `word`, `regex` matchers with `and`/`or` conditions).
- Run custom community exploit templates directly with zero external tool dependencies.

### 6. 🔌 High-Speed TCP Port Scanner & CVE Lookup (`-scan`)
- Concurrent TCP port scanner (`top100`, port ranges like `1-1024`, or comma-separated lists like `80,443,135,445`).
- Banner grabbing and automatic query against NIST NVD CVE databases.

### 7. 🛡️ Advanced WAF Evasion & Adaptive Throttling
- **Adaptive Throttling (`-adaptive`):** Automatically throttles concurrency and introduces jitter upon encountering HTTP 429 / 403 responses.
- **Fingerprint Rotation (`-rotate-ua`):** Dynamically cycles realistic browser User-Agent headers.
- **Header Tampering & Chunking (`-tamper-headers`, `-chunked`, `-raw`):** Injects originating IP headers, chunked transfer encoding, and raw TLS socket bypasses.

### 8. 📊 Professional Multi-Format Reporting
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
*(Or double-click `install.bat`)*

### ⚡ Manual Compilation (Go 1.21+)
```bash
git clone https://github.com/Darksystem-01/NightfallLX.git
cd NightfallLX
go build -ldflags="-s -w" -o nightfalllx .
```

---

## 🎮 CLI Usage Examples

### 1. Passive OSINT Reconnaissance
```bash
nightfalllx -osint -domain target.com
```

### 2. High-Speed Web Fuzzing with Auto-Regex Filtering
```bash
nightfalllx -u "http://target.lab/FUZZ" -w wordlist.txt -auto-regex -t 40
```

### 3. User Enumeration with Differential Analysis
```bash
nightfalllx -u "http://target.lab/login" -X POST -d "username=admin&password=123" -m userenum
```

### 4. Turbo Race Condition Attack (Limit Bypass)
```bash
nightfalllx -u "http://target.lab/api/redeem" -X POST -d '{"coupon":"FREE2026"}' -race -race-threads 25 -race-rounds 2
```

### 5. Full Vulnerability & Secrets Audit
```bash
nightfalllx -u "http://target.lab/?id=1" -m all -p http://127.0.0.1:8080 -report-html report.html -report-sarif report.sarif
```

### 6. Fast Port Scan with CVE Enrichment
```bash
nightfalllx -scan -domain target.lab -scan-ports "80,443,8080,8443" -scan-cve
```

### 7. Run Nuclei Community Templates
```bash
nightfalllx -u "http://target.lab" -templates ./nuclei-templates/http/cves/
```

### 8. Environment & TLS Diagnostics
```bash
nightfalllx -doctor -u https://target.lab
```

---

## 🧪 Verification & Tests

To execute the entire 15-package unit and integration test suite:

```bash
cd nightfalllx-go
go test -v -count=1 ./...
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

NightfallLX is developed for authorized penetration testing, security research, and vulnerability assessments only. Testing target systems without explicit prior mutual consent is illegal.
