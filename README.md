# NightfallLX

[![Go](https://img.shields.io/badge/go-1.20%2B-blue.svg)](https://golang.org/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/Darksystem-01/NightfallLX/actions)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Next-Generation High-Performance Web Vulnerability Assessment & Recon Suite**

NightfallLX is an evidence-first, multi-threaded security assessment and web fuzzing platform (with both high-speed Go runtime and modular Python framework) designed for bug bounty hunters, CTF players, and security engineers.

---

## ⚡ Key Highlights

- 🖱️ **Interactive Mouse-Controlled TUI Dashboard (`nightfalllx -i`):** Cyberpunk terminal interface with full ANSI SGR mouse click navigation and keyboard support.
- 🔍 **Deep Technology & Exact Version Detector (`nightfalllx --tech`):** Wappalyzer-grade identification of web servers (Apache, Nginx, IIS), exact language runtimes (e.g. PHP 8.2.10 via headers & Easter Eggs), frameworks (Laravel, Django, Spring Boot, Express, Rails), template engines (Blade, Twig, Jinja2, Smarty, Thymeleaf), frontend libraries, and defensive security header audits.
- 📬 **Burp Suite Raw HTTP Request Parser (`-r request.txt`):** Native parsing of raw HTTP requests exported from Burp Suite (headers, cookies, query/POST params, and `*`/`FUZZ` injection markers).
- 🌐 **ffuf-Compatible Subdomain & VHost Finder (`--sub`):** High-speed virtual host and subdomain fuzzing with **Auto-Calibration (`-ac`)** to automatically eliminate wildcard/catch-all false positives, paired with rich matchers and filters (`-mc`, `-fc`, `-ms`, `-fs`, `-mw`, `-fw`, `-ml`, `-fl`).
- ⚡ **Mega-Fast 1,800+ req/sec Goroutine Fuzzer:** Ultra-fast directory and parameter fuzzing with zero runtime dependencies.
- 🛡️ **Intelligent Native Go XSS Engine (`pkg/xss`):** Reflection context classification via `golang.org/x/net/html` AST (10 distinct contexts), character probing (`<>"'/\();=`), 339 embedded harmless test vectors, static DOM source-to-sink flow analysis (enabled by default; disable via `--dom=false` or `--no-dom`), form parsing with automatic CSRF token re-fetching (`--forms`), and stored XSS detection (`--stored`).
- 🔎 **Version-Matched Reference Lookup (`pkg/intel`):** Automatically correlates detected server banners (e.g. `Server: PHP/3.4.5`) with local `searchsploit` exploit databases and NIST NVD 2.0 REST API (`-nvd`). Metadata and local paths only; strictly **zero execution, compilation, or downloading** of exploits.
- ⚡ **Enhanced Module Vectors (50–100 per category):** Expanded marker-based test vectors for `lfi`, `sqli` (with dual-scaling 3s and 6s time-based tests configurable via `-sqli-delay`), `ssti`, `cmdi`, `ssrf`, `redirect`, `nosqli`, and `xxe` with zero false positives.
- 📋 **Executive Lab Reports:** Automatic generation of Markdown (`lab_report.md`) and JSON (`lab_report.json`) with isolated "Version-matched intel (not verified)" section and ready-to-replay `curl` commands.

---

## 🚀 One-Step Global Installation

Any user can clone the repository and install `nightfalllx` globally into their terminal with a single command:

```bash
git clone https://github.com/Darksystem-01/NightfallLX.git
cd NightfallLX
./install.sh
```

Now `nightfalllx` is available globally from **any directory** in your terminal!

```bash
nightfalllx --version
```

---

## 🎮 Usage Guide

### 1. Interactive Mouse Dashboard
Launch the mouse-controllable TUI dashboard with neon cyber graphics:
```bash
nightfalllx -i
# or
nightfalllx --ui
```

### 2. Deep Technology & Exact Version Fingerprinting
Scan web servers, exact PHP versions, frameworks, and template engines:
```bash
nightfalllx --tech -u http://target.lab
```

### 3. Burp Suite Raw Request Assessment
Pass an exported Burp Suite request file directly to the scanner:
```bash
nightfalllx -r request.txt -m all -p http://127.0.0.1:8080
```

### 4. Subdomain & VHost Fuzzing (ffuf-style)
Discover hidden virtual hosts on a target IP with automatic wildcard calibration:
```bash
nightfalllx -sub -u http://10.129.20.10 -domain target.htb -t 50
```

### 5. High-Speed Web Fuzzing
Fuzz web endpoints with custom status codes and size/word filters:
```bash
nightfalllx -u http://target.lab/FUZZ -w wordlist.txt -t 50 -mc 200,301,302,403 -fw 12
```

### 6. Comprehensive Vulnerability Assessment
Run all 10 security testing modules with Burp Suite proxy integration:
```bash
nightfalllx -u http://target.lab/app.php?id=1 -m all -p http://127.0.0.1:8080 -o my_audit
```

### 7. Diagnostics & Troubleshooting
Test your DNS, TCP, TLS, and proxy connectivity:
```bash
nightfalllx --doctor -u http://target.lab -p http://127.0.0.1:8080
```

---

## 🧪 Testing

To run the complete test suites:

```bash
# Go test suite (0.02s)
cd nightfalllx-go && go test -v ./...

# Python test suite (43 passed)
PYTHONPATH=. pytest
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
