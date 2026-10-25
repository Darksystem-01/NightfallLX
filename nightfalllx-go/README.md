# NightfallLX (Go Edition v2.0)

High-performance Web Vulnerability Assessment, Fuzzer & Deep OSINT Reconnaissance Framework written in pure **Go (Golang)**. Zero external runtime dependencies.

---

## 📦 Package Architecture (15 Packages)

| Package | Purpose & Features |
| :--- | :--- |
| `pkg/osint` | Passive OSINT reconnaissance: crt.sh Certificate Transparency, DNS, SPF & DMARC email spoofing audit, CNAME Subdomain Takeover detection, and Wayback Machine historical URL discovery. |
| `pkg/modules` | 20+ Vulnerability testing modules: SQLi, SSTI, LFI, CMDi, XSS, CORS, SSRF, JWT, WAF, IDOR, CSRF, XXE, NoSQLi, File Upload, CRLF, Host Header, and **User Enumeration (`userenum`)**. |
| `pkg/fuzzer` | ffuf-compatible directory & parameter fuzzer (3,000+ req/sec), VHost/Subdomain finder, Auto-calibration (`-ac`), Regex matching (`-mr`), Regex filtering (`-fr`), and **Auto-Regex (`-auto-regex`)**. |
| `pkg/client` | High-throughput HTTP client with connection reuse, Token-bucket rate limiter (`-rate`), Smart retry with exponential backoff on 429/503 (`-retry`), Raw TCP/TLS socket mode (`-raw`), and HTTP/2. |
| `pkg/race` | Turbo Intruder-style nanosecond gate-synchronized race condition testing engine (`-race`, `-race-threads`, `-race-rounds`). |
| `pkg/secrets` | TruffleHog-grade real-time credential & API key scanner with Shannon entropy analysis (`-m secrets`). |
| `pkg/nuclei_engine` | Native runner for Nuclei v3 YAML templates with status, word, and regex matchers (`-templates`, `-template-tags`). |
| `pkg/portscan` | Multi-threaded TCP port scanner (`-scan`, `-scan-ports`) with banner grabbing and NIST NVD CVE lookup (`-scan-cve`). |
| `pkg/parser` | PortSwigger-style Param Miner (`-mine-params`), OpenAPI/Swagger & GraphQL schema parser, and Burp Suite raw request parser (`-r`). |
| `pkg/detector` | Wappalyzer-grade technology stack & exact version fingerprinting (`-tech`). |
| `pkg/sitemap` | Recursive web crawler and JavaScript endpoint extractor (`-map`, `-spider`). |
| `pkg/reporters` | Multi-format reporting engine: Interactive Cyber HTML Dashboard (`-report-html`), SARIF v2.1.0 (`-report-sarif`), JSON (`-report-json`), and Markdown (`-o`). |
| `pkg/troubleshoot` | Pre-flight connectivity, DNS, TCP, TLS 1.3, and proxy diagnostics (`-doctor`). |
| `pkg/oast` | Out-of-Band Application Security Testing (Interactsh & custom webhooks) for blind vulnerability detection. |
| `pkg/tui` | Mouse-controllable interactive terminal dashboard (`-i`). |

---

## 🛠️ Build & Installation

```bash
# Build standalone binary
go build -ldflags="-s -w" -o nightfalllx.exe .
```

---

## 🧪 Running Unit Tests

All 15 packages include comprehensive unit and integration tests:

```bash
go test -v -count=1 ./...
```

---

## 📜 License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.
