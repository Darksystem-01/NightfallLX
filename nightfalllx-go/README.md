# NightfallLX (Go Edition v2.0)

High-performance, detection-focused Web Vulnerability Assessment, Fuzzer, and Reconnaissance CLI written in **idiomatic Go**. Designed for web penetration testers and security auditors working on authorized targets: HackTheBox machines, local Docker labs, and operator-owned environments.

Its primary design principle is **zero false positives**: every finding is backed by deterministic response analysis, AST parsing, differential validation, or non-destructive marker tokens. It **never exploits**, **never runs code it discovers**, and **never sends confidential target data to third parties**.

---

## What's New in v2.0 (XSS Engine & Reference Intel)

### 1. Intelligent Go XSS Detection Engine (`pkg/xss`)
Modeled on the architectural concepts of XSStrike, engineered from first principles in idiomatic Go:
- **HTML Context Classification**: Parses HTTP response bodies into an AST using `golang.org/x/net/html`. Classifies reflections into precise contexts: `html-text`, `attribute-quoted`, `attribute-unquoted`, `js-string-single`, `js-string-double`, `js-template`, `js-raw`, `url-attribute`, `html-comment`, and `tag-name`.
- **Character Probing**: Sends harmless character survival probes (`< > " ' ` / ( ) ; =`) to detect active sanitizers or WAF filters before injecting vectors, avoiding wasteful requests.
- **Embedded Harmless Vector Corpus**: 339 curated, non-destructive test vectors embedded with `//go:embed` across 10 functional categories (`html-tag`, `attribute-context`, `js-string-context`, `js-template-context`, `url-scheme`, `event-handler`, `svg`, `math`, `combined-context`, `filter-robustness`). All vectors use harmless canaries (`alert(1)` or random tokens); **no cookie stealing, no external callbacks, no persistent vandalism**.
- **Three-Tier Confidence Grading**:
  - `confirmed`: Active executable HTML node created containing the unescaped canary. Regex alone never produces `confirmed`.
  - `probable`: Injected string reflected unescaped in a dangerous context, or static DOM source-to-sink flow detected.
  - `possible`: Surviving special characters or filter anomaly.
- **Static DOM Flow Analysis (`--dom`)**: Tracks client-side data flows from sources (`location.hash`, `location.search`, `location.href`, `document.URL`, `document.referrer`, `window.name`, `postMessage`) to dangerous sinks (`innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout`, `setInterval`, `location`, `jQuery.html()`). Reports file, line number, source, and sink. Enabled by default; disable with `--dom=false` or `--no-dom`.
- **Form Parsing & CSRF Re-fetching (`--forms`)**: Automatically discovers HTML forms, parses inputs, and re-fetches origin pages before each submission to maintain valid CSRF / anti-automation tokens.
- **Stored Reflection Testing (`--stored`)**: Submits unique tokens via forms, crawls linked pages, and identifies persistent reflection. The report explicitly highlights that test tokens remain stored on the target.
- **Headless Browser DOM Validation (`--dom-browser`)**: Gracefully checks for local Chromium/Chrome on `PATH`. If missing, execution proceeds without interruption.

### 2. Version-Matched Reference Lookup (`pkg/intel`)
Automatic public vulnerability metadata referencing for detected technologies:
- **Zero-Exploit Guarantee**: Strictly parses public reference metadata. Never downloads, copies, compiles, opens, or executes exploit payloads.
- **Local Exploit-DB Index**: Safely queries the local `searchsploit` utility using sanitized argument slices (`--json -- <query>`). Prevents command injection and rejects leading hyphens.
- **NVD 2.0 REST API (`-nvd`)**: Optional keyword search against the National Vulnerability Database with automated rate-limiting, local disk caching in `.intel_cache/`, and CVSS scoring. Reads optional `NVD_API_KEY`.
- **Automatic Banner Triggering**: Automatically matches server banners (e.g., `Server: PHP/3.4.5`, `X-Powered-By`, `<meta name="generator">`). Can be disabled with `--no-intel` or queried manually via `--intel-query "<product> <version>"`.
- **Distinct Report Section**: Reference results appear in an isolated section titled *"Version-matched intel (not verified)"* with explicit notices that version detection may be imprecise.

### 3. Expanded Module Test Sets
All core test sets have been expanded to 50–100 non-destructive, marker-based entries with category and source headers:
- `lfi`: Traversal variants (Unix, Windows, URL-encoded, double-encoded, null-byte, `/proc/version`, PHP filter streams).
- `sqli`: Error-based heuristics across MySQL, PostgreSQL, MSSQL, Oracle, SQLite, boolean differential pairs, and dual-scaling time-based checks (actual code defaults: 3s delay with 6s secondary confirmation via `-sqli-delay`).
- `ssti`: Polyglots and deterministic math expressions (`{{7*7}}`, `${7*7}`, `#{7*7}`) across Jinja2, Twig, Smarty, Freemarker, Velocity, SpringEL, Pebble, ERB, Mako, etc.
- `cmdi`: Non-destructive echo markers (`whoami`, `id`) with argument/operator separators (`;`, `&&`, `|`, `||`, `$()`, backticks).
- `ssrf`: Cloud metadata endpoints (AWS, GCP, Azure, DO, OCI, Alibaba, Kubernetes) and alternative loopback encodings (Decimal, Octal, Hex, IPv6).
- `redirect`: Open redirect schemes (`//`, `/\`, `@`, URI encoding).
- `nosqli`: NoSQL operator injection (`$ne`, `$gt`, `$where`) in JSON and form values.
- `xxe`: Safe entity declarations reading standard test files (`/etc/passwd`, `win.ini`) and PHP filter streams.

---

## Flag Mapping & XSStrike Compatibility

NightfallLX preserves all existing CLI flags and introduces long-named options for advanced capabilities:

| Short / Common Tool Flag | NightfallLX Flag | Description |
|---|---|---|
| `-u` | `-u <url>` | Target URL |
| `-d` | `-d <data>` | POST body data (preserved) |
| `-p` | `-p <proxy>` | HTTP/SOCKS5 proxy (e.g., `http://127.0.0.1:8080`) |
| `-b` | `-b <cookie>` | Cookie header string (maps from `-c` in other tools) |
| `-m` | `-m <modules>` | Comma-separated module list (`xss`, `sqli`, `all`, etc.) |
| `-X` | `-X <method>` | HTTP method (`GET`, `POST`, `PUT`, `DELETE`) |
| `-m POST` | `-X POST` | Legacy shim: only triggers if `-m` equals `POST` or starts with `POST,` |
| `-t` | `-t <threads>` | Concurrency worker count (default: 10) |
| `-w` | `-w <wordlist>` | Wordlist for parameter brute-forcing / fuzzing |
| `-o` | `-o <dir>` | Output directory for markdown and JSON reports |
| `-d` (in XSStrike) | `--dom` | Static DOM source-to-sink analysis (enabled by default; disable with `--dom=false` or `--no-dom`) |
| *New* | `--no-dom` | Disable static DOM XSS source-to-sink analysis |
| *New* | `-sqli-delay <sec>` | Delay in seconds for time-based SQL injection tests (default: 3s; secondary confirmation: 6s) |
| `-l` (in XSStrike) | `--forms` | Parse HTML forms and test input fields |
| `-p` (in XSStrike) | `--param-brute` | Parameter discovery / brute-force before scanning |
| `-f` (in XSStrike) | `--xss-fuzz` | Parameter fuzzing mode |
| *New* | `--crawl` | Spider target site and run XSS engine on all discovered endpoints with parameters or forms (honoring `-max-urls` and `-depth`) |
| *New* | `--stored` | Test for stored/persistent XSS via form submissions |
| *New* | `--dom-browser` | Attempt headless Chromium verification for DOM sinks |
| *New* | `--header "H: V"` | Repeatable custom HTTP header flag |
| *New* | `--log <file>` | Custom log output path |
| *New* | `--intel-query "P V"` | Query local searchsploit / NVD for `<product> <version>` |
| *New* | `--no-intel` | Disable automated version-matched reference lookup |
| *New* | `-nvd` | Enable remote NVD 2.0 API lookup for detected versions |

---

## Usage Examples

### 1. Reflected and DOM XSS Assessment
```bash
nightfalllx -u "http://target.lab/search?q=test" -m xss --dom
```

### 2. Form Testing with Stored XSS Check and Crawling
```bash
nightfalllx -u "http://target.lab/guestbook" -m xss --forms --stored --crawl
```

### 3. Version-Matched Reference Lookup
```bash
# Automatically detects 'Server: PHP/3.4.5' or queries specific version
nightfalllx -u "http://target.lab/" --intel-query "Apache 2.4.49" -nvd
```

### 4. Comprehensive Audit with Custom Headers & Proxy
```bash
nightfalllx -u "http://target.lab/portal" \
  -H "Authorization: Bearer dev-token" \
  --header "X-Forwarded-For: 127.0.0.1" \
  -p "http://127.0.0.1:8080" \
  -m all --dom --forms -o ./reports
```

---

## Safety and Operational Rules

1. **Authorized Use Only**: NightfallLX is strictly intended for authorized engagements, CTF/HackTheBox lab targets, and operator-owned infrastructure.
2. **Zero Exploitation**: Findings are confirmed using non-destructive canary tokens (`alert(1)` or unique random strings) and standard error signatures.
3. **Zero Third-Party Leaks**: NightfallLX never sends target application data, session tokens, or parameters to third parties.
4. **Reference Isolation**: Exploits indexed by `searchsploit` are cited by metadata and local file path only. Files are never opened, modified, or executed.

---

## Building & Verification

### Build Binary
```bash
cd nightfalllx-go
go build -o /home/cyborg/.local/bin/nightfalllx main.go
```

### Run Tests
```bash
# Static analysis
go vet ./...

# Comprehensive test suite with race detector
go test -count=1 -race ./...
```
