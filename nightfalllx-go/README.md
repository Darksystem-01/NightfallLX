# NightfallLX (Go Edition v2.1)

High-performance, detection-focused Web Vulnerability Assessment, Fuzzer, and Reconnaissance CLI written in **idiomatic Go**. Designed for web penetration testers and security auditors working on authorized targets: HackTheBox machines, local Docker labs, and operator-owned environments.

Its primary design principle is **zero false positives**: every finding is backed by deterministic response analysis, AST parsing, differential validation, or non-destructive marker tokens. It **never exploits**, **never runs code it discovers**, and **never sends confidential target data to third parties**.

## 📚 Documentation
- [Complete Cheat Sheet (CHEATSHEET.md)](CHEATSHEET.md)

---

## What's New in v2.1 (Integrations, Plugins & Reporting)

### 1. WPScan, NVD & Exploit-DB Enrichment
- **WPScan API v3**: Supply `--wpscan-token` (or `WPSCAN_API_TOKEN`) to look up core, plugin, and theme vulnerabilities, including fixed versions, CVEs, CVSS scores, and references. Results are matched against detected versions so already-fixed issues are skipped.
- **NVD CVE enrichment**: When `NVD_API_KEY` is present, the exploit mapper resolves CVEs found by WPScan or the built-in catalog against the NVD 2.0 API to enrich findings with authoritative CVSS scores and descriptions. NVD lookups are rate-limited and cached for 24 hours in `.intel_cache/`.
- **Optional Exploit-DB copies**: `--download-exploits` downloads matching public exploit records from Exploit-DB into `--loot-dir` (default `loot/`) for manual review. Downloaded files are never opened or executed by NightfallLX.
- **Version-aware WPScan matching**: WordPress core, plugin, and theme versions are compared with `fixed_in`; findings at or above the fixed version are discarded.
- **Actionable result caps**: Automated reference lookups require a detected version and are capped per query and overall. Use `--intel-query` for deliberate versionless searches.

### 2. Plugin System (`pkg/plugins`)
- Go `plugin`-based extensions load from `~/.nightfalllx/plugins` (override with `NIGHTFALLX_PLUGIN_DIR`) when `--plugins` is enabled.
- Each plugin exports a package-level `Plugin` symbol with `Name() string` and `Execute(target string, client *http.Client) (string, error)`.
- A buildable example lives at `pkg/plugins/examples/sample_plugin.go`.
- Plugins run in-process with the operator's privileges and can make arbitrary network calls. Only load plugins you have reviewed and trust.
- Go plugins are supported on Linux and macOS. Windows requires a custom `.dll` loader; NightfallLX reports this explicitly rather than silently skipping plugins.

### 3. HTML & SARIF Reports
- `--html` writes a self-contained dark-theme HTML dashboard with severity filters, search, expandable finding details, and version-intel tables.
- `--sarif` writes SARIF 2.1.0 for GitHub code scanning and other SARIF consumers, including CWE-aware rule IDs, severity mapping, target locations, and intel results.
- Markdown and JSON reports remain the default outputs.

### 4. Resumable Scans & Profiles
- Scan state is saved to `.nightfalllx/state.json` after each completed module. `--resume` restores findings, completed modules, and intel only when the target URL and HTTP method match the saved scan.
- `--save-profile <name>` captures explicitly supplied CLI flags under `~/.nightfalllx/profiles/<name>.json`.
- `--profile <name>` applies saved flags that were not supplied explicitly, so one-off overrides still win.
- Interrupted scans save their state and exit with status `130` after `SIGINT`/`SIGTERM`.

### 5. Global Cancellation, Rate Limiting & Update Checks
- A shared rate limiter now governs the main HTTP client, fuzzer, and spider, so `-rate` applies across workers rather than per goroutine.
- `context.Context` cancellation propagates through the HTTP client, fuzzer, spider, crawl/XSS loop, exploit mapper, WPScan/NVD clients, and between plugin executions.
- At startup NightfallLX performs a short, non-blocking GitHub release check and warns when a newer version exists. Disable it with `--no-update-check` or `NIGHTFALLX_NO_UPDATE_CHECK=1`.

---

## Exploit Mapper (v2.0)

The `exploit-mapper` module performs deep, read-only fingerprinting before mapping public vulnerability references:

- **WordPress/plugin/theme fingerprinting** from generators, asset paths, readme files, and version strings.
- **Cloudflare/WAF detection** with guidance for authorized origin discovery.
- **CVE-first mapping** using a built-in catalog and version comparisons, plus CVE/EDB metadata, CVSS severity, and references.
- **Dynamic Metasploit search**: when `msfconsole` is available, NightfallLX runs only `search <keyword>; exit` to discover relevant modules. Disable with `--msf-search=false`.
- **Structured Attack Plan** with candidate exploits, Metasploit commands for reference, next steps, and an explicit no-execution notice.

NightfallLX never runs exploit modules, never executes downloaded exploit code, and never modifies target state through this module.

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
- **Zero-Exploit Guarantee**: Strictly parses public reference metadata. Exploit code is downloaded only when `--download-exploits` is explicitly supplied, and is never opened, compiled, or executed.
- **Local Exploit-DB Index**: Safely queries the local `searchsploit` utility using sanitized argument slices (`--json -- <query>`). Prevents command injection and rejects leading hyphens.
- **NVD 2.0 REST API (`-nvd`)**: Optional keyword search against the National Vulnerability Database with automated rate-limiting, local disk caching in `.intel_cache/`, and CVSS scoring. Reads optional `NVD_API_KEY`; when the key is present, automated intel enables NVD without requiring `-nvd`.
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
| *New* | `-rate <n>` | Global maximum HTTP requests per second across scan workers |
| *New* | `--wpscan-token <token>` | WPScan API token (default: `WPSCAN_API_TOKEN`) |
| *New* | `--download-exploits` | Download matching Exploit-DB records into `--loot-dir` for manual review |
| *New* | `--loot-dir <dir>` | Directory for downloaded exploit records (default: `loot`) |
| *New* | `--plugins` | Load trusted Go plugins from `--plugin-dir` |
| *New* | `--plugin-dir <dir>` | Plugin directory (default: `~/.nightfalllx/plugins`) |
| *New* | `--html` | Write an HTML report alongside Markdown/JSON output |
| *New* | `--sarif` | Write a SARIF 2.1.0 report alongside Markdown/JSON output |
| *New* | `--resume` | Resume the last scan from `.nightfalllx/state.json` |
| *New* | `--profile <name>` | Apply saved CLI flags from `~/.nightfalllx/profiles/<name>.json` |
| *New* | `--save-profile <name>` | Save explicitly supplied CLI flags as a profile and exit |
| *New* | `--msf-search=false` | Disable read-only dynamic Metasploit module searches |
| *New* | `--no-update-check` | Disable the startup GitHub release check |

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

### 5. Exploit Mapping with WPScan, NVD & Exploit-DB
```bash
export NVD_API_KEY="your-nvd-key"
nightfalllx -u "http://target.lab/" -m exploit-mapper \
  --wpscan-token "your-wpscan-token" \
  --download-exploits --loot-dir ./loot \
  -o ./reports --html --sarif
```

### 6. Saving and Reusing a Profile
```bash
# Save the flags used for this engagement, then reuse them later
nightfalllx -u "http://target.lab/" -H "Authorization: Bearer dev-token" \
  --save-profile lab-auth
nightfalllx --profile lab-auth -m all --html --sarif -o ./reports
```

### 7. Resuming an Interrupted Assessment
```bash
nightfalllx -u "http://target.lab/" -m all --resume
# If interrupted with Ctrl+C, rerun the same command to continue
nightfalllx -u "http://target.lab/" -m all --resume
```

### 8. Loading a Trusted Plugin
```bash
mkdir -p ~/.nightfalllx/plugins
go build -buildmode=plugin \
  -o ~/.nightfalllx/plugins/sample.so \
  ./pkg/plugins/examples/sample_plugin.go
nightfalllx -u "http://target.lab/" -m headers --plugins
```

---

## External Vulnerability Integrations

### WPScan
Set a token via `--wpscan-token` or `WPSCAN_API_TOKEN`. The client calls `https://wpscan.com/api/v3` for detected WordPress core, plugin, and theme versions. Fixed-version comparisons prevent reporting vulnerabilities that no longer apply.

### NVD
Set `NVD_API_KEY` to enable authenticated NVD 2.0 lookups. NightfallLX resolves CVEs found by WPScan or the built-in catalog, applies authoritative CVSS scores and English descriptions, rate-limits requests, and caches results in `.intel_cache/` for 24 hours.

### Exploit-DB
`--download-exploits` fetches raw public exploit records into `--loot-dir` as `edb-<ID>.txt`. The downloader validates numeric EDB IDs, caps downloads at 10 MiB, uses restrictive file permissions, and reuses existing local copies. Files are for manual review only and are never opened or executed.

---

## Plugin System

A plugin exports a package-level symbol named `Plugin`:

```go
type Plugin interface {
    Name() string
    Execute(target string, client *http.Client) (string, error)
}
```

Loader behavior:
- `--plugins` enables plugin loading.
- `--plugin-dir` overrides `~/.nightfalllx/plugins`; `NIGHTFALLX_PLUGIN_DIR` is also honored.
- On Linux/macOS the loader discovers `*.so` files; on Windows it reports that Go's `plugin` package is unsupported and that a custom `.dll` loader is required.
- A plugin failure is reported as a load/execution warning and does not abort the assessment.

Security note: plugins execute in-process with your privileges. Review plugin source before loading it, especially any plugin that handles credentials or target data.

---

## Reports, Resume State & Profiles

- `--html` adds a standalone HTML dashboard; `--sarif` adds SARIF 2.1.0 output. Both are written next to the Markdown and JSON reports when `-o` is set.
- Resume state defaults to `.nightfalllx/state.json`. It records the target, method, module list, completed/pending modules, findings, and intel. A successful scan removes the file; interrupted scans keep it. Resume refuses state from a different URL or HTTP method.
- Profiles live in `~/.nightfalllx/profiles/<name>.json`. Explicit CLI flags take precedence over profile values. Profile names are limited to 1–64 alphanumeric, dot, underscore, or hyphen characters. Profiles and state files are written with owner-only (`0600`) permissions; avoid saving secrets on shared systems.

---

## Cancellation, Rate Limiting & Updates

- `-rate` is enforced by a shared limiter used by the main client, fuzzer, and spider.
- `SIGINT`/`SIGTERM` cancels in-flight requests and subprocesses, saves resume state, and exits with status `130`.
- The startup update check calls the GitHub releases API with a short timeout and never blocks the assessment. Disable it with `--no-update-check` or `NIGHTFALLX_NO_UPDATE_CHECK=1`.

---

## Safety and Operational Rules

1. **Authorized Use Only**: NightfallLX is strictly intended for authorized engagements, CTF/HackTheBox lab targets, and operator-owned infrastructure.
2. **Zero Exploitation**: Findings are confirmed using non-destructive canary tokens (`alert(1)` or unique random strings) and standard error signatures.
3. **Zero Third-Party Leaks**: NightfallLX never sends target application data, session tokens, or parameters to third parties.
4. **Reference Isolation**: Exploits indexed by `searchsploit` are cited by metadata and local file path only. Optional Exploit-DB downloads via `--download-exploits` are saved for manual review and are never opened or executed.
5. **Plugin Trust**: Plugins run in-process with operator privileges. Only load code you have reviewed and trust.
6. **No Exploit Execution**: NightfallLX does not run Metasploit modules, exploit payloads, or downloaded exploit code.

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

# Comprehensive test suite
go test -count=1 ./...

# Comprehensive test suite with race detector
go test -count=1 -race ./...
```

### Build the Sample Plugin
```bash
go build -buildmode=plugin -o /tmp/sample.so ./pkg/plugins/examples/sample_plugin.go
```
