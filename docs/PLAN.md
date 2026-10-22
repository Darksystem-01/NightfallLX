# Implementation Plan: XSS Detection Engine & Version-Matched Intel

## Overview
This plan outlines the systematic development, verification, and integration of:
1. Native Go XSS Detection Engine (`pkg/xss`) with HTML context classification via `golang.org/x/net/html`, character probing, harmless marker test vectors (300+ vectors embedded via `go:embed`), DOM source-to-sink static analysis, form parsing, stored XSS checks, crawling, and parameter brute-forcing.
2. Version-Matched Reference Lookup (`pkg/intel`) with automated banner detection, secure `searchsploit` JSON metadata extraction, NVD 2.0 REST API fallback with rate-limiting, and dedicated unverified reporting.
3. Expanded marker-based test vector sets (50-100 entries each) for existing modules: LFI, SQLi, SSTI, CMDi, SSRF, Open Redirect, NoSQLi, and XXE.
4. Comprehensive test lab (`testdata/xss_lab/`), integration tests, CLI flag mapping, documentation (`README.md`, `docs/MORNING_REPORT.md`), and Git branch push.

---

## Checkpoint Schedule

### Checkpoint 1: Native Go XSS Engine (`pkg/xss`)
- **1.1 Structure & Context Classifier:**
  - Create `pkg/xss/context.go`: classify reflections into `html-text`, `attribute-quoted`, `attribute-unquoted`, `js-string` (single/double), `js-template`, `js-raw`, `url-attribute` (`href`, `src`, `action`), `html-comment`, and `tag-name` using `golang.org/x/net/html`.
- **1.2 Character Probing:**
  - Create `pkg/xss/probe.go`: send character probe (`< > " ' ` / ( ) ; =`) with unique canaries; determine which special characters survive unescaped/unfiltered to avoid futile vector transmission.
- **1.3 Test-Vector Corpus (`pkg/xss/vectors/`):**
  - Create category files: `html_tag.txt`, `attribute_context.txt`, `js_string_context.txt`, `js_template_context.txt`, `url_scheme.txt`, `event_handler.txt`, `svg.txt`, `math.txt`, `combined_context.txt`, `filter_robustness.txt`.
  - Embed with `//go:embed vectors/*.txt`. Ensure 300+ safe, harmless marker payloads using `alert(1)` or `{{canary}}`.
- **1.4 Engine & Confidence Determination:**
  - Create `pkg/xss/engine.go`:
    - Re-parse HTML response tree with `golang.org/x/net/html` after test vector injection.
    - `confirmed`: active executable node holding unescaped marker (event handler attribute like `onload`/`onerror`, `<script>` tag, or `javascript:` URL in an active attribute). Regex alone never produces confirmed.
    - `probable`: reflected unescaped in a dangerous context, but parse does not prove immediate execution.
    - `possible`: partial special character survival or filter anomaly.
- **1.5 DOM Analysis (`pkg/xss/dom.go`):**
  - Static AST/regex source-to-sink flow analysis across inline scripts and same-origin linked JS files. Sources: `location.hash`, `location.search`, `location.href`, `document.URL`, `document.referrer`, `window.name`, `postMessage`. Sinks: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `setTimeout`, `setInterval`, `location`, `jQuery.html()`.
  - Browser validation flag (`--dom-browser`): optional headless Chrome check if binary exists on system; graceful skip if absent.
- **1.6 Forms & Stored XSS (`pkg/xss/forms.go` & `pkg/xss/stored.go`):**
  - Extract HTML forms, inputs, CSRF tokens; re-fetch form page before each submission to refresh tokens.
  - Stored check (`--stored`): submit unique canary via forms, crawl endpoints to check if canary appears in executable context.
- **1.7 Unit Tests:** `pkg/xss/xss_test.go` verifying reflection parsing, context detection, probing, and DOM analysis with positive and negative fixtures.

### Checkpoint 2: Version-Matched Reference Lookup (`pkg/intel`)
- **2.1 Core Intel Engine (`pkg/intel/intel.go`):**
  - Data models: `IntelFinding`, `IntelReport`, `QueryTarget`.
  - Strict input validation regex (`^[a-zA-Z0-9._ -]+$`), length capping, rejection of leading hyphens.
- **2.2 Searchsploit Integration (`pkg/intel/searchsploit.go`):**
  - Use `exec.Command("searchsploit", "--json", "--", query)` — no shell string.
  - Parse JSON array output: `Title`, `EDB-ID`, `Path`, `Type`, `Platform`, `Date`.
  - Extract CVE IDs via `CVE-\d{4}-\d{4,}` regex.
  - Safety rule: Never open, execute, compile, or copy any exploit file.
  - Install hint if searchsploit is missing from `$PATH`.
- **2.3 NVD 2.0 REST API Client (`pkg/intel/nvd.go`):**
  - Query NVD API `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=...`.
  - Rate limiting (5 requests per 30s for unauthenticated).
  - API key from `NVD_API_KEY` environment variable.
  - Local JSON caching in `.intel_cache/`.
- **2.4 Unit Tests:** `pkg/intel/intel_test.go` with fake searchsploit mock script on `$PATH`, `httptest.Server` for NVD, and input sanitization validation.

### Checkpoint 3: Expanded Test Sets for Existing Modules
- Expand vector arrays in `pkg/modules/`:
  - `lfi.go`: 60+ entries (Linux, Windows, PHP wrappers, log poison patterns, path truncation).
  - `sqli.go`: 80+ entries (MySQL, MSSQL, PostgreSQL, Oracle, SQLite; boolean, error, time, union).
  - `ssti.go`: 60+ entries (Jinja2, Twig, Freemarker, Pebble, Velocity, Smarty, ERB, Mako, Pug).
  - `cmdi.go`: 60+ entries (Linux/Unix, Windows cmd/powershell, whitespace bypasses, command separators).
  - `ssrf.go`: 50+ entries (AWS, GCP, Azure, Oracle Cloud, localhost alternate encodings, IPv6, DNS rebinding).
  - `redirect.go`: 50+ entries (protocol-relative, backslash evasion, URL encoding, subdomain bypass).
  - `nosqli.go`: 50+ entries (MongoDB, CouchDB, operator injections, JSON regex, boolean differential).
  - `xxe.go`: 50+ entries (file retrieval, parameter entities, OOB canaries, UTF-16 encodings).
- All vectors must use safe harmless markers and include header comments detailing category and context.

### Checkpoint 4: CLI Integration, Flag Mapping & Reporters
- Wire new flags in `nightfalllx-go/main.go`:
  - `--dom`, `--dom-browser`, `--forms`, `--param-brute`, `--xss-fuzz`, `--crawl`, `--log`, `--header`, `--intel-query`, `--no-intel`, `-nvd`, `--stored`.
  - Wire XSS engine into module execution and standalone runner.
  - Wire automated banner extraction (`Server`, `X-Powered-By`, generator tag, `tech.go`) to trigger `intel.Lookup` unless `--no-intel` is passed.
- Update `pkg/reporters/markdown.go` and `pkg/reporters/json.go`:
  - Add separate section: `## Version-Matched Intel (Not Verified)`.
  - Include warning disclaimer that banner versions may be inaccurate and results require manual review.
  - Keep `Finding` struct backward compatible.

### Checkpoint 5: Test Environment (`testdata/xss_lab/`) & Integration Tests
- Build comprehensive local test server in `testdata/xss_lab/server.go`:
  - Reflected HTML-text endpoint (`/reflected-text?q=...`)
  - Quoted attribute endpoint (`/attr-quote?name=...`)
  - Unquoted attribute endpoint (`/attr-unquote?val=...`)
  - JS string context endpoint (`/js-string?user=...`)
  - JS template literal endpoint (`/js-template?theme=...`)
  - DOM XSS page with `location.hash` to `element.innerHTML` (`/dom-hash`)
  - Stored comment form with CSRF token (`/stored-comments` + `/post-comment`)
  - Filter endpoint blocking `<script>` but permitting `<img onerror=...>` (`/filter-test?input=...`)
  - Version banner endpoint returning `Server: PHP/3.4.5` (`/version-test`)
  - Clean static negative control page (`/clean`)
- Integration test in `integration_xss_intel_test.go`:
  - Assert confirmed, probable, and possible confidence classifications.
  - Assert DOM finding detection.
  - Assert stored XSS finding detection.
  - Assert intel section triggered by `PHP/3.4.5`.
  - Assert ZERO findings on `/clean`.

### Checkpoint 6: Verification, Documentation & Git Push
- Run `go vet ./...` and `go test -count=1 -race ./...`.
- Update `README.md` with complete flag documentation, XSStrike flag mappings, examples, and safety notices.
- Update `.gitignore` with lab outputs, cache files, and report files.
- Recompile binary to `/home/cyborg/.local/bin/nightfalllx`.
- Update `docs/STATUS.md` and generate comprehensive `docs/MORNING_REPORT.md`.
- Commit changes and push to branch `feat/xss-searchsploit`.
