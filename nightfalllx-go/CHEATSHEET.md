# NightfallLX v2.1 — Complete Cheat Sheet

> **Authorized testing only.** Use NightfallLX exclusively against systems you own or have explicit written permission to assess. Version 2.1 is **detection and reference-only**: it does not exploit vulnerabilities, deploy payloads, open reverse shells, or hand off sessions.

## Table of Contents

1. [Introduction & Installation](#1-introduction--installation)
2. [Global CLI Flags](#2-global-cli-flags)
3. [Scanning Modes](#3-scanning-modes)
4. [The 23 Vulnerability Modules](#4-the-23-vulnerability-modules)
5. [Advanced Usage & Integrations](#5-advanced-usage--integrations)
6. [Output & Reporting](#6-output--reporting)
7. [Troubleshooting & Tips](#7-troubleshooting--tips)
8. [Quick Reference](#8-quick-reference)

---

## 1. Introduction & Installation

### What NightfallLX is

NightfallLX is a Go-based web assessment CLI for:

- Technology and version fingerprinting.
- Site mapping and endpoint discovery.
- Parameter discovery and high-speed fuzzing.
- 23 non-destructive vulnerability modules.
- Native reflected/DOM XSS analysis.
- WordPress/CVE/Exploit-DB reference mapping.
- WPScan and NVD enrichment.
- JSON, Markdown, HTML, and SARIF reporting.
- Profiles, resumable scans, OAST callbacks, and plugins.

### Requirements

- Go **1.26+** (matches `go.mod`).
- Linux, macOS, or Windows for the main binary.
- Go plugins (`.so`) only on Linux/macOS.
- `searchsploit` and `msfconsole` are optional.
- A wordlist is optional; built-in lab wordlists are used when `-w` is omitted.

### Build and install

```bash
git clone https://github.com/Darksystem-01/NightfallLX.git
cd NightfallLX/nightfalllx-go

# Build
go build -trimpath -o nightfalllx main.go

# Verify
./nightfalllx --version
./nightfalllx --doctor -u http://target.lab

# Install to PATH
mkdir -p "$HOME/.local/bin"
install -m 0755 nightfalllx "$HOME/.local/bin/nightfalllx"
export PATH="$HOME/.local/bin:$PATH"
```

### Doctor diagnostics

```bash
# Basic environment and target checks
nightfalllx --doctor -u http://target.lab

# Include a wordlist and Burp proxy check
nightfalllx --doctor \
  -u http://target.lab \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -p http://127.0.0.1:8080
```

`--doctor` checks Go runtime, proxy reachability, wordlist access, DNS, TCP, HTTP latency, and TLS where applicable.

### SecLists and wordlists

> **Important:** v2.1 does **not** auto-download SecLists. The doctor’s wordlist hint mentions `--download-wordlists`, but that flag is not implemented in this release.

Install SecLists manually:

```bash
# Debian/Kali
sudo apt install seclists

# Or clone
git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/SecLists

# Common examples
ls /usr/share/seclists/Discovery/Web-Content/common.txt
ls /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

If `-w` is omitted, the fuzzer uses a built-in lab wordlist. This is convenient for HTB-style labs but not a substitute for a full engagement wordlist.

### Update check

NightfallLX performs a short GitHub release check on startup.

```bash
nightfalllx --no-update-check -u http://target.lab
NIGHTFALLX_NO_UPDATE_CHECK=1 nightfalllx -u http://target.lab
```

---

## 2. Global CLI Flags

`-o` is an output **base name**, not a directory. Create the parent directory first:

```bash
mkdir -p reports
nightfalllx -u http://target.lab -m all -o reports/scan
```

### Target and input

| Flag | Type | Default | Description |
|---|---|---|---|
| `-u` | string | `""` | Target URL or `FUZZ` template |
| `-r` | string | `""` | Burp-style raw HTTP request file |
| `-domain` | string | `""` | Domain for subdomain/VHost discovery |
| `-https`, `-ssl` | bool | `false` | Force HTTPS when using `-r` or a bare host |
| `-X` | string | `GET` | HTTP method |
| `-d` | string | `""` | Request body; supports `FUZZ` |
| `-H`, `--header` | repeatable string | none | Custom request header |
| `-H2` | repeatable string | none | Secondary-identity header for IDOR/auth tests |
| `-b` | string | `""` | Cookie header |
| `-b2` | string | `""` | Secondary-identity cookie |
| `-bearer` | string | `""` | Bearer token for authenticated scans |
| `-p` | string | `""` | HTTP proxy, e.g. `http://127.0.0.1:8080` |
| `-k` | bool | `true` | Disable TLS verification (`-k=false` to verify) |
| `-timeout` | int | `15` | Per-request timeout in seconds |
| `-json` | bool | `false` | Treat the request body as JSON; does **not** mean JSON report output |
| `-rate` | int | `0` | Global requests per second; `0` = unlimited |
| `-sqli-delay` | int | `3` | Delay in seconds for time-based SQL injection probes |

### Scope and authorization

| Flag | Type | Default | Description |
|---|---|---|---|
| `-scope` | string | `""` | Allowed hosts or path to a scope file; comma-separated and `*.domain` supported |
| `-scope-off` | bool | `false` | Disable the scope guard; use only on authorized targets |

### Authentication

| Flag | Type | Default | Description |
|---|---|---|---|
| `-login-url` | string | `""` | Login endpoint |
| `-login-data` | string | `""` | Login body with `{{user}}` and `{{pass}}` placeholders |
| `-login-user` | string | `""` | Username; also `LOGIN_USER` |
| `-login-pass` | string | `""` | Password; also `LOGIN_PASS` |
| `-login-success-regex` | string | `""` | Regex confirming successful login |
| `-login-success-status` | int | `0` | Expected login status code |
| `-logout-regex` | string | `""` | Regex indicating session expiry and triggering re-login |
| `-refresh-url` | string | `""` | Token refresh endpoint |
| `-refresh-json-path` | string | `access_token` | JSON field containing the refreshed token |

### Scanning modes

| Flag | Type | Default | Description |
|---|---|---|---|
| `-tech` | bool | `false` | Technology and exact-version detection |
| `-map`, `-spider` | bool | `false` | Spider and print a site map |
| `-crawl` | bool | `false` | Crawl and run the XSS engine on parameters/forms |
| `-depth` | int | `3` | Spider recursion depth |
| `-max-urls` | int | `50` | Maximum URLs to crawl |
| `-shodan` | bool | `false` | Shodan OSINT mode |
| `-shodan-key` | string | `""` | Shodan API key; falls back to `SHODAN_API_KEY` and local key files |
| `-i`, `-ui`, `-tui` | bool | `false` | Interactive TUI dashboard |
| `-m` | string | `all` | Comma-separated module list |

### XSS and DOM analysis

| Flag | Type | Default | Description |
|---|---|---|---|
| `-dom` | bool | `true` | Static DOM source-to-sink analysis |
| `-no-dom` | bool | `false` | Disable DOM analysis |
| `-dom-browser` | bool | `false` | Try Chromium/Chrome DOM validation |
| `-forms` | bool | `false` | Parse forms and test fields with CSRF refresh |
| `-stored` | bool | `false` | Stored reflection testing through forms |
| `-xss-fuzz` | bool | `false` | Filter-survival probing/fuzzing |
| `-log` | string | `""` | Additional Markdown log path |

### Fuzzing and matching

| Flag | Type | Default | Description |
|---|---|---|---|
| `-w` | string | `""` | Wordlist path |
| `-fuzz` | bool | `false` | Explicitly enable fuzzing |
| `-dir` | bool | `false` | Directory brute-forcing mode (`gobuster dir` compatible) |
| `-x`, `-extensions`, `-e` | string | `""` | File extensions (e.g. `php,html,txt`) |
| `-subdomain`, `-sub` | bool | `false` | Subdomain/VHost discovery |
| `-t` | int | `40` | Concurrency workers |
| `-ac` | bool | `true` | Auto-calibrate wildcard responses |
| `-mc` | string | `""` | Match status codes |
| `-fc` | string | `404` | Filter status codes |
| `-ms` | string | `""` | Match response sizes |
| `-fs` | string | `""` | Filter response sizes |
| `-mw` | string | `""` | Match word counts |
| `-fw` | string | `""` | Filter word counts |
| `-ml` | string | `""` | Match line counts |
| `-fl` | string | `""` | Filter line counts |

### Discovery and OAST

| Flag | Type | Default | Description |
|---|---|---|---|
| `-discover-params` | bool | `false` | Hidden parameter discovery via response bisection |
| `-param-brute` | bool | `false` | Brute-force hidden parameter names; requires `-w` |
| `-oast-listen` | string | `""` | Local OAST listener, e.g. `0.0.0.0:8888` |
| `-oast-host` | string | `""` | Public callback host, e.g. `10.10.14.5:8888` |
| `-oast-wait` | int | `10` | OAST server default wait; SSRF/CMDi/XXE probes use fixed 3s windows in v2.1 |

### Intel, exploit mapper, and APIs

| Flag | Type | Default | Description |
|---|---|---|---|
| `-intel-query` | string | `""` | Manual product/version lookup, e.g. `"Apache 2.4.49"` |
| `-no-intel` | bool | `false` | Disable all intel/reference lookups, including `--intel-query` |
| `-nvd` | bool | `false` | Enable NVD lookup; also auto-enabled when `NVD_API_KEY` is set |
| `-wpscan-token` | string | `WPSCAN_API_TOKEN` | WPScan API token |
| `-msf-search` | bool | `true` | Allow read-only `msfconsole search` in exploit-mapper |
| `-download-exploits` | bool | `false` | Download raw Exploit-DB entries for manual review |
| `-loot-dir` | string | `loot` | Download directory |

### Plugins, reports, state, and profiles

| Flag | Type | Default | Description |
|---|---|---|---|
| `-plugins` | bool | `false` | Load plugins |
| `-plugin-dir` | string | `~/.nightfalllx/plugins` | Plugin directory; also `NIGHTFALLX_PLUGIN_DIR` |
| `-html` | bool | `false` | Write HTML report |
| `-sarif` | bool | `false` | Write SARIF 2.1.0 report |
| `-o` | string | `lab_report` | Output base name |
| `-resume` | bool | `false` | Resume `.nightfalllx/state.json` |
| `-profile` | string | `""` | Load a named profile |
| `-save-profile` | string | `""` | Save explicit flags as a profile and exit |
| `-no-update-check` | bool | `false` | Disable startup update check; also `NIGHTFALLX_NO_UPDATE_CHECK=1` |

### Diagnostics

| Flag | Type | Default | Description |
|---|---|---|---|
| `-doctor`, `-troubleshoot` | bool | `false` | Environment/target diagnostics |
| `-version`, `-V` | bool | `false` | Print version |
| `-h`, `-help`, `--help` | bool | — | Print help |

### Requested shorthands not implemented in v2.1

These are intentionally documented rather than invented:

| Flag | Status | Use instead |
|---|---|---|
| `-f` | Not implemented | `-fuzz` for fuzzing; there is no `--force` flag |
| `-q` | Not implemented | No quiet mode; redirect output if needed |
| `-v` | Not implemented | No verbose flag; use `--doctor`, `--log`, or module output |
| `--c2` | Not implemented | No built-in C2; NightfallLX is detection/reference-only |
| `--pwn`, `--force` | Not implemented | NightfallLX does not exploit or hand off shells |
| `--download-wordlists` | Not implemented | Install SecLists manually |

---

## 3. Scanning Modes

### Mode 1 — Recon and fingerprinting

```bash
# Technology and version fingerprint
nightfalllx -tech -u http://target.lab

# Spider and print the site map
nightfalllx -map -u http://target.lab -depth 3 -max-urls 100

# Hidden parameter discovery
nightfalllx -u http://target.lab/search -discover-params \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Shodan OSINT
export SHODAN_API_KEY="your-key"
nightfalllx -shodan -u https://target.lab
```

The tech detector reports technologies, versions, headers, and evidence. Site-map output is terminal-only.

`-tech`, `-map`, and `-shodan` are standalone modes: they return immediately, so run them separately from `-m all`. Use `-crawl` when you want XSS findings and crawl reports.

### Mode 2 — Vulnerability scanning

```bash
# All default modules
nightfalllx -u 'http://target.lab/?id=1' -m all -o reports/scan

# Selected modules
nightfalllx -u 'http://target.lab/?id=1' -m sqli,lfi,cmdi -o reports/injection

# POST/JSON target
nightfalllx -u http://target.lab/api/user \
  -X POST -json -d '{"id":1,"name":"test"}' \
  -m sqli,idor,massassign -o reports/api

# Opt-in upload testing
nightfalllx -u http://target.lab/upload -m upload
```

`-m all` runs the 22 default vulnerability modules plus `exploit-mapper`. `upload` is deliberately opt-in and must be named explicitly.

### Mode 3 — Fuzzing and VHosts

```bash
# Directory brute-forcing (gobuster-compatible)
nightfalllx dir -u http://target.lab/ \
  -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt \
  -x php,html,sql,js,txt

# URL fuzzing
nightfalllx -u 'http://target.lab/FUZZ' \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,204,301,302,403

# Host-header / VHost fuzzing
nightfalllx -u http://target.lab \
  -H 'Host: FUZZ.target.lab' \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# POST-body fuzzing
nightfalllx -u http://target.lab/login \
  -X POST -d 'user=FUZZ&pass=test' -w users.txt

# Subdomain mode
nightfalllx -domain target.lab -subdomain -w subdomains.txt
```

Fuzzing triggers when `FUZZ` or `*` appears in the URL, body, or a header value, or when `-fuzz` is passed. Use `-ac=false` only when auto-calibration hides real results.

### Mode 4 — Exploit mapper

```bash
export WPSCAN_API_TOKEN="your-wpscan-token"
export NVD_API_KEY="your-nvd-key"

nightfalllx -u http://target.lab/ -m exploit-mapper \
  --download-exploits --loot-dir loot \
  -o reports/exploit-map --html --sarif
```

The mapper performs:

- WordPress core/plugin/theme fingerprinting.
- WAF/Cloudflare detection.
- CVE catalog matching by version.
- WPScan API lookups.
- Searchsploit metadata lookup.
- Read-only `msfconsole search` when enabled.
- NVD CVE enrichment when `NVD_API_KEY` is set.
- Optional raw Exploit-DB download for manual review.

Disable dynamic Metasploit searches with `-msf-search=false`. The mapper never executes Metasploit modules or downloaded files.

### Mode 5 — XSS engine

```bash
# Reflected XSS with DOM analysis
nightfalllx -u 'http://target.lab/search?q=test' -m xss --dom

# Forms, stored reflection, and crawling
nightfalllx -u http://target.lab/guestbook --forms --stored --crawl

# Headless browser DOM validation, if Chromium is installed
nightfalllx -u http://target.lab/app -m xss --dom-browser

# Filter-survival fuzzing
nightfalllx -u 'http://target.lab/?q=FUZZ' -m xss --xss-fuzz
```

The native engine classifies HTML/attribute/JS/URL contexts and reports three confidence tiers: `confirmed`, `probable`, and `possible`. `--crawl` is standalone: it runs the crawl/XSS engine and returns before the normal `-m` pipeline.

### Mode 6 — Authenticated scans

```bash
# Form login
nightfalllx -u http://target.lab/dashboard \
  -login-url http://target.lab/login \
  -login-data 'user={{user}}&pass={{pass}}' \
  -login-user admin -login-pass 'secret' \
  -login-success-status 302 \
  -m all -o reports/auth

# Bearer token
nightfalllx -u http://target.lab/api/me \
  -bearer 'eyJ...' \
  -H 'Authorization: Bearer eyJ...' \
  -m jwt,idor,exposure
```

Login credentials can also come from `LOGIN_USER` and `LOGIN_PASS`. Use `-refresh-url` and `-refresh-json-path` when tokens expire during a long scan.

### Mode 7 — OAST/out-of-band

```bash
# Listen locally; advertise the VPN/lab address the target can reach
nightfalllx -u 'http://target.lab/?url=test' \
  -m ssrf,cmdi,xxe \
  --oast-listen 0.0.0.0:8888 \
  --oast-host 10.10.14.5:8888
```

Use `ip -4 addr show tun0` to find the HTB VPN address. The target must be able to reach `--oast-host`; `127.0.0.1` usually will not work for remote targets. OAST callbacks are HTTP-based.

`--oast-wait` sets the OAST server default, but the SSRF, CMDi, and XXE modules currently use 3-second hit windows. Do not expect `--oast-wait 30` to make those modules wait longer in v2.1.

### Mode 8 — Interactive TUI

```bash
nightfalllx -i -u http://target.lab
```

The dashboard supports mouse clicks, number keys, arrow keys, Enter, and `q` to quit. Use option 10 for a full assessment. There is no shell handoff or “PWNED” phase in v2.1.

---

## 4. The 23 Vulnerability Modules

> Confirmation grades: `confirmed` = deterministic evidence; `probable` and `info` are explicitly **not** 100% confidence. Version 2.1 never converts a vulnerability into active exploitation.

### Injection modules (7)

| Module | Attack Vector | Confirmation Rule (confirmed grade) | Example Command |
|---|---|---|---|
| `sqli` | SQL query semantics | DB error signature, boolean status/body differential, or dual-delay time scaling | `nightfalllx -u 'http://target.lab/?id=1' -m sqli` |
| `ssti` | Template expression evaluation | Two different expressions both evaluate to the expected output | `nightfalllx -u 'http://target.lab/?name=test' -m ssti` |
| `lfi` | File inclusion/path traversal | Known-file regex match, or decoded PHP source via `php://filter` | `nightfalllx -u 'http://target.lab/?file=test' -m lfi` |
| `cmdi` | OS command injection | `id`/`whoami` output pattern or OAST callback; timing-only result is `probable` | `nightfalllx -u 'http://target.lab/?cmd=test' -m cmdi --oast-listen 0.0.0.0:8888 --oast-host 10.10.14.5:8888` |
| `xxe` | XML external entities | Sensitive-file regex or OAST callback from entity resolution | `nightfalllx -u http://target.lab/xml -m xxe --oast-listen 0.0.0.0:8888 --oast-host 10.10.14.5:8888` |
| `nosqli` | MongoDB operator injection | Mongo error signature or `$ne`/`$eq` differential | `nightfalllx -u http://target.lab/api -X POST -json -d '{"user":"test"}' -m nosqli` |
| `crlf` | CRLF/header injection | Injected header or cookie appears in the response headers | `nightfalllx -u 'http://target.lab/?next=test' -m crlf` |

### Client-side modules (4)

| Module | Attack Vector | Confirmation Rule (confirmed grade) | Example Command |
|---|---|---|---|
| `xss` | Reflected/DOM XSS | Native engine finds an executable HTML node containing the canary; module-level check requires raw unescaped reflection | `nightfalllx -u 'http://target.lab/?q=test' -m xss --dom --forms` |
| `cors` | Cross-origin data access | `Access-Control-Allow-Origin` reflects the exact test origin and `Access-Control-Allow-Credentials: true` | `nightfalllx -u http://target.lab/api -m cors` |
| `redirect` | Open redirect | `Location` host matches the `example.com` canary | `nightfalllx -u 'http://target.lab/?next=test' -m redirect` |
| `csrf` | State-changing request forgery | Missing anti-CSRF token and no `SameSite=Lax/Strict` (95%); `SameSite` present downgrades confidence | `nightfalllx -u http://target.lab/profile -X POST -d 'email=a@b.c' -m csrf` |

### Server-side and authorization modules (9)

| Module | Attack Vector | Confirmation Rule (confirmed grade) | Example Command |
|---|---|---|---|
| `ssrf` | Server-side request forgery | OAST callback proves server-initiated request | `nightfalllx -u 'http://target.lab/?url=test' -m ssrf --oast-listen 0.0.0.0:8888 --oast-host 10.10.14.5:8888` |
| `idor` | Object-level authorization | Secondary identity receives `200` with ≥70% body similarity and >20 bytes | `nightfalllx -u 'http://target.lab/api/user?id=1' -b 'session=A' -b2 'session=B' -m idor` |
| `jwt` | Token authentication bypass | Forged `none` or weak-secret token is accepted (`200/204`) where unauthenticated access is denied/different | `nightfalllx -u http://target.lab/api/me -H 'Authorization: Bearer <jwt>' -m jwt` |
| `massassign` | Over-posting privileged fields | Privileged field value is echoed or persists in a follow-up response | `nightfalllx -u http://target.lab/api/user -X POST -json -d '{"username":"test"}' -m massassign` |
| `protopollution` | `__proto__`/constructor pollution | Pollution marker appears in the response or a follow-up request | `nightfalllx -u http://target.lab/api/merge -X POST -json -d '{"a":1}' -m protopollution` |
| `deserialize` | Insecure deserialization signals | Serialized object signature matches a known language/runtime pattern; this confirms exposure, not RCE | `nightfalllx -u http://target.lab/ -m deserialize` |
| `graphql` | Schema/introspection exposure | Introspection response contains `data.__schema` | `nightfalllx -u http://target.lab/graphql -m graphql` |
| `hostheader` | Host header injection | Canary appears as the host in a `Location` redirect; body reflection is `probable` | `nightfalllx -u http://target.lab/reset -m hostheader` |
| `upload` | Unrestricted file upload | Uploaded file is retrievable and contains the unique marker | `nightfalllx -u http://target.lab/upload -m upload` |

### Configuration and exposure modules (3)

| Module | Attack Vector | Confirmation Rule (confirmed grade) | Example Command |
|---|---|---|---|
| `headers` | Security header/cookie posture | Missing header or flag; heuristic `possible`/`probable`, never confirmed | `nightfalllx -u http://target.lab/ -m headers` |
| `exposure` | Sensitive file/backup/API exposure | Known sensitive file returns a deterministic content-pattern match | `nightfalllx -u http://target.lab/ -m exposure` |
| `waf` | WAF/reverse-proxy fingerprint | Signature match; informational only | `nightfalllx -u http://target.lab/ -m waf` |

### Recon module (not counted in the 23)

| Module | Purpose | Example |
|---|---|---|
| `exploit-mapper` | WordPress fingerprinting, CVE/WPScan/NVD/Searchsploit mapping, Metasploit search plan | `nightfalllx -u http://target.lab/ -m exploit-mapper` |

---

## 5. Advanced Usage & Integrations

### C2/Sliver integration status

**Not implemented in v2.1.** There is no `--c2` flag, no Sliver client, no session listing, and no shell handoff. There is also no `AgentBrain` runtime or automatic exploitation phase. NightfallLX stops at detection, verification, and reference mapping; its output is findings and reference metadata, not sessions. Keep C2 tooling separate and operate it only within your authorized lab rules.

### WPScan and NVD

```bash
export WPSCAN_API_TOKEN="your-token"
export NVD_API_KEY="your-nvd-key"

nightfalllx -u http://target.lab/ -m exploit-mapper \
  --wpscan-token "$WPSCAN_API_TOKEN" \
  -o reports/wpscan --html --sarif
```

- WPScan queries core, plugin, and theme versions and skips vulnerabilities at or above `fixed_in`.
- NVD enriches mapped CVEs with CVSS and English descriptions.
- NVD responses are rate-limited and cached in `.intel_cache/` for 24 hours.
- Automatic lookups require a detected version; use `--intel-query "Product Version"` for a deliberate versionless query.
- Searchsploit results are capped at 25 per query; combined intel is capped at 100 findings to keep reports actionable.

### Profiles

```bash
# Save explicitly supplied flags; this exits without scanning
nightfalllx -u http://target.lab \
  -H 'Authorization: Bearer dev-token' \
  -m all --save-profile lab-auth

# Reuse the profile; explicit flags still override profile values
nightfalllx --profile lab-auth -o reports/lab --html --sarif
```

Profiles live at `~/.nightfalllx/profiles/<name>.json` and are written with `0600` permissions. They can contain tokens or credentials; protect them accordingly.

### Resume

```bash
# Start a scan
nightfalllx -u http://target.lab/ -m all -o reports/lab

# Interrupt with Ctrl+C, then rerun the same target/method
nightfalllx -u http://target.lab/ -m all --resume -o reports/lab
```

State is stored at `.nightfalllx/state.json`. It records the target, method, module list, completed/pending modules, findings, and intel. Resume compares the saved target URL and method; use the same URL string and HTTP method. A successful scan removes the state file. Interrupted scans save state and exit with status `130`.

### Plugins

```bash
mkdir -p ~/.nightfalllx/plugins

go build -buildmode=plugin \
  -o ~/.nightfalllx/plugins/sample.so \
  ./pkg/plugins/examples/sample_plugin.go

nightfalllx -u http://target.lab/ -m headers \
  --plugins --plugin-dir ~/.nightfalllx/plugins
```

A plugin exports a package-level `Plugin` symbol with `Name() string` and `Execute(target string, client *http.Client) (string, error)`. Plugins run in-process with your privileges. Linux/macOS use `.so`; Windows requires a custom `.dll` loader and is not supported by the built-in loader.

### Auto-update check

```bash
nightfalllx -u http://target.lab --no-update-check
```

The check has a short timeout. Offline labs can disable it globally:

```bash
export NIGHTFALLX_NO_UPDATE_CHECK=1
```

---

## 6. Output & Reporting

| Format | Trigger | Default File | Best For |
|---|---|---|---|
| Markdown | Always in a normal assessment; crawl only when findings exist | `<base>.md` | Human review, notes, engagement appendices |
| JSON | Always in a normal assessment; crawl only when findings exist | `<base>.json` | Automation, parsing, dashboards |
| HTML | `--html` | `<base>.html` | Visual dashboard, severity filtering, client review |
| SARIF | `--sarif` | `<base>.sarif` | CI/CD, GitHub Advanced Security, SARIF viewers |
| Log | `--log <file>` | user path | Additional Markdown-format log |

```bash
mkdir -p reports
nightfalllx -u http://target.lab/ -m all \
  -o reports/scan \
  --html --sarif --log reports/scan.log
```

- `-o` is a base path. Parent directories must already exist.
- HTML and SARIF are available for normal assessments and `--crawl`; standalone `-tech`, `-map`, `-shodan`, and fuzzer modes do not write them.
- SARIF includes findings and intel references; intel entries are emitted as `note` results.
- HTML includes severity filters, search, expandable evidence, and intel tables.

### GitHub SARIF upload example

```yaml
- name: Upload NightfallLX SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reports/scan.sarif
```

### JSON automation example

```bash
nightfalllx -u http://target.lab/ -m all -o reports/scan
jq '{total: .total_findings, by_severity: ([.findings[].severity] | group_by(.) | map({severity: .[0], count: length}))}' \
  reports/scan.json
```

---

## 7. Troubleshooting & Tips

### “Scope guard refusal”

Exact error:

```text
scope guard refusal: host 'example.com' is not in authorized scope (use -scope or -scope-off)
```

Fix:

```bash
# Add the target host or a wildcard
nightfalllx -u http://target.lab -scope target.lab -m all

# Explicitly disable only for authorized isolated labs
nightfalllx -u http://target.lab -scope-off -m all
```

### Wordlist missing

If a supplied `-w` path does not exist, fuzzing returns an error. Use a valid path or omit `-w` to use the built-in lab list:

```bash
test -r /usr/share/seclists/Discovery/Web-Content/common.txt
nightfalllx -u 'http://target.lab/FUZZ' \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

The doctor hint about `--download-wordlists` is stale; install SecLists manually.

### OAST callback not received

- Use the VPN/lab address, not `127.0.0.1`, for `--oast-host`.
- Confirm the target can reach your listener.
- Open the chosen port in the lab firewall.
- Put `--oast-host` in the form the target can resolve, e.g. `10.10.14.5:8888`.
- OAST is HTTP-based; there is no built-in DNS server.

### WAF or rate limiting

```bash
# Slow down and route through Burp
nightfalllx -u http://target.lab -m all \
  -rate 3 -p http://127.0.0.1:8080 -timeout 30
```

The `waf` module only fingerprints. v2.1 has no AgentBrain component or automatic evasion engine. Use manual header, rate, and proxy adjustments.

### Update check appears slow or fails offline

```bash
nightfalllx --no-update-check -u http://target.lab
NIGHTFALLX_NO_UPDATE_CHECK=1 nightfalllx -u http://target.lab
```

### Plugin load errors

- The `.so` must be built with `-buildmode=plugin` using a compatible Go toolchain.
- Linux/macOS only for the built-in loader.
- Windows `.dll` loading is not implemented.
- Only load plugins you have reviewed.

### Resume does not work

Resume requires:

- The same target URL string.
- The same HTTP method.
- A state file at `.nightfalllx/state.json` in the current working directory.
- An interrupted, not fully completed, scan.

### HTML/SARIF files are missing

They are created only in assessment/crawl modes and require `-o` plus the flag:

```bash
nightfalllx -u http://target.lab/ -m all -o reports/scan --html --sarif
```

### HTB and lab checklist

1. Connect to the VPN and confirm `tun0` is up.
2. Add hostnames to `/etc/hosts` when needed.
3. Run `-tech` and `-map` first as separate recon passes.
4. Use `-scope` to prevent accidental out-of-scope requests.
5. Keep `-rate` low on unstable labs.
6. Use `--no-update-check` and `--no-intel` for offline runs.
7. Use `--oast-host` with the `tun0` address for blind SSRF/XXE/CMDi.
8. Save reports with `-o reports/<target>`.
9. Do not use active exploitation, reverse shells, or C2 in shared lab infra.

---

## 8. Quick Reference

| # | Command | What It Does |
|---|---|---|
| 1 | `nightfalllx -tech -u http://target` | Technology and exact-version fingerprinting |
| 2 | `nightfalllx -u 'http://target/?id=1' -m all` | Full default assessment |
| 3 | `nightfalllx -u http://target -m exploit-mapper` | WordPress/CVE/Exploit-DB/Metasploit mapping |
| 4 | `nightfalllx --crawl -u http://target` | Crawl endpoints and run the XSS engine |
| 5 | `nightfalllx -u http://target -H 'Host: FUZZ.target' -w list.txt` | VHost fuzzing |

### Copy-paste lab starter

```bash
TARGET='http://target.lab'
mkdir -p "reports/$(echo "$TARGET" | sed 's#https\?://##; s#/.*##')"

nightfalllx -u "$TARGET" -scope "$(echo "$TARGET" | sed 's#https\?://##; s#/.*##')" \
  -m all -rate 5 -timeout 20 \
  -o "reports/$(echo "$TARGET" | sed 's#https\?://##; s#/.*##')/scan" \
  --html --sarif --no-update-check
```

---

**Final reminder:** NightfallLX v2.1 is an assessment and reference tool. It does not exploit, deploy payloads, provide C2, or hand off shells. Use it only where authorization is explicit and documented.
