# Architecture & Engineering Decisions

## 1. Project License & Attribution
- **Repository License:** License file missing from repo; MIT claim unverified until the owner adds it.
- **Third-Party Attribution & Source Integrity:**
  - The native Go XSS detection engine (`pkg/xss`) is designed and implemented from first principles in idiomatic Go. No third-party code is translated line-by-line.
  - All test vectors and character probes are authored as short, deterministic marker-based strings using safe canaries (e.g. `alert(1)`, unique random tokens `lxcanary...`). Total active vector count is 339 across 10 embedded category files.
  - CC BY-SA sources: No text or code copied. All logic and patterns are independently written.
  - Third-party Go dependencies used: `golang.org/x/net/html` (BSD-3-Clause license) for robust, standard-compliant HTML5 DOM tree parsing.

## 2. Reference Archive Status
- **Archive:** `Nightfalllx cheat sheet.zip`
- **Location:** Found at `/home/cyborg/Nightfalllx cheat sheet.zip`.
- **Extraction:** Extracted to `/home/cyborg/.gemini/antigravity-ide/scratch/cheatsheets/` (outside the repository tree).
- **Usage:** Contents are treated strictly as reference data for categories, reflection contexts, and filter evasion edge-cases. No executable files or exploit code imported.

## 3. Flag Mapping Decisions
Existing flags preserve exact backward compatibility:
- `-d`: POST data
- `-p`: Proxy URL
- `-b`: Cookie
- `-m`: Vulnerability module list (`-m sqli,xss` or `-m all`)
- `-X`: HTTP Method (maps method; legacy compatibility shim: if `-m` equals `POST` or starts with `POST,`, it is treated as a legacy shim mapping to `-X POST`)
- `-t`: Concurrency worker threads
- `-k`: TLS certificate verification bypass
- `-timeout`: Network timeout in seconds
- `-rate`: Rate limiter (requests per second)
- `-H`: Custom HTTP headers (repeatable)
- `-w`: Wordlist file path
- `-o`: Report output base filename

New long-named flags:
- `--dom`: Static DOM source-to-sink analysis (enabled by default; disable with `--dom=false` or `--no-dom`)
- `--no-dom`: Disable static DOM source-to-sink analysis
- `-sqli-delay`: Base delay in seconds for time-based SQL injection tests (actual code default: 3s; secondary confirmation probe uses 6s; replaces any earlier 1s->4s drafts)
- `--dom-browser`: Optional headless Chrome/Chromium DOM validation if installed
- `--forms`: Automatic HTML form extraction and testing (with CSRF token regeneration)
- `--param-brute`: Parameter discovery using wordlist
- `--xss-fuzz`: Filter probing and fuzzing mode with `-mc`, `-fc`, `-ms`, `-fs`
- `--crawl`: Runs the sitemap spider (`pkg/sitemap`) first, then feeds all discovered URLs with parameters or forms to the XSS engine honoring `-max-urls` and `-depth`
- `--log <file>`: Dedicated log file output
- `--header "Name: value"`: Repeatable custom header flag (alias to `-H`)
- `--intel-query "<product> <version>"`: Manual searchsploit / NVD reference lookup query
- `--no-intel`: Disable automatic version-matched reference lookup
- `-nvd`: Enable NIST NVD 2.0 REST API lookup (using `NVD_API_KEY` if provided)
- `--stored`: Test for stored XSS by submitting canary through forms and re-crawling

## 4. Intel & Reference Lookup Safety Guardrails
- `searchsploit` invocation uses `exec.Command` with an argument slice (`--json`, `--`, query). Shell execution (`sh -c`) is strictly prohibited.
- Query sanitization: Strict regex validation `^[a-zA-Z0-9._ -]+$` with length cap (64 chars) and leading-hyphen rejection to prevent argument injection.
- Execution prevention: The tool NEVER opens, downloads, compiles, copies, or runs any exploit file. It only displays metadata (EDB-ID, CVE, Title, Type, Platform) and local file path.
- All intelligence results are rendered under an unverified section: "Version-matched intel (not verified)" with a disclaimer that banner versions may be inaccurate.
