# NightfallLX (Go Edition v2.0)

High-performance Web Vulnerability Assessment, Fuzzer, and Recon Framework written in **Go (Golang)**. Designed for HackTheBox labs and authorized security audits with deterministic checks, dual-scaling verification, and zero false positives.

## Core Capabilities

- **Blazing Fast**: Powered by Go goroutines and shared `http.Transport` connection reuse (20,000+ req/s).
- **Out-of-Band (OAST) Listener**: Built-in HTTP callback server for blind SSRF, XXE, and harmless command injection (`-oast-listen`, `-oast-host`, `-oast-wait`).
- **Time-Based SQLi Engine**: Dual-scaling delay verification (e.g. 3s -> 6s) across MySQL, PostgreSQL, MSSQL, and SQLite respecting `-sqli-delay` and `-timeout`.
- **Parameter Discovery (Arjun-style)**: High-speed heuristic response bisection with `-discover-params -w wordlist.txt`.
- **Authenticated Scanning**: Automated session management via CookieJar, login flow (`-login-url`, `-login-data 'user={{user}}&pass={{pass}}'`), auto-relogin on 401/403 or `-logout-regex`, and bearer token refresh (`-bearer`, `-refresh-url`).
- **JSON Body Support**: Deep recursive tree walking for nested JSON parameters (`"user.id"`, `"items[0].name"`) with type-preserving payload mutation.
- **Scope Guard**: Mandatory target scope enforcement (`-scope target.lab` or `-scope scope.txt`).
- **Rate Limiting**: Configurable request ceiling (`-rate <req/s>`).
- **23 Specialized Modules**:
  - `sqli`: Error-based, boolean differential, and dual-delay time-based SQL injection.
  - `lfi`: Path traversal and PHP filter stream wrapper analysis.
  - `ssrf`: Cloud metadata, internal loopback, and OAST callback verification.
  - `xxe`: Local file disclosure and blind OAST entity resolution.
  - `cmdi`: Safe whoami/id reflection, timing probes, and harmless OAST callbacks (curl/wget/nslookup).
  - `graphql`: Schema introspection query exposure and 10-query multiplexed batching tests.
  - `jwt`: Algorithm `none`/`None` bypass and weak HMAC secret verification against unauthenticated baseline.
  - `protopollution`: Prototype pollution detection in JSON bodies (`__proto__`, `constructor.prototype`) with reflection verification.
  - `massassign`: Over-posting privileged fields (`role`, `isAdmin`, `balance`) in JSON and form data.
  - `deserialize`: Passive signature detection for Java (`rO0AB`), PHP (`O:s:`), .NET ViewState, and Python pickle (`gASV`).
  - `nosqli`: MongoDB operator injection (`$ne`, `$gt`, `$where`) in JSON and form params.
  - `upload`: Opt-in multipart upload validation with deterministic GET marker verification (`-m upload`).
  - `crlf`: Raw unencoded query splitting and header injection (`%0d%0a`).
  - `headers`, `exposure`, `cors`, `redirect`, `waf`, `hostheader`, `csrf`, `idor`.
- **Three-Tier Confidence Reporting**:
  - `confirmed`: 100% deterministic marker, verified OAST hit, or proven dual differential.
  - `probable`: Strong differential status or high statistical confidence.
  - `possible`: Single anomaly, unconfirmed reflection, or potential architectural indicator.

---

## Command Reference & Usage Examples

### 1. Out-of-Band (OAST) Vulnerability Scanning
```bash
# Start built-in callback server and inject OAST payloads into SSRF, XXE, and CMDi
nightfalllx -u "http://target.lab/api/fetch?url=http://example.com" \
  -oast-listen 0.0.0.0:8888 \
  -oast-host 10.10.14.5:8888 \
  -m ssrf,cmdi,xxe
```

### 2. Time-Based SQL Injection
```bash
# Run dual-scaling time-based SQLi with 3s base delay
nightfalllx -u "http://target.lab/products?category=1" -m sqli -sqli-delay 3
```

### 3. Hidden Parameter Discovery
```bash
# Bisect wordlist to discover hidden endpoints parameters and feed into audit
nightfalllx -u "http://target.lab/api/v1/search" -discover-params -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

### 4. Authenticated Scanning
```bash
# Login with credentials, maintain cookie session, and test protected endpoints
nightfalllx -u "http://target.lab/admin/dashboard" \
  -login-url "http://target.lab/auth/login" \
  -login-data "user={{user}}&pass={{pass}}" \
  -login-user "admin" \
  -login-pass "secret123" \
  -login-success-regex "dashboard" \
  -logout-regex "Please log in" \
  -m all
```

### 5. Nested JSON Body Assessment
```bash
# Inject into nested JSON leaf attributes with type preservation
nightfalllx -u "http://target.lab/api/order" -X POST \
  -d '{"order":{"id":100,"customer":"alice"}}' -json \
  -m sqli,idor,nosqli,protopollution
```

### 6. Scope Guard & Rate Limiting
```bash
# Restrict outbound requests to target host and cap at 50 requests/second
nightfalllx -u "http://target.lab/?id=1" -scope target.lab -rate 50 -m all
```

---

## Verification & Tests

Run full test suite:
```bash
go vet ./...
go test -count=1 -v ./...
```
