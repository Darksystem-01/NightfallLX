# NightfallLX (Go Edition)

High-performance Web Vulnerability Assessment & Fuzzer Framework written in **Go (Golang)**. Inspired by `ffuf` and `curl`.

## Features

- **Blazing Fast**: Powered by Go goroutines and optimized `net/http` connection pooling (1,000+ req/sec).
- **Standalone Binary**: Zero external runtime dependencies. Runs anywhere as a single compiled executable.
- **Dual Mode**:
  1. **High-Speed Fuzzer (`ffuf` style)**: Keyword replacement (`FUZZ`) in URL, query parameters, POST data, and headers.
  2. **Vulnerability Verification**: Differential assessment for **SQLi**, **SSTI**, **LFI/Path Traversal**, and **Safe CMDi**.
- **Lab & Burp Suite Ready**: Built-in `-p http://127.0.0.1:8080` proxy routing and `-k` (insecure TLS) support.
- **Instant Reporting**: Generates ready-to-use reproduction `curl` commands and writes `lab_report.md` + `lab_report.json`.

## Quick Start

### 1. Build
```bash
go build -ldflags="-s -w" -o nightfalllx main.go
```

### 2. High-Speed Fuzzing (`ffuf` style)
```bash
# Directory & file discovery
./nightfalllx -u http://10.129.x.x/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 50

# POST data fuzzing with custom headers
./nightfalllx -u http://target.lab/api/login -X POST -d "user=admin&token=FUZZ" -H "X-API-Key: secret" -mc 200 -t 40

# Route all fuzzing traffic through Burp Suite
./nightfalllx -u http://target.lab/FUZZ -p http://127.0.0.1:8080 -t 10
```

### 3. Vulnerability Assessment (SQLi, SSTI, LFI, CMDi)
```bash
# Test all modules against target parameter
./nightfalllx -u "http://10.129.x.x/view.php?page=home" -m all

# Target specific modules with POST body
./nightfalllx -u "http://target.lab/search" -X POST -d "query=test" -m sqli,ssti
```

## Running Tests
```bash
go test -v ./...
```
