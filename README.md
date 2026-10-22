# NightfallLX

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/Darksystem-01/NightfallLX/actions)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Advanced AI-Assisted Web Vulnerability Assessment Framework**

NightfallLX is an evidence-first security assessment framework for authorised
web application testing. It combines adaptive HTTP behaviour, WAF-aware payload
mutation, and bounded verification to turn ambiguous scanner output into
defensible findings.

## Features

- **0-100 Confidence Engine** — findings are scored from converging signals, not
  a single reflected payload or timing sample.
- **WAF Evasion** — fingerprint-driven payload mutation, encoding changes, and
  browser-like TLS profiles through `curl_cffi`.
- **SQLi** — boolean and time-based verification with bounded MySQL
  `@@version` extraction.
- **XSS** — DOM-aware verification with execution-context checks.
- **LFI** — read-only PHP filter disclosure checks.
- **Safe RCE PoC** — fixed harmless `id`, `whoami`, and `sleep` probes only.
- **Doctor & Bootstrap** — environment checks plus automatic SecLists download.

## Quick Start

```bash
git clone https://github.com/Darksystem-01/NightfallLX.git
cd NightfallLX
pip install -e .
nightfalllx --doctor
```

Download the SecLists wordlists on first use:

```bash
nightfalllx --download-wordlists
```

Show the version:

```bash
nightfalllx --version
```

## Usage

```bash
nightfalllx -u http://127.0.0.1:8080
nightfalllx -u http://127.0.0.1:8080 --auto
nightfalllx -u http://127.0.0.1:8080 --modules sqli,xss,lfi
```

## Requirements

- Python 3.10+
- Optional external tools: `ffuf`, `nmap`, `sqlmap`

## Legal Disclaimer

NightfallLX is intended **only** for systems you own or have explicit written
authorisation to test. Unauthorised access, scanning, or exploitation is illegal
and unethical. The authors accept no liability for misuse or damage caused by
this software. Always define scope, follow the rules of engagement, and stop if
you do not have permission.
