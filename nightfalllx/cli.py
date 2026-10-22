"""NightfallLX command line entry point."""

from __future__ import annotations

import argparse
import importlib.util
import platform
import runpy
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from nightfalllx import __version__
from nightfalllx.core.console import Console
from nightfalllx.core.finding import Finding
from nightfalllx.core.http import HttpClient
from nightfalllx.core.registry import MODULE_REGISTRY
from nightfalllx.core.target import TargetSpec
import nightfalllx.modules  # registers built-in modules
from nightfalllx.reporters.json_reporter import write_json_report
from nightfalllx.reporters.markdown import write_markdown_report

try:
    from colorama import init as _colorama_init

    _colorama_init()
    _HAS_COLORAMA = True
except ImportError:
    _HAS_COLORAMA = False

_GREEN = "\033[32m" if _HAS_COLORAMA else ""
_RED = "\033[31m" if _HAS_COLORAMA else ""
_YELLOW = "\033[33m" if _HAS_COLORAMA else ""
_CYAN = "\033[36m" if _HAS_COLORAMA else ""
_BOLD = "\033[1m" if _HAS_COLORAMA else ""
_RESET = "\033[0m" if _HAS_COLORAMA else ""


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    ok: bool
    detail: str
    fix: str = ""


def legacy_entrypoint() -> Path:
    here = Path(__file__).resolve()
    candidates = (
        here.parents[1] / "nightfalllx_legacy.py",
        here.parent / "nightfalllx_legacy.py",
        Path.cwd() / "nightfalllx_legacy.py",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "nightfalllx_legacy.py was not found; reinstall the package with 'pip install -e .'"
    )


def _package_check(name: str, module: str) -> DoctorCheck:
    present = importlib.util.find_spec(module) is not None
    return DoctorCheck(
        name=name,
        ok=present,
        detail="installed" if present else "not installed",
        fix=f"python -m pip install {name}",
    )


def _tool_check(name: str, package: str) -> DoctorCheck:
    location = shutil.which(name)
    return DoctorCheck(
        name=name,
        ok=location is not None,
        detail=location or "not found in PATH",
        fix=f"sudo apt install {package}",
    )


def doctor_checks() -> list[DoctorCheck]:
    python_ok = sys.version_info >= (3, 10)
    return [
        DoctorCheck(
            "python",
            python_ok,
            platform.python_version(),
            "install Python 3.10 or newer",
        ),
        _package_check("curl_cffi", "curl_cffi"),
        _package_check("requests", "requests"),
        _package_check("colorama", "colorama"),
        _tool_check("ffuf", "ffuf"),
        _tool_check("nmap", "nmap"),
        _tool_check("sqlmap", "sqlmap"),
    ]


def run_doctor() -> int:
    checks = doctor_checks()
    name_width = max(len("Check"), *(len(check.name) for check in checks))
    detail_width = max(len("Details"), *(len(check.detail) for check in checks))
    print("NightfallLX doctor")
    print(f"Platform: {platform.platform()}")
    print(f"{'Check':<{name_width}}  {'Status':<7}  Details")
    print(f"{'-' * name_width}  {'-' * 7}  {'-' * detail_width}")
    for check in checks:
        status = "OK" if check.ok else "MISSING"
        colour = _GREEN if check.ok else _RED
        print(f"{check.name:<{name_width}}  {colour}{status:<7}{_RESET}  {check.detail}")
    missing = [check for check in checks if not check.ok]
    if missing:
        print("\nInstall missing components:")
        for check in missing:
            print(f"  {check.name:<{name_width}}  {check.fix}")
        return 1
    print("\nAll checks passed.")
    return 0


def _parse_headers(header_list: list[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for h in header_list or []:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def _run_modular_scan(args: argparse.Namespace) -> int:
    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    url_without_query = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    query_params: dict[str, str] = {}
    if parsed.query:
        raw_qs = parse_qs(parsed.query, keep_blank_values=True)
        query_params = {k: v[0] if v else "" for k, v in raw_qs.items()}

    body_data: dict[str, str] = {}
    if args.data:
        raw_data = parse_qs(args.data, keep_blank_values=True)
        body_data = {k: v[0] if v else "" for k, v in raw_data.items()}

    method = args.method.upper()
    headers = _parse_headers(args.headers)

    target = TargetSpec(
        url=url_without_query,
        method=method,
        params=query_params if method == "GET" else {},
        data=body_data if method == "POST" else (query_params if not body_data else body_data),
        headers=headers,
        authorized=True,
    )

    console = Console(verbose=args.verbose, quiet=args.quiet)
    client = HttpClient(
        console=console,
        timeout=args.timeout,
        delay=args.delay,
        proxy=args.proxy,
        verify=not args.insecure,
        cookie=args.cookie,
        headers=headers,
    )

    banner = (
        f"{_BOLD}{_CYAN}NightfallLX v{__version__}{_RESET} - "
        f"{_YELLOW}Modular Web Vulnerability Assessment Framework{_RESET}\n"
        f"Target: {_BOLD}{target.url}{_RESET} [{target.method}]\n"
        f"Parameters: {list(target.parameters) or 'None'}\n"
        f"Proxy: {args.proxy or 'Direct'}\n"
    )
    print(banner)

    if not target.parameters:
        print(f"{_YELLOW}[!] Warning: No request parameters found to test.{_RESET}")
        print("    Provide parameters in the URL (e.g. -u http://target.lab/?id=1) or with -d 'id=1'")

    wanted_modules = [m.strip().lower() for m in args.modules.split(",") if m.strip()]
    if "all" in wanted_modules:
        modules_to_run = list(MODULE_REGISTRY.keys())
    else:
        modules_to_run = [m for m in wanted_modules if m in MODULE_REGISTRY]

    findings: list[Finding] = []
    for mod_name in modules_to_run:
        mod_cls = MODULE_REGISTRY[mod_name]
        print(f"{_CYAN}[*] Running module: {_BOLD}{mod_name}{_RESET} ...")
        try:
            mod_instance = mod_cls(client)
            mod_findings = mod_instance.run(target)
            for f in mod_findings:
                status = f"{_BOLD}{_GREEN}[CONFIRMED]{_RESET}" if f.confidence >= 90 else f"{_YELLOW}[SUSPICIOUS]{_RESET}"
                print(f"    {status} {_BOLD}{f.title}{_RESET} (param={f.parameter}, confidence={f.confidence}%)")
            findings.extend(mod_findings)
        except Exception as exc:
            print(f"    {_RED}[!] Error in {mod_name}: {exc}{_RESET}")

    out_base = Path(args.output)
    md_file = write_markdown_report(target, findings, out_base.with_suffix(".md"))
    json_file = write_json_report(target, findings, out_base.with_suffix(".json"))

    print("\n" + "=" * 60)
    print(f"{_BOLD}Scan Complete!{_RESET} Total Confirmed Findings: {_BOLD}{len(findings)}{_RESET}")
    print(f"Reports saved to:")
    print(f"  Markdown: {_GREEN}{md_file}{_RESET}")
    print(f"  JSON:     {_GREEN}{json_file}{_RESET}")
    print("=" * 60)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nightfalllx",
        description="NightfallLX - Modular Web Vulnerability Assessment & High-Speed Fuzzer Framework",
    )
    parser.add_argument("-u", "--url", help="Target URL or template (e.g. http://10.129.x.x/FUZZ or http://target.lab/?id=1)")
    parser.add_argument("-r", "--request", help="Burp Suite raw HTTP request file (e.g. -r request.txt)")
    parser.add_argument("--domain", help="Base domain for subdomain / VHost discovery (e.g. --domain target.lab)")
    parser.add_argument("--https", "--ssl", dest="https", action="store_true", help="Force HTTPS scheme (useful with -r or raw domain)")
    parser.add_argument("-m", "--modules", default="all", help="Comma-separated modules or 'all' (sqli, ssti, lfi, rce, xss)")
    parser.add_argument("-X", "--method", default="GET", choices=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"], help="HTTP Method (default: GET)")
    parser.add_argument("-d", "--data", help="POST data body (e.g. 'user=FUZZ&pass=admin')")
    parser.add_argument("-H", "--header", dest="headers", action="append", help="Custom HTTP header (can repeat, e.g. -H 'Auth: Bearer FUZZ')")
    parser.add_argument("-b", "--cookie", help="Cookie header value")
    parser.add_argument("-p", "--proxy", help="HTTP proxy URL (e.g. http://127.0.0.1:8080 for Burp Suite)")
    parser.add_argument("-k", "--insecure", action="store_true", default=True, help="Disable TLS certificate verification (default: True for labs)")
    parser.add_argument("-o", "--output", default="lab_report", help="Output report base path (default: lab_report)")
    parser.add_argument("-w", "--wordlist", help="Wordlist file path for high-speed fuzzing / subdomain discovery")
    parser.add_argument("-t", "--threads", type=int, default=40, help="Number of concurrent worker threads (default: 40)")
    parser.add_argument("--subdomain", "--sub", dest="subdomain", action="store_true", help="Enable Subdomain / VHost discovery mode (ffuf-style)")
    parser.add_argument("-ac", "--auto-calibrate", dest="auto_calibrate", action="store_true", default=True, help="Auto-calibrate baseline wildcard responses")
    parser.add_argument("-mc", "--match-codes", help="Match HTTP status codes, comma-separated (e.g. 200,204,301,302,403)")
    parser.add_argument("-fc", "--filter-codes", default="404", help="Filter HTTP status codes, comma-separated (default: 404)")
    parser.add_argument("-ms", "--match-size", help="Match response size by byte length, comma-separated")
    parser.add_argument("-fs", "--filter-size", help="Filter response size by byte length, comma-separated (e.g. 0,404)")
    parser.add_argument("-mw", "--match-words", help="Match response word counts, comma-separated")
    parser.add_argument("-fw", "--filter-words", help="Filter response word counts, comma-separated")
    parser.add_argument("-ml", "--match-lines", help="Match response line counts, comma-separated")
    parser.add_argument("-fl", "--filter-lines", help="Filter response line counts, comma-separated")
    parser.add_argument("--fuzz", action="store_true", help="Explicitly enable high-speed directory/parameter fuzzing mode")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests in seconds")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet output")
    parser.add_argument("--doctor", action="store_true", help="Run environment diagnostic check")
    parser.add_argument("-V", "--version", action="store_true", help="Show program version")
    parser.add_argument("--download-wordlists", action="store_true", help="Download SecLists wordlists")
    parser.add_argument("--legacy", action="store_true", help="Run legacy monolit scanner mode")
    parser.add_argument("--auto", action="store_true", help="Run planner auto mode (legacy)")
    parser.add_argument("--full-scan", action="store_true", help="Run full brute force scan (legacy)")
    parser.add_argument("--list-modules", action="store_true", help="List registered modules")
    return parser


def _parse_int_set(raw: str | None) -> set[int]:
    if not raw:
        return set()
    return {int(x.strip()) for x in raw.split(",") if x.strip().isdigit()}


def _run_fuzzer(args: argparse.Namespace) -> int:
    from nightfalllx.core.fuzzer import (
        DEFAULT_FILTER_CODES,
        DEFAULT_MATCH_CODES,
        FastFuzzer,
        FuzzerConfig,
    )

    match_codes = _parse_int_set(args.match_codes) if args.match_codes else set(DEFAULT_MATCH_CODES)
    filter_codes = _parse_int_set(args.filter_codes) if args.filter_codes else set(DEFAULT_FILTER_CODES)
    filter_sizes = _parse_int_set(args.filter_size)
    filter_words = _parse_int_set(args.filter_words)
    filter_lines = _parse_int_set(args.filter_lines)
    match_sizes = _parse_int_set(args.match_size)
    match_words = _parse_int_set(args.match_words)
    match_lines = _parse_int_set(args.match_lines)
    headers = _parse_headers(args.headers)

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = ("https://" if args.https else "http://") + url

    config = FuzzerConfig(
        url=url,
        wordlist_path=args.wordlist,
        method=args.method.upper(),
        data=args.data,
        headers=headers,
        cookie=args.cookie,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        proxy=args.proxy,
        insecure=args.insecure,
        auto_calibrate=args.auto_calibrate,
        is_subdomain=args.subdomain,
        match_codes=match_codes,
        filter_codes=filter_codes,
        filter_sizes=filter_sizes,
        filter_words=filter_words,
        filter_lines=filter_lines,
        match_sizes=match_sizes,
        match_words=match_words,
        match_lines=match_lines,
    )
    fuzzer = FastFuzzer(config)
    results = fuzzer.run()

    if args.output:
        import json

        out_json = Path(args.output).with_suffix(".fuzz.json")
        data = [
            {
                "word": r.word,
                "url": r.url,
                "status": r.status,
                "length": r.length,
                "words": r.words,
                "lines": r.lines,
                "duration_ms": r.duration_ms,
                "redirect_url": r.redirect_url,
            }
            for r in results
        ]
        out_json.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"Fuzz results saved to: {_GREEN}{out_json}{_RESET}")

    return 0


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    if "--version" in args_list or "-V" in args_list:
        print(f"nightfalllx {__version__}")
        return 0
    if "--doctor" in args_list:
        return run_doctor()
    if "--download-wordlists" in args_list:
        from nightfalllx.core.wordlists import ensure_wordlists

        try:
            path = ensure_wordlists()
        except Exception as exc:
            print(f"Wordlist download failed: {exc}", file=sys.stderr)
            return 1
        print(f"SecLists: {path}")
        return 0

    if "--list-modules" in args_list or "--legacy" in args_list or "--auto" in args_list or "--full-scan" in args_list or ("-u" in args_list and ("--sarif-out" in args_list or "--exclude" in args_list)):
        try:
            script = legacy_entrypoint()
            original_argv = sys.argv
            sys.argv = [original_argv[0], *args_list]
            try:
                runpy.run_path(str(script), run_name="__main__")
                return 0
            except SystemExit as exc:
                code = exc.code
                return code if isinstance(code, int) else (0 if code is None else 1)
            finally:
                sys.argv = original_argv
        except FileNotFoundError:
            pass

    parser = _build_parser()
    args, unknown = parser.parse_known_args(args_list)

    # 1. Handle Burp Suite Raw Request file (-r)
    if args.request:
        from nightfalllx.core.request_parser import parse_raw_request_file
        try:
            raw_req = parse_raw_request_file(args.request, force_https=args.https)
            if not args.url:
                args.url = raw_req.full_url
            if args.method == "GET" and raw_req.method:
                args.method = raw_req.method
            if not args.data and raw_req.body:
                args.data = raw_req.body
            if not args.cookie and raw_req.cookie:
                args.cookie = raw_req.cookie
            req_headers = [f"{k}: {v}" for k, v in raw_req.headers.items()]
            args.headers = (args.headers or []) + req_headers
            if raw_req.has_fuzz:
                args.fuzz = True
            print(f"{_GREEN}[+] Loaded Burp Suite Raw Request from:{_RESET} {args.request} [{args.method} {args.url}]")
        except Exception as exc:
            print(f"{_RED}[!] Error loading request file: {exc}{_RESET}", file=sys.stderr)
            return 1

    # 2. Handle Subdomain Discovery mode (--subdomain / -sub)
    if args.subdomain:
        args.fuzz = True
        if not args.url and args.domain:
            scheme = "https" if args.https else "http"
            args.url = f"{scheme}://{args.domain}"
        if args.domain and args.url:
            args.headers = (args.headers or []) + [f"Host: FUZZ.{args.domain}"]
        elif args.url:
            clean_host = args.url.replace("http://", "").replace("https://", "").strip("/")
            if "/" in clean_host:
                clean_host = clean_host.split("/")[0]
            if not any("Host:" in h for h in (args.headers or [])) and "FUZZ" not in args.url:
                args.headers = (args.headers or []) + [f"Host: FUZZ.{clean_host}"]

    if not args.url:
        # Fallback to legacy or show help
        try:
            script = legacy_entrypoint()
            original_argv = sys.argv
            sys.argv = [original_argv[0], *args_list]
            try:
                runpy.run_path(str(script), run_name="__main__")
                return 0
            except SystemExit as exc:
                code = exc.code
                return code if isinstance(code, int) else (0 if code is None else 1)
            finally:
                sys.argv = original_argv
        except FileNotFoundError:
            parser.print_help()
            return 1

    # Check if user requested fuzzing (or used FUZZ keyword or wordlist)
    has_fuzz_keyword = "FUZZ" in (args.url or "") or "*" in (args.url or "") or \
        (args.data and ("FUZZ" in args.data or "*" in args.data)) or \
        (args.headers and any("FUZZ" in h or "*" in h for h in args.headers))
    if args.fuzz or has_fuzz_keyword or args.wordlist:
        return _run_fuzzer(args)

    return _run_modular_scan(args)
