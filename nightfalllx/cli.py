"""NightfallLX command line entry point."""

from __future__ import annotations

import importlib.util
import platform
import runpy
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from nightfalllx import __version__

try:
    from colorama import init as _colorama_init

    _colorama_init()
    _HAS_COLORAMA = True
except ImportError:
    _HAS_COLORAMA = False

_GREEN = "\033[32m" if _HAS_COLORAMA else ""
_RED = "\033[31m" if _HAS_COLORAMA else ""
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
    checks = [
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
    return checks


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


def _exit_code(code: object) -> int:
    if code is None:
        return 0
    if isinstance(code, int):
        return code
    return 1


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--version" in args or "-V" in args:
        print(f"nightfalllx {__version__}")
        return 0
    if "--doctor" in args:
        return run_doctor()
    if "--download-wordlists" in args:
        from nightfalllx.core.wordlists import ensure_wordlists

        try:
            path = ensure_wordlists()
        except Exception as exc:
            print(f"Wordlist download failed: {exc}", file=sys.stderr)
            return 1
        print(f"SecLists: {path}")
        return 0

    script = legacy_entrypoint()
    original_argv = sys.argv
    sys.argv = [original_argv[0], *args]
    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as exc:
        return _exit_code(exc.code)
    finally:
        sys.argv = original_argv
    return 0
