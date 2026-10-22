"""Characterization tests for NightfallLX's current CLI surface.

These tests are intentionally conservative: they pin the observable behaviour
that the package refactor must preserve, without asserting implementation
details. Everything runs against loopback only.
"""

from __future__ import annotations

import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "nightfalllx_legacy.py"
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
EXPECTED_MODULES = [
    "recon",
    "cors",
    "exposure",
    "redirect",
    "ssti",
    "sqli",
    "xss",
    "cmdi",
    "lfi",
    "xxe",
    "ssrf",
    "graphql",
    "jwt",
    "oauth",
    "idor",
    "hostheader",
    "login",
    "smuggling",
]


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )


def clean(text: str) -> str:
    return ANSI_RE.sub("", text)


class RecordingHandler(BaseHTTPRequestHandler):
    requests: list[tuple[str, str]] = []

    def do_GET(self) -> None:
        type(self).requests.append(("GET", self.path))
        body = (
            b"<html><body>"
            b"<form action='/login' method='post'><input name='user'></form>"
            b"<a href='?id=1'>item</a>"
            b"</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "vapf-characterization")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def local_server():
    RecordingHandler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), RecordingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_help_lists_modes_and_reporting_defaults(tmp_path: Path) -> None:
    result = run_cli("--help", cwd=tmp_path)
    output = clean(result.stdout)

    assert result.returncode == 0, result.stderr
    assert "usage: nightfalllx" in output
    assert "Scan modes:" in output
    for flag in ("--auto", "--modules", "--full-scan", "--exclude", "--list-modules"):
        assert flag in output
    assert ".vapf-loot/" in output
    assert "--sarif-out" in output
    assert "detection" in output.lower()


def test_list_modules_characterizes_registry(tmp_path: Path) -> None:
    result = run_cli("--list-modules", cwd=tmp_path)
    output = clean(result.stdout)

    assert result.returncode == 0, result.stderr
    rows = re.findall(r"^\s{2}([a-z]+)\s+", output, flags=re.MULTILINE)
    assert rows == EXPECTED_MODULES
    assert "All probes are detection/validation only" in output


def test_plan_mode_is_default_and_sends_no_probes(
    tmp_path: Path, local_server: tuple[ThreadingHTTPServer, int]
) -> None:
    _, port = local_server
    url = f"http://127.0.0.1:{port}/?id=1"

    result = run_cli("-u", url, cwd=tmp_path)
    output = clean(result.stdout)

    assert result.returncode == 0, result.stderr
    assert "plan (no probes sent)" in output
    assert "run suggestions:" in output
    assert "module:" not in output
    assert "Scope OK: 127.0.0.1" in output
    for module in ("cors", "exposure", "redirect", "hostheader"):
        assert module in output

    assert RecordingHandler.requests == [("GET", "/?id=1")]
    plan = tmp_path / ".vapf-loot" / "scan_plan.md"
    assert plan.is_file()
    assert "| Module | Why it was suggested |" in plan.read_text(encoding="utf-8")
