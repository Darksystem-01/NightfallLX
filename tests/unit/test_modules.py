from __future__ import annotations

import base64
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from nightfalllx.core.console import Console
from nightfalllx.core.http import HttpClient
from nightfalllx.core.target import TargetSpec
from nightfalllx.modules.lfi import LFIModule
from nightfalllx.modules.rce import RCEModule
from nightfalllx.modules.sqli import SQLiModule
from nightfalllx.modules.xss import XSSModule

VERSION = "8.0.32"


class ModuleHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        self._handle(parsed.path, parse_qs(parsed.query, keep_blank_values=True))

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        self._handle(urlparse(self.path).path, parse_qs(body, keep_blank_values=True))

    def _handle(self, path: str, query: dict[str, list[str]]) -> None:
        value = query.get("q", [""])[0]
        status = 200
        if path == "/sqli":
            oracle = re.search(
                r"ASCII\(SUBSTRING\(\(@@version\),([0-9]+),1\)\)>([0-9]+)",
                value,
            )
            if oracle:
                position = int(oracle.group(1))
                threshold = int(oracle.group(2))
                code = ord(VERSION[position - 1]) if position <= len(VERSION) else 0
                body = "normal page" if code > threshold else ""
            elif "AND 1=1" in value:
                body = "normal page"
            elif "AND 1=2" in value:
                body = ""
            else:
                body = "normal page"
        elif path == "/xss":
            body = value
        elif path == "/lfi":
            body = base64.b64encode(b"<?php echo 'vapf'; ?>").decode("ascii")
        elif path == "/rce":
            if "; id" in value:
                body = "uid=1000(vapf) gid=1000(vapf)"
            elif "| whoami" in value:
                body = "vapf"
            elif "; sleep " in value:
                match = re.search(r"; sleep ([0-9.]+)", value)
                if match:
                    time.sleep(float(match.group(1)))
                body = "ok"
            else:
                body = "safe"
        elif path == "/rce-blind":
            if "; sleep " in value:
                match = re.search(r"; sleep ([0-9.]+)", value)
                if match:
                    time.sleep(float(match.group(1)))
            body = "safe"
        else:
            body = "ok"

        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture()
def server_url() -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ModuleHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture()
def client():
    value = HttpClient(console=Console(verbose=False, quiet=True), delay=0, timeout=2)
    try:
        yield value
    finally:
        value.close()


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_sqli_module_confirms_and_fingerprints_version(client, server_url: str, method: str) -> None:
    if method == "GET":
        target = TargetSpec(server_url + "/sqli", params={"q": "1"}, authorized=True)
    else:
        target = TargetSpec(server_url + "/sqli", method="POST", data={"q": "1"}, authorized=True)

    findings = SQLiModule(client, rate_limit=1000).run(target)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.confidence == 100
    assert finding.severity.value == "HIGH"
    assert "8.0.32" in finding.detail


def test_xss_module_returns_verified_finding(client, server_url: str) -> None:
    target = TargetSpec(server_url + "/xss", params={"q": "1"}, authorized=True)
    findings = XSSModule(client).run(target)
    assert len(findings) == 1
    assert findings[0].confidence == 100


def test_lfi_module_returns_verified_finding(client, server_url: str) -> None:
    target = TargetSpec(server_url + "/lfi", params={"q": "index.php"}, authorized=True)
    findings = LFIModule(client).run(target)
    assert len(findings) == 1
    assert findings[0].confidence == 100
    assert findings[0].cwe_id == 98


def test_rce_module_confirms_harmless_output(client, server_url: str) -> None:
    target = TargetSpec(server_url + "/rce", params={"q": "1"}, authorized=True)
    findings = RCEModule(client, sleep_delay=0.15).run(target)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.confidence == 100
    assert finding.severity.value == "CRITICAL"
    assert "RCE confirmed via harmless command execution" in finding.detail


def test_rce_module_confirms_time_based_sleep(client, server_url: str) -> None:
    target = TargetSpec(server_url + "/rce-blind", params={"q": "1"}, authorized=True)
    findings = RCEModule(client, sleep_delay=0.15).run(target)
    assert len(findings) == 1
    assert findings[0].confidence == 100


def test_modules_refuse_unauthorized_targets(client, server_url: str) -> None:
    target = TargetSpec(server_url + "/xss", params={"q": "1"})
    with pytest.raises(PermissionError):
        XSSModule(client).run(target)
