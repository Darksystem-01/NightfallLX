from __future__ import annotations

import base64
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from nightfalllx.core.agent import EvasionPlan
from nightfalllx.core.console import Console
from nightfalllx.core.http import HttpClient
from nightfalllx.core.mutator import Mutation
from nightfalllx.core.verifier import VulnerabilityVerifier


class VerifyHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        value = query.get("q", [""])[0]
        status = 200

        if parsed.path == "/ssti":
            body = "none"
            for expression, result in (
                ("{{7*7}}", "49"),
                ("{{7*8}}", "56"),
                ("${7*7}", "49"),
                ("${7*8}", "56"),
                ("<%= 7*7 %>", "49"),
                ("<%= 7*8 %>", "56"),
                ("#{7*7}", "49"),
                ("#{7*8}", "56"),
            ):
                if expression in value:
                    body = f"value={result}"
                    break
        elif parsed.path == "/xss":
            body = value
        elif parsed.path == "/lfi":
            body = base64.b64encode(b"<?php echo 'vapf'; ?>").decode("ascii")
        elif parsed.path == "/sqli":
            match = re.search(r"SLEEP\(([0-9.]+)\)", value)
            oracle = re.search(r"ASCII\(SUBSTRING\(\(@@version\),([0-9]+),1\)\)>([0-9]+)", value)
            if match:
                time.sleep(float(match.group(1)))
                body = "ok"
            elif oracle:
                position = int(oracle.group(1))
                threshold = int(oracle.group(2))
                version = "8.0.32"
                code = ord(version[position - 1]) if position <= len(version) else 0
                body = "normal page" if code > threshold else ""
            elif "AND 1=1" in value:
                body = "normal page"
            elif "AND 1=2" in value:
                body = ""
            else:
                body = "normal page"
        elif parsed.path == "/waf":
            values = query.get("q", [])
            if values == ["bad"]:
                status = 403
                body = "request blocked by security policy"
            else:
                body = "allowed"
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
def target() -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), VerifyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture()
def verifier(target: str):
    client = HttpClient(console=Console(verbose=False, quiet=True), delay=0, timeout=2)
    value = VulnerabilityVerifier(client, authorized=True)
    try:
        yield value
    finally:
        client.close()


def test_ssti_requires_two_independent_arithmetic_results(verifier, target: str) -> None:
    result = verifier.verify_ssti(target + "/ssti", "q")
    assert result.vulnerable
    assert result.confidence == 100
    assert result.confidence_label == "confirmed"
    assert any(signal.name == "math_second" and signal.passed for signal in result.signals)


def test_xss_requires_parsed_dom_script(verifier, target: str) -> None:
    result = verifier.verify_xss(target + "/xss", "q")
    assert result.vulnerable
    assert result.confidence == 100
    assert any(signal.name == "parsed_script" and signal.passed for signal in result.signals)


def test_lfi_decodes_php_filter_output_without_storing_source(verifier, target: str) -> None:
    result = verifier.verify_lfi(target + "/lfi", "q")
    assert result.vulnerable
    assert result.confidence == 100
    assert "source not stored" in result.evidence.summary
    assert "<?php" not in result.evidence.response


def test_boolean_sqli_requires_repeatable_differential(verifier, target: str) -> None:
    result = verifier.verify_boolean_sqli(target + "/sqli", "q")
    assert result.vulnerable
    assert result.confidence == 100


def test_time_based_sqli_uses_statistical_samples(verifier, target: str) -> None:
    result = verifier.verify_time_based_sqli(
        target + "/sqli",
        "q",
        "' OR SLEEP({delay})-- ",
        delay=0.15,
        samples=3,
    )
    assert result.vulnerable
    assert result.confidence == 100
    assert "stdev" in result.detail


def test_hpp_bypass_detects_duplicate_parameter(verifier, target: str) -> None:
    result = verifier.verify_hpp_bypass(target + "/waf", "q", "bad")
    assert result.vulnerable
    assert result.confidence == 100


def test_verifier_requires_authorization(target: str) -> None:
    client = HttpClient(console=Console(verbose=False, quiet=True), delay=0)
    value = VulnerabilityVerifier(client)
    with pytest.raises(PermissionError):
        value.verify_ssti(target + "/ssti", "q")
    client.close()


def test_http_client_activates_curl_cffi_for_random_tls_plan(target: str) -> None:
    pytest.importorskip("curl_cffi")
    client = HttpClient(console=Console(verbose=False, quiet=True), delay=0, timeout=2)
    plan = EvasionPlan(
        waf="Cloudflare",
        confidence=90,
        aggressive=True,
        use_hpp=False,
        tls_profile="random",
        mutations=(Mutation("1", "identity"),),
        reason="test",
    )
    response = client.request_evasive("GET", target + "/sqli", "q", "1", plan)
    assert client._backend == "curl_cffi"
    assert response.status == 200
    client.close()


def test_http_client_uses_evasion_plan_mutations(target: str) -> None:
    client = HttpClient(console=Console(verbose=False, quiet=True), delay=0, timeout=2)
    plan = EvasionPlan(
        waf="Generic WAF/block",
        confidence=80,
        aggressive=True,
        use_hpp=True,
        tls_profile="random",
        mutations=(Mutation("bad", "identity"), Mutation("1", "benign")),
        reason="test",
    )
    response = client.request_evasive("GET", target + "/waf", "q", "bad", plan, params={"q": "1"})
    assert response.status == 200
    assert response.text == "allowed"
    client.close()
