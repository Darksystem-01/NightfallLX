from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from nightfalllx.core.fuzzer import FastFuzzer, FuzzerConfig


class FuzzServerHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = self.path
        if path == "/admin":
            self._send(200, b"admin panel secret")
        elif path == "/login":
            self._send(200, b"login form")
        elif path == "/redirect":
            self.send_response(301)
            self.send_header("Location", "/new-location")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif "canary" in path:
            self._send(200, b"SOFT-404 NOT FOUND PAGE CONTENT")
        else:
            self._send(404, b"not found")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        if "user=admin" in body:
            self._send(200, b"welcome admin")
        else:
            self._send(403, b"forbidden")

    def _send(self, status: int, data: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture()
def fuzz_server() -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), FuzzServerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_fast_fuzzer_finds_directories(fuzz_server: str) -> None:
    config = FuzzerConfig(
        url=f"{fuzz_server}/FUZZ",
        wordlist=["admin", "login", "notfound1", "notfound2", "redirect"],
        threads=5,
        auto_calibrate=False,
    )
    fuzzer = FastFuzzer(config)
    results = fuzzer.run()

    found_words = {r.word: r.status for r in results}
    assert "admin" in found_words
    assert found_words["admin"] == 200
    assert "login" in found_words
    assert found_words["login"] == 200
    assert "redirect" in found_words
    assert found_words["redirect"] == 301
    assert "notfound1" not in found_words


def test_fast_fuzzer_post_data_replacement(fuzz_server: str) -> None:
    config = FuzzerConfig(
        url=f"{fuzz_server}/login",
        method="POST",
        data="user=FUZZ&pass=123",
        wordlist=["guest", "admin", "test"],
        threads=5,
        match_codes={200},
        auto_calibrate=False,
    )
    fuzzer = FastFuzzer(config)
    results = fuzzer.run()

    assert len(results) == 1
    assert results[0].word == "admin"
    assert results[0].status == 200


def test_fast_fuzzer_auto_calibration(fuzz_server: str) -> None:
    config = FuzzerConfig(
        url=f"{fuzz_server}/FUZZ",
        wordlist=["admin", "login", "canary-test"],
        threads=5,
        auto_calibrate=True,
    )
    fuzzer = FastFuzzer(config)
    results = fuzzer.run()

    found = [r.word for r in results]
    assert "admin" in found
    assert "login" in found
    # soft-404 canary-test should be filtered out by byte length!
    assert "canary-test" not in found
