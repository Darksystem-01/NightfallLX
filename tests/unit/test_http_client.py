from __future__ import annotations

import ssl
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from nightfalllx.core.console import Console
from nightfalllx.core.http import HttpClient, build_ssl_context


class HttpHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"vapf-http-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-VAPF-Test", "yes")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


class HttpsHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"vapf-https-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


def start_server(handler: type[BaseHTTPRequestHandler], tls: ssl.SSLContext | None = None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    if tls is not None:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def make_self_signed_cert(tmp_path: Path) -> tuple[Path, Path]:
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def test_http_client_returns_normalised_response() -> None:
    server, thread = start_server(HttpHandler)
    try:
        port = server.server_address[1]
        client = HttpClient(console=Console(verbose=False, quiet=True), delay=0)
        response = client.get(f"http://127.0.0.1:{port}/")
        assert response.ok
        assert response.status == 200
        assert response.text == "vapf-http-ok"
        assert response.header("x-vapf-test") == "yes"
        assert client.request_count == 1
        client.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.filterwarnings("ignore:ssl.TLSVersion.TLSv1 is deprecated")
def test_ssl_context_disables_verification_and_supports_legacy_tls() -> None:
    context = build_ssl_context("TLSv1_2", verify=False)
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2

    legacy = build_ssl_context("TLSv1_0", verify=False)
    assert legacy.verify_mode == ssl.CERT_NONE
    assert legacy.minimum_version == ssl.TLSVersion.TLSv1
    assert legacy.maximum_version == ssl.TLSVersion.TLSv1


def test_https_client_accepts_self_signed_certificate(tmp_path: Path) -> None:
    cert_path, key_path = make_self_signed_cert(tmp_path)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    server, thread = start_server(HttpsHandler, server_context)
    try:
        port = server.server_address[1]
        client = HttpClient(
            console=Console(verbose=False, quiet=True),
            verify=False,
            tls_profile="modern",
            delay=0,
        )
        response = client.get(f"https://127.0.0.1:{port}/")
        assert response.ok, response.error
        assert response.text == "vapf-https-ok"
        client.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
