"""Tests for Burp raw request parser."""

from nightfalllx.core.request_parser import parse_raw_request


def test_parse_burp_post_request():
    raw = (
        "POST /login.php?action=auth HTTP/1.1\r\n"
        "Host: target.lab:8080\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Cookie: sess=xyz123\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "\r\n"
        "username=admin&password=FUZZ"
    )
    req = parse_raw_request(raw)
    assert req.method == "POST"
    assert req.host == "target.lab:8080"
    assert req.full_url == "http://target.lab:8080/login.php?action=auth"
    assert req.cookie == "sess=xyz123"
    assert req.query_params["action"] == "auth"
    assert req.post_params["username"] == "admin"
    assert req.post_params["password"] == "FUZZ"
    assert req.has_fuzz is True


def test_parse_burp_https_asterisk():
    raw = (
        "GET /item/42* HTTP/1.1\n"
        "Host: api.target.lab\n"
        "Authorization: Bearer token123\n\n"
    )
    req = parse_raw_request(raw, force_https=True)
    assert req.scheme == "https"
    assert req.full_url == "https://api.target.lab/item/42*"
    assert req.has_fuzz is True
