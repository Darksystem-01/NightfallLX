package parser

import (
	"testing"
)

func TestParseRawRequest(t *testing.T) {
	raw := "POST /admin/login.php?source=burp HTTP/1.1\r\n" +
		"Host: target.lab:8080\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Cookie: session=xyz789; role=guest\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 29\r\n" +
		"\r\n" +
		"username=admin&password=FUZZ"

	req, err := ParseRawRequest([]byte(raw), false)
	if err != nil {
		t.Fatalf("ParseRawRequest failed: %v", err)
	}

	if req.Method != "POST" {
		t.Errorf("expected Method=POST, got %s", req.Method)
	}
	if req.Host != "target.lab:8080" {
		t.Errorf("expected Host=target.lab:8080, got %s", req.Host)
	}
	if req.FullURL != "http://target.lab:8080/admin/login.php?source=burp" {
		t.Errorf("expected FullURL http://target.lab:8080/admin/login.php?source=burp, got %s", req.FullURL)
	}
	if req.Cookie != "session=xyz789; role=guest" {
		t.Errorf("expected cookie, got %s", req.Cookie)
	}
	if req.QueryParams["source"] != "burp" {
		t.Errorf("expected query param source=burp, got %s", req.QueryParams["source"])
	}
	if req.PostParams["username"] != "admin" {
		t.Errorf("expected post param username=admin, got %s", req.PostParams["username"])
	}
	if req.PostParams["password"] != "FUZZ" {
		t.Errorf("expected post param password=FUZZ, got %s", req.PostParams["password"])
	}
	if !req.HasFuzzPoint {
		t.Errorf("expected HasFuzzPoint=true")
	}

	target := req.ToTarget()
	if target.URL != "http://target.lab:8080/admin/login.php" {
		t.Errorf("expected Target URL without query, got %s", target.URL)
	}
}

func TestParseRawRequestWithAsterisk(t *testing.T) {
	raw := "GET /api/user/101* HTTP/1.1\n" +
		"Host: api.target.lab\n" +
		"Authorization: Bearer mytoken\n\n"

	req, err := ParseRawRequest([]byte(raw), true)
	if err != nil {
		t.Fatalf("ParseRawRequest failed: %v", err)
	}

	if req.Scheme != "https" {
		t.Errorf("expected Scheme=https, got %s", req.Scheme)
	}
	if req.FullURL != "https://api.target.lab/api/user/101*" {
		t.Errorf("expected FullURL https://api.target.lab/api/user/101*, got %s", req.FullURL)
	}
	if !req.HasFuzzPoint {
		t.Errorf("expected HasFuzzPoint=true for asterisk")
	}
}
