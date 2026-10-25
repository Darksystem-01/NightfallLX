package client

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBypassHeaders(t *testing.T) {
	h := BypassHeaders()
	want := map[string]string{
		"X-Originating-IP":          "127.0.0.1",
		"X-Forwarded-Host":          "localhost",
		"X-Custom-IP-Authorization": "127.0.0.1",
	}
	for k, v := range want {
		if got := h[k]; got != v {
			t.Fatalf("%s = %q, want %q", k, got, v)
		}
	}

	// A fresh map must be returned each call.
	h["X-Originating-IP"] = "10.0.0.1"
	if BypassHeaders()["X-Originating-IP"] != "127.0.0.1" {
		t.Fatal("BypassHeaders leaked shared state")
	}
}

func TestApplyBypassHeaders(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.test/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9")

	ApplyBypassHeaders(req)

	if got := req.Header.Get("X-Forwarded-For"); got != "203.0.113.9" {
		t.Fatalf("operator header overwritten: %q", got)
	}
	if got := req.Header.Get("X-Originating-IP"); got != "127.0.0.1" {
		t.Fatalf("missing bypass header, got %q", got)
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "localhost" {
		t.Fatalf("missing X-Forwarded-Host, got %q", got)
	}
}

func TestDoubleURLEncode(t *testing.T) {
	in := "' OR 1=1--"
	out := DoubleURLEncode(in)
	if !strings.Contains(out, "%2527") {
		t.Fatalf("expected %%2527 in %q", out)
	}
	if !strings.Contains(out, "%253D") {
		t.Fatalf("expected %%253D in %q", out)
	}

	once, err := url.QueryUnescape(out)
	if err != nil {
		t.Fatalf("first unescape: %v", err)
	}
	twice, err := url.QueryUnescape(once)
	if err != nil {
		t.Fatalf("second unescape: %v", err)
	}
	if twice != in {
		t.Fatalf("roundtrip = %q, want %q", twice, in)
	}
}

func TestOverlongUTF8(t *testing.T) {
	got := OverlongUTF8("<script>'")
	if !strings.HasPrefix(got, "%C0%BC") {
		t.Fatalf("expected overlong '<' prefix, got %q", got)
	}
	if !strings.Contains(got, "%C0%A7") {
		t.Fatalf("expected overlong quote in %q", got)
	}
	if !strings.Contains(got, "script") {
		t.Fatalf("alphanumerics should stay readable, got %q", got)
	}

	raw := string(OverlongUTF8Bytes("<"))
	if raw != "\xC0\xBC" {
		t.Fatalf("raw overlong = % x, want c0 bc", []byte(raw))
	}
	if OverlongUTF8("abcUNION") != "abcUNION" {
		t.Fatal("safe payload should be unchanged")
	}
}

func TestRandomizeCaseSeed(t *testing.T) {
	in := "UNION SELECT 1=1"
	out := RandomizeCaseSeed(in, 42)

	if !strings.EqualFold(out, in) {
		t.Fatalf("case change altered letters: %q vs %q", out, in)
	}
	if out == in {
		t.Fatalf("expected at least one case flip, got %q", out)
	}
	if strings.Contains(out, " ") != strings.Contains(in, " ") {
		t.Fatal("spaces must be preserved")
	}

	// Deterministic for a fixed seed.
	if RandomizeCaseSeed(in, 42) != out {
		t.Fatal("RandomizeCaseSeed is not deterministic")
	}
}

func TestNullByteInjection(t *testing.T) {
	got := InjectNullByte("../../etc/passwd", 6)
	if got != "../../%00etc/passwd" {
		t.Fatalf("InjectNullByte = %q", got)
	}

	raw := InjectNullByteRaw("ab", 1)
	if raw != "a\x00b" {
		t.Fatalf("InjectNullByteRaw = %q", raw)
	}

	variants := NullByteVariants("abc")
	if len(variants) != 3 {
		t.Fatalf("expected 3 variants, got %d", len(variants))
	}
	for _, v := range variants {
		if !strings.Contains(v, "%00") {
			t.Fatalf("variant %q missing null byte", v)
		}
	}
	if InjectNullByte("abc", -5) != "%00abc" || InjectNullByte("abc", 99) != "abc%00" {
		t.Fatal("offset clamping failed")
	}
}

func TestMutatePayload(t *testing.T) {
	variants := MutatePayload("<script>alert(1)</script>")
	if len(variants) != len(AllEvasionTechniques) {
		t.Fatalf("expected %d variants, got %d", len(AllEvasionTechniques), len(variants))
	}

	seen := make(map[EvasionTechnique]bool)
	for _, v := range variants {
		seen[v.Technique] = true
		if v.Payload == "" {
			t.Fatalf("empty payload for %s", v.Technique)
		}
	}
	for _, tech := range AllEvasionTechniques {
		if !seen[tech] {
			t.Fatalf("missing technique %s", tech)
		}
	}

	only := MutatePayload("x", EvasionDoubleURL)
	if len(only) != 1 || only[0].Technique != EvasionDoubleURL {
		t.Fatalf("unexpected selection: %+v", only)
	}
}

func TestChunkedBody(t *testing.T) {
	got := string(ChunkedBody([]byte("abcdef")))
	want := "4\r\nabcd\r\n2\r\nef\r\n0\r\n\r\n"
	if got != want {
		t.Fatalf("ChunkedBody = %q, want %q", got, want)
	}

	if string(ChunkedBody(nil)) != "0\r\n\r\n" {
		t.Fatalf("empty body framing = %q", string(ChunkedBody(nil)))
	}

	custom := string(ChunkedBodyWithSize([]byte("abc"), 3))
	if custom != "3\r\nabc\r\n0\r\n\r\n" {
		t.Fatalf("custom chunk size = %q", custom)
	}
}

func TestApplyChunkedEncoding(t *testing.T) {
	req, _ := http.NewRequest("POST", "http://example.test/", strings.NewReader("a=1"))
	ApplyChunkedEncoding(req)

	if req.ContentLength != -1 {
		t.Fatalf("ContentLength = %d, want -1", req.ContentLength)
	}
	if len(req.TransferEncoding) != 1 || req.TransferEncoding[0] != "chunked" {
		t.Fatalf("TransferEncoding = %v", req.TransferEncoding)
	}
}

func TestClientHeaderTampering(t *testing.T) {
	var gotOrigin, gotHost string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrigin = r.Header.Get("X-Originating-IP")
		gotHost = r.Header.Get("X-Forwarded-Host")
		w.WriteHeader(200)
	}))
	defer ts.Close()

	c := NewClient("", 3*time.Second, true, "", nil).SetHeaderTampering(true)
	if _, err := c.Request("GET", ts.URL, "", nil); err != nil {
		t.Fatalf("request: %v", err)
	}
	if gotOrigin != "127.0.0.1" || gotHost != "localhost" {
		t.Fatalf("bypass headers not sent: origin=%q host=%q", gotOrigin, gotHost)
	}
}

func TestClientChunkedEncoding(t *testing.T) {
	var gotTE string
	var gotBody string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TransferEncoding) > 0 {
			gotTE = r.TransferEncoding[0]
		}
		body := make([]byte, 64)
		n, _ := r.Body.Read(body)
		gotBody = string(body[:n])
		w.WriteHeader(200)
	}))
	defer ts.Close()

	c := NewClient("", 3*time.Second, true, "", nil).SetChunkedEncoding(true)
	if _, err := c.Request("POST", ts.URL, "hello=world", nil); err != nil {
		t.Fatalf("request: %v", err)
	}
	if gotTE != "chunked" {
		t.Fatalf("Transfer-Encoding = %q, want chunked", gotTE)
	}
	if gotBody != "hello=world" {
		t.Fatalf("body = %q", gotBody)
	}
}
