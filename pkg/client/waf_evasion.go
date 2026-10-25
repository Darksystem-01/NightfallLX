package client

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// EvasionTechnique identifies a payload mutation used to slip past signature
// based WAF rules.
type EvasionTechnique string

const (
	// EvasionDoubleURL encodes a payload twice ("'" -> %2527).
	EvasionDoubleURL EvasionTechnique = "double-url"
	// EvasionOverlongUTF8 encodes dangerous bytes as overlong UTF-8 sequences
	// ("<" -> %C0%BC), a classic normalization mismatch bypass.
	EvasionOverlongUTF8 EvasionTechnique = "overlong-utf8"
	// EvasionCaseRandomize flips the case of ASCII letters ("SELECT" -> "sElEcT").
	EvasionCaseRandomize EvasionTechnique = "case-random"
	// EvasionNullByte injects encoded NUL bytes at random/selected offsets.
	EvasionNullByte EvasionTechnique = "null-byte"
)

// AllEvasionTechniques lists every supported mutation.
var AllEvasionTechniques = []EvasionTechnique{
	EvasionDoubleURL,
	EvasionOverlongUTF8,
	EvasionCaseRandomize,
	EvasionNullByte,
}

// PayloadVariant is a single mutated form of a payload.
type PayloadVariant struct {
	Technique EvasionTechnique `json:"technique"`
	Payload   string           `json:"payload"`
}

// BypassHeaders returns a fresh set of headers that abuse common reverse-proxy
// and application trust decisions (IP allowlists, vhost routing, URL rewriting).
func BypassHeaders() map[string]string {
	return map[string]string{
		"X-Originating-IP":          "127.0.0.1",
		"X-Forwarded-Host":          "localhost",
		"X-Custom-IP-Authorization": "127.0.0.1",
		"X-Forwarded-For":           "127.0.0.1",
		"X-Remote-IP":               "127.0.0.1",
		"X-Remote-Addr":             "127.0.0.1",
		"X-Client-IP":               "127.0.0.1",
		"X-Real-IP":                 "127.0.0.1",
		"X-Original-URL":            "/",
		"X-Rewrite-URL":             "/",
	}
}

// ApplyBypassHeaders injects the evasion headers into req. Headers that are
// already present are left untouched so operator-supplied values win.
func ApplyBypassHeaders(req *http.Request) {
	if req == nil {
		return
	}
	for k, v := range BypassHeaders() {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}
}

// singleURLEncode percent-encodes every byte outside the RFC 3986 unreserved
// set. Unlike url.QueryEscape it never emits '+', which keeps repeated
// encoding/decoding lossless.
func singleURLEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 2)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '-', '_', '.', '~':
		return true
	}
	return false
}

// DoubleURLEncode applies percent-encoding twice so a WAF that decodes once
// still sees an encoded payload ("<" -> %253C).
func DoubleURLEncode(s string) string {
	return singleURLEncode(singleURLEncode(s))
}

// overlongTargets are the bytes most useful to smuggle past HTML/SQL/XSS filters.
func isOverlongTarget(c byte) bool {
	switch c {
	case '<', '>', '\'', '"', '/', '\\', '.', '(', ')', ';', '=', '`', '{', '}', '[', ']', '|', '%':
		return true
	}
	return c < 0x20 || c >= 0x7f
}

// overlongBytes returns the 2-byte overlong UTF-8 representation of an ASCII
// byte. Browsers and naive decoders normalize it back to the ASCII character,
// while byte-oriented WAF signatures do not.
func overlongBytes(c byte) [2]byte {
	if c < 0x40 {
		return [2]byte{0xC0 | (c >> 6), 0x80 | (c & 0x3F)}
	}
	return [2]byte{0xC1 | ((c - 0x40) >> 6), 0x80 | (c & 0x3F)}
}

// OverlongUTF8 returns a percent-encoded payload where dangerous characters are
// replaced with overlong UTF-8 sequences (e.g. "<" -> %C0%BC).
func OverlongUTF8(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 2)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isOverlongTarget(c) {
			b.WriteByte(c)
			continue
		}
		seq := overlongBytes(c)
		fmt.Fprintf(&b, "%%%02X%%%02X", seq[0], seq[1])
	}
	return b.String()
}

// OverlongUTF8Bytes is the raw (non percent-encoded) form of OverlongUTF8,
// suitable for request bodies and raw socket payloads.
func OverlongUTF8Bytes(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isOverlongTarget(c) {
			out = append(out, c)
			continue
		}
		seq := overlongBytes(c)
		out = append(out, seq[0], seq[1])
	}
	return out
}

// RandomizeCase flips the case of ASCII letters using a time-seeded RNG.
func RandomizeCase(s string) string {
	return RandomizeCaseSeed(s, time.Now().UnixNano())
}

// RandomizeCaseSeed is RandomizeCase with a deterministic seed, useful for
// reproducible scans and tests. At least one letter is always flipped so the
// result never equals the input when a letter exists.
func RandomizeCaseSeed(s string, seed int64) string {
	b := []byte(s)
	rng := rand.New(rand.NewSource(seed))
	flipped := false
	firstLetter := -1

	for i, c := range b {
		isLower := c >= 'a' && c <= 'z'
		isUpper := c >= 'A' && c <= 'Z'
		if !isLower && !isUpper {
			continue
		}
		if firstLetter == -1 {
			firstLetter = i
		}
		if rng.Intn(2) == 0 {
			if isLower {
				b[i] = c - ('a' - 'A')
			} else {
				b[i] = c + ('a' - 'A')
			}
			flipped = true
		}
	}

	if !flipped && firstLetter != -1 {
		c := b[firstLetter]
		if c >= 'a' && c <= 'z' {
			b[firstLetter] = c - ('a' - 'A')
		} else {
			b[firstLetter] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// InjectNullByte inserts an encoded NUL (%00) at the given byte offset. The
// offset is clamped to [0, len(s)].
func InjectNullByte(s string, at int) string {
	if at < 0 {
		at = 0
	}
	if at > len(s) {
		at = len(s)
	}
	return s[:at] + "%00" + s[at:]
}

// InjectNullByteRaw inserts a literal NUL byte at the given offset.
func InjectNullByteRaw(s string, at int) string {
	if at < 0 {
		at = 0
	}
	if at > len(s) {
		at = len(s)
	}
	return s[:at] + "\x00" + s[at:]
}

// NullByteVariants returns prefix, middle and suffix NUL-injection variants.
func NullByteVariants(s string) []string {
	mid := len(s) / 2
	return []string{
		"%00" + s,
		InjectNullByte(s, mid),
		s + "%00",
	}
}

// MutatePayload returns one variant per requested technique. With no
// techniques supplied it applies every known technique.
func MutatePayload(payload string, techniques ...EvasionTechnique) []PayloadVariant {
	if len(techniques) == 0 {
		techniques = AllEvasionTechniques
	}

	variants := make([]PayloadVariant, 0, len(techniques))
	for _, t := range techniques {
		switch t {
		case EvasionDoubleURL:
			variants = append(variants, PayloadVariant{Technique: t, Payload: DoubleURLEncode(payload)})
		case EvasionOverlongUTF8:
			variants = append(variants, PayloadVariant{Technique: t, Payload: OverlongUTF8(payload)})
		case EvasionCaseRandomize:
			variants = append(variants, PayloadVariant{Technique: t, Payload: RandomizeCase(payload)})
		case EvasionNullByte:
			variants = append(variants, PayloadVariant{Technique: t, Payload: InjectNullByte(payload, len(payload)/2)})
		}
	}
	return variants
}

// ChunkedBody frames body using HTTP/1.1 chunked transfer encoding, splitting
// it into small chunks so signature engines cannot match across boundaries.
func ChunkedBody(body []byte) []byte {
	return ChunkedBodyWithSize(body, 4)
}

// ChunkedBodyWithSize is ChunkedBody with an explicit chunk size.
func ChunkedBodyWithSize(body []byte, chunkSize int) []byte {
	if chunkSize <= 0 {
		chunkSize = 4
	}

	var buf bytes.Buffer
	for len(body) > 0 {
		n := chunkSize
		if n > len(body) {
			n = len(body)
		}
		fmt.Fprintf(&buf, "%x\r\n", n)
		buf.Write(body[:n])
		buf.WriteString("\r\n")
		body = body[n:]
	}
	buf.WriteString("0\r\n\r\n")
	return buf.Bytes()
}

// ApplyChunkedEncoding configures req to be sent with
// "Transfer-Encoding: chunked" and an unknown content length. The Go transport
// performs the framing, so proxies that only inspect Content-Length bodies
// cannot see the whole payload.
func ApplyChunkedEncoding(req *http.Request) {
	if req == nil {
		return
	}
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
}

// ChunkedReader wraps r so that reading it yields a valid chunked body. It is
// handy when constructing raw requests manually.
func ChunkedReader(r io.Reader) io.Reader {
	body, err := io.ReadAll(r)
	if err != nil {
		return strings.NewReader("0\r\n\r\n")
	}
	return bytes.NewReader(ChunkedBody(body))
}

// SetHeaderTampering enables/disables injection of the bypass headers for every
// request sent through the client.
func (c *Client) SetHeaderTampering(enabled bool) *Client {
	c.HeaderTampering = enabled
	return c
}

// SetChunkedEncoding enables/disables chunked transfer encoding for request
// bodies sent through the client.
func (c *Client) SetChunkedEncoding(enabled bool) *Client {
	c.ChunkedEncoding = enabled
	return c
}
