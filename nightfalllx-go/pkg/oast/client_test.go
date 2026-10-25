package oast

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeListener is a configurable OAST collector used by the tests. It serves
// /register and /poll and hands out whatever interactions the test produced.
type fakeListener struct {
	mu           sync.Mutex
	interactions []interactionEnvelope
	polls        int
	registrations int
	server       *httptest.Server
}

func newFakeListener(t *testing.T) *fakeListener {
	t.Helper()
	fl := &fakeListener{}
	fl.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register":
			fl.mu.Lock()
			fl.registrations++
			fl.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
		case "/poll":
			fl.mu.Lock()
			fl.polls++
			events := append([]interactionEnvelope(nil), fl.interactions...)
			fl.mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"interactions": events})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fl.server.Close)
	return fl
}

func (f *fakeListener) domain() string {
	return strings.TrimPrefix(f.server.URL, "http://")
}

func (f *fakeListener) push(events ...interactionEnvelope) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.interactions = append(f.interactions, events...)
}

func (f *fakeListener) pollCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.polls
}

func newTestClient(t *testing.T, fl *fakeListener) *Client {
	t.Helper()
	c, err := New(Config{
		ServerURL:    fl.server.URL,
		Domain:       fl.domain(),
		Scheme:       "http",
		PollInterval: 10 * time.Millisecond,
		Timeout:      2 * time.Second,
		Collector:    CollectorListener,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNewValidatesConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"missing domain", Config{ServerURL: "http://127.0.0.1:1"}},
		{"missing server", Config{Domain: "oast.test"}},
		{"bad scheme", Config{ServerURL: "http://127.0.0.1:1", Domain: "oast.test", Scheme: "ftp"}},
		{"bad collector", Config{ServerURL: "http://127.0.0.1:1", Domain: "oast.test", Collector: "nope"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func TestNewRequiresReachableCollector(t *testing.T) {
	// Closed server: registration must fail rather than silently degrade.
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := ts.URL
	ts.Close()

	_, err := New(Config{ServerURL: url, Domain: "oast.test", Collector: CollectorListener, Timeout: 300 * time.Millisecond})
	if err == nil {
		t.Fatal("expected registration failure for an unreachable collector")
	}
}

func TestGenerateProducesUniqueTokensAndMetadata(t *testing.T) {
	fl := newFakeListener(t)
	c := newTestClient(t, fl)
	defer c.Close(context.Background())

	const count = 250
	seen := make(map[string]struct{}, count)

	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			reg, err := c.Generate(Registration{
				Module:    "ssrf",
				Target:    "http://target.lab/fetch",
				Parameter: "url",
				Payload:   fmt.Sprintf("payload-%d", i),
			})
			if err != nil {
				t.Errorf("Generate: %v", err)
				return
			}
			if !strings.HasPrefix(reg.Host, reg.Token+".") {
				t.Errorf("host %q does not embed token %q", reg.Host, reg.Token)
			}
			if reg.URL != "http://"+reg.Host+"/" {
				t.Errorf("unexpected callback URL %q", reg.URL)
			}
			if len(reg.Token) != 20 {
				t.Errorf("token %q has length %d, want 20", reg.Token, len(reg.Token))
			}
			for _, r := range reg.Token {
				if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') {
					t.Errorf("token %q contains a non DNS-safe character %q", reg.Token, r)
				}
			}
			if reg.CreatedAt.IsZero() {
				t.Error("CreatedAt was not populated")
			}

			mu.Lock()
			if _, dup := seen[reg.Token]; dup {
				t.Errorf("duplicate token %q", reg.Token)
			}
			seen[reg.Token] = struct{}{}
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	if got := len(c.Registrations()); got != count {
		t.Fatalf("registrations = %d, want %d", got, count)
	}
	if len(seen) != count {
		t.Fatalf("unique tokens = %d, want %d", len(seen), count)
	}

	// Token length and length bounds.
	if _, err := c.Generate(Registration{}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if c.Registrations()[0].Token == c.Registrations()[1].Token {
		t.Fatal("sequential tokens collided")
	}
}

func TestPollCorrelatesInteractionsAndDeduplicates(t *testing.T) {
	fl := newFakeListener(t)
	c := newTestClient(t, fl)
	defer c.Close(context.Background())

	ssrf, err := c.Generate(Registration{Module: "ssrf", Target: "http://target.lab/fetch", Parameter: "url", Payload: "http://x"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	rce, err := c.Generate(Registration{Module: "cmdi", Target: "http://target.lab/ping", Parameter: "host", Payload: "nslookup"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	fl.push(
		interactionEnvelope{Protocol: "http", UniqueID: ssrf.Token, FullID: ssrf.Host, RemoteAddress: "10.0.0.5:51515", RawRequest: "GET / HTTP/1.1", Timestamp: "2026-05-31T10:00:00Z"},
		interactionEnvelope{Protocol: "dns", UniqueID: rce.Token, FullID: rce.Host, RemoteAddress: "10.0.0.5:53", Timestamp: "2026-05-31T10:00:01Z"},
		// Unknown token must be ignored.
		interactionEnvelope{Protocol: "http", UniqueID: "unknown-token", FullID: "unknown-token.oast.test"},
	)

	matches, err := c.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("matches = %d, want 2", len(matches))
	}

	byToken := make(map[string]Match, len(matches))
	for _, m := range matches {
		byToken[m.Registration.Token] = m
	}

	httpMatch, ok := byToken[ssrf.Token]
	if !ok {
		t.Fatalf("no match for ssrf token")
	}
	if httpMatch.Registration.Module != "ssrf" || httpMatch.Registration.Parameter != "url" {
		t.Errorf("registration metadata lost: %+v", httpMatch.Registration)
	}
	if len(httpMatch.Interactions) != 1 || httpMatch.Interactions[0].Protocol != ProtocolHTTP {
		t.Fatalf("unexpected ssrf interactions: %+v", httpMatch.Interactions)
	}
	if got := ClientIP(httpMatch.Interactions[0].RemoteAddress); got != "10.0.0.5" {
		t.Errorf("ClientIP = %q, want 10.0.0.5", got)
	}
	if httpMatch.Interactions[0].Timestamp.IsZero() {
		t.Error("timestamp was not parsed")
	}

	dnsMatch, ok := byToken[rce.Token]
	if !ok {
		t.Fatalf("no match for cmdi token")
	}
	if dnsMatch.Interactions[0].Protocol != ProtocolDNS {
		t.Errorf("protocol = %q, want dns", dnsMatch.Interactions[0].Protocol)
	}

	// Second poll returns nothing: interactions are deduplicated.
	matches, err = c.Poll(context.Background())
	if err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("second poll returned %d matches, want 0", len(matches))
	}
}

func TestWaitForDeliversBufferedInteractionImmediately(t *testing.T) {
	fl := newFakeListener(t)
	c := newTestClient(t, fl)
	defer c.Close(context.Background())

	reg, err := c.Generate(Registration{Module: "xxe", Target: "http://target.lab/xml", Parameter: "(XML Body)"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	fl.push(interactionEnvelope{Protocol: "http", UniqueID: reg.Token, FullID: reg.Host, RemoteAddress: "127.0.0.1:9000"})

	if err := c.collect(context.Background()); err != nil {
		t.Fatalf("collect: %v", err)
	}

	start := time.Now()
	items, ok := c.WaitFor(context.Background(), reg.Token, time.Second)
	if !ok {
		t.Fatal("expected a callback")
	}
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Fatalf("buffered callback took %v, expected an immediate return", elapsed)
	}
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
}

func TestWaitForPollsUntilCallbackArrives(t *testing.T) {
	fl := newFakeListener(t)
	c := newTestClient(t, fl)
	defer c.Close(context.Background())

	reg, err := c.Generate(Registration{Module: "ssrf"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	go func() {
		// Deliver only after a few polls so the wait loop has to spin.
		time.Sleep(60 * time.Millisecond)
		fl.push(interactionEnvelope{Protocol: "http", UniqueID: reg.Token, FullID: reg.Host})
	}()

	items, ok := c.WaitFor(context.Background(), reg.Token, 2*time.Second)
	if !ok || len(items) != 1 {
		t.Fatalf("WaitFor = (%v, %v), want one interaction", items, ok)
	}
	if fl.pollCount() < 2 {
		t.Fatalf("poll count = %d, expected repeated polling", fl.pollCount())
	}
}

func TestWaitForTimeoutAndContextCancel(t *testing.T) {
	fl := newFakeListener(t)
	c := newTestClient(t, fl)
	defer c.Close(context.Background())

	reg, err := c.Generate(Registration{Module: "ssrf"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	start := time.Now()
	if _, ok := c.WaitFor(context.Background(), reg.Token, 80*time.Millisecond); ok {
		t.Fatal("expected a timeout, got a callback")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("timeout took %v, expected ~80ms", elapsed)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := c.WaitFor(ctx, reg.Token, 5*time.Second); ok {
		t.Fatal("expected cancellation, got a callback")
	}

	// Unknown and empty token lists return immediately.
	if _, ok := c.WaitFor(context.Background(), "does-not-exist", 20*time.Millisecond); ok {
		t.Fatal("unknown token produced a callback")
	}
	if got := c.WaitAny(context.Background(), nil, time.Second); got != nil {
		t.Fatalf("WaitAny(nil) = %v, want nil", got)
	}
}

func TestWaitAnyDoesNotStealOtherTokens(t *testing.T) {
	fl := newFakeListener(t)
	c := newTestClient(t, fl)
	defer c.Close(context.Background())

	first, _ := c.Generate(Registration{Module: "cmdi", Parameter: "a"})
	second, _ := c.Generate(Registration{Module: "cmdi", Parameter: "b"})

	fl.push(
		interactionEnvelope{Protocol: "http", UniqueID: first.Token, FullID: first.Host},
		interactionEnvelope{Protocol: "http", UniqueID: second.Token, FullID: second.Host},
	)

	matches := c.WaitAny(context.Background(), []string{first.Token}, time.Second)
	if len(matches) != 1 || matches[0].Registration.Token != first.Token {
		t.Fatalf("WaitAny returned %+v, want only the first token", matches)
	}

	// The second token's interaction must still be buffered.
	items, ok := c.WaitFor(context.Background(), second.Token, time.Second)
	if !ok || len(items) != 1 {
		t.Fatalf("second token lost its buffered interaction: %v %v", items, ok)
	}
}

func TestCloseIsIdempotentAndBlocksNewRegistrations(t *testing.T) {
	fl := newFakeListener(t)
	c := newTestClient(t, fl)

	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := c.Generate(Registration{Module: "ssrf"}); err == nil {
		t.Fatal("Generate after Close succeeded")
	}
	if _, err := c.Poll(context.Background()); err == nil {
		t.Fatal("Poll after Close succeeded")
	}
}

func TestLooksLikeInteractsh(t *testing.T) {
	cases := map[string]bool{
		"https://oast.pro":                     true,
		"https://interactsh.example.net":       true,
		"https://oast-1.internal.corp":         true,
		"https://collector.example.com":        false,
		"http://127.0.0.1:9000":                false,
	}
	for url, want := range cases {
		if got := looksLikeInteractsh(url); got != want {
			t.Errorf("looksLikeInteractsh(%q) = %v, want %v", url, got, want)
		}
	}
}

func TestParseListenerBodyShapes(t *testing.T) {
	event := `{"protocol":"dns","unique-id":"abc123","full-id":"abc123.oast.test","remote-address":"1.2.3.4:53","timestamp":1717000000}`

	tests := []struct {
		name string
		body string
		want int
	}{
		{"empty", "", 0},
		{"null", "null", 0},
		{"bare array", "[" + event + "]", 1},
		{"interactions wrapper", `{"interactions":[` + event + `]}`, 1},
		{"data wrapper", `{"data":[` + event + `]}`, 1},
		{"base64 data", `{"data":["` + base64.StdEncoding.EncodeToString([]byte(event)) + `"]}`, 1},
		{"no events", `{"message":"ok"}`, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseListenerBody([]byte(tc.body))
			if err != nil {
				t.Fatalf("parseListenerBody: %v", err)
			}
			if len(got) != tc.want {
				t.Fatalf("events = %d, want %d", len(got), tc.want)
			}
			if tc.want > 0 {
				if got[0].Token != "abc123" {
					t.Errorf("token = %q, want abc123", got[0].Token)
				}
				if got[0].Protocol != ProtocolDNS {
					t.Errorf("protocol = %q, want dns", got[0].Protocol)
				}
				if got[0].Timestamp.Unix() != 1717000000 {
					t.Errorf("timestamp = %v, want unix 1717000000", got[0].Timestamp)
				}
			}
		})
	}

	if _, err := parseListenerBody([]byte(`{"error":true,"message":"boom"}`)); err == nil {
		t.Fatal("expected an error field to surface")
	}
	if _, err := parseListenerBody([]byte(`not-json`)); err == nil {
		t.Fatal("expected malformed JSON to fail")
	}
}

func TestParseTimestampFormats(t *testing.T) {
	cases := []struct {
		in   interface{}
		want time.Time
	}{
		{"2026-05-31T10:00:00Z", time.Date(2026, 5, 31, 10, 0, 0, 0, time.UTC)},
		{"2026-05-31T10:00:00.500Z", time.Date(2026, 5, 31, 10, 0, 0, 500_000_000, time.UTC)},
		{float64(1717000000), time.Unix(1717000000, 0).UTC()},
		{float64(1717000000000), time.UnixMilli(1717000000000).UTC()},
		{json.Number("1717000000"), time.Unix(1717000000, 0).UTC()},
	}
	for _, tc := range cases {
		if got := parseTimestamp(tc.in); !got.Equal(tc.want) {
			t.Errorf("parseTimestamp(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestInteractshCollectorRoundTrip exercises the full Interactsh wire protocol:
// RSA-OAEP wrapped AES key, AES-CFB encrypted events and registration.
func TestInteractshCollectorRoundTrip(t *testing.T) {
	var (
		mu       sync.Mutex
		pubKey   *rsa.PublicKey
		corrID   string
		secret   string
		events   []map[string]any
		deregged int32
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register":
			var req struct {
				PublicKey string `json:"public-key"`
				Secret    string `json:"secret"`
				CorrID    string `json:"correlation-id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			block, _ := pem.Decode([]byte(req.PublicKey))
			if block == nil {
				http.Error(w, "bad pem", http.StatusBadRequest)
				return
			}
			parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			rsaPub, ok := parsed.(*rsa.PublicKey)
			if !ok {
				http.Error(w, "not rsa", http.StatusBadRequest)
				return
			}
			mu.Lock()
			pubKey, corrID, secret = rsaPub, req.CorrID, req.Secret
			mu.Unlock()
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
		case "/deregister":
			atomic.AddInt32(&deregged, 1)
			_, _ = w.Write([]byte(`{"message":"deregistered"}`))
		case "/poll":
			mu.Lock()
			id, gotSecret := corrID, secret
			pending := events
			events = nil
			pk := pubKey
			mu.Unlock()

			if r.URL.Query().Get("id") != id || r.URL.Query().Get("secret") != gotSecret {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if pk == nil || len(pending) == 0 {
				_, _ = w.Write([]byte(`{"data":[],"aes_key":""}`))
				return
			}

			aesKey := make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pk, aesKey, nil)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			encrypted := make([]string, 0, len(pending))
			for _, ev := range pending {
				plain, _ := json.Marshal(ev)
				encrypted = append(encrypted, encryptCFB(aesKey, plain))
			}

			_ = json.NewEncoder(w).Encode(map[string]any{
				"data":    encrypted,
				"aes_key": base64.StdEncoding.EncodeToString(wrapped),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c, err := New(Config{
		ServerURL:    server.URL,
		Domain:       "oast.test",
		PollInterval: 10 * time.Millisecond,
		Timeout:      2 * time.Second,
		Collector:    CollectorInteractsh,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close(context.Background())

	mu.Lock()
	if pubKey == nil || corrID == "" || secret == "" {
		mu.Unlock()
		t.Fatal("interactsh registration did not deliver a public key and credentials")
	}
	mu.Unlock()

	reg, err := c.Generate(Registration{Module: "cmdi", Target: "http://target.lab/ping", Parameter: "host", Payload: "nslookup"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	mu.Lock()
	events = append(events, map[string]any{
		"protocol":       "dns",
		"unique-id":      reg.Token,
		"full-id":        reg.Host,
		"remote-address": "203.0.113.9:53",
		"raw-request":    reg.Host,
		"timestamp":      "2026-05-31T11:22:33Z",
	})
	mu.Unlock()

	matches, err := c.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(matches))
	}
	if matches[0].Registration.Token != reg.Token {
		t.Fatalf("correlated to %q, want %q", matches[0].Registration.Token, reg.Token)
	}
	if matches[0].Interactions[0].Protocol != ProtocolDNS {
		t.Fatalf("protocol = %q, want dns", matches[0].Interactions[0].Protocol)
	}

	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if atomic.LoadInt32(&deregged) != 1 {
		t.Fatalf("deregister calls = %d, want 1", atomic.LoadInt32(&deregged))
	}
}

// encryptCFB mirrors the Interactsh payload shape: iv || AES-CFB ciphertext.
func encryptCFB(key, plain []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	out := make([]byte, aes.BlockSize+len(plain))
	copy(out, iv)
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(out[aes.BlockSize:], plain)
	return base64.StdEncoding.EncodeToString(out)
}

func TestInteractshCollectorHandlesPollErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register":
			_, _ = w.Write([]byte(`{"message":"ok"}`))
		case "/poll":
			http.Error(w, "server on fire", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c, err := New(Config{ServerURL: server.URL, Domain: "oast.test", Collector: CollectorInteractsh, Timeout: time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close(context.Background())

	if _, err := c.Poll(context.Background()); err == nil {
		t.Fatal("expected poll error to surface")
	}
}
