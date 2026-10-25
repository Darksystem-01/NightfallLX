// Package oast implements an out-of-band application security testing (OAST)
// engine. It generates unique callback domains, maps every token back to the
// request that produced it, polls a collector for HTTP/DNS interactions and
// correlates the received callbacks with the vulnerable parameter and payload.
//
// The engine is designed to confirm blind vulnerabilities (SSRF, blind RCE,
// blind XXE) without relying on response content or timing side channels.
package oast

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Protocol identifies the transport an interaction arrived on.
type Protocol string

const (
	ProtocolHTTP Protocol = "http"
	ProtocolDNS  Protocol = "dns"
	ProtocolSMTP Protocol = "smtp"
)

// String returns the wire name of the protocol.
func (p Protocol) String() string { return string(p) }

// CollectorKind selects how interactions are retrieved from the OAST backend.
type CollectorKind string

const (
	// CollectorAuto picks Interactsh when the server host looks like an
	// Interactsh deployment and a generic HTTP listener otherwise.
	CollectorAuto CollectorKind = "auto"
	// CollectorInteractsh talks the stock Interactsh register/poll protocol
	// (RSA-OAEP protected AES key, AES-CFB encrypted event payloads).
	CollectorInteractsh CollectorKind = "interactsh"
	// CollectorListener talks to a custom listener that exposes JSON
	// interactions over HTTP.
	CollectorListener CollectorKind = "listener"
)

// Config configures a Client.
type Config struct {
	// ServerURL is the base URL of the interaction collector, for example
	// https://oast.pro, https://interactsh.example.net or http://127.0.0.1:9000.
	ServerURL string
	// Domain is the callback domain (or host:port) appended to every token,
	// for example "oast.pro" or "127.0.0.1:9000". Required.
	Domain string
	// Scheme is used when building callback URLs. Defaults to "http".
	Scheme string
	// TokenLength is the number of random base32 characters per token.
	// Defaults to 20 and is clamped to [8, 52].
	TokenLength int
	// PollInterval is the delay between collector polls while waiting for a
	// callback. Defaults to 2s.
	PollInterval time.Duration
	// Timeout bounds every collector HTTP request. Defaults to 10s.
	Timeout time.Duration
	// Collector selects the backend protocol. Defaults to CollectorAuto.
	Collector CollectorKind
	// HTTPClient optionally overrides the HTTP client used for collector calls.
	HTTPClient *http.Client
	// Now optionally overrides the clock (used by tests).
	Now func() time.Time
	// Rand optionally overrides the entropy source (used by tests).
	Rand io.Reader
}

// Registration binds a unique OAST token to the request that used it.
type Registration struct {
	// Token is the unique, non-guessable label embedded in the callback host.
	Token string
	// Host is Token + "." + Domain, the hostname handed to the target.
	Host string
	// URL is the full HTTP callback URL handed to the target.
	URL string
	// Module is the detector that generated the payload (ssrf, cmdi, xxe...).
	Module string
	// Target is the URL under test.
	Target string
	// Parameter is the vulnerable parameter or header that carried the payload.
	Parameter string
	// Payload is the exact injected value (may contain the callback URL).
	Payload string
	// CreatedAt is when the registration was created.
	CreatedAt time.Time
}

// Interaction is a single out-of-band callback observed by the collector.
type Interaction struct {
	Protocol      Protocol
	Token         string
	FullID        string
	RemoteAddress string
	RawRequest    string
	RawResponse   string
	Timestamp     time.Time
}

// Match groups the interactions received for one registration.
type Match struct {
	Registration Registration
	Interactions []Interaction
}

// collector is the transport-specific half of the engine.
type collector interface {
	Register(ctx context.Context) error
	Poll(ctx context.Context) ([]Interaction, error)
	Close(ctx context.Context) error
}

// Client generates OAST payloads and correlates callbacks with registrations.
// It is safe for concurrent use.
type Client struct {
	cfg        Config
	httpClient *http.Client
	collector  collector
	now        func() time.Time
	rnd        io.Reader

	mu      sync.Mutex
	regs    map[string]Registration
	order   []string
	pending map[string][]Interaction
	seen    map[string]struct{}
	closed  bool
}

// ErrTokenNotFound is returned when a token was never registered.
var ErrTokenNotFound = errors.New("oast: token not registered")

// New validates cfg, builds the collector backend and performs the initial
// registration handshake.
func New(cfg Config) (*Client, error) {
	cfg.ServerURL = strings.TrimSpace(cfg.ServerURL)
	cfg.Domain = strings.TrimSpace(cfg.Domain)
	cfg.Domain = strings.TrimPrefix(cfg.Domain, ".")
	cfg.Domain = strings.TrimSuffix(cfg.Domain, "/")

	if cfg.Domain == "" {
		return nil, errors.New("oast: callback domain is required")
	}
	if cfg.ServerURL == "" {
		return nil, errors.New("oast: collector server URL is required")
	}
	if _, err := url.Parse(cfg.ServerURL); err != nil {
		return nil, fmt.Errorf("oast: invalid collector URL: %w", err)
	}

	if cfg.Scheme == "" {
		cfg.Scheme = "http"
	}
	cfg.Scheme = strings.ToLower(cfg.Scheme)
	if cfg.Scheme != "http" && cfg.Scheme != "https" {
		return nil, fmt.Errorf("oast: invalid callback scheme %q", cfg.Scheme)
	}
	if cfg.TokenLength == 0 {
		cfg.TokenLength = 20
	}
	if cfg.TokenLength < 8 {
		cfg.TokenLength = 8
	}
	if cfg.TokenLength > 52 {
		cfg.TokenLength = 52
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 2 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Collector == "" {
		cfg.Collector = CollectorAuto
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	rnd := cfg.Rand
	if rnd == nil {
		rnd = rand.Reader
	}

	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				MaxIdleConns:        20,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     60 * time.Second,
				ForceAttemptHTTP2:   true,
			},
		}
	}

	c := &Client{
		cfg:        cfg,
		httpClient: hc,
		now:        now,
		rnd:        rnd,
		regs:       make(map[string]Registration),
		pending:    make(map[string][]Interaction),
		seen:       make(map[string]struct{}),
	}

	kind := cfg.Collector
	if kind == CollectorAuto {
		kind = CollectorListener
		if looksLikeInteractsh(cfg.ServerURL) {
			kind = CollectorInteractsh
		}
	}

	switch kind {
	case CollectorInteractsh:
		c.collector = newInteractshCollector(cfg.ServerURL, hc, rnd)
	case CollectorListener:
		c.collector = newListenerCollector(cfg.ServerURL, cfg.Domain, hc)
	default:
		return nil, fmt.Errorf("oast: unknown collector kind %q", cfg.Collector)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	if err := c.collector.Register(ctx); err != nil {
		return nil, err
	}

	return c, nil
}

// looksLikeInteractsh reports whether a collector base URL most likely points
// at a stock Interactsh server.
func looksLikeInteractsh(serverURL string) bool {
	u, err := url.Parse(serverURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return strings.Contains(host, "interactsh") ||
		strings.Contains(host, "oast.") ||
		strings.Contains(host, "oast-") ||
		strings.HasPrefix(host, "oast")
}

// Domain returns the configured callback domain.
func (c *Client) Domain() string { return c.cfg.Domain }

// ServerURL returns the configured collector base URL.
func (c *Client) ServerURL() string { return c.cfg.ServerURL }

// Generate creates a fresh token, registers it and returns it fully qualified.
// The Token field of reg is ignored and always replaced.
func (c *Client) Generate(reg Registration) (Registration, error) {
	if c == nil {
		return Registration{}, errors.New("oast: nil client")
	}

	token, err := c.newToken()
	if err != nil {
		return Registration{}, err
	}

	reg.Token = token
	reg.Host = token + "." + c.cfg.Domain
	reg.URL = c.cfg.Scheme + "://" + reg.Host + "/"
	reg.CreatedAt = c.now()

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return Registration{}, errors.New("oast: client is closed")
	}
	if _, exists := c.regs[token]; exists {
		c.mu.Unlock()
		return Registration{}, fmt.Errorf("oast: duplicate token %q", token)
	}
	c.regs[token] = reg
	c.order = append(c.order, token)
	c.mu.Unlock()

	return reg, nil
}

// newToken produces a lowercase base32 token of the configured length.
func (c *Client) newToken() (string, error) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	buf := make([]byte, (c.cfg.TokenLength*5+7)/8)
	if _, err := io.ReadFull(c.rnd, buf); err != nil {
		return "", fmt.Errorf("oast: entropy failure: %w", err)
	}
	token := strings.ToLower(enc.EncodeToString(buf))
	if len(token) > c.cfg.TokenLength {
		token = token[:c.cfg.TokenLength]
	}
	// Base32 never emits digits beyond [2-7] or vowels issues, but strip
	// anything that could break a DNS label to be safe.
	token = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, token)
	if token == "" {
		return "", errors.New("oast: generated an empty token")
	}
	return token, nil
}

// Registrations returns a snapshot of every registration, oldest first.
func (c *Client) Registrations() []Registration {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]Registration, 0, len(c.order))
	for _, token := range c.order {
		out = append(out, c.regs[token])
	}
	return out
}

// Registration looks up a token.
func (c *Client) Registration(token string) (Registration, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	reg, ok := c.regs[token]
	if !ok {
		return Registration{}, ErrTokenNotFound
	}
	return reg, nil
}

// collect fetches interactions from the backend, deduplicates them and stores
// them per token. It never drains the pending buffers.
func (c *Client) collect(ctx context.Context) error {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return errors.New("oast: client is closed")
	}

	interactions, err := c.collector.Poll(ctx)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, in := range interactions {
		in.Token = strings.ToLower(strings.TrimSpace(in.Token))
		if in.Token == "" {
			continue
		}
		if _, known := c.regs[in.Token]; !known {
			continue
		}
		key := in.key()
		if _, dup := c.seen[key]; dup {
			continue
		}
		c.seen[key] = struct{}{}
		c.pending[in.Token] = append(c.pending[in.Token], in)
	}

	return nil
}

// Poll retrieves interactions once and drains every buffered match.
func (c *Client) Poll(ctx context.Context) ([]Match, error) {
	if err := c.collect(ctx); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var matches []Match
	for _, token := range c.order {
		items := c.pending[token]
		if len(items) == 0 {
			continue
		}
		delete(c.pending, token)
		matches = append(matches, Match{
			Registration: c.regs[token],
			Interactions: items,
		})
	}
	return matches, nil
}

// WaitFor blocks until the given token receives at least one interaction or
// the timeout elapses. Previously buffered interactions are returned
// immediately. The boolean reports whether a callback was observed.
func (c *Client) WaitFor(ctx context.Context, token string, timeout time.Duration) ([]Interaction, bool) {
	matches := c.wait(ctx, []string{token}, timeout)
	if len(matches) == 0 {
		return nil, false
	}
	return matches[0].Interactions, true
}

// WaitAny blocks until at least one of the given tokens receives an
// interaction or the timeout elapses. All buffered matches for the supplied
// tokens are returned. Tokens owned by other callers are left untouched.
func (c *Client) WaitAny(ctx context.Context, tokens []string, timeout time.Duration) []Match {
	return c.wait(ctx, tokens, timeout)
}

func (c *Client) wait(ctx context.Context, tokens []string, timeout time.Duration) []Match {
	if c == nil || len(tokens) == 0 {
		return nil
	}
	if timeout <= 0 {
		timeout = c.cfg.PollInterval
	}
	deadline := c.now().Add(timeout)

	for {
		if matches := c.take(tokens); len(matches) > 0 {
			return matches
		}

		remaining := deadline.Sub(c.now())
		if remaining <= 0 {
			return nil
		}
		wait := c.cfg.PollInterval
		if wait > remaining {
			wait = remaining
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}

		// A poll error is not fatal: collectors are frequently unavailable
		// for a short window, but a later poll may still deliver the hit.
		_ = c.collect(ctx)

		if c.now().After(deadline) {
			return c.take(tokens)
		}
	}
}

// take drains buffered interactions for the requested tokens only.
func (c *Client) take(tokens []string) []Match {
	want := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		want[strings.ToLower(strings.TrimSpace(token))] = struct{}{}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var matches []Match
	for _, token := range c.order {
		if _, ok := want[token]; !ok {
			continue
		}
		items := c.pending[token]
		if len(items) == 0 {
			continue
		}
		delete(c.pending, token)
		matches = append(matches, Match{
			Registration: c.regs[token],
			Interactions: items,
		})
	}
	return matches
}

// Close releases collector resources (deregistering from Interactsh when
// possible). It is idempotent.
func (c *Client) Close(ctx context.Context) error {
	if c == nil {
		return nil
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), c.cfg.Timeout)
		defer cancel()
	}
	return c.collector.Close(ctx)
}

// key returns a stable deduplication key for an interaction.
func (i Interaction) key() string {
	return strings.Join([]string{
		string(i.Protocol),
		i.Token,
		i.FullID,
		i.RemoteAddress,
		fmt.Sprintf("%d", i.Timestamp.UnixNano()),
		i.RawRequest,
		i.RawResponse,
	}, "|")
}

// sortInteractions orders interactions oldest first for stable reporting.
func sortInteractions(items []Interaction) {
	sort.Slice(items, func(i, j int) bool {
		return items[i].Timestamp.Before(items[j].Timestamp)
	})
}

// normalizeProtocol folds collector-specific protocol spellings.
func normalizeProtocol(raw string) Protocol {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "dns", "dns-interaction":
		return ProtocolDNS
	case "smtp", "smtp-interaction", "mail":
		return ProtocolSMTP
	default:
		return ProtocolHTTP
	}
}

// interactionEnvelope is the flexible JSON shape accepted from custom listeners.
type interactionEnvelope struct {
	Protocol      string      `json:"protocol"`
	UniqueID      string      `json:"unique-id"`
	Token         string      `json:"token"`
	FullID        string      `json:"full-id"`
	RemoteAddress string      `json:"remote-address"`
	RawRequest    string      `json:"raw-request"`
	RawResponse   string      `json:"raw-response"`
	Timestamp     interface{} `json:"timestamp"`
}

// toInteraction converts a listener event into an Interaction.
func (e interactionEnvelope) toInteraction() Interaction {
	token := strings.ToLower(strings.TrimSpace(e.UniqueID))
	if token == "" {
		token = strings.ToLower(strings.TrimSpace(e.Token))
	}
	if token == "" && e.FullID != "" {
		token = strings.ToLower(strings.SplitN(e.FullID, ".", 2)[0])
	}

	return Interaction{
		Protocol:      normalizeProtocol(e.Protocol),
		Token:         token,
		FullID:        e.FullID,
		RemoteAddress: e.RemoteAddress,
		RawRequest:    e.RawRequest,
		RawResponse:   e.RawResponse,
		Timestamp:     parseTimestamp(e.Timestamp),
	}
}

// parseTimestamp accepts unix seconds, unix milliseconds, RFC3339 strings and
// JSON numbers.
func parseTimestamp(raw interface{}) time.Time {
	switch v := raw.(type) {
	case nil:
		return time.Now().UTC()
	case string:
		v = strings.TrimSpace(v)
		if v == "" {
			return time.Now().UTC()
		}
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
			if ts, err := time.Parse(layout, v); err == nil {
				return ts.UTC()
			}
		}
		if f, err := parseFloat(v); err == nil {
			return unixToTime(f)
		}
	case float64:
		return unixToTime(v)
	case json.Number:
		if f, err := v.Float64(); err == nil {
			return unixToTime(f)
		}
	}
	return time.Now().UTC()
}

func unixToTime(f float64) time.Time {
	if f > 1e12 { // milliseconds
		return time.UnixMilli(int64(f)).UTC()
	}
	return time.Unix(int64(f), 0).UTC()
}

func parseFloat(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return f, err
}

// ClientIP extracts the remote host from a RemoteAddress of the form host:port.
func ClientIP(remoteAddress string) string {
	if host, _, err := net.SplitHostPort(remoteAddress); err == nil {
		return host
	}
	return remoteAddress
}
