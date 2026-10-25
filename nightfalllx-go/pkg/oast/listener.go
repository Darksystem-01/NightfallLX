package oast

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// listenerCollector talks to a custom OAST listener that exposes plain JSON
// interactions. It is intentionally permissive so that small self-hosted
// receivers, lab sinks and webhook relays can all be used.
//
// Wire contract:
//
//	POST {base}/register   {"domain": "...", "secret": "..."}   (optional)
//	GET  {base}/poll?domain=...&secret=...&id=...
//	200  {"interactions": [ {event}, ... ]}
//	   | [ {event}, ... ]
//	   | {"data": [ "<base64 JSON event>" | {event}, ... ]}
//
// An event uses the Interactsh field names:
//
//	{"protocol":"http","unique-id":"<token>","full-id":"<token>.<domain>",
//	 "remote-address":"1.2.3.4:5678","raw-request":"...","raw-response":"...",
//	 "timestamp":"2026-01-02T15:04:05Z"}
type listenerCollector struct {
	base   string
	domain string
	http   *http.Client
	secret string
}

func newListenerCollector(serverURL, domain string, hc *http.Client) *listenerCollector {
	return &listenerCollector{
		base:   strings.TrimRight(serverURL, "/"),
		domain: domain,
		http:   hc,
		secret: randomHex(rand.Reader, 16),
	}
}

func (c *listenerCollector) Register(ctx context.Context) error {
	payload, err := json.Marshal(map[string]string{
		"domain": c.domain,
		"secret": c.secret,
	})
	if err != nil {
		return fmt.Errorf("oast: encode listener registration: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/register", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("oast: listener registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("oast: listener registration failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

	// A listener may be read-only (no /register endpoint); that is fine as
	// long as polling is available.
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return nil
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("oast: listener registration rejected: %s", resp.Status)
	}
	return nil
}

func (c *listenerCollector) Poll(ctx context.Context) ([]Interaction, error) {
	q := url.Values{}
	q.Set("domain", c.domain)
	q.Set("secret", c.secret)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/poll?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("oast: listener poll request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "NightfallLX/1.0 (+https://github.com/Darksystem-01/NightfallLX)")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oast: listener poll failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("oast: read listener poll: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oast: listener poll rejected: %s", resp.Status)
	}
	return parseListenerBody(body)
}

func (c *listenerCollector) Close(context.Context) error { return nil }

// parseListenerBody accepts the documented listener response shapes.
func parseListenerBody(body []byte) ([]Interaction, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || bytes.Equal(body, []byte("null")) {
		return nil, nil
	}

	// Bare array of events.
	if body[0] == '[' {
		var events []interactionEnvelope
		if err := json.Unmarshal(body, &events); err != nil {
			return nil, fmt.Errorf("oast: decode listener events: %w", err)
		}
		return envelopesToInteractions(events), nil
	}

	var wrapper struct {
		Interactions []interactionEnvelope `json:"interactions"`
		Data         []json.RawMessage     `json:"data"`
		Message      string                `json:"message"`
		Error        bool                  `json:"error"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("oast: decode listener response: %w", err)
	}
	if wrapper.Error {
		return nil, fmt.Errorf("oast: listener error: %s", wrapper.Message)
	}

	out := envelopesToInteractions(wrapper.Interactions)
	for _, raw := range wrapper.Data {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			continue
		}

		var env interactionEnvelope
		if raw[0] == '{' {
			if err := json.Unmarshal(raw, &env); err != nil {
				continue
			}
			out = append(out, env.toInteraction())
			continue
		}

		// Encoded event: base64 JSON.
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		if len(decoded) > 0 && decoded[0] == '{' {
			if err := json.Unmarshal(decoded, &env); err == nil {
				out = append(out, env.toInteraction())
			}
		}
	}
	return out, nil
}

func envelopesToInteractions(events []interactionEnvelope) []Interaction {
	out := make([]Interaction, 0, len(events))
	for _, env := range events {
		if env.UniqueID == "" && env.Token == "" && env.FullID == "" {
			continue
		}
		out = append(out, env.toInteraction())
	}
	return out
}
