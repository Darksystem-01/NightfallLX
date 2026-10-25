package oast

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// interactshCollector implements the stock Interactsh register/poll protocol.
//
// Handshake:
//   - POST /register {"public-key": PEM, "secret": ..., "correlation-id": ...}
//   - GET  /poll?id=<correlation-id>&secret=<secret>
//   - POST /deregister {"correlation-id": ..., "secret": ...}
//
// The poll response protects event payloads with an RSA-OAEP(SHA-256) wrapped
// AES key; each event is AES-CFB encrypted with a per-response IV prefix.
type interactshCollector struct {
	base    string
	http    *http.Client
	priv    *rsa.PrivateKey
	corrID  string
	secret  string
}

func newInteractshCollector(serverURL string, hc *http.Client, rnd io.Reader) *interactshCollector {
	priv, err := rsa.GenerateKey(rnd, 2048)
	if err != nil {
		// A deterministic fallback keeps the constructor infallible; if key
		// generation fails the registration step reports the failure.
		priv = nil
	}

	return &interactshCollector{
		base:    strings.TrimRight(serverURL, "/"),
		http:    hc,
		priv:    priv,
		corrID: randomHex(rnd, 20),
		secret: randomHex(rnd, 32),
	}
}

func (c *interactshCollector) Register(ctx context.Context) error {
	if c.priv == nil {
		return errors.New("oast: interactsh RSA key generation failed")
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&c.priv.PublicKey)
	if err != nil {
		return fmt.Errorf("oast: marshal interactsh public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	payload := map[string]string{
		"public-key":     string(pubPEM),
		"secret":         c.secret,
		"correlation-id": c.corrID,
	}

	resp, err := c.postJSON(ctx, c.base+"/register", payload)
	if err != nil {
		return fmt.Errorf("oast: interactsh registration failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oast: interactsh registration rejected: %s", resp.Status)
	}
	return nil
}

func (c *interactshCollector) Poll(ctx context.Context) ([]Interaction, error) {
	q := url.Values{}
	q.Set("id", c.corrID)
	q.Set("secret", c.secret)

	endpoint := c.base + "/poll?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("oast: interactsh poll request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "NightfallLX/1.0 (+https://github.com/Darksystem-01/NightfallLX)")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oast: interactsh poll failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("oast: read interactsh poll: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oast: interactsh poll rejected: %s", resp.Status)
	}

	var pollResp struct {
		Data    []string `json:"data"`
		AESKey  string   `json:"aes_key"`
		TLDData []string `json:"tlddata"`
		Message string   `json:"message"`
		Error   bool     `json:"error"`
	}
	if err := json.Unmarshal(body, &pollResp); err != nil {
		return nil, fmt.Errorf("oast: decode interactsh poll: %w", err)
	}
	if pollResp.Error {
		return nil, fmt.Errorf("oast: interactsh poll error: %s", pollResp.Message)
	}
	if len(pollResp.Data) == 0 {
		return nil, nil
	}

	key, err := c.unwrapAESKey(pollResp.AESKey)
	if err != nil {
		return nil, err
	}

	decrypted := make([]string, 0, len(pollResp.TLDData)+len(pollResp.Data))
	decrypted = append(decrypted, pollResp.TLDData...)
	decrypted = append(decrypted, pollResp.Data...)

	events := make([]Interaction, 0, len(decrypted))
	for _, item := range decrypted {
		plain, err := decryptCFB(key, strings.TrimSpace(item))
		if err != nil {
			// One corrupt record must not discard the whole batch.
			continue
		}
		events = append(events, parseInteractshEvent(plain)...)
	}
	return events, nil
}

func (c *interactshCollector) Close(ctx context.Context) error {
	if c.priv == nil {
		return nil
	}
	payload := map[string]string{
		"correlation-id": c.corrID,
		"secret":         c.secret,
	}
	resp, err := c.postJSON(ctx, c.base+"/deregister", payload)
	if err != nil {
		return nil // best effort
	}
	defer resp.Body.Close()
	return nil
}

// unwrapAESKey decrypts the RSA-OAEP protected AES key from a poll response.
func (c *interactshCollector) unwrapAESKey(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, errors.New("oast: interactsh poll is missing the aes key")
	}
	wrapped, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("oast: decode interactsh aes key: %w", err)
	}
	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.priv, wrapped, nil)
	if err != nil {
		return nil, fmt.Errorf("oast: decrypt interactsh aes key: %w", err)
	}
	return key, nil
}

// decryptCFB decrypts a base64 payload shaped as iv || AES-CFB ciphertext.
func decryptCFB(key []byte, encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("oast: decode interactsh payload: %w", err)
	}
	if len(raw) < aes.BlockSize {
		return nil, errors.New("oast: interactsh payload shorter than IV")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("oast: init interactsh cipher: %w", err)
	}

	iv, ciphertext := raw[:aes.BlockSize], raw[aes.BlockSize:]
	plain := make([]byte, len(ciphertext))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(plain, ciphertext)
	return plain, nil
}

// interactshEvent is the decrypted event document.
type interactshEvent struct {
	Protocol      string `json:"protocol"`
	UniqueID      string `json:"unique-id"`
	FullID        string `json:"full-id"`
	RemoteAddress string `json:"remote-address"`
	RawRequest    string `json:"raw-request"`
	RawResponse   string `json:"raw-response"`
	Timestamp     string `json:"timestamp"`
}

// parseInteractshEvent accepts either a single event object or a JSON array of
// events, which some Interactsh versions return inside one record.
func parseInteractshEvent(plain []byte) []Interaction {
	plain = bytes.TrimSpace(plain)
	if len(plain) == 0 {
		return nil
	}

	var single interactshEvent
	if err := json.Unmarshal(plain, &single); err == nil && single.UniqueID != "" {
		return []Interaction{single.toInteraction()}
	}

	var batch []interactshEvent
	if err := json.Unmarshal(plain, &batch); err == nil {
		out := make([]Interaction, 0, len(batch))
		for _, ev := range batch {
			if ev.UniqueID == "" {
				continue
			}
			out = append(out, ev.toInteraction())
		}
		return out
	}
	return nil
}

func (e interactshEvent) toInteraction() Interaction {
	return Interaction{
		Protocol:      normalizeProtocol(e.Protocol),
		Token:         strings.ToLower(e.UniqueID),
		FullID:        e.FullID,
		RemoteAddress: e.RemoteAddress,
		RawRequest:    e.RawRequest,
		RawResponse:   e.RawResponse,
		Timestamp:     parseTimestamp(e.Timestamp),
	}
}

func (c *interactshCollector) postJSON(ctx context.Context, endpoint string, payload any) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "NightfallLX/1.0 (+https://github.com/Darksystem-01/NightfallLX)")
	return c.http.Do(req)
}

// randomHex returns n random bytes hex encoded. When the entropy source fails
// it degrades to a timestamp-derived value to keep the engine usable.
func randomHex(rnd io.Reader, n int) string {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rnd, buf); err != nil {
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))[:n*2]
	}
	return hex.EncodeToString(buf)
}
