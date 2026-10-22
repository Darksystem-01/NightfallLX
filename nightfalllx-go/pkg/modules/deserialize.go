package modules

import (
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"regexp"
	"strings"
)

type DeserializeModule struct{}

func NewDeserializeModule() *DeserializeModule {
	return &DeserializeModule{}
}

func (m *DeserializeModule) Name() string {
	return "deserialize"
}

func (m *DeserializeModule) Description() string {
	return "Insecure Deserialization signature analyzer (Passive detection for Java, PHP, .NET, Python)"
}

type serializeSignature struct {
	Language string
	Regex    *regexp.Regexp
	CWEID    int
	Severity Severity
}

var serializeSignatures = []serializeSignature{
	{
		Language: "Java Object Serialization",
		Regex:    regexp.MustCompile(`(?:rO0AB[A-Za-z0-9+/=]{4,}|aced0005)`),
		CWEID:    502,
		Severity: SeverityHigh,
	},
	{
		Language: "PHP Object Serialization",
		Regex:    regexp.MustCompile(`(?i)(?:O:\d+:"[^"]+":\d+:\{|O%3A\d+%3A%22)`),
		CWEID:    502,
		Severity: SeverityHigh,
	},
	{
		Language: ".NET ViewState Serialization",
		Regex:    regexp.MustCompile(`(?:/wEPDw[A-Za-z0-9+/=]{8,}|/wE[A-Za-z0-9+/=]{8,})`),
		CWEID:    502,
		Severity: SeverityMedium,
	},
	{
		Language: "Python Pickle Serialization",
		Regex:    regexp.MustCompile(`(?:gASV[A-Za-z0-9+/=]{8,}|(?:\\x80\\x0[345]))`),
		CWEID:    502,
		Severity: SeverityHigh,
	},
}

func (m *DeserializeModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	testedLocations := make(map[string]bool)

	checkValue := func(location, value string) {
		if value == "" {
			return
		}
		decodedVal, _ := url.QueryUnescape(value)

		for _, sig := range serializeSignatures {
			locKey := fmt.Sprintf("%s:%s", sig.Language, location)
			if testedLocations[locKey] {
				continue
			}

			if sig.Regex.MatchString(value) || sig.Regex.MatchString(decodedVal) {
				testedLocations[locKey] = true
				matched := sig.Regex.FindString(value)
				if matched == "" {
					matched = sig.Regex.FindString(decodedVal)
				}
				if len(matched) > 60 {
					matched = matched[:60] + "..."
				}

				f := &Finding{
					Module:      m.Name(),
					Title:       fmt.Sprintf("Serialized Object Identified (%s)", sig.Language),
					Severity:    sig.Severity,
					URL:         target.URL,
					Parameter:   location,
					Payload:     matched,
					Detail:      fmt.Sprintf("Detected %s binary/base64 signature in %s. If deserialized without validation, this may lead to remote code execution.", sig.Language, location),
					Evidence:    fmt.Sprintf("Signature pattern matched in %s: %s", location, matched),
					Remediation: "Never deserialize untrusted user input. Use safe data exchange formats such as JSON or Protocol Buffers, or implement cryptographic signing and type-filtering (Look-Ahead ObjectInputStream / ObjectInputFilter).",
					CWEID:       sig.CWEID,
				}
				f.SetConfidence(ConfidenceConfirmed)
				findings = append(findings, f)
			}
		}
	}

	// 1. Check Query Parameters
	for k, v := range target.Params {
		checkValue(fmt.Sprintf("Query Parameter '%s'", k), v)
	}

	// 2. Check Form Data Parameters
	for k, v := range target.Data {
		checkValue(fmt.Sprintf("POST Parameter '%s'", k), v)
	}

	// 3. Check Cookies
	if c.Cookie != "" {
		for _, part := range strings.Split(c.Cookie, ";") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) == 2 {
				checkValue(fmt.Sprintf("Cookie '%s'", kv[0]), kv[1])
			}
		}
	}

	// 4. Check Headers
	for k, v := range target.Headers {
		checkValue(fmt.Sprintf("Header '%s'", k), v)
	}

	// 5. Check Initial Server Response
	resp, err := c.Request("GET", target.URL, "", nil)
	if err == nil && resp != nil {
		for _, cookie := range resp.Headers["Set-Cookie"] {
			checkValue("Response Set-Cookie", cookie)
		}
		// Also inspect body for ViewState
		for _, sig := range serializeSignatures {
			if sig.Language == ".NET ViewState Serialization" && sig.Regex.MatchString(resp.Body) {
				locKey := fmt.Sprintf("%s:Response Body", sig.Language)
				if !testedLocations[locKey] {
					testedLocations[locKey] = true
					matched := sig.Regex.FindString(resp.Body)
					if len(matched) > 60 {
						matched = matched[:60] + "..."
					}
					f := &Finding{
						Module:      m.Name(),
						Title:       ".NET ViewState Identified in Page Body",
						Severity:    SeverityInfo,
						URL:         target.URL,
						Parameter:   "__VIEWSTATE",
						Payload:     matched,
						Detail:      "ASP.NET ViewState was detected in HTML body. Ensure ViewState MAC validation (EnableViewStateMac) is enforced.",
						Evidence:    matched,
						Remediation: "Ensure EnableViewStateMac is set to true and machineKey is securely generated.",
						CWEID:       502,
					}
					f.SetConfidence(ConfidenceConfirmed)
					findings = append(findings, f)
				}
			}
		}
	}

	return findings, nil
}
