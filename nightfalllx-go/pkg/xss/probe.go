package xss

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"nightfalllx/pkg/client"
	"strings"
)

// ProbeCharacters defines the core special characters tested for filter survival.
const ProbeCharacters = `<>"'` + "`" + `/();={}`

// ProbeResult records which special characters survived reflection unescaped.
type ProbeResult struct {
	Canary         string        `json:"canary"`
	SurvivingChars map[rune]bool `json:"surviving_chars"`
	Reflections    []*Reflection `json:"reflections"`
	Blocked        bool          `json:"blocked"`
	StatusCode     int           `json:"status_code"`
}

// RandomToken generates a short alphanumeric token for markers and canaries.
func RandomToken(prefix string, length int) string {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)[:length]
}

// BuildProbePayload generates a unique canary-delimited probe string.
func BuildProbePayload(canary string) string {
	return fmt.Sprintf("%s%s%s", canary, ProbeCharacters, canary)
}

// AnalyzeProbeResponse determines which characters in ProbeCharacters survived unescaped.
func AnalyzeProbeResponse(body, canary string) *ProbeResult {
	res := &ProbeResult{
		Canary:         canary,
		SurvivingChars: make(map[rune]bool),
		Reflections:    FindReflections(body, canary),
	}

	if !strings.Contains(body, canary) {
		return res
	}

	// Find the probe window between canaries
	startIdx := strings.Index(body, canary)
	if startIdx != -1 {
		after := body[startIdx+len(canary):]
		endIdx := strings.Index(after, canary)
		var probeWindow string
		if endIdx != -1 {
			probeWindow = after[:endIdx]
		} else {
			probeWindow = after
		}

		for _, ch := range ProbeCharacters {
			if strings.ContainsRune(probeWindow, ch) {
				res.SurvivingChars[ch] = true
			}
		}
	}

	return res
}

// SupportsVector returns true if all characters in requiredChars survive in this reflection.
func (p *ProbeResult) SupportsVector(requiredChars string) bool {
	if p == nil {
		return true // if probing wasn't run, don't filter out
	}
	for _, ch := range requiredChars {
		if !p.SurvivingChars[ch] {
			return false
		}
	}
	return true
}

// SendProbe sends the character probe to the target for the given parameter.
func SendProbe(param string, target *Target, c *client.Client) (*ProbeResult, error) {
	canary := RandomToken("lxpb", 8)
	probeStr := BuildProbePayload(canary)

	var resp *client.Response
	var err error

	if target.IsJSON && target.RawJSON != "" {
		body := strings.ReplaceAll(target.RawJSON, `"`+param+`": ""`, `"`+param+`": "`+probeStr+`"`)
		if body == target.RawJSON {
			body = strings.ReplaceAll(target.RawJSON, param, probeStr)
		}
		headers := copyHeaders(target.Headers)
		headers["Content-Type"] = "application/json"
		resp, err = c.DoCustom("POST", target.URL, headers, body)
	} else if strings.ToUpper(target.Method) == "POST" {
		data := copyParams(target.Data)
		data[param] = probeStr
		resp, err = c.Post(target.URL, data)
	} else {
		reqURL := target.BuildURLWithParam(param, probeStr)
		resp, err = c.Get(reqURL)
	}

	if err != nil {
		return nil, err
	}

	result := AnalyzeProbeResponse(resp.Body, canary)
	result.StatusCode = resp.StatusCode
	if resp.StatusCode == 403 || resp.StatusCode == 400 || resp.StatusCode == 406 {
		result.Blocked = true
	}

	return result, nil
}

func copyParams(m map[string]string) map[string]string {
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

func copyHeaders(m map[string]string) map[string]string {
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}
