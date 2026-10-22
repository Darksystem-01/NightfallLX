package modules

import (
	"encoding/json"
	"fmt"
	"nightfalllx/pkg/client"
	"strings"
)

type ProtoPollutionModule struct{}

func NewProtoPollutionModule() *ProtoPollutionModule {
	return &ProtoPollutionModule{}
}

func (m *ProtoPollutionModule) Name() string {
	return "protopollution"
}

func (m *ProtoPollutionModule) Description() string {
	return "Prototype Pollution injection detector for Node.js/JavaScript backends"
}

var protoPayloads = []struct {
	Name    string
	Payload string
	Marker  string
}{
	{
		Name:    "Direct __proto__ pollution",
		Payload: `{"__proto__":{"nflx":"polluted"}}`,
		Marker:  `"nflx":"polluted"`,
	},
	{
		Name:    "Constructor prototype pollution",
		Payload: `{"constructor":{"prototype":{"nflx":"polluted"}}}`,
		Marker:  `"nflx":"polluted"`,
	},
}

func (m *ProtoPollutionModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	method := strings.ToUpper(target.Method)
	if method != "POST" && method != "PUT" && method != "PATCH" && !target.IsJSON {
		return nil, nil
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	// 1. Establish baseline
	baseResp, _ := c.Request("GET", target.URL, "", nil)

	for _, probe := range protoPayloads {
		var reqBody string
		if target.IsJSON && target.RawJSON != "" {
			// Merge prototype pollution object into JSON root
			var rawMap map[string]interface{}
			if err := json.Unmarshal([]byte(target.RawJSON), &rawMap); err == nil {
				var probeMap map[string]interface{}
				_ = json.Unmarshal([]byte(probe.Payload), &probeMap)
				for k, v := range probeMap {
					rawMap[k] = v
				}
				merged, _ := json.Marshal(rawMap)
				reqBody = string(merged)
			}
		}
		if reqBody == "" {
			reqBody = probe.Payload
		}

		resp, err := c.Request("POST", target.URL, reqBody, headers)
		if err != nil || resp == nil {
			continue
		}

		// Check response to injection
		markerReflected := strings.Contains(resp.Body, probe.Marker) || strings.Contains(resp.Body, "polluted")

		// 2. Follow-up verification request
		followUpResp, _ := c.Request("GET", target.URL, "", nil)
		followUpReflected := false
		if followUpResp != nil {
			if strings.Contains(followUpResp.Body, probe.Marker) || strings.Contains(followUpResp.Body, "polluted") {
				// Ensure marker was not in original baseline
				if baseResp == nil || (!strings.Contains(baseResp.Body, probe.Marker) && !strings.Contains(baseResp.Body, "polluted")) {
					followUpReflected = true
				}
			}
		}

		if followUpReflected || markerReflected {
			f := &Finding{
				Module:      m.Name(),
				Title:       "Server-Side Prototype Pollution (Marker Confirmed)",
				Severity:    SeverityCritical,
				URL:         target.URL,
				Parameter:   "(JSON Body)",
				Payload:     probe.Payload,
				Detail:      fmt.Sprintf("Injected %s into JSON body; pollution marker was confirmed reflected in application output.", probe.Name),
				Evidence:    fmt.Sprintf("Found '%s' reflected in response or follow-up GET request.", probe.Marker),
				Remediation: "Freeze Object.prototype (Object.freeze(Object.prototype)), use Map objects, or validate against __proto__ and constructor properties.",
				CWEID:       1321,
			}
			f.SetConfidence(ConfidenceConfirmed)
			findings = append(findings, f)
			break
		} else if resp.StatusCode == 200 || resp.StatusCode == 201 {
			// Status OK without confirming reflection -> mark as possible
			f := &Finding{
				Module:      m.Name(),
				Title:       "Potential Prototype Pollution (Accepted Payload)",
				Severity:    SeverityMedium,
				URL:         target.URL,
				Parameter:   "(JSON Body)",
				Payload:     probe.Payload,
				Detail:      fmt.Sprintf("Server accepted prototype pollution payload '%s' with HTTP %d, but subsequent reflection was not confirmed.", probe.Name, resp.StatusCode),
				Evidence:    fmt.Sprintf("HTTP %d received for payload %s", resp.StatusCode, probe.Payload),
				Remediation: "Sanitize JSON keys against __proto__ and constructor.prototype.",
				CWEID:       1321,
			}
			f.SetConfidence(ConfidencePossible)
			findings = append(findings, f)
			break
		}
	}

	return findings, nil
}
