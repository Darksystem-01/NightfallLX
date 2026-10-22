package modules

import (
	"encoding/json"
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"strings"
)

type MassAssignModule struct{}

func NewMassAssignModule() *MassAssignModule {
	return &MassAssignModule{}
}

func (m *MassAssignModule) Name() string {
	return "massassign"
}

func (m *MassAssignModule) Description() string {
	return "Mass Assignment / Over-Posting Privileged Parameter Injection Detector"
}

var privilegedFields = []struct {
	Field    string
	ValStr   string
	ValJSON  interface{}
	Expected string
}{
	{"role", "admin", "admin", `"role":"admin"`},
	{"isAdmin", "true", true, `"isAdmin":true`},
	{"is_admin", "true", true, `"is_admin":true`},
	{"admin", "true", true, `"admin":true`},
	{"verified", "true", true, `"verified":true`},
	{"balance", "99999", 99999, `"balance":99999`},
}

func (m *MassAssignModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	method := strings.ToUpper(target.Method)
	if method != "POST" && method != "PUT" && method != "PATCH" {
		return nil, nil
	}

	for _, priv := range privilegedFields {
		var reqBody string
		headers := map[string]string{}

		if target.IsJSON {
			headers["Content-Type"] = "application/json"
			var rootMap map[string]interface{}
			if target.RawJSON != "" {
				_ = json.Unmarshal([]byte(target.RawJSON), &rootMap)
			}
			if rootMap == nil {
				rootMap = make(map[string]interface{})
			}
			rootMap[priv.Field] = priv.ValJSON
			outBytes, _ := json.Marshal(rootMap)
			reqBody = string(outBytes)
		} else {
			headers["Content-Type"] = "application/x-www-form-urlencoded"
			vals := url.Values{}
			for k, v := range target.Data {
				vals.Set(k, v)
			}
			vals.Set(priv.Field, priv.ValStr)
			reqBody = vals.Encode()
		}

		resp, err := c.Request(method, target.URL, reqBody, headers)
		if err != nil || resp == nil {
			continue
		}

		// 1. Direct response echo check
		echoed := strings.Contains(strings.ToLower(resp.Body), strings.ToLower(priv.Expected)) ||
			strings.Contains(resp.Body, fmt.Sprintf(`"%s":"%s"`, priv.Field, priv.ValStr))

		// 2. Follow-up GET check
		followUpEchoed := false
		followUpResp, _ := c.Request("GET", target.URL, "", nil)
		if followUpResp != nil {
			if strings.Contains(strings.ToLower(followUpResp.Body), strings.ToLower(priv.Expected)) {
				followUpEchoed = true
			}
		}

		if echoed || followUpEchoed {
			f := &Finding{
				Module:      m.Name(),
				Title:       fmt.Sprintf("Mass Assignment / Privileged Parameter Binding (%s)", priv.Field),
				Severity:    SeverityHigh,
				URL:         target.URL,
				Parameter:   priv.Field,
				Payload:     fmt.Sprintf("%s=%s [Test Data]", priv.Field, priv.ValStr),
				Detail:      fmt.Sprintf("Privileged parameter '%s' was accepted and bound into server state (test value: '%s').", priv.Field, priv.ValStr),
				Evidence:    fmt.Sprintf("Matched expected binding in response: %s", priv.Expected),
				Remediation: "Use DTOs (Data Transfer Objects) and strict property allowlists in request models. Never bind HTTP parameters directly to database models.",
				CWEID:       915,
			}
			f.SetConfidence(ConfidenceConfirmed)
			findings = append(findings, f)
			break
		} else if resp.StatusCode == 200 || resp.StatusCode == 201 {
			// Status 200 without echo -> mark as possible
			f := &Finding{
				Module:      m.Name(),
				Title:       fmt.Sprintf("Potential Mass Assignment Parameter Accepted (%s)", priv.Field),
				Severity:    SeverityMedium,
				URL:         target.URL,
				Parameter:   priv.Field,
				Payload:     fmt.Sprintf("%s=%s [Test Data]", priv.Field, priv.ValStr),
				Detail:      fmt.Sprintf("Endpoint accepted privileged field '%s' with HTTP %d, but reflection could not be confirmed.", priv.Field, resp.StatusCode),
				Evidence:    fmt.Sprintf("HTTP %d received for payload containing %s", resp.StatusCode, priv.Field),
				Remediation: "Implement allowlists on bindable entity properties.",
				CWEID:       915,
			}
			f.SetConfidence(ConfidencePossible)
			findings = append(findings, f)
			break
		}
	}

	return findings, nil
}
