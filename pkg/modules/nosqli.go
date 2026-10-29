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

var mongoErrorRegex = regexp.MustCompile(`(?i)(MongoError|MongoServerError|Can't canonicalize query|Cannot use '\$|unknown operator: \$|BSONObj size|Cast to ObjectId failed)`)

func (m *NoSQLiModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	for _, param := range target.Parameters() {
		origVal := target.Params[param]
		if isPost {
			origVal = target.Data[param]
		}
		if origVal == "" {
			origVal = "1"
		}

		// Fetch baseline
		var baseResp *client.Response
		if isPost {
			baseResp, _ = c.Request("POST", target.URL, target.BuildDataWithParam(param, origVal), nil)
		} else {
			baseResp, _ = c.Request("GET", target.BuildURLWithParam(param, origVal), "", nil)
		}
		if baseResp == nil || baseResp.StatusCode != 200 {
			continue
		}

		// Ensure baseline does not already disclose Mongo errors
		baselineHasMongoError := mongoErrorRegex.MatchString(baseResp.Body)

		// 1. Error-based probe: inject malformed operator
		if !baselineHasMongoError {
			malformedPayload := `{"$where": "this"}`
			var errResp *client.Response
			var err error
			if isPost {
				errResp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, malformedPayload), nil)
			} else {
				errResp, err = c.Request("GET", target.BuildURLWithParam(param, malformedPayload), "", nil)
			}

			if err == nil && errResp != nil && mongoErrorRegex.MatchString(errResp.Body) {
				evidence := mongoErrorRegex.FindString(errResp.Body)
				findings = append(findings, &Finding{
					Module:      m.Name(),
					Title:       "Error-Based NoSQL (MongoDB) Injection",
					Severity:    SeverityHigh,
					Confidence:  100,
					URL:         target.URL,
					Parameter:   param,
					Payload:     malformedPayload,
					Detail:      fmt.Sprintf("Disclosed database engine error via injected NoSQL operator: '%s'", evidence),
					Evidence:    evidence,
					Remediation: "Sanitize user input and prevent passing raw objects into NoSQL query constructors.",
					CWEID:       943,
				})
				continue
			}
		}

		// 2. Differential probe: True vs False condition ($ne vs $eq)
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
			// If True condition succeeds (e.g. 200 OK with data) while False condition fails (e.g. 401/404 or empty)
			simTrue := Similarity(baseResp.Body, trueResp.Body)
			simFalse := Similarity(baseResp.Body, falseResp.Body)
			if trueResp.StatusCode == 200 && simTrue >= 0.85 && (falseResp.StatusCode != 200 || simFalse < 0.65) {
				findings = append(findings, &Finding{
					Module:      m.Name(),
					Title:       "Differential Boolean NoSQL (MongoDB) Injection",
					Severity:    SeverityHigh,
					Confidence:  95,
					URL:         target.URL,
					Parameter:   param,
					Payload:     fmt.Sprintf("%s[$ne]=nflx_nonexistent_9999", param),
					Detail:      fmt.Sprintf("Parameter '%s' evaluated injected NoSQL operator '$ne' differentially (True: %d, False: %d).", param, trueResp.StatusCode, falseResp.StatusCode),
					Evidence:    fmt.Sprintf("True status: %d (bytes: %d) vs False status: %d (bytes: %d)", trueResp.StatusCode, trueResp.Bytes, falseResp.StatusCode, falseResp.Bytes),
					Remediation: "Ensure input parameters are strictly validated as primitive strings rather than objects or query selector hashes.",
					CWEID:       943,
				})
			}
		}
	}

	return findings, nil
}
