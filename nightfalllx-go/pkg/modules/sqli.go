package modules

import (
	"fmt"
	"nightfalllx/pkg/client"
	"strings"
)

type SQLiModule struct{}

func NewSQLiModule() *SQLiModule {
	return &SQLiModule{}
}

func (m *SQLiModule) Name() string {
	return "sqli"
}

func (m *SQLiModule) Description() string {
	return "Differential boolean-based SQL injection detector"
}

var sqliPairs = [][2]string{
	{"%s AND 1=1", "%s AND 1=2"},
	{"%s' AND '1'='1", "%s' AND '1'='2"},
	{"%s' AND 1=1-- -", "%s' AND 1=2-- -"},
	{"%s\" AND \"1\"=\"1", "%s\" AND \"1\"=\"2"},
	{"%s\" AND 1=1-- -", "%s\" AND 1=2-- -"},
	{"%s') AND ('1'='1", "%s') AND ('1'='2"},
	{"%s') AND 1=1-- -", "%s') AND 1=2-- -"},
}

func (m *SQLiModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
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
		var err error
		if isPost {
			baseResp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, origVal), nil)
		} else {
			baseResp, err = c.Request("GET", target.BuildURLWithParam(param, origVal), "", nil)
		}
		if err != nil || baseResp.StatusCode >= 500 {
			continue
		}

		for _, pair := range sqliPairs {
			truePayload := fmt.Sprintf(pair[0], origVal)
			falsePayload := fmt.Sprintf(pair[1], origVal)

			var trueResp, falseResp *client.Response
			if isPost {
				trueResp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, truePayload), nil)
				if err != nil {
					continue
				}
				falseResp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, falsePayload), nil)
				if err != nil {
					continue
				}
			} else {
				trueResp, err = c.Request("GET", target.BuildURLWithParam(param, truePayload), "", nil)
				if err != nil {
					continue
				}
				falseResp, err = c.Request("GET", target.BuildURLWithParam(param, falsePayload), "", nil)
				if err != nil {
					continue
				}
			}

			trueSim := Similarity(baseResp.Body, trueResp.Body)
			falseSim := Similarity(baseResp.Body, falseResp.Body)
			separation := trueSim - falseSim

			if trueSim >= 0.88 && falseSim <= 0.82 && separation >= 0.10 {
				findings = append(findings, &Finding{
					Module:      m.Name(),
					Title:       "SQL Injection (Boolean-based Blind)",
					Severity:    SeverityHigh,
					Confidence:  100,
					URL:         target.URL,
					Parameter:   param,
					Payload:     fmt.Sprintf("%s vs %s", truePayload, falsePayload),
					Detail:      fmt.Sprintf("Boolean differential verified: true similarity=%.3f, false similarity=%.3f, separation=%.3f", trueSim, falseSim, separation),
					Evidence:    fmt.Sprintf("True response bytes: %d, False response bytes: %d", trueResp.Bytes, falseResp.Bytes),
					Remediation: "Use parameterized queries (prepared statements) for all database operations.",
					CWEID:       89,
				})
				break
			}
		}
	}

	return findings, nil
}
