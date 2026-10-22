package modules

import (
	"encoding/json"
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"regexp"
	"strings"
)

type GraphQLModule struct{}

func NewGraphQLModule() *GraphQLModule {
	return &GraphQLModule{}
}

func (m *GraphQLModule) Name() string {
	return "graphql"
}

func (m *GraphQLModule) Description() string {
	return "GraphQL Introspection, Schema Exposure, and Query Batching Vulnerability Assessment"
}

var (
	introspectionQuery = `{"query":"query IntrospectionQuery{__schema{queryType{name}types{name kind}}}"}`
	introspectionRegex = regexp.MustCompile(`(?i)"__schema"\s*:\s*\{.*?"types"`)
	typenameQuery      = `{"query":"{__typename}"}`
	batchQuery         = `{"query":"query BatchTest{q1:__typename q2:__typename q3:__typename q4:__typename q5:__typename q6:__typename q7:__typename q8:__typename q9:__typename q10:__typename}"}`
)

func (m *GraphQLModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil, nil
	}
	baseURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)

	candidateURLs := []string{target.URL}
	if !strings.HasSuffix(target.URL, "/graphql") {
		candidateURLs = append(candidateURLs, baseURL+"/graphql", baseURL+"/api/graphql", baseURL+"/v1/graphql")
	}

	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}

	for _, endpoint := range candidateURLs {
		// 1. Confirm GraphQL-specific endpoint shape
		shapeResp, shapeErr := c.Request("POST", endpoint, typenameQuery, headers)
		if shapeErr != nil || shapeResp == nil || shapeResp.StatusCode >= 500 {
			continue
		}

		// Valid GraphQL response must parse as JSON and contain "data" or "errors"
		var shapeMap map[string]interface{}
		if err := json.Unmarshal([]byte(shapeResp.Body), &shapeMap); err != nil {
			continue
		}
		if _, hasData := shapeMap["data"]; !hasData {
			if _, hasErrors := shapeMap["errors"]; !hasErrors {
				continue
			}
		}

		// 2. Introspection Query Test
		introResp, introErr := c.Request("POST", endpoint, introspectionQuery, headers)
		if introErr == nil && introResp != nil && introResp.StatusCode == 200 {
			if introspectionRegex.MatchString(introResp.Body) {
				snippet := introResp.Body
				if len(snippet) > 200 {
					snippet = snippet[:200]
				}
				f := &Finding{
					Module:      m.Name(),
					Title:       "GraphQL Schema Introspection Enabled",
					Severity:    SeverityMedium,
					URL:         endpoint,
					Parameter:   "query",
					Payload:     introspectionQuery,
					Detail:      "GraphQL introspection is globally enabled, permitting complete schema discovery including types, fields, and mutations.",
					Evidence:    snippet,
					Remediation: "Disable GraphQL introspection queries in production environments (e.g. Apollo Server disable Introspection).",
					CWEID:       200,
				}
				f.SetConfidence(ConfidenceConfirmed)
				findings = append(findings, f)
			}
		}

		// 3. Batching Test: 10 aliased queries in one request
		batchResp, batchErr := c.Request("POST", endpoint, batchQuery, headers)
		if batchErr == nil && batchResp != nil && batchResp.StatusCode == 200 {
			var batchMap map[string]interface{}
			if err := json.Unmarshal([]byte(batchResp.Body), &batchMap); err == nil {
				if dataObj, ok := batchMap["data"].(map[string]interface{}); ok {
					allProcessed := true
					for i := 1; i <= 10; i++ {
						aliasKey := fmt.Sprintf("q%d", i)
						if _, exists := dataObj[aliasKey]; !exists {
							allProcessed = false
							break
						}
					}
					if allProcessed {
						f := &Finding{
							Module:      m.Name(),
							Title:       "GraphQL Query Batching Enabled (Rate Limit Bypass Indicator)",
							Severity:    SeverityLow,
							URL:         endpoint,
							Parameter:   "query",
							Payload:     batchQuery,
							Detail:      "Server executed 10 batch-aliased operations within a single HTTP request, indicating lack of query batching limits.",
							Evidence:    "Executed q1 through q10 operations concurrently in single response data object.",
							Remediation: "Implement query batching limits or disable query multiplexing to prevent brute-force attacks.",
							CWEID:       799,
						}
						f.SetConfidence(ConfidencePossible)
						findings = append(findings, f)
					}
				}
			}
		}

		if len(findings) > 0 {
			break
		}
	}

	return findings, nil
}
