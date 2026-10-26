package modules

import (
	"encoding/json"
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"sort"
	"strings"
	"sync"
	"time"
)

var defaultGraphQLEndpoints = []string{
	"/graphql",
	"/api/graphql",
	"/v1/graphql",
	"/v2/graphql",
	"/query",
	"/api/query",
	"/gql",
	"/graph",
	"/graphql/console",
}

// Full standard GraphQL Introspection query
const fullIntrospectionQuery = `{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind fields { name args { name } } } } }"}`

// Lightweight introspection query for rapid probing
const lightIntrospectionQuery = `{"query":"query { __schema { queryType { name } mutationType { name } types { name } } }"}`

// GraphQLReport holds security analysis and schema intelligence of a target GraphQL instance.
type GraphQLReport struct {
	TargetURL           string         `json:"target_url"`
	Endpoint            string         `json:"endpoint"`
	IntrospectionOpen   bool           `json:"introspection_open"`
	BatchingAllowed     bool           `json:"batching_allowed"`
	GETQueryAllowed     bool           `json:"get_query_allowed"`
	FieldSuggestions    bool           `json:"field_suggestions"`
	QueriesDiscovered   []string       `json:"queries"`
	MutationsDiscovered []string       `json:"mutations"`
	TypesDiscovered     []string       `json:"types"`
	Findings            []Finding      `json:"findings"`
	Duration            time.Duration  `json:"duration"`
}

// RunGraphQLAudit performs a comprehensive security assessment on target GraphQL endpoints.
func RunGraphQLAudit(baseURL string, c *client.Client) *GraphQLReport {
	start := time.Now()

	u, err := url.Parse(baseURL)
	if err != nil {
		return &GraphQLReport{TargetURL: baseURL}
	}

	rootURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	candidateEndpoints := []string{}

	// If user passed a specific endpoint (e.g. /graphql)
	if u.Path != "" && u.Path != "/" {
		candidateEndpoints = append(candidateEndpoints, u.Path)
	}
	for _, ep := range defaultGraphQLEndpoints {
		if u.Path != ep {
			candidateEndpoints = append(candidateEndpoints, ep)
		}
	}

	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}

	var activeEndpoint string
	var initialSchemaData map[string]interface{}

	// 1. Detect Active GraphQL Endpoint
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 6)

	for _, ep := range candidateEndpoints {
		path := ep
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fullURL := rootURL + path
			resp, err := c.Request("POST", fullURL, `{"query":"{__typename}"}`, headers)
			if err != nil || resp == nil || resp.StatusCode >= 400 {
				return
			}

			// Verify if response is valid GraphQL JSON
			var jsonMap map[string]interface{}
			if err := json.Unmarshal([]byte(resp.Body), &jsonMap); err == nil {
				if _, hasData := jsonMap["data"]; hasData || strings.Contains(resp.Body, "__typename") {
					mu.Lock()
					if activeEndpoint == "" {
						activeEndpoint = path
					}
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()

	if activeEndpoint == "" {
		// Fallback check root URL directly
		resp, _ := c.Request("POST", baseURL, `{"query":"{__typename}"}`, headers)
		if resp != nil && (strings.Contains(resp.Body, `"data"`) || strings.Contains(resp.Body, `"errors"`)) {
			activeEndpoint = u.Path
		}
	}

	if activeEndpoint == "" {
		return &GraphQLReport{
			TargetURL: baseURL,
			Duration:  time.Since(start),
		}
	}

	targetEndpointURL := rootURL + activeEndpoint
	report := &GraphQLReport{
		TargetURL: baseURL,
		Endpoint:  targetEndpointURL,
	}

	// 2. Test Introspection Query (__schema)
	introResp, err := c.Request("POST", targetEndpointURL, fullIntrospectionQuery, headers)
	if err == nil && introResp != nil && introResp.StatusCode == 200 {
		var schemaResult map[string]interface{}
		if err := json.Unmarshal([]byte(introResp.Body), &schemaResult); err == nil {
			if data, ok := schemaResult["data"].(map[string]interface{}); ok {
				if schema, ok := data["__schema"].(map[string]interface{}); ok {
					report.IntrospectionOpen = true
					initialSchemaData = schema
					parseSchema(report, schema)
				}
			}
		}
	}

	// If full query failed, attempt lightweight schema query
	if !report.IntrospectionOpen {
		lightResp, err := c.Request("POST", targetEndpointURL, lightIntrospectionQuery, headers)
		if err == nil && lightResp != nil && lightResp.StatusCode == 200 {
			if strings.Contains(lightResp.Body, `"__schema"`) {
				report.IntrospectionOpen = true
			}
		}
	}

	if report.IntrospectionOpen {
		report.Findings = append(report.Findings, Finding{
			Module:      "graphql",
			Title:       "GraphQL Introspection Schema Publicly Exposed",
			Severity:    SeverityHigh,
			Confidence:  100,
			URL:         targetEndpointURL,
			Payload:     fullIntrospectionQuery,
			Detail:      fmt.Sprintf("GraphQL Introspection is enabled on %s. Attacker can dump the entire database schema, internal types, and all available mutations/queries.", targetEndpointURL),
			Evidence:    fmt.Sprintf("Discovered %d queries, %d mutations, %d custom types.", len(report.QueriesDiscovered), len(report.MutationsDiscovered), len(report.TypesDiscovered)),
			Remediation: "Disable GraphQL Introspection in production environments (e.g. Apollo Server: 'introspection: false').",
			CWEID:       200,
			CVSS:        7.5,
		})
	}

	// 3. Test GraphQL Batching Attack (Array of multiple queries in single request)
	batchPayload := `[{"query":"{__typename}"},{"query":"{__typename}"}]`
	batchResp, err := c.Request("POST", targetEndpointURL, batchPayload, headers)
	if err == nil && batchResp != nil && batchResp.StatusCode == 200 {
		var arr []interface{}
		if err := json.Unmarshal([]byte(batchResp.Body), &arr); err == nil && len(arr) >= 2 {
			report.BatchingAllowed = true
			report.Findings = append(report.Findings, Finding{
				Module:      "graphql",
				Title:       "GraphQL Query Batching Enabled (Brute-Force & Denial of Service Vector)",
				Severity:    SeverityMedium,
				Confidence:  95,
				URL:         targetEndpointURL,
				Payload:     batchPayload,
				Detail:      "The GraphQL server executes multiple batched queries sent as a JSON array within a single HTTP request.",
				Evidence:    fmt.Sprintf("Sent 2 batched queries, received %d responses.", len(arr)),
				Remediation: "Disable query batching or enforce strict rate-limiting per operation count rather than HTTP request count.",
				CWEID:       799,
				CVSS:        5.3,
			})
		}
	}

	// 4. Test GET-based GraphQL Queries (CSRF / Cache Poisoning Risk)
	getURL := fmt.Sprintf("%s?query=%s", targetEndpointURL, url.QueryEscape("{__typename}"))
	getResp, err := c.Request("GET", getURL, "", nil)
	if err == nil && getResp != nil && getResp.StatusCode == 200 && strings.Contains(getResp.Body, `"data"`) {
		report.GETQueryAllowed = true
		report.Findings = append(report.Findings, Finding{
			Module:      "graphql",
			Title:       "GraphQL Executable Over HTTP GET Method",
			Severity:    SeverityLow,
			Confidence:  90,
			URL:         getURL,
			Detail:      "GraphQL queries can be executed via HTTP GET query parameters, increasing susceptibility to CSRF and Web Cache Poisoning.",
			Evidence:    "GET request returned 200 OK with valid GraphQL JSON data.",
			Remediation: "Only accept GraphQL mutations and queries via POST requests with application/json Content-Type.",
			CWEID:       352,
			CVSS:        3.7,
		})
	}

	// 5. Test Field Suggestion Information Disclosure
	badQuery := `{"query":"{ nonExistentSecretSecurityField1337 }"}`
	suggestResp, err := c.Request("POST", targetEndpointURL, badQuery, headers)
	if err == nil && suggestResp != nil {
		if strings.Contains(strings.ToLower(suggestResp.Body), "did you mean") {
			report.FieldSuggestions = true
		}
	}

	_ = initialSchemaData
	report.Duration = time.Since(start)
	return report
}

// parseSchema extracts queries, mutations, and types from the introspection result.
func parseSchema(rep *GraphQLReport, schema map[string]interface{}) {
	queryTypeName := "Query"
	mutationTypeName := "Mutation"

	if qt, ok := schema["queryType"].(map[string]interface{}); ok && qt != nil {
		if name, ok := qt["name"].(string); ok && name != "" {
			queryTypeName = name
		}
	}
	if mt, ok := schema["mutationType"].(map[string]interface{}); ok && mt != nil {
		if name, ok := mt["name"].(string); ok && name != "" {
			mutationTypeName = name
		}
	}

	types, ok := schema["types"].([]interface{})
	if !ok {
		return
	}

	for _, t := range types {
		tMap, ok := t.(map[string]interface{})
		if !ok {
			continue
		}
		tName, _ := tMap["name"].(string)
		if strings.HasPrefix(tName, "__") {
			continue // Skip built-in introspection metadata types
		}

		rep.TypesDiscovered = append(rep.TypesDiscovered, tName)

		fields, ok := tMap["fields"].([]interface{})
		if !ok {
			continue
		}

		for _, f := range fields {
			fMap, ok := f.(map[string]interface{})
			if !ok {
				continue
			}
			fName, _ := fMap["name"].(string)

			if tName == queryTypeName {
				rep.QueriesDiscovered = append(rep.QueriesDiscovered, fName)
			} else if tName == mutationTypeName {
				rep.MutationsDiscovered = append(rep.MutationsDiscovered, fName)
			}
		}
	}

	sort.Strings(rep.QueriesDiscovered)
	sort.Strings(rep.MutationsDiscovered)
	sort.Strings(rep.TypesDiscovered)
}

// PrintGraphQLReport prints an interactive, high-impact terminal view of the GraphQL security posture.
func PrintGraphQLReport(rep *GraphQLReport) {
	fmt.Println()
	fmt.Println("\033[1;35m╔══════════════════════════════════════════════════════════════════════════════╗\033[0m")
	fmt.Println("\033[1;35m║   🔮  NightfallLX GraphQL & Modern API Security Auditing Engine              ║\033[0m")
	if rep.Endpoint != "" {
		fmt.Printf("\033[1;35m║   Active Endpoint: \033[1;37m%-56s\033[1;35m ║\033[0m\n", rep.Endpoint)
	} else {
		fmt.Printf("\033[1;35m║   Target Base    : \033[1;37m%-56s\033[1;35m ║\033[0m\n", rep.TargetURL)
	}
	fmt.Println("\033[1;35m╚══════════════════════════════════════════════════════════════════════════════╝\033[0m")
	fmt.Println()

	if rep.Endpoint == "" {
		fmt.Printf("\033[33m[-] No active GraphQL endpoints discovered on %s across standard paths.\033[0m\n", rep.TargetURL)
		fmt.Printf("\033[36m[*] Pro Tip: Use `-spider` to crawl API routes or specify exact path `-u https://target.com/api/graphql`\033[0m\n\n")
		return
	}

	fmt.Printf("\033[1;32m[+] Discovered Active GraphQL Instance:\033[0m \033[1;34m%s\033[0m\n\n", rep.Endpoint)

	// Posture checklist
	introTag := "\033[1;32m[DISABLED (Secure)]\033[0m"
	if rep.IntrospectionOpen {
		introTag = "\033[1;31m[EXPOSED (Vulnerable - CVSS 7.5)]\033[0m"
	}
	batchTag := "\033[1;32m[DISABLED (Secure)]\033[0m"
	if rep.BatchingAllowed {
		batchTag = "\033[1;33m[ENABLED (Rate-limit bypass risk)]\033[0m"
	}
	getTag := "\033[1;32m[DISABLED (POST Only)]\033[0m"
	if rep.GETQueryAllowed {
		getTag = "\033[1;33m[ALLOWED (GET Method Enabled)]\033[0m"
	}
	suggestTag := "\033[1;32m[DISABLED]\033[0m"
	if rep.FieldSuggestions {
		suggestTag = "\033[1;33m[ENABLED (Did-You-Mean Disclosure)]\033[0m"
	}

	fmt.Println("\033[1;36m[●] GraphQL Posture Assessment:\033[0m")
	fmt.Printf("    ├── Introspection Query : %s\n", introTag)
	fmt.Printf("    ├── Query Batching      : %s\n", batchTag)
	fmt.Printf("    ├── HTTP GET Execution  : %s\n", getTag)
	fmt.Printf("    └── Field Suggestions   : %s\n\n", suggestTag)

	if rep.IntrospectionOpen {
		fmt.Printf("\033[1;32m[+] Schema Intelligence Discovered via Introspection:\033[0m\n")
		fmt.Printf("    ├── Queries   : \033[1;33m%d\033[0m queries discovered\n", len(rep.QueriesDiscovered))
		limit := 8
		if len(rep.QueriesDiscovered) < limit {
			limit = len(rep.QueriesDiscovered)
		}
		for i := 0; i < limit; i++ {
			fmt.Printf("    │   ├── query: \033[37m%s\033[0m\n", rep.QueriesDiscovered[i])
		}
		if len(rep.QueriesDiscovered) > limit {
			fmt.Printf("    │   └── ... and %d more queries.\n", len(rep.QueriesDiscovered)-limit)
		}

		fmt.Printf("    ├── Mutations : \033[1;31m%d\033[0m mutations discovered\n", len(rep.MutationsDiscovered))
		limitM := 8
		if len(rep.MutationsDiscovered) < limitM {
			limitM = len(rep.MutationsDiscovered)
		}
		for i := 0; i < limitM; i++ {
			fmt.Printf("    │   ├── mutation: \033[31m%s\033[0m\n", rep.MutationsDiscovered[i])
		}
		if len(rep.MutationsDiscovered) > limitM {
			fmt.Printf("    │   └── ... and %d more mutations.\n", len(rep.MutationsDiscovered)-limitM)
		}

		fmt.Printf("    └── Types     : \033[1;36m%d\033[0m types defined\n\n", len(rep.TypesDiscovered))
	}

	if len(rep.Findings) > 0 {
		fmt.Printf("\033[1;31m[!] Identified %d Security Vulnerabilities on GraphQL Instance:\033[0m\n", len(rep.Findings))
		for _, f := range rep.Findings {
			sevColor := "\033[1;33m"
			if f.Severity == SeverityCritical || f.Severity == SeverityHigh {
				sevColor = "\033[1;31m"
			}
			fmt.Printf("    %s[%-8s]\033[0m \033[1m%s\033[0m\n", sevColor, f.Severity, f.Title)
			fmt.Printf("             Evidence : %s\n", f.Evidence)
			fmt.Printf("             Fix      : %s\n", f.Remediation)
		}
		fmt.Println()
	}

	fmt.Printf("\033[1m[*] GraphQL audit completed in %v.\033[0m\n\n", rep.Duration.Round(time.Millisecond))
}
