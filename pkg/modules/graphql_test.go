package modules

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"strings"
	"testing"
	"time"
)

func TestGraphQLModule_IntrospectionAndHiddenQuery(t *testing.T) {
	// Mock GraphQL Server mimicking app.discover.hard SocialGraph
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		query, _ := body["query"].(string)

		// 1. Probe
		if strings.Contains(query, "__typename") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"__typename":"Query"}}`))
			return
		}

		// 2. Introspection
		if strings.Contains(query, "__schema") {
			w.WriteHeader(http.StatusOK)
			mockSchema := `{
				"data": {
					"__schema": {
						"queryType": {"name": "Query"},
						"mutationType": null,
						"types": [
							{
								"name": "Query",
								"fields": [
									{"name": "me"},
									{"name": "users"},
									{"name": "user"},
									{"name": "flag"}
								]
							},
							{
								"name": "User",
								"fields": [
									{"name": "id"},
									{"name": "username"},
									{"name": "email"},
									{"name": "role"}
								]
							}
						]
					}
				}
			}`
			_, _ = w.Write([]byte(mockSchema))
			return
		}

		// 3. Hidden query: flag
		if strings.Contains(query, "flag") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"flag":"CTF{graphql_introspection_reveals_hidden_gems_9918}"}}`))
			return
		}

		// 4. BOLA / IDOR query: user(id: 1) or user(id: 2)
		if strings.Contains(query, "user(id: 2)") || strings.Contains(query, "user(id: 1)") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"user":{"id":2,"username":"admin","email":"admin@discover.hard","role":"superadmin"}}}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"me":{"id":1,"username":"cyborg"}}}`))
	}))
	defer server.Close()

	c := client.NewClient("", 5*time.Second, false, "", nil)

	// Test RunGraphQLAudit
	rep := RunGraphQLAudit(server.URL, c)

	if rep.Endpoint != server.URL+"/graphql" {
		t.Errorf("Expected endpoint %s/graphql, got %s", server.URL, rep.Endpoint)
	}

	if !rep.IntrospectionOpen {
		t.Errorf("Expected IntrospectionOpen to be true")
	}

	foundFlagFinding := false
	foundIDORFinding := false
	for _, f := range rep.Findings {
		if strings.Contains(f.Title, "Flag") || strings.Contains(f.Evidence, "CTF{") {
			foundFlagFinding = true
		}
		if strings.Contains(f.Title, "IDOR") || strings.Contains(f.Title, "BOLA") {
			foundIDORFinding = true
		}
	}

	if !foundFlagFinding {
		t.Errorf("Expected finding for sensitive flag disclosure from hidden query 'flag'")
	}
	if !foundIDORFinding {
		t.Errorf("Expected finding for GraphQL IDOR/BOLA")
	}

	// Test Module Run
	mod := NewGraphQLModule()
	target := &Target{URL: server.URL, Method: "GET"}
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("Unexpected error from GraphQLModule.Run: %v", err)
	}
	if len(findings) == 0 {
		t.Errorf("Expected findings from GraphQLModule.Run, got 0")
	}
}
