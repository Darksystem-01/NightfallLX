package parser

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"nightfalllx/pkg/client"
)

func TestParseOpenAPISchema(t *testing.T) {
	swaggerJSON := `{
		"swagger": "2.0",
		"basePath": "/api/v1",
		"paths": {
			"/users": {
				"get": {
					"summary": "List all users",
					"parameters": [
						{"name": "limit", "in": "query", "type": "integer"},
						{"name": "offset", "in": "query", "type": "integer"}
					]
				},
				"post": {
					"summary": "Create user",
					"parameters": [
						{"name": "body", "in": "body"}
					]
				}
			},
			"/users/{id}": {
				"parameters": [
					{"name": "id", "in": "path"}
				],
				"delete": {
					"summary": "Delete user"
				}
			}
		}
	}`

	endpoints, err := ParseOpenAPISchema([]byte(swaggerJSON))
	if err != nil {
		t.Fatalf("failed to parse Swagger JSON: %v", err)
	}

	if len(endpoints) != 3 {
		t.Fatalf("expected 3 endpoints, got %d", len(endpoints))
	}

	foundGetUsers := false
	for _, ep := range endpoints {
		if ep.Path == "/api/v1/users" && ep.Method == "GET" {
			foundGetUsers = true
			if len(ep.Parameters) != 2 {
				t.Errorf("expected 2 parameters for GET /users, got %d", len(ep.Parameters))
			}
		}
	}

	if !foundGetUsers {
		t.Errorf("expected to find GET /api/v1/users")
	}
}

func TestParseGraphQLIntrospection(t *testing.T) {
	gqlJSON := `{
		"data": {
			"__schema": {
				"queryType": {
					"fields": [
						{
							"name": "getUser",
							"args": [{"name": "id"}]
						},
						{
							"name": "listProducts",
							"args": [{"name": "category"}, {"name": "limit"}]
						}
					]
				},
				"mutationType": {
					"fields": [
						{
							"name": "deleteAccount",
							"args": [{"name": "userId"}, {"name": "token"}]
						}
					]
				}
			}
		}
	}`

	endpoints, err := ParseGraphQLIntrospection([]byte(gqlJSON))
	if err != nil {
		t.Fatalf("failed to parse GraphQL introspection: %v", err)
	}

	if len(endpoints) != 3 {
		t.Fatalf("expected 3 GraphQL operations, got %d", len(endpoints))
	}

	foundQuery := false
	foundMutation := false
	for _, ep := range endpoints {
		if ep.Summary == "Query: getUser" {
			foundQuery = true
		}
		if ep.Summary == "Mutation: deleteAccount" {
			foundMutation = true
		}
	}

	if !foundQuery || !foundMutation {
		t.Errorf("expected both query and mutation to be extracted")
	}
}

func TestDetectAndParseAPISchemas(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/swagger.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"swagger": "2.0",
				"paths": {
					"/api/orders": {
						"get": {"summary": "Orders"}
					}
				}
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c := client.NewClient("", 3*time.Second, true, "", nil)
	endpoints, err := DetectAndParseAPISchemas(server.URL, c)
	if err != nil {
		t.Fatalf("detection failed: %v", err)
	}

	if len(endpoints) == 0 {
		t.Fatalf("expected discovered API endpoints, got 0")
	}
	if endpoints[0].Path != "/api/orders" {
		t.Errorf("expected path '/api/orders', got '%s'", endpoints[0].Path)
	}
}
