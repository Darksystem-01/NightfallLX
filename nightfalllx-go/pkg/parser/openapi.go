package parser

import (
	"encoding/json"
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"sort"
	"strings"
)

// APIEndpoint represents an endpoint discovered from OpenAPI/Swagger or GraphQL introspection.
type APIEndpoint struct {
	Path       string   `json:"path"`
	Method     string   `json:"method"`
	Summary    string   `json:"summary,omitempty"`
	Parameters []string `json:"parameters,omitempty"`
	Source     string   `json:"source"` // "swagger", "openapi", "graphql"
}

// CommonAPISchemaPaths lists popular OpenAPI/Swagger JSON specifications.
var CommonAPISchemaPaths = []string{
	"/swagger.json",
	"/openapi.json",
	"/v2/api-docs",
	"/v3/api-docs",
	"/api-docs",
	"/swagger/v1/swagger.json",
	"/api/swagger.json",
	"/api/openapi.json",
	"/docs/swagger.json",
	"/doc/swagger.json",
}

// CommonGraphQLPaths lists typical GraphQL endpoint locations.
var CommonGraphQLPaths = []string{
	"/graphql",
	"/api/graphql",
	"/v1/graphql",
	"/gql",
	"/query",
}

// GraphQLIntrospectionQuery is a standard query to retrieve schema types and operations.
const GraphQLIntrospectionQuery = `{"query": "{ __schema { queryType { fields { name args { name } } } mutationType { fields { name args { name } } } } }"}`

// ParseOpenAPISchema parses Swagger 2.0 or OpenAPI 3.0+ JSON specifications.
func ParseOpenAPISchema(data []byte) ([]APIEndpoint, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON specification: %w", err)
	}

	source := "openapi"
	if _, ok := raw["swagger"]; ok {
		source = "swagger"
	}

	basePath := ""
	if bp, ok := raw["basePath"].(string); ok {
		basePath = strings.TrimSuffix(bp, "/")
	}

	pathsObj, ok := raw["paths"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("no 'paths' definition found in specification")
	}

	var endpoints []APIEndpoint
	httpMethods := map[string]bool{
		"get": true, "post": true, "put": true, "delete": true,
		"patch": true, "head": true, "options": true,
	}

	for p, methodsVal := range pathsObj {
		methodsMap, isMap := methodsVal.(map[string]interface{})
		if !isMap {
			continue
		}

		fullPath := basePath + p
		if !strings.HasPrefix(fullPath, "/") {
			fullPath = "/" + fullPath
		}

		// Extract path-level parameters
		var pathParams []string
		if pParams, ok := methodsMap["parameters"].([]interface{}); ok {
			for _, paramVal := range pParams {
				if paramMap, ok := paramVal.(map[string]interface{}); ok {
					if name, ok := paramMap["name"].(string); ok {
						pathParams = append(pathParams, name)
					}
				}
			}
		}

		for method, opVal := range methodsMap {
			lowerMethod := strings.ToLower(method)
			if !httpMethods[lowerMethod] {
				continue
			}

			opMap, ok := opVal.(map[string]interface{})
			if !ok {
				continue
			}

			summary := ""
			if s, ok := opMap["summary"].(string); ok {
				summary = s
			} else if desc, ok := opMap["description"].(string); ok {
				summary = desc
			}

			params := append([]string(nil), pathParams...)
			if opParams, ok := opMap["parameters"].([]interface{}); ok {
				for _, paramVal := range opParams {
					if paramMap, ok := paramVal.(map[string]interface{}); ok {
						if name, ok := paramMap["name"].(string); ok {
							params = append(params, name)
						}
					}
				}
			}

			// In OpenAPI 3.0, check requestBody -> schema -> properties
			if reqBody, ok := opMap["requestBody"].(map[string]interface{}); ok {
				if content, ok := reqBody["content"].(map[string]interface{}); ok {
					for _, mediaVal := range content {
						if mediaMap, ok := mediaVal.(map[string]interface{}); ok {
							if schema, ok := mediaMap["schema"].(map[string]interface{}); ok {
								if props, ok := schema["properties"].(map[string]interface{}); ok {
									for propName := range props {
										params = append(params, propName)
									}
								}
							}
						}
					}
				}
			}

			endpoints = append(endpoints, APIEndpoint{
				Path:       fullPath,
				Method:     strings.ToUpper(lowerMethod),
				Summary:    summary,
				Parameters: uniqueStrings(params),
				Source:     source,
			})
		}
	}

	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Path == endpoints[j].Path {
			return endpoints[i].Method < endpoints[j].Method
		}
		return endpoints[i].Path < endpoints[j].Path
	})

	return endpoints, nil
}

// ParseGraphQLIntrospection parses the result of a GraphQL __schema introspection query.
func ParseGraphQLIntrospection(data []byte) ([]APIEndpoint, error) {
	var resp struct {
		Data struct {
			Schema struct {
				QueryType struct {
					Fields []struct {
						Name string `json:"name"`
						Args []struct {
							Name string `json:"name"`
						} `json:"args"`
					} `json:"fields"`
				} `json:"queryType"`
				MutationType struct {
					Fields []struct {
						Name string `json:"name"`
						Args []struct {
							Name string `json:"name"`
						} `json:"args"`
					} `json:"fields"`
				} `json:"mutationType"`
			} `json:"__schema"`
		} `json:"data"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal GraphQL introspection JSON: %w", err)
	}

	schema := resp.Data.Schema
	var endpoints []APIEndpoint

	// Queries
	for _, f := range schema.QueryType.Fields {
		var args []string
		for _, a := range f.Args {
			args = append(args, a.Name)
		}
		endpoints = append(endpoints, APIEndpoint{
			Path:       "/graphql",
			Method:     "POST",
			Summary:    fmt.Sprintf("Query: %s", f.Name),
			Parameters: args,
			Source:     "graphql",
		})
	}

	// Mutations
	for _, f := range schema.MutationType.Fields {
		var args []string
		for _, a := range f.Args {
			args = append(args, a.Name)
		}
		endpoints = append(endpoints, APIEndpoint{
			Path:       "/graphql",
			Method:     "POST",
			Summary:    fmt.Sprintf("Mutation: %s", f.Name),
			Parameters: args,
			Source:     "graphql",
		})
	}

	return endpoints, nil
}

// DetectAndParseAPISchemas automatically checks common Swagger/OpenAPI and GraphQL endpoints on target host.
func DetectAndParseAPISchemas(baseURL string, c *client.Client) ([]APIEndpoint, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	base := fmt.Sprintf("%s://%s", u.Scheme, u.Host)

	var allEndpoints []APIEndpoint

	// 1. Probe OpenAPI / Swagger JSON schemas
	for _, p := range CommonAPISchemaPaths {
		testURL := base + p
		resp, err := c.Request("GET", testURL, "", nil)
		if err == nil && resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Body, `"paths"`) {
			if eps, err := ParseOpenAPISchema([]byte(resp.Body)); err == nil && len(eps) > 0 {
				allEndpoints = append(allEndpoints, eps...)
				break // Found active API specification
			}
		}
	}

	// 2. Probe GraphQL Introspection
	headers := map[string]string{"Content-Type": "application/json"}
	for _, p := range CommonGraphQLPaths {
		testURL := base + p
		resp, err := c.Request("POST", testURL, GraphQLIntrospectionQuery, headers)
		if err == nil && resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Body, `__schema`) {
			if eps, err := ParseGraphQLIntrospection([]byte(resp.Body)); err == nil && len(eps) > 0 {
				for i := range eps {
					eps[i].Path = p
				}
				allEndpoints = append(allEndpoints, eps...)
				break // Found active GraphQL schema
			}
		}
	}

	return allEndpoints, nil
}

func uniqueStrings(arr []string) []string {
	m := make(map[string]bool)
	var res []string
	for _, s := range arr {
		if !m[s] && s != "" {
			m[s] = true
			res = append(res, s)
		}
	}
	sort.Strings(res)
	return res
}
