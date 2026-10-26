package nuclei_engine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"testing"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func TestNucleiExecution(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/actuator/env" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"profiles":[],"server.port":"8080","spring.datasource.password":"secret"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tmplYAML := `
id: springboot-actuator-env
info:
  name: Spring Boot Actuator Env Exposure
  author: pentester
  severity: high
  tags: spring,exposure
http:
  - method: GET
    path:
      - "{{BaseURL}}/actuator/env"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "profiles"
          - "server.port"
`

	var tmpl NucleiTemplate
	if err := yaml.Unmarshal([]byte(tmplYAML), &tmpl); err != nil {
		t.Fatalf("failed to unmarshal yaml: %v", err)
	}

	c := client.NewClient("", 5*time.Second, false, "", nil)
	exec := NewExecutor(c, []*NucleiTemplate{&tmpl})

	res, err := exec.ExecuteTemplate(&tmpl, server.URL)
	if err != nil {
		t.Fatalf("unexpected execution error: %v", err)
	}

	if res == nil || !res.Matched {
		t.Fatalf("expected template match on %s/actuator/env", server.URL)
	}

	if res.TemplateID != "springboot-actuator-env" {
		t.Errorf("expected id 'springboot-actuator-env', got %s", res.TemplateID)
	}

	finding := res.ToFinding()
	if finding.Module != "nuclei" {
		t.Errorf("expected finding module 'nuclei', got %s", finding.Module)
	}
}

func TestNucleiExecuteParallel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/test-vuln" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `vulnerable-admin-console`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tmplYAML := `
id: admin-console-check
info:
  name: Admin Console Check
  author: pentester
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/test-vuln"
    matchers:
      - type: word
        words:
          - "vulnerable-admin-console"
`
	var tmpl NucleiTemplate
	if err := yaml.Unmarshal([]byte(tmplYAML), &tmpl); err != nil {
		t.Fatalf("failed to unmarshal yaml: %v", err)
	}

	c := client.NewClient("", 5*time.Second, false, "", nil)
	exec := NewExecutor(c, []*NucleiTemplate{&tmpl})

	matchedCount := 0
	results := exec.ExecuteParallel([]*NucleiTemplate{&tmpl, &tmpl}, server.URL, 5, func(res *TemplateResult) {
		matchedCount++
	})

	if len(results) != 2 {
		t.Errorf("expected 2 matches in parallel execution, got %d", len(results))
	}
}

func TestDiscoveryAndTagInference(t *testing.T) {
	bin, err := FindNucleiBinary()
	if err != nil {
		t.Logf("Notice: official nuclei binary not found on this environment: %v", err)
	} else {
		t.Logf("Discovered nuclei binary: %s", bin)
	}

	tmplDir, err := FindTemplatesDir()
	if err != nil {
		t.Logf("Notice: templates directory not found: %v", err)
	} else {
		t.Logf("Discovered templates dir: %s", tmplDir)
	}

	tags := InferTagsFromTech([]string{"Apache 2.4", "PHP 8.1", "WordPress 6.2"})
	if !strings.Contains(tags, "apache") || !strings.Contains(tags, "wordpress") || !strings.Contains(tags, "php") {
		t.Errorf("expected tags to contain apache, wordpress, php; got: %s", tags)
	}
}
