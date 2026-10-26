package nuclei_engine

import (
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/modules"
	"strings"
	"sync"
)

// TemplateResult models findings from a template execution.
type TemplateResult struct {
	TemplateID      string            `json:"template_id"`
	TemplateName    string            `json:"template_name"`
	Severity        string            `json:"severity"`
	Matched         bool              `json:"matched"`
	URL             string            `json:"url"`
	MatchedAt       string            `json:"matched_at"`
	ExtractedValues map[string]string `json:"extracted_values,omitempty"`
	CurlCommand     string            `json:"curl_command"`
}

// Executor coordinates running Nuclei templates.
type Executor struct {
	Client    *client.Client
	Templates []*NucleiTemplate
}

// NewExecutor creates a template runner.
func NewExecutor(c *client.Client, templates []*NucleiTemplate) *Executor {
	return &Executor{
		Client:    c,
		Templates: templates,
	}
}

// ExecuteTemplate runs a single template against a target URL.
func (e *Executor) ExecuteTemplate(tmpl *NucleiTemplate, targetURL string) (*TemplateResult, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	baseURL := strings.TrimRight(targetURL, "/")
	rootURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	hostname := u.Hostname()

	for _, reqDef := range tmpl.HTTP {
		method := reqDef.Method
		if method == "" {
			method = "GET"
		}

		paths := reqDef.Path
		if len(paths) == 0 {
			paths = []string{""}
		}

		for _, pathTmpl := range paths {
			resolvedPath := strings.ReplaceAll(pathTmpl, "{{BaseURL}}", baseURL)
			resolvedPath = strings.ReplaceAll(resolvedPath, "{{RootURL}}", rootURL)
			resolvedPath = strings.ReplaceAll(resolvedPath, "{{Hostname}}", hostname)

			if !strings.HasPrefix(resolvedPath, "http://") && !strings.HasPrefix(resolvedPath, "https://") {
				if strings.HasPrefix(resolvedPath, "/") {
					resolvedPath = rootURL + resolvedPath
				} else {
					resolvedPath = baseURL + "/" + resolvedPath
				}
			}

			body := strings.ReplaceAll(reqDef.Body, "{{BaseURL}}", baseURL)
			body = strings.ReplaceAll(body, "{{RootURL}}", rootURL)
			body = strings.ReplaceAll(body, "{{Hostname}}", hostname)

			resp, err := e.Client.Request(method, resolvedPath, body, reqDef.Headers)
			if err != nil || resp == nil {
				continue
			}

			// Evaluate matchers
			matchersCond := strings.ToLower(reqDef.MatchersCondition)
			if matchersCond == "" {
				matchersCond = "or"
			}

			allMatched := (len(reqDef.Matchers) > 0)
			anyMatched := false

			for _, m := range reqDef.Matchers {
				matched := EvaluateMatcher(&m, resp)
				if matched {
					anyMatched = true
				} else {
					allMatched = false
				}
			}

			isMatch := false
			if matchersCond == "and" && allMatched {
				isMatch = true
			} else if matchersCond == "or" && anyMatched {
				isMatch = true
			}

			if isMatch {
				curlCmd := fmt.Sprintf("curl -i -s -k -X %s '%s'", method, resolvedPath)
				if body != "" {
					curlCmd += fmt.Sprintf(" -d '%s'", body)
				}
				for k, v := range reqDef.Headers {
					curlCmd += fmt.Sprintf(" -H '%s: %s'", k, v)
				}

				return &TemplateResult{
					TemplateID:   tmpl.ID,
					TemplateName: tmpl.Info.Name,
					Severity:     strings.ToUpper(tmpl.Info.Severity),
					Matched:      true,
					URL:          targetURL,
					MatchedAt:    resolvedPath,
					CurlCommand:  curlCmd,
				}, nil
			}
		}
	}

	return nil, nil
}

// ToFinding converts a TemplateResult to standard modules.Finding.
func (tr *TemplateResult) ToFinding() *modules.Finding {
	var sev modules.Severity
	switch tr.Severity {
	case "CRITICAL":
		sev = modules.SeverityCritical
	case "HIGH":
		sev = modules.SeverityHigh
	case "MEDIUM":
		sev = modules.SeverityMedium
	case "LOW":
		sev = modules.SeverityLow
	default:
		sev = modules.SeverityInfo
	}

	return &modules.Finding{
		Module:      "nuclei",
		Title:       fmt.Sprintf("[%s] %s", tr.TemplateID, tr.TemplateName),
		Severity:    sev,
		Confidence:  95,
		URL:         tr.MatchedAt,
		Parameter:   "template",
		Payload:     tr.TemplateID,
		Detail:      fmt.Sprintf("Nuclei rule '%s' matched against target endpoint.", tr.TemplateID),
		Evidence:    fmt.Sprintf("Reproduce via: %s", tr.CurlCommand),
		Remediation: "Review official CVE / advisory documentation for this template ID.",
		CWEID:       200,
		CVSS:        7.0,
	}
}

// ExecuteParallel runs templates concurrently using a worker pool.
func (e *Executor) ExecuteParallel(tmpls []*NucleiTemplate, targetURL string, concurrency int, onMatch func(*TemplateResult)) []*TemplateResult {
	if concurrency <= 0 {
		concurrency = 20
	}
	if concurrency > len(tmpls) {
		concurrency = len(tmpls)
	}

	jobs := make(chan *NucleiTemplate, len(tmpls))
	for _, t := range tmpls {
		jobs <- t
	}
	close(jobs)

	var (
		mu      sync.Mutex
		results []*TemplateResult
		wg      sync.WaitGroup
	)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for tmpl := range jobs {
				res, err := e.ExecuteTemplate(tmpl, targetURL)
				if err == nil && res != nil && res.Matched {
					mu.Lock()
					results = append(results, res)
					mu.Unlock()
					if onMatch != nil {
						onMatch(res)
					}
				}
			}
		}()
	}

	wg.Wait()
	return results
}
