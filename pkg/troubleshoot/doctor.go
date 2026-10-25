package troubleshoot

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

type CheckResult struct {
	Name    string
	Passed  bool
	Message string
	Fix     string
}

// Doctor performs environment, target connectivity, and proxy troubleshooting.
type Doctor struct {
	TargetURL    string
	ProxyURL     string
	WordlistPath string
	Timeout      time.Duration
}

func NewDoctor(targetURL, proxyURL, wordlistPath string) *Doctor {
	return &Doctor{
		TargetURL:    targetURL,
		ProxyURL:     proxyURL,
		WordlistPath: wordlistPath,
		Timeout:      5 * time.Second,
	}
}

func (d *Doctor) RunAll() []CheckResult {
	var checks []CheckResult

	// 1. System info
	checks = append(checks, CheckResult{
		Name:    "System Runtime",
		Passed:  true,
		Message: fmt.Sprintf("%s/%s (Go %s, %d CPUs)", runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU()),
	})

	// 2. Proxy Check (if specified, or test default 127.0.0.1:8080)
	if d.ProxyURL != "" {
		checks = append(checks, d.checkProxy(d.ProxyURL))
	} else {
		// Test if Burp is running locally
		if isPortOpen("127.0.0.1:8080") {
			checks = append(checks, CheckResult{
				Name:    "Burp Suite (127.0.0.1:8080)",
				Passed:  true,
				Message: "Detected active Burp Suite proxy on port 8080 (hint: use -p http://127.0.0.1:8080)",
			})
		}
	}

	// 3. Wordlist Check
	if d.WordlistPath != "" {
		checks = append(checks, d.checkWordlist(d.WordlistPath))
	}

	// 4. Target connectivity checks
	if d.TargetURL != "" {
		u, err := url.Parse(d.TargetURL)
		if err != nil {
			checks = append(checks, CheckResult{
				Name:    "URL Parsing",
				Passed:  false,
				Message: fmt.Sprintf("Malformed URL: %v", err),
				Fix:     "Check syntax, must include scheme (e.g. http://10.129.x.x)",
			})
			return checks
		}

		host := u.Hostname()
		port := u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}

		// DNS resolution
		checks = append(checks, d.checkDNS(host))

		// TCP Socket connection
		addr := net.JoinHostPort(host, port)
		checks = append(checks, d.checkTCP(addr))

		// HTTP latency and response
		checks = append(checks, d.checkHTTP(d.TargetURL))

		// TLS check if HTTPS
		if u.Scheme == "https" {
			checks = append(checks, d.checkTLS(host, port))
		}
	}

	return checks
}

func (d *Doctor) checkProxy(proxyStr string) CheckResult {
	pURL, err := url.Parse(proxyStr)
	if err != nil {
		return CheckResult{
			Name:    "Proxy Configuration",
			Passed:  false,
			Message: fmt.Sprintf("Invalid proxy format: %v", err),
			Fix:     "Specify proxy as http://127.0.0.1:8080",
		}
	}

	conn, err := net.DialTimeout("tcp", pURL.Host, d.Timeout)
	if err != nil {
		return CheckResult{
			Name:    "Proxy Reachability",
			Passed:  false,
			Message: fmt.Sprintf("Proxy at %s is not reachable (%v)", pURL.Host, err),
			Fix:     "Ensure Burp Suite / Caido is open and proxy listener is running on that port.",
		}
	}
	conn.Close()

	return CheckResult{
		Name:    "Proxy Reachability",
		Passed:  true,
		Message: fmt.Sprintf("Successfully connected to proxy at %s", pURL.Host),
	}
}

func (d *Doctor) checkWordlist(path string) CheckResult {
	info, err := os.Stat(path)
	if err != nil {
		return CheckResult{
			Name:    "Wordlist File",
			Passed:  false,
			Message: fmt.Sprintf("Cannot access %s: %v", path, err),
			Fix:     "Verify file path or download SecLists via --download-wordlists",
		}
	}
	return CheckResult{
		Name:    "Wordlist File",
		Passed:  true,
		Message: fmt.Sprintf("Wordlist found: %s (%.1f KB)", path, float64(info.Size())/1024),
	}
}

func (d *Doctor) checkDNS(host string) CheckResult {
	// If it's already an IP address, skip DNS
	if net.ParseIP(host) != nil {
		return CheckResult{
			Name:    "Host Address",
			Passed:  true,
			Message: fmt.Sprintf("Direct IP target: %s", host),
		}
	}

	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return CheckResult{
			Name:    "DNS Resolution",
			Passed:  false,
			Message: fmt.Sprintf("Could not resolve hostname '%s': %v", host, err),
			Fix:     "Add target to /etc/hosts (e.g. '10.129.x.x target.lab')",
		}
	}

	var ipStrs []string
	for _, ip := range ips {
		ipStrs = append(ipStrs, ip.String())
	}
	return CheckResult{
		Name:    "DNS Resolution",
		Passed:  true,
		Message: fmt.Sprintf("Resolved '%s' -> %s", host, strings.Join(ipStrs, ", ")),
	}
}

func (d *Doctor) checkTCP(addr string) CheckResult {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, d.Timeout)
	if err != nil {
		return CheckResult{
			Name:    "TCP Handshake",
			Passed:  false,
			Message: fmt.Sprintf("Connection refused/timed out to %s (%v)", addr, err),
			Fix:     "Check if port is open (nmap), VPN is active, or firewall is blocking traffic.",
		}
	}
	rtt := time.Since(start)
	conn.Close()

	return CheckResult{
		Name:    "TCP Handshake",
		Passed:  true,
		Message: fmt.Sprintf("Connected to %s in %v", addr, rtt.Round(time.Millisecond)),
	}
}

func (d *Doctor) checkHTTP(rawURL string) CheckResult {
	client := &http.Client{
		Timeout: d.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	start := time.Now()
	resp, err := client.Get(rawURL)
	if err != nil {
		return CheckResult{
			Name:    "HTTP Responsiveness",
			Passed:  false,
			Message: fmt.Sprintf("HTTP GET failed: %v", err),
			Fix:     "Verify target web service is running and not hanging.",
		}
	}
	defer resp.Body.Close()
	latency := time.Since(start)

	msg := fmt.Sprintf("HTTP %d (%s) in %v", resp.StatusCode, resp.Status, latency.Round(time.Millisecond))
	if latency > 1500*time.Millisecond {
		msg += " [WARN: High latency, consider using --threads 10]"
	}

	return CheckResult{
		Name:    "HTTP Responsiveness",
		Passed:  true,
		Message: msg,
	}
}

func (d *Doctor) checkTLS(host, port string) CheckResult {
	addr := net.JoinHostPort(host, port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: d.Timeout}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return CheckResult{
			Name:    "TLS / SSL Handshake",
			Passed:  false,
			Message: fmt.Sprintf("TLS handshake failed: %v", err),
			Fix:     "Target might be plaintext HTTP or uses unsupported cipher suites.",
		}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	return CheckResult{
		Name:    "TLS / SSL Handshake",
		Passed:  true,
		Message: fmt.Sprintf("TLS Version: 0x%04x, Cipher: 0x%04x", state.Version, state.CipherSuite),
	}
}

func isPortOpen(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func PrintDoctorReport(checks []CheckResult) int {
	fmt.Printf("\n\033[1;36mNightfallLX Diagnostics & Troubleshooting\033[0m\n")
	fmt.Printf("%-24s  %-8s  %s\n", "Component", "Status", "Details")
	fmt.Printf("%s  %s  %s\n", strings.Repeat("-", 24), strings.Repeat("-", 8), strings.Repeat("-", 40))

	hasErrors := false
	for _, c := range checks {
		status := "\033[32m[PASS]\033[0m"
		if !c.Passed {
			status = "\033[31m[FAIL]\033[0m"
			hasErrors = true
		}
		fmt.Printf("%-24s  %-8s  %s\n", c.Name, status, c.Message)
		if !c.Passed && c.Fix != "" {
			fmt.Printf("   \033[33m-> Recommended Fix: %s\033[0m\n", c.Fix)
		}
	}
	fmt.Println()

	if hasErrors {
		fmt.Printf("\033[1;31m[!] Diagnostics detected issues that may prevent successful scanning.\033[0m\n\n")
		return 1
	}

	fmt.Printf("\033[1;32m[✓] All diagnostics passed! Environment and target are ready.\033[0m\n\n")
	return 0
}
