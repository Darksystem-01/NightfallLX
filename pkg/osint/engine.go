package osint

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RunOSINT coordinates concurrent passive intelligence gathering on the domain.
func RunOSINT(cfg Config) (*OSINTReport, error) {
	start := time.Now()
	cleanDomain := strings.TrimSpace(strings.ToLower(cfg.Domain))
	cleanDomain = strings.TrimPrefix(cleanDomain, "http://")
	cleanDomain = strings.TrimPrefix(cleanDomain, "https://")
	if idx := strings.Index(cleanDomain, "/"); idx != -1 {
		cleanDomain = cleanDomain[:idx]
	}

	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}

	var wg sync.WaitGroup
	var dnsRep *OSINTReport
	var certSubs []string
	var waybackURLs []string
	var secTxt string

	// Task 1: DNS & SPF/DMARC Security Audit
	wg.Add(1)
	go func() {
		defer wg.Done()
		rep, _ := AuditDNS(cleanDomain, cfg.Timeout)
		dnsRep = rep
	}()

	// Task 2: Certificate Transparency Subdomains (crt.sh)
	wg.Add(1)
	go func() {
		defer wg.Done()
		subs, _ := FetchCertSubdomains(cleanDomain, cfg.Timeout)
		certSubs = subs
	}()

	// Task 3: Wayback Machine Historical URLs
	if cfg.FetchArchive {
		wg.Add(1)
		go func() {
			defer wg.Done()
			urls, _ := FetchWaybackURLs(cleanDomain, cfg.Timeout)
			waybackURLs = urls
		}()
	}

	// Task 4: Security.txt Check
	wg.Add(1)
	go func() {
		defer wg.Done()
		secTxt = checkSecurityTxt(cleanDomain, cfg.Timeout)
	}()

	wg.Wait()

	finalReport := &OSINTReport{
		Domain:             cleanDomain,
		SensitiveEndpoints: waybackURLs,
		SecurityTxt:        secTxt,
		Duration:           time.Since(start),
	}

	if dnsRep != nil {
		finalReport.TargetIPs = dnsRep.TargetIPs
		finalReport.CloudProvider = dnsRep.CloudProvider
		finalReport.NameServers = dnsRep.NameServers
		finalReport.MailServers = dnsRep.MailServers
		finalReport.SPFRecord = dnsRep.SPFRecord
		finalReport.DMARCRecord = dnsRep.DMARCRecord
		finalReport.DMARCStatus = dnsRep.DMARCStatus
		finalReport.Findings = append(finalReport.Findings, dnsRep.Findings...)
	}

	// Subdomain Resolution & Takeover Checks (Parallel)
	if len(certSubs) > 0 {
		var subWg sync.WaitGroup
		subSem := make(chan struct{}, 20)
		subResults := make([]SubdomainResult, len(certSubs))

		for i, sub := range certSubs {
			subWg.Add(1)
			go func(idx int, host string) {
				defer subWg.Done()
				subSem <- struct{}{}
				defer func() { <-subSem }()

				res := SubdomainResult{
					Hostname: host,
					Source:   "Certificate Transparency (crt.sh)",
				}

				// Resolve IP
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if ips, err := net.DefaultResolver.LookupHost(ctx, host); err == nil && len(ips) > 0 {
					res.IPs = ips
				}

				// Check CNAME takeover risk if enabled
				if cfg.CheckTakeover {
					cname, takeoverService := CheckSubdomainTakeover(host)
					res.CNAME = cname
					if takeoverService != "" {
						res.Takeover = takeoverService
					}
				}

				subResults[idx] = res
			}(i, sub)
		}
		subWg.Wait()

		for _, sr := range subResults {
			if sr.Hostname != "" {
				finalReport.Subdomains = append(finalReport.Subdomains, sr)
				if sr.Takeover != "" {
					finalReport.Findings = append(finalReport.Findings, OSINTFinding{
						Title:       fmt.Sprintf("Potential Subdomain Takeover on %s (%s)", sr.Hostname, sr.Takeover),
						Severity:    "HIGH",
						Description: fmt.Sprintf("Subdomain %s has a CNAME pointing to %s (%s) which may be unregistered or abandoned.", sr.Hostname, sr.CNAME, sr.Takeover),
						Evidence:    fmt.Sprintf("CNAME: %s -> %s", sr.Hostname, sr.CNAME),
						Remediation: "Remove or update the stale CNAME DNS record, or claim the resource on the third-party provider.",
					})
				}
			}
		}
	}

	return finalReport, nil
}

func checkSecurityTxt(domain string, timeout time.Duration) string {
	client := &http.Client{Timeout: 4 * time.Second}
	urls := []string{
		fmt.Sprintf("https://%s/.well-known/security.txt", domain),
		fmt.Sprintf("https://%s/security.txt", domain),
	}
	for _, u := range urls {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "NightfallLX-OSINT/2.0")
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			content := string(b)
			if strings.Contains(strings.ToLower(content), "contact:") {
				return strings.TrimSpace(content)
			}
		}
	}
	return ""
}

// PrintOSINTReport renders a high-visibility terminal report.
func PrintOSINTReport(rep *OSINTReport) {
	fmt.Println()
	fmt.Println("\033[1;35m╔══════════════════════════════════════════════════════════════════════════════╗\033[0m")
	fmt.Println("\033[1;35m║              🎯 NightfallLX Deep OSINT Intelligence Report                   ║\033[0m")
	fmt.Printf("\033[1;35m║  Target Domain : \033[1;37m%-58s\033[1;35m ║\033[0m\n", rep.Domain)
	fmt.Println("\033[1;35m╚══════════════════════════════════════════════════════════════════════════════╝\033[0m")
	fmt.Println()

	// 1. Infrastructure Overview
	fmt.Println("\033[1;36m[+] Infrastructure & Network Intelligence:\033[0m")
	fmt.Printf("    ├── Cloud Provider  : \033[1;32m%s\033[0m\n", rep.CloudProvider)
	if len(rep.TargetIPs) > 0 {
		fmt.Printf("    ├── Resolved IPs    : %s\n", strings.Join(rep.TargetIPs, ", "))
	}
	if len(rep.NameServers) > 0 {
		fmt.Printf("    ├── Name Servers    : %s\n", strings.Join(rep.NameServers, ", "))
	}
	if len(rep.MailServers) > 0 {
		fmt.Printf("    └── Mail Servers    : %s\n", strings.Join(rep.MailServers, ", "))
	}
	fmt.Println()

	// 2. Email Spoofing & Security Posture
	fmt.Println("\033[1;36m[+] Email Security Posture (SPF & DMARC):\033[0m")
	spfDisplay := rep.SPFRecord
	if spfDisplay == "" {
		spfDisplay = "\033[1;31m[MISSING] (Vulnerable to forged emails)\033[0m"
	}
	fmt.Printf("    ├── SPF Record      : %s\n", spfDisplay)

	dmarcDisplay := rep.DMARCRecord
	switch rep.DMARCStatus {
	case DMARCMissing:
		dmarcDisplay = "\033[1;31m[MISSING] (High Risk: Allows spoofing & executive impersonation)\033[0m"
	case DMARCWeak:
		dmarcDisplay = fmt.Sprintf("\033[1;33m[WEAK (p=none)] %s\033[0m", rep.DMARCRecord)
	case DMARCSecure:
		dmarcDisplay = fmt.Sprintf("\033[1;32m[SECURE (enforced)] %s\033[0m", rep.DMARCRecord)
	}
	fmt.Printf("    └── DMARC Policy    : %s\n\n", dmarcDisplay)

	// 3. Subdomains Discovered
	fmt.Printf("\033[1;36m[+] Certificate Transparency Subdomains (%d discovered):\033[0m\n", len(rep.Subdomains))
	if len(rep.Subdomains) == 0 {
		fmt.Println("    [-] No public certificate logs recorded.")
	} else {
		limit := 15
		if len(rep.Subdomains) < limit {
			limit = len(rep.Subdomains)
		}
		for i := 0; i < limit; i++ {
			s := rep.Subdomains[i]
			ipStr := ""
			if len(s.IPs) > 0 {
				ipStr = fmt.Sprintf(" [%s]", s.IPs[0])
			}
			takeoverStr := ""
			if s.Takeover != "" {
				takeoverStr = fmt.Sprintf(" \033[1;31m[⚠️ Takeover: %s]\033[0m", s.Takeover)
			}
			fmt.Printf("    ├── \033[1;37m%-35s\033[0m%s%s\n", s.Hostname, ipStr, takeoverStr)
		}
		if len(rep.Subdomains) > limit {
			fmt.Printf("    └── ... and \033[1m%d\033[0m more subdomains.\n", len(rep.Subdomains)-limit)
		}
	}
	fmt.Println()

	// 4. Wayback Machine Sensitive Endpoints
	if len(rep.SensitiveEndpoints) > 0 {
		fmt.Printf("\033[1;36m[+] Archived Sensitive Endpoints & Historical URLs (%d discovered):\033[0m\n", len(rep.SensitiveEndpoints))
		limit := 10
		if len(rep.SensitiveEndpoints) < limit {
			limit = len(rep.SensitiveEndpoints)
		}
		for i := 0; i < limit; i++ {
			fmt.Printf("    ├── \033[33m%s\033[0m\n", rep.SensitiveEndpoints[i])
		}
		if len(rep.SensitiveEndpoints) > limit {
			fmt.Printf("    └── ... and \033[1m%d\033[0m more historical URLs.\n", len(rep.SensitiveEndpoints)-limit)
		}
		fmt.Println()
	}

	// 5. Security.txt
	if rep.SecurityTxt != "" {
		fmt.Println("\033[1;32m[+] Security Contact & Disclosure Policy (security.txt):\033[0m")
		for _, line := range strings.Split(rep.SecurityTxt, "\n") {
			if strings.TrimSpace(line) != "" {
				fmt.Printf("    │ %s\n", line)
			}
		}
		fmt.Println()
	}

	// 6. Security Vulnerabilities & Findings
	if len(rep.Findings) > 0 {
		fmt.Printf("\033[1;31m[!] Passive OSINT Security Findings (%d identified):\033[0m\n", len(rep.Findings))
		for _, f := range rep.Findings {
			sevColor := "\033[1;33m" // Yellow for MEDIUM
			if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
				sevColor = "\033[1;31m" // Red
			}
			fmt.Printf("    %s[%-8s]\033[0m \033[1m%s\033[0m\n", sevColor, f.Severity, f.Title)
			fmt.Printf("             Evidence : %s\n", f.Evidence)
			fmt.Printf("             Fix      : %s\n", f.Remediation)
		}
		fmt.Println()
	}

	fmt.Printf("\033[1m[*] OSINT Scan completed in %v.\033[0m\n\n", rep.Duration.Round(time.Millisecond))
}
