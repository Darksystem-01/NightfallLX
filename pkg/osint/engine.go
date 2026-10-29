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

	// Task 5: Exploit-DB GHDB & DorkSearch Generation
	var ghdbDorks []GoogleDork
	if cfg.IncludeDorks {
		ghdbDorks = GenerateDorks(cleanDomain)
	}

	wg.Wait()

	finalReport := &OSINTReport{
		Domain:             cleanDomain,
		SensitiveEndpoints: waybackURLs,
		SecurityTxt:        secTxt,
		GoogleDorks:        ghdbDorks,
		Duration:           time.Since(start),
	}

	if dnsRep != nil {
		finalReport.TargetIPs = dnsRep.TargetIPs
		finalReport.CloudProvider = dnsRep.CloudProvider
		finalReport.NameServers = dnsRep.NameServers
		finalReport.MailServers = dnsRep.MailServers
		finalReport.SOARecord = dnsRep.SOARecord
		finalReport.TXTRecords = dnsRep.TXTRecords
		finalReport.SPFRecord = dnsRep.SPFRecord
		finalReport.DMARCRecord = dnsRep.DMARCRecord
		finalReport.DMARCStatus = dnsRep.DMARCStatus
		finalReport.Findings = append(finalReport.Findings, dnsRep.Findings...)

		if finalReport.SOARecord != nil && finalReport.SOARecord.AdminEmail != "" {
			adminEmail := finalReport.SOARecord.AdminEmail
			finalReport.Emails = append([]string{adminEmail + " (SOA Hostmaster)"}, finalReport.Emails...)
		}

		// Task 1b: Passive Team Cymru ASN & BGP Network Range Discovery
		if cfg.CheckASN && len(dnsRep.TargetIPs) > 0 {
			if asnRec, err := LookupASN(dnsRep.TargetIPs[0], 3*time.Second); err == nil && asnRec != nil {
				finalReport.ASNInfo = fmt.Sprintf("%s (%s, %s)", asnRec.ASN, asnRec.OrgName, asnRec.Country)
				if asnRec.CIDR != "" {
					finalReport.CIDRRanges = append(finalReport.CIDRRanges, asnRec.CIDR)
				}
			}
		}

		// Task 1c: DNS Zone Transfer (AXFR) Audit
		if cfg.CheckAXFR && len(dnsRep.NameServers) > 0 {
			isVuln, vulnNS, records := TestAXFR(cleanDomain, dnsRep.NameServers, 3*time.Second)
			if isVuln {
				finalReport.AXFRResults = records
				finalReport.Findings = append(finalReport.Findings, OSINTFinding{
					Title:       fmt.Sprintf("Critical DNS Zone Transfer (AXFR) Leak on %s", vulnNS),
					Severity:    "CRITICAL",
					Description: fmt.Sprintf("Name server %s allows unauthenticated AXFR zone transfers, allowing external attackers to dump the entire internal DNS zone for %s.", vulnNS, cleanDomain),
					Evidence:    fmt.Sprintf("Vulnerable NS: %s (Zone transfer accepted)", vulnNS),
					Remediation: "Restrict AXFR zone transfers to authorized secondary nameservers only via TSIG keys or 'allow-transfer' IP restrictions.",
				})
			}
		}
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

	// Task 6: High-Precision Admin Panel & Authentication Portal Hunter
	if cfg.CheckAdmin {
		portals := HuntAdminPortals(cleanDomain, certSubs, waybackURLs, cfg.Timeout)
		finalReport.AdminPortals = portals
		for _, p := range portals {
			if p.StatusCode == 200 && p.HasLoginForm {
				finalReport.Findings = append(finalReport.Findings, OSINTFinding{
					Title:       fmt.Sprintf("Exposed %s with Authentication Interface", p.Type),
					Severity:    "HIGH",
					Description: fmt.Sprintf("Public administrative endpoint %s was discovered exposing an active authentication interface (%s).", p.URL, p.Title),
					Evidence:    fmt.Sprintf("URL: %s, Status: %d, Title: %s", p.URL, p.StatusCode, p.Title),
					Remediation: "Enforce strict IP allowlisting, VPN access, and multi-factor authentication (MFA) on administrative portals.",
				})
			}
		}
	}

	// Task 7: Corporate Email Intelligence & Pattern Hunter
	if cfg.CheckEmails {
		dossier := HarvestEmails(cleanDomain, waybackURLs, secTxt, 3*time.Second)
		finalReport.Emails = dossier.Emails
		finalReport.EmailPattern = dossier.Pattern
	}

	// Task 8: Automated DNS Enumeration Intelligence (dnsenum)
	if cfg.CheckDNSEnum {
		dnsRes, err := RunDNSEnum(DNSEnumConfig{
			Domain:     cleanDomain,
			Wordlist:   cfg.DNSEnumWordlist,
			Threads:    15,
			TimeoutSec: 5,
			NoReverse:  true,
		})
		if err == nil && dnsRes != nil {
			finalReport.DNSEnum = dnsRes
			if finalReport.SOARecord == nil {
				finalReport.SOARecord = dnsRes.SOARecord
			}
			if len(finalReport.TXTRecords) == 0 {
				finalReport.TXTRecords = dnsRes.TXTRecords
			}
			if len(finalReport.MailServers) == 0 && len(dnsRes.MailServers) > 0 {
				for _, mx := range dnsRes.MailServers {
					valStr := ""
					if mx.Value != "" {
						valStr = " -> " + mx.Value
					}
					finalReport.MailServers = append(finalReport.MailServers, fmt.Sprintf("%s [%s]%s", mx.Host, mx.Type, valStr))
				}
			}
			if dnsRes.SOARecord != nil && dnsRes.SOARecord.AdminEmail != "" {
				adminEmail := dnsRes.SOARecord.AdminEmail
				found := false
				for _, e := range finalReport.Emails {
					if strings.Contains(e, adminEmail) {
						found = true
						break
					}
				}
				if !found {
					finalReport.Emails = append([]string{adminEmail + " (SOA Hostmaster)"}, finalReport.Emails...)
				}
			}
			for _, s := range dnsRes.Subdomains {
				alreadyExists := false
				for _, existing := range finalReport.Subdomains {
					if strings.EqualFold(existing.Hostname, s.Host) {
						alreadyExists = true
						break
					}
				}
				if !alreadyExists {
					finalReport.Subdomains = append(finalReport.Subdomains, SubdomainResult{
						Hostname: s.Host,
						Source:   "dnsenum",
						IPs:      []string{s.Value},
					})
				}
			}
			for _, netr := range dnsRes.ClassCNetranges {
				found := false
				for _, c := range finalReport.CIDRRanges {
					if c == netr {
						found = true
						break
					}
				}
				if !found {
					finalReport.CIDRRanges = append(finalReport.CIDRRanges, netr)
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
	if rep.ASNInfo != "" {
		fmt.Printf("    ├── ASN / BGP Info  : \033[1;35m%s\033[0m\n", rep.ASNInfo)
	}
	if len(rep.CIDRRanges) > 0 {
		fmt.Printf("    ├── Network CIDR    : \033[1;33m%s\033[0m\n", strings.Join(rep.CIDRRanges, ", "))
	}
	if len(rep.TargetIPs) > 0 {
		fmt.Printf("    ├── Resolved IPs    : %s\n", strings.Join(rep.TargetIPs, ", "))
	}
	if len(rep.NameServers) > 0 {
		fmt.Printf("    ├── Name Servers    : %s\n", strings.Join(rep.NameServers, ", "))
	}
	if len(rep.AXFRResults) > 0 {
		fmt.Printf("    ├── \033[1;31mDNS Zone (AXFR) : [VULNERABLE - %d records leaked!]\033[0m\n", len(rep.AXFRResults))
	}
	if rep.SOARecord != nil {
		fmt.Printf("    ├── Primary SOA NS  : \033[1;37m%s\033[0m\n", rep.SOARecord.PrimaryNS)
		if rep.SOARecord.AdminEmail != "" {
			fmt.Printf("    ├── \033[1;33mSOA Hostmaster  : \033[1;32m%s\033[0m (Extracted from SOA)\n", rep.SOARecord.AdminEmail)
		}
	}
	if len(rep.MailServers) > 0 {
		fmt.Printf("    └── Mail Servers    : %s\n", strings.Join(rep.MailServers, ", "))
	}
	fmt.Println()

	// 1b. Automated DNS Enumeration Intelligence
	if rep.DNSEnum != nil {
		fmt.Printf("\033[1;36m[+] DNS Enumeration Intelligence (%s):\033[0m\n", rep.DNSEnum.EngineUsed)
		if len(rep.DNSEnum.HostAddresses) > 0 {
			fmt.Printf("    ├── Host A/AAAA Records : %d resolved\n", len(rep.DNSEnum.HostAddresses))
		}
		if len(rep.DNSEnum.NameServers) > 0 {
			fmt.Printf("    ├── Nameservers Probed  : %d servers\n", len(rep.DNSEnum.NameServers))
		}
		if len(rep.DNSEnum.ZoneTransfers) > 0 {
			for _, z := range rep.DNSEnum.ZoneTransfers {
				if z.Vulnerable {
					fmt.Printf("    ├── \033[1;31m[🔥 AXFR VULNERABLE]\033[0m %s -> Leaked %d zone records!\n", z.Server, len(z.Records))
				}
			}
		}
		if len(rep.DNSEnum.ClassCNetranges) > 0 {
			fmt.Printf("    ├── Class C Netranges   : %s\n", strings.Join(rep.DNSEnum.ClassCNetranges, ", "))
		}
		if len(rep.DNSEnum.Subdomains) > 0 {
			fmt.Printf("    └── Subdomains Bruted   : %d valid subdomains discovered\n", len(rep.DNSEnum.Subdomains))
		}
		fmt.Println()
	}


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

	// 2b. Authoritative TXT Records
	if len(rep.TXTRecords) > 0 {
		fmt.Printf("\033[1;36m[+] Authoritative TXT Records (%d records identified):\033[0m\n", len(rep.TXTRecords))
		for i, txt := range rep.TXTRecords {
			typeLabel := "Verification / Token"
			color := "\033[36m"
			lower := strings.ToLower(txt)
			if strings.HasPrefix(lower, "v=spf1") {
				typeLabel = "SPF Policy"
				color = "\033[32m"
			} else if strings.HasPrefix(lower, "v=dmarc1") {
				typeLabel = "DMARC Policy"
				color = "\033[35m"
			} else if strings.Contains(lower, "google-site-verification") {
				typeLabel = "Google Workspace"
				color = "\033[34m"
			} else if strings.Contains(lower, "ms=") {
				typeLabel = "Microsoft 365"
				color = "\033[34m"
			} else if strings.Contains(lower, "anthropic") {
				typeLabel = "Anthropic Claude"
				color = "\033[35m"
			}
			fmt.Printf("    ├── [%d] %s[%-18s]\033[0m %s\n", i+1, color, typeLabel, txt)
		}
		fmt.Println()
	}

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

	// 5b. Discovered Admin Panels & Login Portals
	if len(rep.AdminPortals) > 0 {
		fmt.Printf("\033[1;31m[🔥] Discovered Admin Panels & Login Portals (%d identified):\033[0m\n", len(rep.AdminPortals))
		for _, p := range rep.AdminPortals {
			statusColor := "\033[1;32m" // 200 OK
			if p.StatusCode == 401 || p.StatusCode == 403 {
				statusColor = "\033[1;35m"
			} else if p.StatusCode >= 300 && p.StatusCode < 400 {
				statusColor = "\033[1;33m"
			}
			loginTag := ""
			if p.HasLoginForm {
				loginTag = " \033[1;31m[AUTH FORM]\033[0m"
			}
			fmt.Printf("    ├── %s[%d]\033[0m \033[1;37m%-24s\033[0m \033[34m%s\033[0m%s\n", statusColor, p.StatusCode, p.Type, p.URL, loginTag)
			if p.Title != "" {
				fmt.Printf("    │   ├── Title   : \033[37m%s\033[0m\n", p.Title)
			}
			if p.RedirectURL != "" {
				fmt.Printf("    │   └── Redirect: \033[33m%s\033[0m\n", p.RedirectURL)
			}
		}
		fmt.Println()
	}

	// 5c. Discovered Corporate Emails & Patterns
	if len(rep.Emails) > 0 {
		fmt.Printf("\033[1;36m[📧] Discovered Corporate Emails (%d identified):\033[0m\n", len(rep.Emails))
		if rep.EmailPattern != "" {
			fmt.Printf("    ├── \033[1;35mCorporate Pattern: \033[1;37m%s\033[0m\n", rep.EmailPattern)
		}
		limit := 6
		if len(rep.Emails) < limit {
			limit = len(rep.Emails)
		}
		for i := 0; i < limit; i++ {
			fmt.Printf("    ├── [%d] \033[33m%s\033[0m\n", i+1, rep.Emails[i])
		}
		if len(rep.Emails) > limit {
			fmt.Printf("    └── ... and %d more corporate addresses.\n", len(rep.Emails)-limit)
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

	// 7. Exploit-DB GHDB & DorkSearch Queries
	if len(rep.GoogleDorks) > 0 {
		fmt.Printf("\033[1;36m[+] Exploit-DB GHDB & DorkSearch Queries (%d intelligence vectors):\033[0m\n", len(rep.GoogleDorks))
		limit := 6
		if len(rep.GoogleDorks) < limit {
			limit = len(rep.GoogleDorks)
		}
		for i := 0; i < limit; i++ {
			d := rep.GoogleDorks[i]
			fmt.Printf("    ├── \033[1;37m%-35s\033[0m [\033[36m%s\033[0m]\n", d.Description, d.GHDBSection)
			fmt.Printf("    │   ├── Query: \033[33m%s\033[0m\n", d.Query)
			fmt.Printf("    │   └── Links: \033[34m[Google]\033[0m %s | \033[32m[DuckDuckGo]\033[0m %s\n", d.GoogleURL, d.DuckDuckGoURL)
		}
		if len(rep.GoogleDorks) > limit {
			fmt.Printf("    └── ... and \033[1m%d\033[0m more specialized GHDB dorks (run with \033[1m-dorks\033[0m for full dossier & HTML dashboard).\n", len(rep.GoogleDorks)-limit)
		}
		fmt.Println()
	}

	fmt.Printf("\033[1m[*] OSINT Scan completed in %v.\033[0m\n\n", rep.Duration.Round(time.Millisecond))
}
