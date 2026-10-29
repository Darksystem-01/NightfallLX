package osint

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"nightfalllx/pkg/wordlists"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DNSEnumRecord holds an individual DNS resource record discovered during enumeration.
type DNSEnumRecord struct {
	Host  string `json:"host"`
	TTL   string `json:"ttl,omitempty"`
	Class string `json:"class,omitempty"`
	Type  string `json:"type"` // A, AAAA, CNAME, NS, MX, PTR, TXT
	Value string `json:"value"`
}

// AXFRAttempt records results of a DNS Zone Transfer probe against a specific nameserver.
type AXFRAttempt struct {
	Server      string   `json:"server"`
	Vulnerable  bool     `json:"vulnerable"`
	Status      string   `json:"status"` // "NOTAUTH", "REFUSED", "VULNERABLE", "SUCCESS"
	BindVersion string   `json:"bind_version,omitempty"`
	Records     []string `json:"records,omitempty"`
}

// SOARecord holds parsed Start of Authority parameters for the domain.
type SOARecord struct {
	PrimaryNS  string `json:"primary_ns"`
	AdminEmail string `json:"admin_email"`
	Serial     string `json:"serial"`
	Refresh    string `json:"refresh"`
	Retry      string `json:"retry"`
	Expire     string `json:"expire"`
	MinTTL     string `json:"min_ttl"`
}

// DNSEnumResult aggregates all intelligence discovered via dnsenum / DNS enumeration.
type DNSEnumResult struct {
	Domain          string          `json:"domain"`
	HostAddresses   []DNSEnumRecord `json:"host_addresses"`
	NameServers     []DNSEnumRecord `json:"name_servers"`
	MailServers     []DNSEnumRecord `json:"mail_servers"`
	SOARecord       *SOARecord      `json:"soa_record,omitempty"`
	TXTRecords      []string        `json:"txt_records,omitempty"`
	ZoneTransfers   []AXFRAttempt   `json:"zone_transfers"`
	Subdomains      []DNSEnumRecord `json:"subdomains"`
	ClassCNetranges []string        `json:"class_c_netranges"`
	IPBlocks        []string        `json:"ip_blocks"`
	ReverseLookups  []DNSEnumRecord `json:"reverse_lookups"`
	Duration        time.Duration   `json:"duration"`
	EngineUsed      string          `json:"engine_used"` // "dnsenum binary" or "native go engine"
}

// DNSEnumConfig provides parameters to customize DNS enumeration.
type DNSEnumConfig struct {
	Domain        string
	DNSServer     string // Custom DNS server for queries
	Wordlist      string // Path to subdomain brute-force wordlist
	Threads       int    // Number of threads
	TimeoutSec    int    // TCP/UDP timeout in seconds
	NoReverse     bool   // Skip reverse lookup operations
	Whois         bool   // Perform whois queries on C-class network ranges
	ScrapGoogle   int    // Max subdomains scraped from Google
	PagesGoogle   int    // Google search pages to process
	Subfile       string // Write valid subdomains to this file
	Recursion     bool   // Recursion on subdomains with NS records
	Delay         int    // Delay between WHOIS queries
	ExcludeRegex  string // Exclude PTR records matching regex
	Private       bool   // Show and save private IPs
	LiveOutput    bool   // Stream live formatted output to terminal
}

// RunDNSEnum executes automated DNS enumeration using the installed dnsenum tool or falls back to native Go engine.
func RunDNSEnum(cfg DNSEnumConfig) (*DNSEnumResult, error) {
	start := time.Now()
	cleanDomain := CleanDomain(cfg.Domain)
	if cleanDomain == "" {
		return nil, fmt.Errorf("invalid or empty domain: %s", cfg.Domain)
	}

	result := &DNSEnumResult{
		Domain:          cleanDomain,
		HostAddresses:   make([]DNSEnumRecord, 0),
		NameServers:     make([]DNSEnumRecord, 0),
		MailServers:     make([]DNSEnumRecord, 0),
		ZoneTransfers:   make([]AXFRAttempt, 0),
		Subdomains:      make([]DNSEnumRecord, 0),
		ClassCNetranges: make([]string, 0),
		IPBlocks:        make([]string, 0),
		ReverseLookups:  make([]DNSEnumRecord, 0),
	}

	// Determine best wordlist if none provided
	wordlist := cfg.Wordlist
	if wordlist == "" {
		candidates := []string{
			"/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
			"/usr/share/dnsenum/dns.txt",
		}
		for _, c := range candidates {
			if fi, err := os.Stat(c); err == nil && fi.Size() > 0 {
				wordlist = c
				break
			}
		}
	}

	// Check if dnsenum binary exists in PATH
	dnsenumPath, err := exec.LookPath("dnsenum")
	if err == nil && dnsenumPath != "" {
		result.EngineUsed = fmt.Sprintf("dnsenum v1.3.1 (%s)", dnsenumPath)
		var enrichWg sync.WaitGroup
		enrichWg.Add(1)
		go func() {
			defer enrichWg.Done()
			enrichFullDNSRecords(cleanDomain, result)
		}()

		err = runExternalDNSEnum(dnsenumPath, cleanDomain, wordlist, cfg, result)
		enrichWg.Wait()
		if err == nil {
			result.Duration = time.Since(start)
			result.MailServers = deduplicateRecords(result.MailServers)
			result.Subdomains = deduplicateRecords(result.Subdomains)
			return result, nil
		}
		// If external run had an issue, fallback to native engine below
	}

	// Fallback: High-Performance Native Go DNS Enumeration Engine
	result.EngineUsed = "native Go engine"
	err = runNativeDNSEnum(cleanDomain, wordlist, cfg, result)
	enrichFullDNSRecords(cleanDomain, result)
	result.Duration = time.Since(start)
	return result, err
}

// runExternalDNSEnum executes /usr/bin/dnsenum and parses its output stream
func runExternalDNSEnum(binPath, domain, wordlist string, cfg DNSEnumConfig, res *DNSEnumResult) error {
	args := []string{"--nocolor"}

	if cfg.DNSServer != "" {
		args = append(args, "--dnsserver", cfg.DNSServer)
	}

	threads := cfg.Threads
	if threads <= 0 {
		threads = 15
	}
	args = append(args, "--threads", strconv.Itoa(threads))

	timeout := cfg.TimeoutSec
	if timeout <= 0 {
		timeout = 5
	}
	args = append(args, "-t", strconv.Itoa(timeout))

	if cfg.NoReverse {
		args = append(args, "--noreverse")
	}

	if cfg.Whois {
		args = append(args, "-w")
	}

	if cfg.Delay > 0 {
		args = append(args, "-d", strconv.Itoa(cfg.Delay))
	}

	if cfg.Recursion {
		args = append(args, "-r")
	}

	if cfg.ExcludeRegex != "" {
		args = append(args, "-e", cfg.ExcludeRegex)
	}

	if cfg.Private {
		args = append(args, "--private")
	}

	if cfg.Subfile != "" {
		args = append(args, "--subfile", cfg.Subfile)
	}

	if cfg.ScrapGoogle > 0 {
		args = append(args, "-s", strconv.Itoa(cfg.ScrapGoogle))
		if cfg.PagesGoogle > 0 {
			args = append(args, "-p", strconv.Itoa(cfg.PagesGoogle))
		}
	} else if !cfg.Whois && cfg.ScrapGoogle == 0 {
		// By default avoid blocking on Google captcha scraping unless requested
		args = append(args, "-s", "0")
	}

	if wordlist != "" {
		args = append(args, "-f", wordlist)
	}

	args = append(args, domain)

	cmd := exec.Command(binPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return err
	}

	// Regex for standard DNS record: "host.domain.   3600  IN  A  1.2.3.4"
	dnsRecordRegex := regexp.MustCompile(`^([a-zA-Z0-9\._\-]+)\.?\s+(\d+)?\s*(?:IN)?\s+([A-Z]+)\s+([a-zA-Z0-9\._\:\-]+)`)
	netrangeRegex := regexp.MustCompile(`^\s*([0-9\.]+\/[0-9]+)`)

	currentSection := ""
	scanner := bufio.NewScanner(io.MultiReader(stdout, stderr))

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Parse section headers
		lower := strings.ToLower(trimmed)
		if strings.Contains(lower, "host's addresses:") {
			currentSection = "hosts"
			continue
		} else if strings.Contains(lower, "name servers:") {
			currentSection = "nameservers"
			continue
		} else if strings.Contains(lower, "mail (mx) servers:") {
			currentSection = "mailservers"
			continue
		} else if strings.Contains(lower, "trying zone transfers") {
			currentSection = "zonetransfers"
			continue
		} else if strings.Contains(lower, "brute forcing with") {
			currentSection = "bruteforce"
			continue
		} else if strings.Contains(lower, "class c netranges:") {
			currentSection = "netranges"
			continue
		} else if strings.Contains(lower, "ip blocks:") {
			currentSection = "ipblocks"
			continue
		} else if strings.Contains(lower, "performing reverse lookup") {
			currentSection = "reverse"
			continue
		}

		if trimmed == "" || strings.HasPrefix(trimmed, "____") || strings.HasPrefix(trimmed, "-----") || strings.HasPrefix(trimmed, "dnsenum VERSION") {
			continue
		}

		// Zone transfer line parsing
		if currentSection == "zonetransfers" {
			if strings.Contains(line, "Trying Zone Transfer for") {
				parts := strings.Split(line, " on ")
				ns := ""
				if len(parts) > 1 {
					ns = strings.TrimSpace(parts[1])
					ns = strings.TrimSuffix(ns, "...")
					ns = strings.TrimSuffix(ns, " ...")
					ns = strings.TrimSpace(ns)
				}
				res.ZoneTransfers = append(res.ZoneTransfers, AXFRAttempt{
					Server: ns,
					Status: "Protected (AXFR Query Refused / NOTAUTH)",
				})
			} else if strings.Contains(line, "AXFR record query failed:") || strings.Contains(line, "failed") {
				if len(res.ZoneTransfers) > 0 {
					lastIdx := len(res.ZoneTransfers) - 1
					res.ZoneTransfers[lastIdx].Status = trimmed
					res.ZoneTransfers[lastIdx].Vulnerable = false
				}
			} else if strings.Contains(line, "AXFR record query successful") || strings.Contains(line, "records returned") {
				if len(res.ZoneTransfers) > 0 {
					lastIdx := len(res.ZoneTransfers) - 1
					res.ZoneTransfers[lastIdx].Status = "VULNERABLE (Zone Transferred!)"
					res.ZoneTransfers[lastIdx].Vulnerable = true
				}
			}
			continue
		}

		// Netranges
		if currentSection == "netranges" {
			m := netrangeRegex.FindStringSubmatch(trimmed)
			if len(m) > 1 {
				res.ClassCNetranges = append(res.ClassCNetranges, m[1])
			}
			continue
		}

		// IP Blocks
		if currentSection == "ipblocks" {
			m := netrangeRegex.FindStringSubmatch(trimmed)
			if len(m) > 1 {
				res.IPBlocks = append(res.IPBlocks, m[1])
			}
			continue
		}

		// Resource record matching
		m := dnsRecordRegex.FindStringSubmatch(trimmed)
		if len(m) >= 5 {
			host := strings.TrimSuffix(m[1], ".")
			ttl := m[2]
			recType := m[3]
			val := strings.TrimSuffix(m[4], ".")

			rec := DNSEnumRecord{
				Host:  host,
				TTL:   ttl,
				Type:  recType,
				Value: val,
			}

			switch currentSection {
			case "hosts":
				res.HostAddresses = append(res.HostAddresses, rec)
			case "nameservers":
				res.NameServers = append(res.NameServers, rec)
			case "mailservers":
				res.MailServers = append(res.MailServers, rec)
			case "bruteforce":
				res.Subdomains = append(res.Subdomains, rec)
			case "reverse":
				res.ReverseLookups = append(res.ReverseLookups, rec)
			default:
				if strings.HasSuffix(host, domain) {
					res.Subdomains = append(res.Subdomains, rec)
				}
			}
		}
	}

	_ = cmd.Wait()
	return nil
}

// runNativeDNSEnum performs full multi-threaded Go-based DNS enumeration as a standalone or fallback engine
func runNativeDNSEnum(domain, wordlist string, cfg DNSEnumConfig, res *DNSEnumResult) error {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	if cfg.DNSServer != "" {
		serverAddr := cfg.DNSServer
		if !strings.Contains(serverAddr, ":") {
			serverAddr += ":53"
		}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				return d.DialContext(ctx, "udp", serverAddr)
			},
		}
	}

	var wg sync.WaitGroup

	// 1. Host A / AAAA records
	wg.Add(1)
	go func() {
		defer wg.Done()
		if ips, err := resolver.LookupIP(ctx, "ip", domain); err == nil {
			for _, ip := range ips {
				recType := "A"
				if ip.To4() == nil {
					recType = "AAAA"
				}
				res.HostAddresses = append(res.HostAddresses, DNSEnumRecord{
					Host:  domain,
					Type:  recType,
					Value: ip.String(),
				})
				// Calculate Class C range for IPv4
				if ip4 := ip.To4(); ip4 != nil {
					cRange := fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
					found := false
					for _, r := range res.ClassCNetranges {
						if r == cRange {
							found = true
							break
						}
					}
					if !found {
						res.ClassCNetranges = append(res.ClassCNetranges, cRange)
					}
					res.IPBlocks = append(res.IPBlocks, fmt.Sprintf("%s/32", ip.String()))
				}
			}
		}
	}()

	// 2. Name Servers
	var nsList []string
	wg.Add(1)
	go func() {
		defer wg.Done()
		if nss, err := resolver.LookupNS(ctx, domain); err == nil {
			for _, ns := range nss {
				h := strings.TrimSuffix(ns.Host, ".")
				nsList = append(nsList, h)
				ipVal := ""
				if nsIPs, err := resolver.LookupHost(ctx, h); err == nil && len(nsIPs) > 0 {
					ipVal = nsIPs[0]
				}
				res.NameServers = append(res.NameServers, DNSEnumRecord{
					Host:  h,
					Type:  "NS",
					Value: ipVal,
				})
			}
		}
	}()

	// 3. Mail (MX) Servers
	wg.Add(1)
	go func() {
		defer wg.Done()
		if mxs, err := resolver.LookupMX(ctx, domain); err == nil {
			for _, mx := range mxs {
				h := strings.TrimSuffix(mx.Host, ".")
				ipVal := ""
				if mxIPs, err := resolver.LookupHost(ctx, h); err == nil && len(mxIPs) > 0 {
					ipVal = mxIPs[0]
				}
				res.MailServers = append(res.MailServers, DNSEnumRecord{
					Host:  h,
					Type:  fmt.Sprintf("MX (%d)", mx.Pref),
					Value: ipVal,
				})
			}
		}
	}()

	wg.Wait()

	// 4. Test AXFR Zone Transfer on discovered nameservers
	if len(nsList) > 0 {
		for _, ns := range nsList {
			vuln, _, records := TestAXFR(domain, []string{ns}, 3*time.Second)
			status := "AXFR record query failed: NOTAUTH"
			if vuln {
				status = "VULNERABLE (Zone Transferred!)"
			}
			res.ZoneTransfers = append(res.ZoneTransfers, AXFRAttempt{
				Server:     ns,
				Vulnerable: vuln,
				Status:     status,
				Records:    records,
			})
		}
	}

	// 5. High-Speed Subdomain Brute Force using Wordlist
	var subPrefixes []string
	if wordlist != "" {
		if lines, err := readLines(wordlist, 500); err == nil && len(lines) > 0 {
			subPrefixes = lines
		}
	} else {
		embedded := wordlists.GetWordlist("subdomains", "")
		if len(embedded) > 500 {
			subPrefixes = embedded[:500]
		} else {
			subPrefixes = embedded
		}
	}
	if len(subPrefixes) > 0 {
		res.Subdomains = bruteForceSubdomains(domain, subPrefixes, resolver, cfg.Threads)
	}

	return nil
}

func bruteForceSubdomains(domain string, prefixes []string, resolver *net.Resolver, threads int) []DNSEnumRecord {
	if threads <= 0 {
		threads = 20
	}
	var results []DNSEnumRecord
	var mu sync.Mutex

	jobs := make(chan string, len(prefixes))
	for _, p := range prefixes {
		jobs <- strings.TrimSpace(p)
	}
	close(jobs)

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				if p == "" || strings.HasPrefix(p, "#") {
					continue
				}
				sub := fmt.Sprintf("%s.%s", p, domain)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				ips, err := resolver.LookupHost(ctx, sub)
				cancel()
				if err == nil && len(ips) > 0 {
					mu.Lock()
					results = append(results, DNSEnumRecord{
						Host:  sub,
						Type:  "A",
						Value: ips[0],
					})
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	return results
}

func readLines(path string, maxLines int) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		l := strings.TrimSpace(scanner.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
			if maxLines > 0 && len(lines) >= maxLines {
				break
			}
		}
	}
	return lines, scanner.Err()
}


// LookupSOA queries the Start of Authority record using dig or DNS query
func LookupSOA(domain string, timeout time.Duration) *SOARecord {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dig", "+noall", "+answer", domain, "SOA")
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		for _, l := range strings.Split(string(out), "\n") {
			parts := strings.Fields(l)
			if len(parts) >= 11 && parts[3] == "SOA" {
				adminEmail := parts[5]
				adminEmail = strings.TrimSuffix(adminEmail, ".")
				if idx := strings.Index(adminEmail, "."); idx != -1 {
					adminEmail = adminEmail[:idx] + "@" + adminEmail[idx+1:]
				}
				return &SOARecord{
					PrimaryNS:  strings.TrimSuffix(parts[4], "."),
					AdminEmail: adminEmail,
					Serial:     parts[6],
					Refresh:    parts[7],
					Retry:      parts[8],
					Expire:     parts[9],
					MinTTL:     parts[10],
				}
			}
		}
	}
	return nil
}

// LookupTXTRecords queries all TXT resource records for the domain
func LookupTXTRecords(domain string, timeout time.Duration) []string {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var resolver net.Resolver
	txts, err := resolver.LookupTXT(ctx, domain)
	if err == nil && len(txts) > 0 {
		return txts
	}

	cmd := exec.CommandContext(ctx, "dig", "+noall", "+answer", domain, "TXT")
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		var res []string
		for _, l := range strings.Split(string(out), "\n") {
			l = strings.TrimSpace(l)
			if l == "" {
				continue
			}
			if idx := strings.Index(l, "TXT"); idx != -1 {
				val := strings.TrimSpace(l[idx+3:])
				val = strings.Trim(val, "\"")
				if val != "" {
					res = append(res, val)
				}
			}
		}
		if len(res) > 0 {
			return res
		}
	}
	return nil
}

func enrichFullDNSRecords(domain string, result *DNSEnumResult) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if result.SOARecord == nil {
			result.SOARecord = LookupSOA(domain, 3*time.Second)
		}
	}()
	go func() {
		defer wg.Done()
		if len(result.TXTRecords) == 0 {
			result.TXTRecords = LookupTXTRecords(domain, 3*time.Second)
		}
	}()

	// Always ensure MX records have preferences and IP addresses
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var enrichedMX []DNSEnumRecord
		if mxs, err := net.LookupMX(domain); err == nil && len(mxs) > 0 {
			for _, mx := range mxs {
				h := strings.TrimSuffix(mx.Host, ".")
				ipVal := ""
				if ips, err := net.DefaultResolver.LookupHost(ctx, h); err == nil && len(ips) > 0 {
					ipVal = ips[0]
				}
				enrichedMX = append(enrichedMX, DNSEnumRecord{
					Host:  h,
					Type:  fmt.Sprintf("MX (Pref: %d)", mx.Pref),
					Value: ipVal,
				})
			}
		} else {
			// dig fallback for MX
			cmd := exec.CommandContext(ctx, "dig", "+noall", "+answer", domain, "MX")
			if out, err := cmd.Output(); err == nil && len(out) > 0 {
				for _, l := range strings.Split(string(out), "\n") {
					parts := strings.Fields(l)
					if len(parts) >= 6 && parts[3] == "MX" {
						pref := parts[4]
						h := strings.TrimSuffix(parts[5], ".")
						ipVal := ""
						if ips, err := net.DefaultResolver.LookupHost(ctx, h); err == nil && len(ips) > 0 {
							ipVal = ips[0]
						}
						enrichedMX = append(enrichedMX, DNSEnumRecord{
							Host:  h,
							Type:  fmt.Sprintf("MX (Pref: %s)", pref),
							Value: ipVal,
						})
					}
				}
			}
		}
		if len(enrichedMX) > 0 {
			result.MailServers = enrichedMX
		}
	}()

	wg.Wait()
}

func deduplicateRecords(records []DNSEnumRecord) []DNSEnumRecord {
	seen := make(map[string]bool)
	var unique []DNSEnumRecord
	for _, r := range records {
		key := fmt.Sprintf("%s|%s|%s", r.Host, r.Type, r.Value)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, r)
		}
	}
	return unique
}

// PrintDNSEnumReport outputs an aesthetic, professional cybersecurity terminal report
func PrintDNSEnumReport(res *DNSEnumResult) {
	fmt.Println()
	fmt.Println("[1;36m╔══════════════════════════════════════════════════════════════════════════════╗[0m")
	fmt.Println("[1;36m║            ⚡ NightfallLX Automated DNS Intelligence & Enum Engine           ║[0m")
	fmt.Printf("[1;36m║  Target Domain : [1;37m%-58s[1;36m ║[0m\n", res.Domain)
	fmt.Printf("[1;36m║  Engine Mode   : [1;32m%-58s[1;36m ║[0m\n", res.EngineUsed)
	fmt.Println("[1;36m╚══════════════════════════════════════════════════════════════════════════════╝[0m")
	fmt.Println()

	// 1. Host's Addresses
	fmt.Println("[1;36m[+] Host's Addresses (A / AAAA Records):[0m")
	if len(res.HostAddresses) == 0 {
		fmt.Println("    [-] No direct host IP addresses resolved.")
	} else {
		for _, r := range res.HostAddresses {
			ttlStr := ""
			if r.TTL != "" {
				ttlStr = fmt.Sprintf(" (TTL: %s)", r.TTL)
			}
			fmt.Printf("    ├── [1;37m%-35s[0m [%s] -> [1;32m%s[0m%s\n", r.Host, r.Type, r.Value, ttlStr)
		}
	}
	fmt.Println()

	// 2. Name Servers
	fmt.Printf("[1;36m[+] Name Servers (%d servers):[0m\n", len(res.NameServers))
	if len(res.NameServers) == 0 {
		fmt.Println("    [-] No NS records found.")
	} else {
		for _, r := range res.NameServers {
			ipStr := ""
			if r.Value != "" {
				ipStr = fmt.Sprintf(" -> [32m%s[0m", r.Value)
			}
			fmt.Printf("    ├── [1;37m%-35s[0m%s\n", r.Host, ipStr)
		}
	}
	fmt.Println()

	// 3. Mail (MX) Servers
	fmt.Printf("\033[1;36m[+] Mail (MX) Servers (%d servers):\033[0m\n", len(res.MailServers))
	if len(res.MailServers) == 0 {
		fmt.Println("    [-] No MX records configured.")
	} else {
		for _, r := range res.MailServers {
			ipStr := ""
			if r.Value != "" {
				ipStr = fmt.Sprintf(" -> \033[32m%s\033[0m", r.Value)
			}
			fmt.Printf("    ├── \033[1;37m%-35s\033[0m [%s]%s\n", r.Host, r.Type, ipStr)
		}
	}
	fmt.Println()

	// 3b. Start of Authority (SOA) Record
	if res.SOARecord != nil {
		fmt.Println("\033[1;36m[+] Start of Authority (SOA) Record:\033[0m")
		fmt.Printf("    ├── Primary Nameserver : \033[1;37m%s\033[0m\n", res.SOARecord.PrimaryNS)
		if res.SOARecord.AdminEmail != "" {
			fmt.Printf("    ├── \033[1;33mAdmin Contact Email\033[0m: \033[1;32m%s\033[0m (Extracted from SOA)\n", res.SOARecord.AdminEmail)
		}
		fmt.Printf("    ├── Zone Serial Number : %s\n", res.SOARecord.Serial)
		fmt.Printf("    └── Timers (Ref/Ret/Exp): %s / %s / %s (TTL: %s)\n", res.SOARecord.Refresh, res.SOARecord.Retry, res.SOARecord.Expire, res.SOARecord.MinTTL)
		fmt.Println()
	}

	// 3c. Authoritative TXT Records
	fmt.Printf("\033[1;36m[+] Authoritative TXT Records (%d records):\033[0m\n", len(res.TXTRecords))
	if len(res.TXTRecords) == 0 {
		fmt.Println("    [-] No public TXT records found.")
	} else {
		for i, txt := range res.TXTRecords {
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
	}
	fmt.Println()

	// 4. Zone Transfers (AXFR) & Bind Versions
	fmt.Println("[1;36m[+] Zone Transfers (AXFR) & BIND Version Audit:[0m")
	if len(res.ZoneTransfers) == 0 {
		fmt.Println("    [-] No nameservers available to test zone transfers.")
	} else {
		for _, z := range res.ZoneTransfers {
			if z.Vulnerable {
				fmt.Printf("    ├── [1;31m[🔥 VULNERABLE][0m %-25s -> Full DNS Zone Transfer Leaked! (%d records)\n", z.Server, len(z.Records))
			} else {
				fmt.Printf("    ├── [1;32m[SECURE][0m       %-25s -> %s\n", z.Server, z.Status)
			}
		}
	}
	fmt.Println()

	// 5. Discovered Subdomains
	fmt.Printf("[1;36m[+] Discovered Subdomains & Services (%d discovered):[0m\n", len(res.Subdomains))
	if len(res.Subdomains) == 0 {
		fmt.Println("    [-] No subdomains discovered via brute force / google scraping.")
	} else {
		limit := 25
		if len(res.Subdomains) < limit {
			limit = len(res.Subdomains)
		}
		for i := 0; i < limit; i++ {
			s := res.Subdomains[i]
			fmt.Printf("    ├── [1;37m%-35s[0m [%s] -> [32m%s[0m\n", s.Host, s.Type, s.Value)
		}
		if len(res.Subdomains) > limit {
			fmt.Printf("    └── ... and [1m%d[0m more subdomains.\n", len(res.Subdomains)-limit)
		}
	}
	fmt.Println()

	// 6. Network Netranges & IP Blocks
	if len(res.ClassCNetranges) > 0 || len(res.IPBlocks) > 0 {
		fmt.Println("[1;36m[+] Network Netranges & IP Routing Blocks:[0m")
		if len(res.ClassCNetranges) > 0 {
			fmt.Printf("    ├── Class C Ranges : [1;33m%s[0m\n", strings.Join(res.ClassCNetranges, ", "))
		}
		if len(res.IPBlocks) > 0 {
			fmt.Printf("    └── IP Blocks      : [35m%s[0m\n", strings.Join(res.IPBlocks, ", "))
		}
		fmt.Println()
	}

	// 7. Reverse Lookups (if performed)
	if len(res.ReverseLookups) > 0 {
		fmt.Printf("[1;36m[+] Reverse Lookups (PTR Records) (%d resolved):[0m\n", len(res.ReverseLookups))
		limit := 10
		if len(res.ReverseLookups) < limit {
			limit = len(res.ReverseLookups)
		}
		for i := 0; i < limit; i++ {
			r := res.ReverseLookups[i]
			fmt.Printf("    ├── [33m%-20s[0m -> [1;37m%s[0m\n", r.Value, r.Host)
		}
		if len(res.ReverseLookups) > limit {
			fmt.Printf("    └── ... and %d more PTR records.\n", len(res.ReverseLookups)-limit)
		}
		fmt.Println()
	}

	fmt.Printf("[1m[*] DNS Enumeration completed in %v.[0m\n\n", res.Duration.Round(time.Millisecond))
}
