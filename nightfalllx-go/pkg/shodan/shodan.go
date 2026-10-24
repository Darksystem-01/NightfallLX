package shodan

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// HostInfo represents Shodan /shodan/host/{ip} response
type HostInfo struct {
	IP        string   `json:"ip_str"`
	Hostnames []string `json:"hostnames"`
	Org       string   `json:"org"`
	ISP       string   `json:"isp"`
	ASN       string   `json:"asn"`
	OS        string   `json:"os"`
	City      string   `json:"city"`
	Country   string   `json:"country_name"`
	Ports     []int    `json:"ports"`
	Vulns     []string `json:"vulns"`
	Data      []struct {
		Port      int    `json:"port"`
		Transport string `json:"transport"`
		Product   string `json:"product"`
		Version   string `json:"version"`
		Data      string `json:"data"`
		SSL       *struct {
			Cert struct {
				Subject struct {
					CN string `json:"CN"`
				} `json:"subject"`
			} `json:"cert"`
		} `json:"ssl"`
	} `json:"data"`
}

// DomainInfo represents Shodan /dns/domain/{domain} response
type DomainInfo struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Data       []struct {
		Subdomain string `json:"subdomain"`
		Type      string `json:"type"`
		Value     string `json:"value"`
	} `json:"data"`
	Error string `json:"error"`
}

// ShodanClient client for interacting with Shodan API
type ShodanClient struct {
	APIKey     string
	HTTPClient *http.Client
}

// NewClient creates a new Shodan client from CLI flag, SHODAN_API_KEY environment variable,
// or local host configuration file (~/.config/nightfalllx/shodan.key).
func NewClient(apiKey string) *ShodanClient {
	if apiKey == "" {
		apiKey = os.Getenv("SHODAN_API_KEY")
	}
	if apiKey == "" {
		if home, err := os.UserHomeDir(); err == nil {
			configPaths := []string{
				home + "/.config/nightfalllx/shodan.key",
				home + "/.nightfalllx_shodan",
			}
			for _, cp := range configPaths {
				if data, err := os.ReadFile(cp); err == nil {
					key := strings.TrimSpace(string(data))
					if key != "" {
						apiKey = key
						break
					}
				}
			}
		}
	}
	return &ShodanClient{
		APIKey: strings.TrimSpace(apiKey),
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// LookupHost queries Shodan for IP details
func (s *ShodanClient) LookupHost(ip string) (*HostInfo, error) {
	if s.APIKey == "" {
		return nil, fmt.Errorf("shodan API key required (use -shodan-key <KEY> or export SHODAN_API_KEY=<KEY>)")
	}

	apiURL := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", url.PathEscape(ip), url.QueryEscape(s.APIKey))
	resp, err := s.HTTPClient.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("shodan API request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("invalid Shodan API key (401 Unauthorized)")
	}
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("no information available for IP %s in Shodan", ip)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("shodan returned HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var info HostInfo
	if err := json.Unmarshal(bodyBytes, &info); err != nil {
		return nil, fmt.Errorf("failed to parse Shodan JSON response: %w", err)
	}

	return &info, nil
}

// LookupDomain queries Shodan for domain subdomains and DNS records
func (s *ShodanClient) LookupDomain(domain string) (*DomainInfo, error) {
	if s.APIKey == "" {
		return nil, fmt.Errorf("shodan API key required (use -shodan-key <KEY> or export SHODAN_API_KEY=<KEY>)")
	}

	apiURL := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", url.PathEscape(domain), url.QueryEscape(s.APIKey))
	resp, err := s.HTTPClient.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("shodan API domain request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("invalid Shodan API key (401 Unauthorized)")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("shodan returned HTTP %d for domain %s", resp.StatusCode, domain)
	}

	var info DomainInfo
	if err := json.Unmarshal(bodyBytes, &info); err != nil {
		return nil, fmt.Errorf("failed to parse Shodan domain JSON: %w", err)
	}

	return &info, nil
}

// ResolveTarget extracts IP and Domain from target string (URL or domain or IP)
func ResolveTarget(target string) (domain string, ip string, err error) {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "://") {
		u, parseErr := url.Parse(target)
		if parseErr == nil {
			target = u.Host
		}
	}
	if strings.Contains(target, ":") {
		host, _, splitErr := net.SplitHostPort(target)
		if splitErr == nil {
			target = host
		}
	}

	parsedIP := net.ParseIP(target)
	if parsedIP != nil {
		return "", target, nil
	}

	// It's a hostname / domain
	domain = target
	ips, lookupErr := net.LookupIP(domain)
	if lookupErr == nil && len(ips) > 0 {
		ip = ips[0].String()
	}

	return domain, ip, nil
}

// PrintReport displays the Shodan OSINT reconnaissance report
func PrintReport(domain string, host *HostInfo, dnsInfo *DomainInfo) {
	fmt.Printf("\n\033[1;36m┌──────────────────────────────────────────────────────────────────────────────────┐\033[0m\n")
	fmt.Printf("\033[1;36m│ 🛰️  NightfallLX Shodan OSINT Intelligence & Attack Surface Analysis              │\033[0m\n")
	if domain != "" {
		fmt.Printf("\033[1;36m│ Target Domain: %-66s │\033[0m\n", domain)
	}
	if host != nil {
		fmt.Printf("\033[1;36m│ Resolved IP  : %-66s │\033[0m\n", host.IP)
		fmt.Printf("\033[1;36m│ Organization : %-66s │\033[0m\n", host.Org)
		fmt.Printf("\033[1;36m│ Location     : %-66s │\033[0m\n", fmt.Sprintf("%s, %s (ASN: %s)", host.City, host.Country, host.ASN))
		if host.OS != "" {
			fmt.Printf("\033[1;36m│ OS Detected  : %-66s │\033[0m\n", host.OS)
		}
	}
	fmt.Printf("\033[1;36m├──────────────────────────────────────────────────────────────────────────────────┤\033[0m\n")

	// Discovered Subdomains
	if dnsInfo != nil && (len(dnsInfo.Subdomains) > 0 || len(dnsInfo.Data) > 0) {
		recordMap := make(map[string][]string)
		for _, d := range dnsInfo.Data {
			if d.Subdomain != "" && d.Value != "" {
				full := fmt.Sprintf("%s.%s", d.Subdomain, dnsInfo.Domain)
				recordMap[full] = append(recordMap[full], fmt.Sprintf("%s (%s)", d.Value, d.Type))
			}
		}

		totalCount := len(dnsInfo.Subdomains)
		if len(recordMap) > totalCount {
			totalCount = len(recordMap)
		}
		fmt.Printf("\033[1;33m[+] Passive DNS Subdomains Discovered (%d):\033[0m\n", totalCount)

		for _, sub := range dnsInfo.Subdomains {
			fullSub := fmt.Sprintf("%s.%s", sub, dnsInfo.Domain)
			targetVal := ""
			if vals, ok := recordMap[fullSub]; ok && len(vals) > 0 {
				targetVal = fmt.Sprintf(" \033[90m-> %s\033[0m", strings.Join(vals, ", "))
			}
			fmt.Printf("    ├── \033[1;32m%-28s\033[0m%s\n", fullSub, targetVal)
		}
		fmt.Println()
	}

	// Open Ports & Services
	if host != nil {
		if len(host.Ports) > 0 {
			fmt.Printf("\033[1;33m[+] Open Exposed Ports (%d):\033[0m\n", len(host.Ports))
			for _, port := range host.Ports {
				svcInfo := ""
				for _, d := range host.Data {
					if d.Port == port {
						if d.Product != "" {
							svcInfo = d.Product
							if d.Version != "" {
								svcInfo += " " + d.Version
							}
						}
						break
					}
				}
				if svcInfo == "" {
					svcInfo = getCommonServiceName(port)
				}
				fmt.Printf("    ├── Port \033[1;32m%-6d\033[0m [%s]\n", port, svcInfo)
			}
			fmt.Println()
		}

		// Vulnerabilities (CVEs)
		if len(host.Vulns) > 0 {
			fmt.Printf("\033[1;31m[!] Known CVEs Reported in Shodan (%d):\033[0m\n", len(host.Vulns))
			for _, vuln := range host.Vulns {
				fmt.Printf("    └── \033[1;31m%-16s\033[0m\n", vuln)
			}
			fmt.Println()
		} else {
			fmt.Println("    [✓] No known published CVEs indexed for this IP in Shodan.")
		}
	}
	fmt.Printf("\033[1;36m└──────────────────────────────────────────────────────────────────────────────────┘\033[0m\n\n")
}

func getCommonServiceName(port int) string {
	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 80:
		return "HTTP"
	case 110:
		return "POP3"
	case 143:
		return "IMAP"
	case 443:
		return "HTTPS"
	case 445:
		return "Microsoft-DS / SMB"
	case 1433:
		return "MS-SQL"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 5432:
		return "PostgreSQL"
	case 6379:
		return "Redis"
	case 8080:
		return "HTTP-Alt / Proxy"
	case 8443:
		return "HTTPS-Alt"
	default:
		return "TCP-Service"
	}
}
