package osint

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// Known vulnerable CNAME domains for Subdomain Takeover detection
var takeoverSignatures = map[string]string{
	"github.io":              "GitHub Pages",
	"s3.amazonaws.com":       "AWS S3 Bucket",
	"herokuapp.com":          "Heroku App",
	"azurewebsites.net":      "Microsoft Azure App",
	"trafficmanager.net":     "Azure Traffic Manager",
	"ghost.io":               "Ghost.org Blog",
	"surge.sh":               "Surge.sh Static Host",
	"pantheonsite.io":        "Pantheon Hosting",
	"readme.io":              "ReadMe Docs",
	"zendesk.com":            "Zendesk Help Center",
	"shopify.com":            "Shopify Storefront",
	"fastly.net":             "Fastly CDN",
	"bitbucket.io":           "Bitbucket Pages",
	"cname.vercel-dns.com":   "Vercel Deployment",
}

// AuditDNS performs DNS resolution and checks SPF/DMARC email security configurations.
func AuditDNS(domain string, timeout time.Duration) (*OSINTReport, error) {
	if timeout <= 0 {
		timeout = 7 * time.Second
	}

	report := &OSINTReport{
		Domain:      domain,
		DMARCStatus: DMARCMissing,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var resolver net.Resolver

	// 1. Resolve A / AAAA records
	if ips, err := resolver.LookupIP(ctx, "ip", domain); err == nil {
		for _, ip := range ips {
			report.TargetIPs = append(report.TargetIPs, ip.String())
		}
	}

	// Identify Cloud / CDN Provider based on IPs and PTR
	report.CloudProvider = detectCloudProvider(report.TargetIPs, domain)

	// 2. Resolve NS records
	if nsRecords, err := resolver.LookupNS(ctx, domain); err == nil {
		for _, ns := range nsRecords {
			report.NameServers = append(report.NameServers, strings.TrimSuffix(ns.Host, "."))
		}
	}

	// 3. Resolve MX records with IP resolution and dig fallback
	if mxRecords, err := resolver.LookupMX(ctx, domain); err == nil && len(mxRecords) > 0 {
		for _, mx := range mxRecords {
			h := strings.TrimSuffix(mx.Host, ".")
			ipStr := ""
			if ips, err := resolver.LookupHost(ctx, h); err == nil && len(ips) > 0 {
				ipStr = " -> " + ips[0]
			}
			report.MailServers = append(report.MailServers, fmt.Sprintf("%s (Pref: %d)%s", h, mx.Pref, ipStr))
		}
	} else {
		// Fallback MX query via dig
		cmd := exec.CommandContext(ctx, "dig", "+noall", "+answer", domain, "MX")
		if out, err := cmd.Output(); err == nil && len(out) > 0 {
			for _, l := range strings.Split(string(out), "\n") {
				parts := strings.Fields(l)
				if len(parts) >= 6 && parts[3] == "MX" {
					pref := parts[4]
					h := strings.TrimSuffix(parts[5], ".")
					ipStr := ""
					if ips, err := resolver.LookupHost(ctx, h); err == nil && len(ips) > 0 {
						ipStr = " -> " + ips[0]
					}
					report.MailServers = append(report.MailServers, fmt.Sprintf("%s (Pref: %s)%s", h, pref, ipStr))
				}
			}
		}
	}

	// 4. Resolve Authoritative TXT records & Audit SPF
	if txts, err := resolver.LookupTXT(ctx, domain); err == nil && len(txts) > 0 {
		report.TXTRecords = txts
	}
	if len(report.TXTRecords) == 0 {
		report.TXTRecords = LookupTXTRecords(domain, timeout)
	}
	for _, txt := range report.TXTRecords {
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			report.SPFRecord = txt
			break
		}
	}

	// 4b. Query Start of Authority (SOA) Record
	report.SOARecord = LookupSOA(domain, timeout)

	if report.SPFRecord == "" {
		report.Findings = append(report.Findings, OSINTFinding{
			Title:       "Missing SPF (Sender Policy Framework) Record",
			Severity:    "HIGH",
			Description: "The domain lacks an SPF TXT record. Anyone on the internet can forge emails claiming to come from this domain without receiving a delivery rejection.",
			Evidence:    fmt.Sprintf("No TXT record starting with 'v=spf1' found on %s", domain),
			Remediation: "Publish an SPF record (e.g. 'v=spf1 include:_spf.example.com ~all') to restrict authorized mail servers.",
		})
	} else if strings.Contains(report.SPFRecord, "+all") {
		report.Findings = append(report.Findings, OSINTFinding{
			Title:       "Critical SPF Misconfiguration (+all Permissive)",
			Severity:    "CRITICAL",
			Description: "The SPF record includes '+all', explicitly authorizing ANY server on the internet to send email from this domain.",
			Evidence:    report.SPFRecord,
			Remediation: "Change '+all' to '~all' (SoftFail) or '-all' (HardFail) immediately.",
		})
	}

	// 5. Audit DMARC Record (_dmarc.<domain>)
	dmarcDomain := "_dmarc." + domain
	if dmarcTxts, err := resolver.LookupTXT(ctx, dmarcDomain); err == nil && len(dmarcTxts) > 0 {
		for _, txt := range dmarcTxts {
			if strings.HasPrefix(strings.ToLower(txt), "v=dmarc1") {
				report.DMARCRecord = txt
				break
			}
		}
	}

	if report.DMARCRecord == "" {
		report.DMARCStatus = DMARCMissing
		report.Findings = append(report.Findings, OSINTFinding{
			Title:       "Missing DMARC Record (Email Spoofing / Phishing Risk)",
			Severity:    "HIGH",
			Description: "Domain has no DMARC policy configured on _dmarc." + domain + ". Threat actors can send spoofed phishing emails and impersonate company executives (CEO Fraud / BEC).",
			Evidence:    "No DMARC TXT record found on " + dmarcDomain,
			Remediation: "Deploy a DMARC policy with at least 'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@" + domain + "'.",
		})
	} else {
		lowerDMARC := strings.ToLower(report.DMARCRecord)
		if strings.Contains(lowerDMARC, "p=none") {
			report.DMARCStatus = DMARCWeak
			report.Findings = append(report.Findings, OSINTFinding{
				Title:       "Weak DMARC Policy (p=none)",
				Severity:    "MEDIUM",
				Description: "DMARC policy is set to 'p=none' (monitor-only). Mail servers receiving forged emails from this domain will not reject or quarantine them.",
				Evidence:    report.DMARCRecord,
				Remediation: "Upgrade DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject' once legitimate senders are verified.",
			})
		} else if strings.Contains(lowerDMARC, "p=reject") || strings.Contains(lowerDMARC, "p=quarantine") {
			report.DMARCStatus = DMARCSecure
		}
	}

	return report, nil
}

// CheckSubdomainTakeover checks if a CNAME record points to an unclaimed SaaS provider.
func CheckSubdomainTakeover(subdomain string) (string, string) {
	cname, err := net.LookupCNAME(subdomain)
	if err != nil || cname == "" || cname == subdomain+"." {
		return "", ""
	}
	cleanCNAME := strings.TrimSuffix(strings.ToLower(cname), ".")
	for signature, serviceName := range takeoverSignatures {
		if strings.Contains(cleanCNAME, signature) {
			return cleanCNAME, serviceName
		}
	}
	return cleanCNAME, ""
}

func detectCloudProvider(ips []string, domain string) string {
	for _, ip := range ips {
		if strings.HasPrefix(ip, "104.") || strings.HasPrefix(ip, "172.6") || strings.HasPrefix(ip, "188.114.") {
			return "Cloudflare Anycast CDN"
		}
	}
	// Try reverse lookup on first IP
	if len(ips) > 0 {
		if ptrs, err := net.LookupAddr(ips[0]); err == nil && len(ptrs) > 0 {
			lower := strings.ToLower(ptrs[0])
			if strings.Contains(lower, "google") || strings.Contains(lower, "1e100") {
				return "Google Cloud / GCP"
			}
			if strings.Contains(lower, "amazon") || strings.Contains(lower, "awsglobalaccelerator") {
				return "Amazon Web Services (AWS)"
			}
			if strings.Contains(lower, "azure") || strings.Contains(lower, "trafficmanager") {
				return "Microsoft Azure"
			}
			if strings.Contains(lower, "digitalocean") {
				return "DigitalOcean"
			}
			if strings.Contains(lower, "hetzner") {
				return "Hetzner Online"
			}
			if strings.Contains(lower, "ovh") {
				return "OVHcloud"
			}
			if strings.Contains(lower, "cloudflare") {
				return "Cloudflare"
			}
		}
	}
	return "Direct / Self-Hosted"
}
