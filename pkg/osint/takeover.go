package osint

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"nightfalllx/pkg/client"
	"nightfalllx/pkg/modules"
)

// TakeoverFingerprint specifies detection signatures for dangling cloud CNAMEs.
type TakeoverFingerprint struct {
	Service          string
	CNAMESuffixes    []string
	ResponsePatterns []string
	Remediation      string
}

// BuiltinTakeoverSignatures defines 20+ major cloud provider takeover signatures.
var BuiltinTakeoverSignatures = []TakeoverFingerprint{
	{
		Service:          "GitHub Pages",
		CNAMESuffixes:    []string{"github.io", "github.map.fastly.net"},
		ResponsePatterns: []string{"There isn't a GitHub Pages site here.", "For root URLs (like http://example.com/) you must provide an index.html file"},
		Remediation:      "Claim repository on GitHub with custom domain or delete dangling CNAME record from DNS zone.",
	},
	{
		Service:          "AWS S3 Bucket",
		CNAMESuffixes:    []string{"s3.amazonaws.com", "s3-website", "s3.dualstack"},
		ResponsePatterns: []string{"The specified bucket does not exist", "NoSuchBucket"},
		Remediation:      "Register the abandoned S3 bucket in your AWS account or remove the dangling CNAME.",
	},
	{
		Service:          "Heroku",
		CNAMESuffixes:    []string{"herokuapp.com", "herokudns.com"},
		ResponsePatterns: []string{"No such app", "herokucdn.com/error-pages/no-such-app.html"},
		Remediation:      "Re-attach domain to active Heroku app or delete dangling DNS CNAME entry.",
	},
	{
		Service:          "Microsoft Azure",
		CNAMESuffixes:    []string{"azurewebsites.net", "cloudapp.net", "trafficmanager.net", "azureedge.net"},
		ResponsePatterns: []string{"404 Web Site not found", "The resource you are looking for has been removed"},
		Remediation:      "Claim resource in Azure portal or delete orphaned DNS record.",
	},
	{
		Service:          "Shopify",
		CNAMESuffixes:    []string{"myshopify.com"},
		ResponsePatterns: []string{"Sorry, this shop is currently unavailable", "To continue, please upgrade your plan"},
		Remediation:      "Link domain in active Shopify store or remove CNAME pointing to Shopify.",
	},
	{
		Service:          "Fastly CDN",
		CNAMESuffixes:    []string{"fastly.net", "fastlylb.net"},
		ResponsePatterns: []string{"Fastly error: unknown domain"},
		Remediation:      "Claim service ID in Fastly or remove DNS record pointing to Fastly pool.",
	},
	{
		Service:          "Ghost CMS",
		CNAMESuffixes:    []string{"ghost.io"},
		ResponsePatterns: []string{"The thing you were looking for is no longer here", "The site you are looking for is closed"},
		Remediation:      "Restore Ghost subscription or remove dangling DNS pointer.",
	},
	{
		Service:          "Bitbucket",
		CNAMESuffixes:    []string{"bitbucket.io"},
		ResponsePatterns: []string{"Repository not found"},
		Remediation:      "Create Bitbucket repository under team account or delete dangling CNAME.",
	},
	{
		Service:          "Pantheon",
		CNAMESuffixes:    []string{"pantheonsite.io"},
		ResponsePatterns: []string{"404 error unknown site", "The gods are wise"},
		Remediation:      "Claim site on Pantheon dashboard or delete orphaned DNS pointer.",
	},
	{
		Service:          "Zendesk",
		CNAMESuffixes:    []string{"zendesk.com"},
		ResponsePatterns: []string{"Help Center Closed"},
		Remediation:      "Rebind host mapping in Zendesk Admin or drop DNS CNAME record.",
	},
	{
		Service:          "Tumblr",
		CNAMESuffixes:    []string{"domains.tumblr.com"},
		ResponsePatterns: []string{"Whatever you were looking for doesn't seem to exist at this address"},
		Remediation:      "Claim custom domain in Tumblr blog settings or remove DNS pointer.",
	},
	{
		Service:          "Surge.sh",
		CNAMESuffixes:    []string{"surge.sh"},
		ResponsePatterns: []string{"project not found"},
		Remediation:      "Run 'surge --domain <subdomain>' to secure the namespace or remove DNS entry.",
	},
	{
		Service:          "Readme.io",
		CNAMESuffixes:    []string{"readme.io"},
		ResponsePatterns: []string{"Project doesnt exist... yet!"},
		Remediation:      "Claim Readme project slug or remove DNS record.",
	},
	{
		Service:          "WordPress.com",
		CNAMESuffixes:    []string{"wordpress.com"},
		ResponsePatterns: []string{"Do you want to register"},
		Remediation:      "Register matching blog on WordPress.com or delete dangling CNAME.",
	},
	{
		Service:          "Webflow",
		CNAMESuffixes:    []string{"webflow.io"},
		ResponsePatterns: []string{"The page you are looking for doesn't exist", "The site is not published yet"},
		Remediation:      "Verify custom domain settings in Webflow dashboard or remove DNS record.",
	},
	{
		Service:          "Kinsta",
		CNAMESuffixes:    []string{"kinsta.cloud"},
		ResponsePatterns: []string{"No Site For Domain"},
		Remediation:      "Configure domain in MyKinsta dashboard or clean up DNS zone.",
	},
	{
		Service:          "Helpjuice",
		CNAMESuffixes:    []string{"helpjuice.com"},
		ResponsePatterns: []string{"We could not find what you're looking for"},
		Remediation:      "Claim knowledge base domain in Helpjuice or drop CNAME.",
	},
	{
		Service:          "UptimeRobot",
		CNAMESuffixes:    []string{"stats.uptimerobot.com"},
		ResponsePatterns: []string{"page not found"},
		Remediation:      "Create public status page on UptimeRobot or remove DNS record.",
	},
}

// TakeoverResult represents findings for an individual subdomain.
type TakeoverResult struct {
	Subdomain        string `json:"subdomain"`
	CNAME            string `json:"cname"`
	Service          string `json:"service"`
	Vulnerable       bool   `json:"vulnerable"`
	MatchedSignature string `json:"matched_signature"`
	Remediation      string `json:"remediation"`
}

// TakeoverReport aggregates subdomain takeover audit results.
type TakeoverReport struct {
	TargetDomain    string            `json:"target_domain"`
	CheckedCount    int               `json:"checked_count"`
	VulnerableCount int               `json:"vulnerable_count"`
	Results         []*TakeoverResult `json:"results"`
}

// CheckSubdomainTakeovers audits a list of subdomains for dangling cloud CNAME takeovers.
func CheckSubdomainTakeovers(subdomains []string, c *client.Client) (*TakeoverReport, []*modules.Finding, error) {
	report := &TakeoverReport{
		CheckedCount: len(subdomains),
	}

	if len(subdomains) == 0 {
		return report, nil, nil
	}

	var (
		findings  []*modules.Finding
		mu        sync.Mutex
		wg        sync.WaitGroup
		sem       = make(chan struct{}, 15) // concurrency throttle
	)

	for _, sub := range subdomains {
		sub = strings.TrimSpace(sub)
		if sub == "" {
			continue
		}

		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// 1. Resolve CNAME
			cname, err := net.LookupCNAME(subdomain)
			if err != nil || cname == "" || strings.TrimSuffix(cname, ".") == subdomain {
				return
			}
			cname = strings.TrimSuffix(cname, ".")

			// 2. Check if CNAME matches any known vulnerable provider
			var matchedSig *TakeoverFingerprint
			for _, sig := range BuiltinTakeoverSignatures {
				for _, suffix := range sig.CNAMESuffixes {
					if strings.HasSuffix(strings.ToLower(cname), suffix) {
						matchedSig = &sig
						break
					}
				}
				if matchedSig != nil {
					break
				}
			}

			if matchedSig == nil {
				return
			}

			// 3. Probe HTTP & HTTPS endpoints to verify dangling state
			schemes := []string{"http", "https"}
			for _, scheme := range schemes {
				probeURL := fmt.Sprintf("%s://%s/", scheme, subdomain)
				resp, pErr := c.Request("GET", probeURL, "", nil)
				if pErr != nil || resp == nil {
					continue
				}

				body := resp.Body
				for _, pat := range matchedSig.ResponsePatterns {
					if strings.Contains(body, pat) {
						// Confirmed Subdomain Takeover!
						res := &TakeoverResult{
							Subdomain:        subdomain,
							CNAME:            cname,
							Service:          matchedSig.Service,
							Vulnerable:       true,
							MatchedSignature: pat,
							Remediation:      matchedSig.Remediation,
						}

						finding := &modules.Finding{
							Module:      "takeover",
							Title:       fmt.Sprintf("High-Risk Subdomain Takeover on %s (%s)", subdomain, matchedSig.Service),
							Severity:    modules.SeverityHigh,
							Confidence:  98,
							URL:         probeURL,
							Parameter:   "DNS CNAME",
							Payload:     cname,
							Detail:      fmt.Sprintf("Dangling DNS CNAME pointing to %s (%s) matches abandoned service fingerprint '%s'. An attacker can register the resource and completely hijack this subdomain.", cname, matchedSig.Service, pat),
							Evidence:    fmt.Sprintf("CNAME: %s -> Response Fingerprint: %q", cname, pat),
							Remediation: matchedSig.Remediation,
							CWEID:       284,
							CVSS:        8.2,
						}

						mu.Lock()
						report.Results = append(report.Results, res)
						findings = append(findings, finding)
						report.VulnerableCount++
						mu.Unlock()
						return
					}
				}
			}
		}(sub)
	}

	wg.Wait()
	return report, findings, nil
}

// PrintTakeoverReport displays a styled terminal audit report.
func PrintTakeoverReport(rep *TakeoverReport) {
	fmt.Println("\n\033[1;36m┌──────────────────────────────────────────────────────────────────────────────────┐\033[0m")
	fmt.Printf("\033[1;36m│\033[0m \033[1;37m🎯 NightfallLX Subdomain Takeover (CNAME Hijacking) Audit Engine\033[0m                 \033[1;36m│\033[0m\n")
	fmt.Printf("\033[1;36m│\033[0m Subdomains Audited: \033[1;33m%-61d\033[0m \033[1;36m│\033[0m\n", rep.CheckedCount)
	if rep.VulnerableCount > 0 {
		fmt.Printf("\033[1;36m│\033[0m \033[1;31mTakeover Vulnerable:\033[0m \033[1;31m%-61d\033[0m \033[1;36m│\033[0m\n", rep.VulnerableCount)
	} else {
		fmt.Printf("\033[1;36m│\033[0m \033[1;32mTakeover Status:     0 Dangling / Clean\033[0m                                     \033[1;36m│\033[0m\n")
	}
	fmt.Println("\033[1;36m└──────────────────────────────────────────────────────────────────────────────────┘\033[0m")

	if rep.VulnerableCount == 0 {
		fmt.Println("\033[1;32m[+] All tested subdomains have active backends. No dangling CNAME hijack detected.\033[0m")
		return
	}

	for _, r := range rep.Results {
		fmt.Printf("  \033[1;31m[TAKEOVER VULNERABLE]\033[0m \033[1m%s\033[0m\n", r.Subdomain)
		fmt.Printf("      ├── Service:   \033[1;35m%s\033[0m\n", r.Service)
		fmt.Printf("      ├── CNAME:     \033[33m%s\033[0m\n", r.CNAME)
		fmt.Printf("      ├── Signature: \033[90m%q\033[0m\n", r.MatchedSignature)
		fmt.Printf("      └── Action:    %s\n\n", r.Remediation)
	}
}
