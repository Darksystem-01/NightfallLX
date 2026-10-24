package intel

import (
	"context"
	"net/http"
	"nightfalllx/pkg/detector"
	"os"
	"regexp"
	"strings"
)

var (
	headerVersionRegex = regexp.MustCompile(`(?i)([a-zA-Z0-9_\-]+)[/ _\-]([0-9]+(?:\.[0-9]+)+(?:[a-zA-Z0-9_\-]*)?)`)
	metaGeneratorRegex = regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']`)
)

// ExtractProductVersions extracts software names and versions from tech detection, HTTP headers, HTML metadata, and CLI inputs.
func ExtractProductVersions(techs []*detector.Technology, headers http.Header, htmlBody, manualQuery string) []ProductVersion {
	var list []ProductVersion
	seen := make(map[string]bool)

	add := func(prod, ver, src string) {
		prod = strings.TrimSpace(prod)
		ver = strings.TrimSpace(ver)
		if prod == "" {
			return
		}
		key := strings.ToLower(prod + ":" + ver)
		if !seen[key] {
			seen[key] = true
			list = append(list, ProductVersion{
				Product: prod,
				Version: ver,
				Source:  src,
			})
		}
	}

	// 1. Manual query via --intel-query
	if manualQuery != "" {
		parts := strings.Fields(manualQuery)
		if len(parts) >= 2 {
			add(parts[0], strings.Join(parts[1:], " "), "flag")
		} else if len(parts) == 1 {
			add(parts[0], "", "flag")
		}
	}

	// 2. Technologies identified by detector/tech.go
	for _, t := range techs {
		if t != nil && t.Name != "" {
			add(t.Name, t.Version, "detector")
		}
	}

	// 3. Response headers (Server, X-Powered-By)
	if headers != nil {
		for _, hKey := range []string{"Server", "X-Powered-By"} {
			hVal := headers.Get(hKey)
			if hVal != "" {
				matches := headerVersionRegex.FindAllStringSubmatch(hVal, -1)
				for _, m := range matches {
					if len(m) >= 3 {
						add(m[1], m[2], hKey)
					}
				}
			}
		}
	}

	// 4. Meta generator tag in HTML
	if htmlBody != "" {
		m := metaGeneratorRegex.FindStringSubmatch(htmlBody)
		if len(m) >= 2 {
			genVal := m[1]
			parts := strings.Fields(genVal)
			if len(parts) >= 2 {
				add(parts[0], parts[1], "meta-generator")
			} else {
				add(genVal, "", "meta-generator")
			}
		}
	}

	return list
}

const (
	maxIntelFindingsPerQuery = 25
	maxIntelFindingsTotal    = 100
)

// RunIntel coordinates searchsploit and optional NVD lookups for detected products/versions.
func RunIntel(targetURL string, pvList []ProductVersion, enableNVD bool) *IntelReport {
	return RunIntelContext(context.Background(), targetURL, pvList, enableNVD)
}

// RunIntelContext is the cancellable reference-lookup entry point.
func RunIntelContext(ctx context.Context, targetURL string, pvList []ProductVersion, enableNVD bool) *IntelReport {
	if ctx == nil {
		ctx = context.Background()
	}
	report := &IntelReport{
		Target:     targetURL,
		Disclaimer: "Version detection can be wrong or imprecise. The following public reference metadata is unverified and requires manual confirmation. No exploit code was opened, executed, or tested.",
	}

	ssClient := NewSearchsploitClient()
	report.SearchsploitAvailable = ssClient.IsAvailable()
	if !ssClient.IsAvailable() {
		report.InstallHint = "Install Exploit-DB searchsploit utility: 'sudo apt install exploitdb' or 'snap install searchsploit' to enable offline local reference lookup."
	}

	var nvdClient *NVDClient
	if enableNVD || os.Getenv("NVD_API_KEY") != "" {
		nvdClient = NewNVDClient()
	}

	for _, pv := range pvList {
		if ctx.Err() != nil {
			break
		}
		// Automatic versionless matches are too noisy to be useful. Manual
		// --intel-query input is still allowed and remains capped below.
		if strings.TrimSpace(pv.Version) == "" && pv.Source != "flag" {
			continue
		}
		q := pv.Product
		if pv.Version != "" {
			q = pv.Product + " " + pv.Version
		}
		q = strings.TrimSpace(q)
		if q == "" {
			continue
		}
		report.Queries = append(report.Queries, q)

		// 1. Searchsploit lookup
		if ssClient.IsAvailable() {
			findings, err := ssClient.LookupContext(ctx, pv.Product, pv.Version)
			if err == nil && len(findings) > 0 {
				if len(findings) > maxIntelFindingsPerQuery {
					findings = findings[:maxIntelFindingsPerQuery]
				}
				report.Findings = append(report.Findings, findings...)
			}
		}

		// 2. NVD lookup
		if nvdClient != nil {
			nvdFindings, errNVD := nvdClient.LookupContext(ctx, q)
			if errNVD == nil && len(nvdFindings) > 0 {
				report.Findings = append(report.Findings, nvdFindings...)
			}
		}
		if len(report.Findings) >= maxIntelFindingsTotal {
			report.Findings = report.Findings[:maxIntelFindingsTotal]
			break
		}
	}

	return report
}
