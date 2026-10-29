package cvss

import (
	"strings"
)

// VulnerabilityProfile represents a standard reference vector and metadata for a vulnerability class.
type VulnerabilityProfile struct {
	Name        string
	Vector      string
	CWE         int
	Description string
}

// CanonicalVectors maps vulnerability identifiers/categories to standardized CVSS v3.1 vectors.
var CanonicalVectors = map[string]string{
	// High-Impact Injection & RCE
	"sqli":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // 9.8 Critical
	"cmdi":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // 9.8 Critical
	"ssti":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // 9.8 Critical
	"nosqli":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", // 9.4 Critical
	"upload":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // 9.8 Critical
	"jwt":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", // 9.1 Critical
	"smuggling":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", // 9.1 Critical

	// Web Exploitation & Access
	"ssrf":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", // 8.6 High
	"lfi":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", // 7.5 High
	"xxe":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", // 7.5 High
	"git_dumper":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", // 7.5 High
	"secrets":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", // 7.5 High
	"exposure":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", // 7.5 High
	"xss":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", // 6.1 Medium
	"cors":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", // 6.5 Medium
	"csrf":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", // 6.5 Medium
	"redirect":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", // 6.1 Medium
	"idor":        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", // 6.5 Medium
	"hostheader":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", // 5.4 Medium
	"crlf":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", // 5.4 Medium
	"userenum":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", // 5.3 Medium

	// OSINT / Recon Specific Findings
	"dns_axfr":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", // 7.5 High
	"missing_spf":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", // 5.3 Medium
	"missing_dmarc":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", // 6.5 Medium
	"directory_listing":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", // 5.3 Medium
	"version_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", // 5.3 Medium
	"outdated_component": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", // 5.4 Medium

	// Headers Specific Sub-Findings
	"header_csp":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", // 5.4 Medium
	"header_xfo":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", // 4.3 Medium
	"header_xcto":   "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", // 3.1 Low
	"header_refpol": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", // 3.1 Low
	"header_hsts":   "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", // 5.9 Medium
}

// ClassifyFinding infers the most accurate canonical CVSS v3.1 vector and computed score
// based on module name, finding title, and CWE ID.
func ClassifyFinding(moduleName, title string, cweID int) ScoreResult {
	mod := strings.ToLower(strings.TrimSpace(moduleName))
	t := strings.ToLower(strings.TrimSpace(title))

	var vector string

	// Specific title heuristics
	switch {
	case strings.Contains(t, "zone transfer") || strings.Contains(t, "axfr"):
		vector = CanonicalVectors["dns_axfr"]
	case strings.Contains(t, "spf"):
		vector = CanonicalVectors["missing_spf"]
	case strings.Contains(t, "dmarc"):
		vector = CanonicalVectors["missing_dmarc"]
	case strings.Contains(t, "directory listing") || strings.Contains(t, "index of"):
		vector = CanonicalVectors["directory_listing"]
	case strings.Contains(t, "hsts"):
		vector = CanonicalVectors["header_hsts"]
	case strings.Contains(t, "content-security-policy") || strings.Contains(t, "csp"):
		vector = CanonicalVectors["header_csp"]
	case strings.Contains(t, "x-frame-options") || strings.Contains(t, "clickjacking"):
		vector = CanonicalVectors["header_xfo"]
	case strings.Contains(t, "x-content-type-options"):
		vector = CanonicalVectors["header_xcto"]
	case strings.Contains(t, "referrer-policy"):
		vector = CanonicalVectors["header_refpol"]
	case strings.Contains(t, "version disclosure") || strings.Contains(t, "banner"):
		vector = CanonicalVectors["version_disclosure"]
	case strings.Contains(t, "outdated") || strings.Contains(t, "jquery") || strings.Contains(t, "vulnerable library"):
		vector = CanonicalVectors["outdated_component"]
	case strings.Contains(t, ".git") || strings.Contains(t, "git repository"):
		vector = CanonicalVectors["git_dumper"]
	case strings.Contains(t, "api key") || strings.Contains(t, "secret") || strings.Contains(t, "token"):
		vector = CanonicalVectors["secrets"]
	case strings.Contains(t, "user enumeration"):
		vector = CanonicalVectors["userenum"]
	default:
		// Module mapping
		if vec, ok := CanonicalVectors[mod]; ok {
			vector = vec
		} else {
			// Fallback by CWE
			switch cweID {
			case 89: // SQLi
				vector = CanonicalVectors["sqli"]
			case 78: // CMDi
				vector = CanonicalVectors["cmdi"]
			case 79: // XSS
				vector = CanonicalVectors["xss"]
			case 918: // SSRF
				vector = CanonicalVectors["ssrf"]
			case 22: // Path Traversal
				vector = CanonicalVectors["lfi"]
			case 611: // XXE
				vector = CanonicalVectors["xxe"]
			case 352: // CSRF
				vector = CanonicalVectors["csrf"]
			case 601: // Open Redirect
				vector = CanonicalVectors["redirect"]
			case 639: // IDOR
				vector = CanonicalVectors["idor"]
			case 548: // Dir Listing
				vector = CanonicalVectors["directory_listing"]
			case 200: // Info disclosure
				vector = CanonicalVectors["version_disclosure"]
			case 1104: // Outdated component
				vector = CanonicalVectors["outdated_component"]
			default:
				// Safe standard web vulnerability default: Network, Low AC, None PR, None UI, Medium impact
				vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
			}
		}
	}

	res, err := CalculateVector(vector)
	if err != nil {
		// Guaranteed never to happen with verified canonical vectors
		return ScoreResult{
			VectorString: vector,
			BaseScore:    5.3,
			Severity:     "MEDIUM",
		}
	}
	return res
}
