package reporters

import (
	"encoding/json"
	"fmt"
	"net/url"
	"nightfalllx/pkg/intel"
	"nightfalllx/pkg/modules"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	tokenMaskRegex  = regexp.MustCompile(`(?i)(bearer\s+)[a-zA-Z0-9_\-\.]{8,}`)
	cookieMaskRegex = regexp.MustCompile(`(?i)(session(?:id)?|token|auth|jwt)=([a-zA-Z0-9_\-\.]{6,})`)
)

// WriteMarkdownReport writes a formatted lab assessment report to a markdown file (backward-compatible).
func WriteMarkdownReport(target *modules.Target, findings []*modules.Finding, filePath string) error {
	return WriteMarkdownReportWithIntel(target, findings, nil, filePath)
}

// WriteMarkdownReportWithIntel writes assessment findings and the version-matched intel reference section.
func WriteMarkdownReportWithIntel(target *modules.Target, findings []*modules.Finding, intelRep *intel.IntelReport, filePath string) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	now := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	fmt.Fprintf(f, "# NightfallLX Go Assessment Report\n\n")
	fmt.Fprintf(f, "- **Target URL:** `%s`\n", target.URL)
	fmt.Fprintf(f, "- **Method:** `%s`\n", target.Method)
	fmt.Fprintf(f, "- **Parameters Tested:** `%v`\n", target.Parameters())
	fmt.Fprintf(f, "- **Scan Date:** %s\n", now)
	fmt.Fprintf(f, "- **Total Confirmed Findings:** %d\n\n", len(findings))
	fmt.Fprintf(f, "---\n\n## Findings Summary\n\n")
	fmt.Fprintf(f, "| Module | Title | Severity | Confidence | Parameter |\n")
	fmt.Fprintf(f, "|---|---|---|---|---|\n")

	if len(findings) == 0 {
		fmt.Fprintf(f, "| - | *No confirmed vulnerabilities detected* | - | - | - |\n")
	} else {
		for _, item := range findings {
			confStr := formatConfidence(item)
			fmt.Fprintf(f, "| `%s` | %s | **%s** | %s | `%s` |\n",
				escapeMarkdownPipe(item.Module),
				escapeMarkdownPipe(item.Title),
				escapeMarkdownPipe(string(item.Severity)),
				confStr,
				escapeMarkdownPipe(item.Parameter))
		}
	}

	fmt.Fprintf(f, "\n---\n\n## Detailed Vulnerability Analysis\n\n")

	for idx, item := range findings {
		curlCmd := item.CurlCmd
		if curlCmd == "" {
			curlCmd = buildCurl(target, item.Parameter, item.Payload)
		}
		fmt.Fprintf(f, "### %d. %s\n\n", idx+1, item.Title)
		fmt.Fprintf(f, "- **Module:** `%s`\n", item.Module)
		fmt.Fprintf(f, "- **Severity:** **%s**\n", item.Severity)
		fmt.Fprintf(f, "- **Confidence:** %s\n", formatConfidence(item))
		if item.CWEID > 0 {
			fmt.Fprintf(f, "- **CWE ID:** [CWE-%d](https://cwe.mitre.org/data/definitions/%d.html)\n", item.CWEID, item.CWEID)
		}
		fmt.Fprintf(f, "- **Vulnerable Parameter:** `%s`\n", item.Parameter)
		fmt.Fprintf(f, "- **PoC Payload:** `%s`\n\n", item.Payload)
		fmt.Fprintf(f, "#### Reproduction Command\n```bash\n%s\n```\n\n", curlCmd)
		if item.DetailFormat == "markdown" || isStructuredMarkdown(item.Detail) {
			fmt.Fprintf(f, "#### Analysis & Evidence\n\n%s\n\n", demoteMarkdownHeadings(item.Detail))
		} else {
			fmt.Fprintf(f, "#### Analysis & Evidence\n- **Detail:** %s\n- **Evidence:** %s\n\n", item.Detail, item.Evidence)
		}
		fmt.Fprintf(f, "#### Remediation\n%s\n\n", item.Remediation)
	}

	// Version-Matched Intel Section (Not Verified)
	if intelRep != nil && len(intelRep.Findings) > 0 {
		fmt.Fprintf(f, "\n---\n\n## Version-matched intel (not verified)\n\n")
		fmt.Fprintf(f, "> **Notice:** %s\n\n", intelRep.Disclaimer)
		fmt.Fprintf(f, "| Query | Source | EDB-ID / CVE | Title | Local Reference Path / Score |\n")
		fmt.Fprintf(f, "|---|---|---|---|---|\n")

		for _, item := range intelRep.Findings {
			cveStr := strings.Join(item.CVEs, ", ")
			if cveStr == "" {
				cveStr = item.EDBID
			}
			metaRef := item.LocalPath
			if metaRef == "" && item.CVSS > 0 {
				metaRef = fmt.Sprintf("CVSS: %.1f", item.CVSS)
			}
			fmt.Fprintf(f, "| `%s` | `%s` | %s | %s | `%s` |\n",
				escapeMarkdownPipe(item.Query),
				escapeMarkdownPipe(item.Source),
				escapeMarkdownPipe(cveStr),
				escapeMarkdownPipe(item.Title),
				escapeMarkdownPipe(metaRef))
		}
	}

	return nil
}

func formatConfidence(item *modules.Finding) string {
	lvl := string(item.ConfidenceLevel)
	if lvl == "" {
		if item.Confidence >= 90 {
			lvl = string(modules.ConfidenceConfirmed)
		} else if item.Confidence >= 75 {
			lvl = string(modules.ConfidenceProbable)
		} else {
			lvl = string(modules.ConfidencePossible)
		}
	}
	return fmt.Sprintf("%s (%d%%)", lvl, item.Confidence)
}

func escapeMarkdownPipe(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

func isStructuredMarkdown(detail string) bool {
	trimmed := strings.TrimSpace(detail)
	return strings.HasPrefix(trimmed, "# ") ||
		strings.HasPrefix(trimmed, "## ") ||
		strings.Contains(trimmed, "\n## ")
}

func demoteMarkdownHeadings(detail string) string {
	lines := strings.Split(detail, "\n")
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, "## "):
			lines[i] = "##" + line
		case strings.HasPrefix(line, "# "):
			lines[i] = "##" + line
		}
	}
	return strings.Join(lines, "\n")
}

// WriteJSONReport writes findings to a JSON file (backward-compatible).
func WriteJSONReport(target *modules.Target, findings []*modules.Finding, filePath string) error {
	return WriteJSONReportWithIntel(target, findings, nil, filePath)
}

// WriteJSONReportWithIntel writes findings and intel metadata to a JSON file.
func WriteJSONReportWithIntel(target *modules.Target, findings []*modules.Finding, intelRep *intel.IntelReport, filePath string) error {
	if findings == nil {
		findings = []*modules.Finding{}
	}
	for _, f := range findings {
		if f.ConfidenceLevel == "" {
			if f.Confidence >= 90 {
				f.ConfidenceLevel = modules.ConfidenceConfirmed
			} else if f.Confidence >= 75 {
				f.ConfidenceLevel = modules.ConfidenceProbable
			} else {
				f.ConfidenceLevel = modules.ConfidencePossible
			}
		}
		if f.CurlCmd == "" {
			f.CurlCmd = buildCurl(target, f.Parameter, f.Payload)
		}
	}

	data := map[string]interface{}{
		"target": map[string]interface{}{
			"url":        target.URL,
			"method":     target.Method,
			"parameters": target.Parameters(),
			"is_json":    target.IsJSON,
		},
		"scan_date":      time.Now().UTC().Format(time.RFC3339),
		"total_findings": len(findings),
		"findings":       findings,
	}

	if intelRep != nil {
		data["intel_report"] = intelRep
	}

	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, bytes, 0644)
}

func maskSecrets(s string) string {
	s = tokenMaskRegex.ReplaceAllString(s, "${1}****")
	s = cookieMaskRegex.ReplaceAllString(s, "${1}=****")
	return s
}

func buildCurl(target *modules.Target, param, payload string) string {
	var headersStr string
	for k, v := range target.Headers {
		headersStr += fmt.Sprintf(" -H '%s: %s'", k, maskSecrets(v))
	}

	if target.IsJSON && target.RawJSON != "" {
		body, err := modules.SetJSONLeaf(target.RawJSON, param, payload)
		if err != nil {
			body = target.RawJSON
		}
		return fmt.Sprintf("curl -s -k -X %s%s -H 'Content-Type: application/json' --data '%s' '%s'",
			target.Method, headersStr, maskSecrets(body), target.URL)
	}

	if strings.ToUpper(target.Method) == "POST" {
		vals := url.Values{}
		for k, v := range target.Data {
			vals.Set(k, v)
		}
		vals.Set(param, payload)
		return fmt.Sprintf("curl -s -k -X POST%s --data '%s' '%s'", headersStr, vals.Encode(), target.URL)
	}

	u, err := url.Parse(target.URL)
	if err != nil {
		return fmt.Sprintf("curl -s -k%s '%s'", headersStr, target.URL)
	}
	q := u.Query()
	for k, v := range target.Params {
		q.Set(k, v)
	}
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return fmt.Sprintf("curl -s -k%s '%s'", headersStr, u.String())
}
