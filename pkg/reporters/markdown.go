package reporters

import (
	"fmt"
	"net/url"
	"nightfalllx/pkg/modules"
	"os"
	"strings"
	"time"
)

// WriteMarkdownReport writes a formatted lab assessment report to a markdown file.
func WriteMarkdownReport(target *modules.Target, findings []*modules.Finding, filePath string) error {
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
	fmt.Fprintf(f, "| Module | Title | Severity | CVSS 3.1 | Confidence | Parameter |\n")
	fmt.Fprintf(f, "|---|---|---|---|---|---|\n")

	if len(findings) == 0 {
		fmt.Fprintf(f, "| - | *No confirmed vulnerabilities detected* | - | - | - | - |\n")
	} else {
		for _, item := range findings {
			item.NormalizeCVSS()
			cvssDisplay := fmt.Sprintf("%.1f", item.CVSS)
			if item.CVSS == 0.0 {
				cvssDisplay = "-"
			}
			fmt.Fprintf(f, "| `%s` | %s | **%s** | %s | %d%% | `%s` |\n",
				escapeMarkdownPipe(item.Module),
				escapeMarkdownPipe(item.Title),
				escapeMarkdownPipe(string(item.Severity)),
				cvssDisplay,
				item.Confidence,
				escapeMarkdownPipe(item.Parameter))
		}
	}

	fmt.Fprintf(f, "\n---\n\n## Detailed Vulnerability Analysis\n\n")

	for idx, item := range findings {
		curlCmd := buildCurlFinding(target, item)
		fmt.Fprintf(f, "### %d. %s\n\n", idx+1, item.Title)
		fmt.Fprintf(f, "- **Module:** `%s`\n", item.Module)
		item.NormalizeCVSS()
		fmt.Fprintf(f, "- **Severity:** **%s**\n", item.Severity)
		if item.CVSS > 0 || item.CVSSVector != "" {
			fmt.Fprintf(f, "- **CVSS v3.1:** `%.1f` — `%s`\n", item.CVSS, item.CVSSVector)
		}
		fmt.Fprintf(f, "- **Confidence:** %d%%\n", item.Confidence)
		if item.CWEID > 0 {
			fmt.Fprintf(f, "- **CWE ID:** [CWE-%d](https://cwe.mitre.org/data/definitions/%d.html)\n", item.CWEID, item.CWEID)
		}
		fmt.Fprintf(f, "- **Vulnerable Parameter:** `%s`\n", item.Parameter)
		fmt.Fprintf(f, "- **PoC Payload:** `%s`\n\n", item.Payload)
		fmt.Fprintf(f, "#### Reproduction Command\n```bash\n%s\n```\n\n", curlCmd)
		fmt.Fprintf(f, "#### Analysis & Evidence\n- **Detail:** %s\n- **Evidence:** %s\n\n", item.Detail, item.Evidence)
		fmt.Fprintf(f, "#### Remediation\n%s\n\n", item.Remediation)
	}

	return nil
}

func escapeMarkdownPipe(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

// WriteJSONReport lives in json.go and emits the structured report model.

func buildCurlFinding(target *modules.Target, f *modules.Finding) string {
	if f == nil && target == nil {
		return ""
	}

	reqURL := ""
	if f != nil && f.URL != "" {
		reqURL = f.URL
	} else if target != nil && target.URL != "" {
		reqURL = target.URL
	}

	param := ""
	payload := ""
	module := ""
	if f != nil {
		param = f.Parameter
		payload = f.Payload
		module = f.Module
	}

	trimmedPayload := strings.TrimSpace(payload)
	isJSONPayload := strings.HasPrefix(trimmedPayload, "{") || strings.HasPrefix(trimmedPayload, "[")

	// Case 1: GraphQL / JSON requests
	if module == "graphql" || isJSONPayload {
		// If it's a GET GraphQL probe (e.g. ?query=...)
		if strings.Contains(reqURL, "?query=") || (f != nil && strings.Contains(strings.ToLower(f.Title), "get method")) {
			return fmt.Sprintf("curl -s -k '%s'", reqURL)
		}
		if trimmedPayload != "" {
			safePayload := strings.ReplaceAll(payload, "'", "'\\''")
			return fmt.Sprintf("curl -s -k -X POST -H 'Content-Type: application/json' --data-raw '%s' '%s'", safePayload, reqURL)
		}
	}

	// Case 2: Target or Finding is explicitly POST / PUT
	targetMethod := "GET"
	if target != nil && target.Method != "" {
		targetMethod = strings.ToUpper(target.Method)
	}

	if targetMethod == "POST" || targetMethod == "PUT" || targetMethod == "PATCH" {
		if isJSONPayload {
			safePayload := strings.ReplaceAll(payload, "'", "'\\''")
			return fmt.Sprintf("curl -s -k -X %s -H 'Content-Type: application/json' --data-raw '%s' '%s'", targetMethod, safePayload, reqURL)
		}

		vals := url.Values{}
		if target != nil {
			for k, v := range target.Data {
				vals.Set(k, v)
			}
		}
		if param != "" {
			vals.Set(param, payload)
		}
		encoded := vals.Encode()
		if encoded != "" {
			return fmt.Sprintf("curl -s -k -X %s --data '%s' '%s'", targetMethod, encoded, reqURL)
		}
		return fmt.Sprintf("curl -s -k -X %s '%s'", targetMethod, reqURL)
	}

	// Case 3: GET with parameter swapped
	if target != nil && param != "" {
		swappedURL := target.BuildURLWithParam(param, payload)
		return fmt.Sprintf("curl -s -k '%s'", swappedURL)
	}

	return fmt.Sprintf("curl -s -k '%s'", reqURL)
}

func buildCurl(target *modules.Target, param, payload string) string {
	return buildCurlFinding(target, &modules.Finding{Parameter: param, Payload: payload})
}
