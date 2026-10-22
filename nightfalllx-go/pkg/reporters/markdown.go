package reporters

import (
	"encoding/json"
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
	fmt.Fprintf(f, "| Module | Title | Severity | Confidence | Parameter |\n")
	fmt.Fprintf(f, "|---|---|---|---|---|\n")

	if len(findings) == 0 {
		fmt.Fprintf(f, "| - | *No confirmed vulnerabilities detected* | - | - | - |\n")
	} else {
		for _, item := range findings {
			fmt.Fprintf(f, "| `%s` | %s | **%s** | %d%% | `%s` |\n",
				escapeMarkdownPipe(item.Module),
				escapeMarkdownPipe(item.Title),
				escapeMarkdownPipe(string(item.Severity)),
				item.Confidence,
				escapeMarkdownPipe(item.Parameter))
		}
	}

	fmt.Fprintf(f, "\n---\n\n## Detailed Vulnerability Analysis\n\n")

	for idx, item := range findings {
		curlCmd := buildCurl(target, item.Parameter, item.Payload)
		fmt.Fprintf(f, "### %d. %s\n\n", idx+1, item.Title)
		fmt.Fprintf(f, "- **Module:** `%s`\n", item.Module)
		fmt.Fprintf(f, "- **Severity:** **%s**\n", item.Severity)
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

// WriteJSONReport writes findings to a JSON file.
func WriteJSONReport(target *modules.Target, findings []*modules.Finding, filePath string) error {
	if findings == nil {
		findings = []*modules.Finding{}
	}
	data := map[string]interface{}{
		"target": map[string]interface{}{
			"url":        target.URL,
			"method":     target.Method,
			"parameters": target.Parameters(),
		},
		"scan_date":      time.Now().UTC().Format(time.RFC3339),
		"total_findings": len(findings),
		"findings":       findings,
	}

	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, bytes, 0644)
}

func buildCurl(target *modules.Target, param, payload string) string {
	if target.Method == "POST" {
		vals := url.Values{}
		for k, v := range target.Data {
			vals.Set(k, v)
		}
		vals.Set(param, payload)
		return fmt.Sprintf("curl -s -k -X POST --data '%s' '%s'", vals.Encode(), target.URL)
	}

	u, err := url.Parse(target.URL)
	if err != nil {
		return fmt.Sprintf("curl -s -k '%s'", target.URL)
	}
	q := u.Query()
	for k, v := range target.Params {
		q.Set(k, v)
	}
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return fmt.Sprintf("curl -s -k '%s'", u.String())
}
