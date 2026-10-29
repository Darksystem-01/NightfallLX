package modules

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"nightfalllx/pkg/client"
)

// GitObject represents a discovered Git repository object (file/tree).
type GitObject struct {
	Path     string `json:"path"`
	Size     int    `json:"size"`
	Content  string `json:"content,omitempty"`
	Readable bool   `json:"readable"`
}

// GitDumpReport summarises results of a .git/ exposure audit and dump.
type GitDumpReport struct {
	TargetURL      string       `json:"target_url"`
	Exposed        bool         `json:"exposed"`
	HEADRef        string       `json:"head_ref"`
	DiscoveredFiles []string    `json:"discovered_files"`
	SensitiveFiles  []*GitObject `json:"sensitive_files"`
}

// Critical paths that indicate a live, readable .git directory.
var gitProbeEndpoints = []string{
	"/.git/HEAD",
	"/.git/config",
	"/.git/COMMIT_EDITMSG",
	"/.git/index",
	"/.git/logs/HEAD",
	"/.git/refs/heads/main",
	"/.git/refs/heads/master",
	"/.git/info/refs",
	"/.git/packed-refs",
}

// High-value files to exfiltrate once .git is confirmed accessible.
var gitSensitivePaths = []string{
	"/.git/config",
	"/.git/COMMIT_EDITMSG",
	"/.git/logs/HEAD",
	"/.git/packed-refs",
	"/.git/refs/heads/main",
	"/.git/refs/heads/master",
	"/.git/refs/heads/develop",
	"/.env",
	"/.env.local",
	"/.env.production",
	"/.env.staging",
	"/config/database.yml",
	"/config/secrets.yml",
	"/config/application.yml",
	"/wp-config.php",
	"/configuration.php",
	"/settings.py",
	"/local_settings.py",
	"/app/config/config.php",
	"/laravel/.env",
	"/.aws/credentials",
	"/.ssh/id_rsa",
}

// gitKeywords triggers a high-severity finding when present in dumped content.
var gitKeywords = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey", "private_key",
	"access_key", "credential", "database_url", "db_pass", "smtp_pass", "auth_key",
}

// GitDumperModule checks for and dumps exposed .git repositories.
type GitDumperModule struct{}

func NewGitDumperModule() *GitDumperModule { return &GitDumperModule{} }
func (m *GitDumperModule) Name() string        { return "gitdumper" }
func (m *GitDumperModule) Description() string {
	return "Detects and extracts contents from exposed .git/ directories and sensitive config files"
}
func (m *GitDumperModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	_, findings, err := AuditGitExposure(target.URL, c)
	return findings, err
}

// AuditGitExposure probes for .git/ exposure then exfiltrates high-value files.
func AuditGitExposure(targetURL string, c *client.Client) (*GitDumpReport, []*Finding, error) {
	base, err := url.Parse(targetURL)
	if err != nil {
		return nil, nil, err
	}
	origin := fmt.Sprintf("%s://%s", base.Scheme, base.Host)

	report := &GitDumpReport{TargetURL: targetURL}
	var findings []*Finding

	// ── Phase 1: Confirm .git is accessible ────────────────────────────────
	gitConfirmed := false
	for _, probe := range gitProbeEndpoints {
		probeURL := origin + probe
		resp, pErr := c.Request("GET", probeURL, "", nil)
		if pErr != nil || resp == nil {
			continue
		}
		// .git/HEAD always starts with "ref:" or a raw SHA
		if probe == "/.git/HEAD" {
			if resp.StatusCode == 200 && (strings.Contains(resp.Body, "ref:") || len(resp.Body) == 41) {
				gitConfirmed = true
				report.HEADRef = strings.TrimSpace(resp.Body)
				report.Exposed = true
				report.DiscoveredFiles = append(report.DiscoveredFiles, probeURL)

				findings = append(findings, &Finding{
					Module:      "gitdumper",
					Title:       "Exposed .git/ Repository Directory",
					Severity:    SeverityCritical,
					Confidence:  99,
					URL:         probeURL,
					Parameter:   "path",
					Payload:     "/.git/HEAD",
					Detail:      fmt.Sprintf("The .git/ directory is publicly accessible on %s. An attacker can reconstruct the full source code of the application by downloading Git object files.", origin),
					Evidence:    fmt.Sprintf("GET /.git/HEAD -> HTTP 200, body: %s", strings.TrimSpace(resp.Body)),
					Remediation: "Block all requests to /.git/ in your web server configuration (Nginx: deny all; Apache: Require all denied). Remove the .git directory from your web root entirely.",
					CWEID:       538,
					CVSS:        9.1,
				})
				break
			}
		} else if resp.StatusCode == 200 && len(resp.Body) > 0 {
			report.DiscoveredFiles = append(report.DiscoveredFiles, probeURL)
		}
	}

	if !gitConfirmed {
		// Still check for .git/config exposure even if HEAD check was ambiguous
		cfgURL := origin + "/.git/config"
		resp, _ := c.Request("GET", cfgURL, "", nil)
		if resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Body, "[core]") {
			gitConfirmed = true
			report.Exposed = true
			report.DiscoveredFiles = append(report.DiscoveredFiles, cfgURL)
		}
	}

	// ── Phase 2: Exfiltrate sensitive files ────────────────────────────────
	for _, sensPath := range gitSensitivePaths {
		probeURL := origin + sensPath
		resp, pErr := c.Request("GET", probeURL, "", nil)
		if pErr != nil || resp == nil || resp.StatusCode != 200 || len(resp.Body) == 0 {
			continue
		}
		body := resp.Body

		if !isValidExposedContent(sensPath, body) {
			continue
		}

		obj := &GitObject{
			Path:     sensPath,
			Size:     len(body),
			Readable: true,
		}

		// Detect credential-grade content
		bodyLower := strings.ToLower(body)
		hasCredential := false
		for _, kw := range gitKeywords {
			if strings.Contains(bodyLower, kw) {
				hasCredential = true
				break
			}
		}

		// Truncate displayed content
		preview := body
		if len(preview) > 600 {
			preview = preview[:600] + "\n... [truncated]"
		}
		obj.Content = preview

		report.SensitiveFiles = append(report.SensitiveFiles, obj)
		report.DiscoveredFiles = append(report.DiscoveredFiles, probeURL)

		sev := SeverityHigh
		cvss := 7.5
		detail := fmt.Sprintf("Sensitive file '%s' is publicly readable (HTTP 200, %d bytes).", sensPath, len(body))
		if hasCredential {
			sev = SeverityCritical
			cvss = 9.5
			detail += " File content contains credential-grade keywords (password/token/secret/api_key)."
		}

		title := fmt.Sprintf("Exposed Sensitive File: %s", sensPath)
		if strings.HasPrefix(sensPath, "/.git/") {
			title = fmt.Sprintf("Exposed Git Object: %s", sensPath)
		}

		findings = append(findings, &Finding{
			Module:      "gitdumper",
			Title:       title,
			Severity:    sev,
			Confidence:  95,
			URL:         probeURL,
			Parameter:   "path",
			Payload:     sensPath,
			Detail:      detail,
			Evidence:    fmt.Sprintf("HTTP 200 OK | Size: %d bytes | Preview: %.200s", len(body), body),
			Remediation: "Remove sensitive files from web-accessible directories. Use environment variables for secrets. Add .env and .git to .gitignore.",
			CWEID:       538,
			CVSS:        cvss,
		})
	}

	return report, findings, nil
}

// PrintGitDumpReport renders a colour-coded terminal summary.
func PrintGitDumpReport(rep *GitDumpReport) {
	fmt.Println("\n\033[1;36m┌──────────────────────────────────────────────────────────────────────────────────┐\033[0m")
	fmt.Printf("\033[1;36m│\033[0m \033[1;37m🗂️  NightfallLX Git Repository & Sensitive File Exposure Engine\033[0m                  \033[1;36m│\033[0m\n")
	fmt.Printf("\033[1;36m│\033[0m Target: \033[1;33m%-73s\033[0m \033[1;36m│\033[0m\n", rep.TargetURL)
	if rep.Exposed {
		fmt.Printf("\033[1;36m│\033[0m \033[1;31m.git Status: EXPOSED\033[0m (HEAD: %-52s) \033[1;36m│\033[0m\n", rep.HEADRef)
	} else {
		fmt.Printf("\033[1;36m│\033[0m \033[1;32m.git Status: Protected\033[0m                                                          \033[1;36m│\033[0m\n")
	}
	fmt.Printf("\033[1;36m│\033[0m Files Discovered: \033[1;35m%-64d\033[0m \033[1;36m│\033[0m\n", len(rep.DiscoveredFiles))
	fmt.Println("\033[1;36m└──────────────────────────────────────────────────────────────────────────────────┘\033[0m")

	if len(rep.SensitiveFiles) == 0 {
		fmt.Println("\033[1;32m[+] No sensitive files publicly accessible.\033[0m")
		return
	}

	for _, f := range rep.SensitiveFiles {
		fmt.Printf("\n  \033[1;31m[EXPOSED]\033[0m \033[1m%s\033[0m (%d bytes)\n", f.Path, f.Size)
		if f.Content != "" {
			lines := strings.Split(f.Content, "\n")
			limit := 8
			if len(lines) < limit {
				limit = len(lines)
			}
			for _, l := range lines[:limit] {
				fmt.Printf("    \033[90m│\033[0m %s\n", l)
			}
		}
	}
	fmt.Println()
}


func isValidExposedContent(path, body string) bool {
	trimmed := strings.TrimSpace(body)
	lower := strings.ToLower(trimmed)

	// Reject any HTML document (SPA fallback or 200 OK custom error page)
	if strings.HasPrefix(lower, "<!doctype") ||
		strings.HasPrefix(lower, "<html") ||
		strings.Contains(lower, "<head>") ||
		strings.Contains(lower, "<body>") ||
		strings.Contains(lower, "__next") ||
		strings.Contains(lower, "<div id=\"root\"") {
		return false
	}

	if strings.Contains(path, ".env") {
		envRegex := regexp.MustCompile(`(?m)^[A-Za-z0-9_]{2,}\s*=\s*\S+`)
		return envRegex.MatchString(trimmed)
	}

	if path == "/.git/config" {
		return strings.Contains(trimmed, "[core]") || strings.Contains(trimmed, "[remote")
	}

	if path == "/.git/logs/HEAD" {
		logRegex := regexp.MustCompile(`(?m)^[0-9a-f]{40}\s+[0-9a-f]{40}`)
		return logRegex.MatchString(trimmed)
	}

	if path == "/wp-config.php" {
		return strings.Contains(trimmed, "<?php") && (strings.Contains(trimmed, "define(") || strings.Contains(trimmed, "DB_") || strings.Contains(trimmed, "") || strings.Contains(trimmed, "AUTH_KEY"))
	}

	if path == "/.ssh/id_rsa" {
		return strings.Contains(trimmed, "BEGIN OPENSSH PRIVATE KEY") || strings.Contains(trimmed, "BEGIN RSA PRIVATE KEY")
	}

	if path == "/.aws/credentials" {
		return strings.Contains(trimmed, "aws_access_key_id") || strings.Contains(trimmed, "[default]")
	}

	if strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml") {
		yamlRegex := regexp.MustCompile(`(?m)^[a-zA-Z0-9_\-\.]+\s*:\s*\S+`)
		return yamlRegex.MatchString(trimmed)
	}

	return true
}
