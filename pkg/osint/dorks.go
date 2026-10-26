package osint

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// dorkTemplate represents a master GHDB / DorkSearch rule template.
type dorkTemplate struct {
	GHDBSection string
	Category    string
	Description string
	QueryFmt    string // %s will be replaced with domain
	Severity    string
}

// masterDorkTemplates contains curated high-impact Google Hacking Database (GHDB) and DorkSearch rules.
var masterDorkTemplates = []dorkTemplate{
	// 1. Files Containing Passwords & Secrets (GHDB Category 9 & 2)
	{
		GHDBSection: "GHDB-9 (Files Containing Passwords)",
		Category:    "Secrets & Credentials",
		Description: "Exposed Environment & Database Configuration Files",
		QueryFmt:    `site:%s ext:env | ext:ini | ext:yml | ext:yaml | ext:conf "DB_PASSWORD" | "SECRET_KEY" | "api_key" | "app_secret"`,
		Severity:    "CRITICAL",
	},
	{
		GHDBSection: "GHDB-9 (Files Containing Passwords)",
		Category:    "Secrets & Credentials",
		Description: "RSA/SSH Private Keys & SSL Certificates",
		QueryFmt:    `site:%s ext:pem | ext:key | ext:pkcs12 | ext:pfx | ext:crt "BEGIN RSA PRIVATE KEY" | "BEGIN PRIVATE KEY"`,
		Severity:    "CRITICAL",
	},
	{
		GHDBSection: "GHDB-9 (Files Containing Passwords)",
		Category:    "Secrets & Credentials",
		Description: "CMS Database Credentials (wp-config, configuration.php)",
		QueryFmt:    `site:%s inurl:wp-config.php | inurl:configuration.php | inurl:settings.py "DB_NAME" | "AUTH_KEY" | "SECURE_AUTH_KEY"`,
		Severity:    "CRITICAL",
	},
	{
		GHDBSection: "GHDB-9 (Files Containing Passwords)",
		Category:    "Secrets & Credentials",
		Description: "Cloud & OAuth Credentials / Tokens in Plaintext",
		QueryFmt:    `site:%s "client_secret" | "aws_secret_access_key" | "access_token" | "bearer" ext:json | ext:txt | ext:xml`,
		Severity:    "CRITICAL",
	},

	// 2. Sensitive Directories & Source Code Exposure (GHDB Category 3)
	{
		GHDBSection: "GHDB-3 (Sensitive Directories)",
		Category:    "Exposed Code & Version Control",
		Description: "Exposed Git / SVN Repositories and Configs",
		QueryFmt:    `site:%s inurl:".git" | inurl:".svn" | inurl:".env" | inurl:".dockerignore" | inurl:".gitlab-ci.yml"`,
		Severity:    "HIGH",
	},
	{
		GHDBSection: "GHDB-3 (Sensitive Directories)",
		Category:    "Exposed Code & Version Control",
		Description: "Directory Listing / Open Index of Folders",
		QueryFmt:    `site:%s intitle:"index of /" | intitle:"index of" "parent directory" | "size" | "last modified"`,
		Severity:    "HIGH",
	},
	{
		GHDBSection: "GHDB-3 (Sensitive Directories)",
		Category:    "Exposed Code & Version Control",
		Description: "Software Manifests & Dependency Definitions",
		QueryFmt:    `site:%s inurl:package.json | inurl:composer.json | inurl:pom.xml | inurl:requirements.txt | inurl:Pipfile`,
		Severity:    "MEDIUM",
	},
	{
		GHDBSection: "GHDB-3 (Sensitive Directories)",
		Category:    "Exposed Code & Version Control",
		Description: "Developer Source Backup Files & Editors Swaps",
		QueryFmt:    `site:%s ext:bak | ext:old | ext:backup | ext:swp | ext:save | ext:~ | ext:orig`,
		Severity:    "HIGH",
	},

	// 3. Pages Containing Login Portals (GHDB Category 12)
	{
		GHDBSection: "GHDB-12 (Login Portals)",
		Category:    "Admin & Portals",
		Description: "Administrative Access Panels & Dashboards",
		QueryFmt:    `site:%s inurl:admin | inurl:administrator | inurl:cpanel | inurl:dashboard | inurl:controlpanel`,
		Severity:    "MEDIUM",
	},
	{
		GHDBSection: "GHDB-12 (Login Portals)",
		Category:    "Admin & Portals",
		Description: "Authentication & User Login Endpoints",
		QueryFmt:    `site:%s inurl:login | inurl:signin | inurl:auth | inurl:sso | inurl:wp-login.php`,
		Severity:    "MEDIUM",
	},
	{
		GHDBSection: "GHDB-12 (Login Portals)",
		Category:    "Admin & Portals",
		Description: "Internal Employee & Corporate Single Sign-On (SSO)",
		QueryFmt:    `site:%s intitle:"Sign In" | intitle:"Admin Login" | intitle:"Single Sign-On" | intitle:"Okta"`,
		Severity:    "INFO",
	},

	// 4. Database Files, SQL Backups & Dumps (GHDB Category 5)
	{
		GHDBSection: "GHDB-5 (Vulnerable Files)",
		Category:    "Database & Storage Dumps",
		Description: "Raw Database Dumps and SQL Export Files",
		QueryFmt:    `site:%s ext:sql | ext:db | ext:sqlite | ext:sqlite3 | ext:dump "INSERT INTO" | "CREATE TABLE"`,
		Severity:    "CRITICAL",
	},
	{
		GHDBSection: "GHDB-5 (Vulnerable Files)",
		Category:    "Database & Storage Dumps",
		Description: "Full Site or Database Archive Packages",
		QueryFmt:    `site:%s ext:tar | ext:tar.gz | ext:zip | ext:7z | ext:rar "backup" | "db" | "dump"`,
		Severity:    "HIGH",
	},
	{
		GHDBSection: "GHDB-5 (Vulnerable Files)",
		Category:    "Database & Storage Dumps",
		Description: "Web Database Admin Tools (phpMyAdmin, Adminer)",
		QueryFmt:    `site:%s inurl:phpmyadmin | inurl:pma | inurl:adminer | inurl:dbadmin`,
		Severity:    "HIGH",
	},

	// 5. Error Logs & Debug Information Disclosure (GHDB Category 7)
	{
		GHDBSection: "GHDB-7 (Error Messages)",
		Category:    "Logs & Debug Diagnostics",
		Description: "Application Runtime Error Logs & Stack Traces",
		QueryFmt:    `site:%s ext:log "error" | "exception" | "warning" | "fatal" | "traceback"`,
		Severity:    "HIGH",
	},
	{
		GHDBSection: "GHDB-7 (Error Messages)",
		Category:    "Logs & Debug Diagnostics",
		Description: "PHP Framework Debug Leaks & Warning Messages",
		QueryFmt:    `site:%s "PHP Parse error" | "PHP Fatal error" | "Uncaught exception" | "Warning: mysqli_"`,
		Severity:    "MEDIUM",
	},
	{
		GHDBSection: "GHDB-7 (Error Messages)",
		Category:    "Logs & Debug Diagnostics",
		Description: "Diagnostic & Information Disclosure Pages (phpinfo, server-status)",
		QueryFmt:    `site:%s inurl:phpinfo.php | inurl:info.php | inurl:server-status | inurl:server-info`,
		Severity:    "HIGH",
	},
	{
		GHDBSection: "GHDB-7 (Error Messages)",
		Category:    "Logs & Debug Diagnostics",
		Description: "Interactive Debuggers Exposed (Werkzeug, Django, Laravel Flare)",
		QueryFmt:    `site:%s "Werkzeug powered" | "Traceback (most recent call last)" | "Whoops! There was an error"`,
		Severity:    "CRITICAL",
	},

	// 6. APIs, Microservices & Documentation (DorkSearch Category)
	{
		GHDBSection: "DorkSearch-API (API Recon)",
		Category:    "APIs & Microservices",
		Description: "Swagger / OpenAPI Interactive API Documentation",
		QueryFmt:    `site:%s inurl:swagger | inurl:swagger-ui | inurl:swagger.json | inurl:api-docs | inurl:openapi.json`,
		Severity:    "MEDIUM",
	},
	{
		GHDBSection: "DorkSearch-API (API Recon)",
		Category:    "APIs & Microservices",
		Description: "GraphQL Consoles & Interactive Playgrounds",
		QueryFmt:    `site:%s inurl:graphql | inurl:graphiql | inurl:altair | inurl:playground`,
		Severity:    "MEDIUM",
	},
	{
		GHDBSection: "DorkSearch-API (API Recon)",
		Category:    "APIs & Microservices",
		Description: "REST API Endpoint Discovery (v1, v2, v3)",
		QueryFmt:    `site:%s inurl:"/api/v1" | inurl:"/api/v2" | inurl:"/rest" | inurl:"/v1/api"`,
		Severity:    "INFO",
	},

	// 7. Third-Party Leaks & Cloud Buckets (DorkSearch & External GHDB)
	{
		GHDBSection: "DorkSearch-Cloud (Cloud Storage)",
		Category:    "Cloud & 3rd-Party Leaks",
		Description: "Amazon AWS S3 Public Buckets",
		QueryFmt:    `site:s3.amazonaws.com "%s"`,
		Severity:    "HIGH",
	},
	{
		GHDBSection: "DorkSearch-Cloud (Cloud Storage)",
		Category:    "Cloud & 3rd-Party Leaks",
		Description: "Microsoft Azure Blob Public Storage Containers",
		QueryFmt:    `site:blob.core.windows.net "%s"`,
		Severity:    "HIGH",
	},
	{
		GHDBSection: "DorkSearch-Cloud (Cloud Storage)",
		Category:    "Cloud & 3rd-Party Leaks",
		Description: "Google Cloud Storage (GCS) Public Buckets",
		QueryFmt:    `site:storage.googleapis.com "%s"`,
		Severity:    "HIGH",
	},
	{
		GHDBSection: "DorkSearch-Cloud (Cloud Storage)",
		Category:    "Cloud & 3rd-Party Leaks",
		Description: "Public GitHub Repositories Referencing Target Secrets",
		QueryFmt:    `site:github.com "%s" "password" | "secret" | "api_key" | "token"`,
		Severity:    "HIGH",
	},
	{
		GHDBSection: "DorkSearch-Cloud (Cloud Storage)",
		Category:    "Cloud & 3rd-Party Leaks",
		Description: "Public Pastebin / Paste Dumps Referencing Target",
		QueryFmt:    `site:pastebin.com "%s"`,
		Severity:    "MEDIUM",
	},
	{
		GHDBSection: "DorkSearch-Cloud (Cloud Storage)",
		Category:    "Cloud & 3rd-Party Leaks",
		Description: "Public Trello Boards & Project Workspaces",
		QueryFmt:    `site:trello.com "%s"`,
		Severity:    "MEDIUM",
	},

	// 8. Confidential Documents & PII (GHDB Category 8)
	{
		GHDBSection: "GHDB-8 (Sensitive Info)",
		Category:    "Documents & PII Leaks",
		Description: "Confidential / Internal Office Documents",
		QueryFmt:    `site:%s ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx "confidential" | "internal use only" | "strictly private"`,
		Severity:    "HIGH",
	},
	{
		GHDBSection: "GHDB-8 (Sensitive Info)",
		Category:    "Documents & PII Leaks",
		Description: "Exposed Customer / Employee PII in CSV or Excel",
		QueryFmt:    `site:%s ext:csv | ext:tsv | ext:xls | ext:xlsx "email" | "password" | "phone" | "ssn" | "salary"`,
		Severity:    "HIGH",
	},
}

// GenerateDorks creates customized Exploit-DB GHDB and DorkSearch intelligence queries for the target.
func GenerateDorks(domain string) []GoogleDork {
	cleanDomain := strings.TrimSpace(strings.ToLower(domain))
	cleanDomain = strings.TrimPrefix(cleanDomain, "http://")
	cleanDomain = strings.TrimPrefix(cleanDomain, "https://")
	if idx := strings.Index(cleanDomain, "/"); idx != -1 {
		cleanDomain = cleanDomain[:idx]
	}
	if idx := strings.Index(cleanDomain, ":"); idx != -1 {
		cleanDomain = cleanDomain[:idx]
	}

	dorks := make([]GoogleDork, 0, len(masterDorkTemplates))
	for _, tpl := range masterDorkTemplates {
		query := fmt.Sprintf(tpl.QueryFmt, cleanDomain)
		encodedQuery := url.QueryEscape(query)

		dorks = append(dorks, GoogleDork{
			Category:      tpl.Category,
			Description:   tpl.Description,
			Query:         query,
			Severity:      tpl.Severity,
			GHDBSection:   tpl.GHDBSection,
			GoogleURL:     "https://www.google.com/search?q=" + encodedQuery,
			DorkSearchURL: "https://dorksearch.com/?q=" + encodedQuery,
			BingURL:       "https://www.bing.com/search?q=" + encodedQuery,
		})
	}
	return dorks
}

// PrintDorksReport renders a comprehensive, categorized terminal view of GHDB & DorkSearch intelligence.
func PrintDorksReport(domain string, dorks []GoogleDork) {
	fmt.Println()
	fmt.Println("\033[1;31m╔══════════════════════════════════════════════════════════════════════════════╗\033[0m")
	fmt.Println("\033[1;31m║   🔥 Exploit-DB GHDB & DorkSearch OSINT Reconnaissance Engine               ║\033[0m")
	fmt.Printf("\033[1;31m║   Target Domain : \033[1;37m%-58s\033[1;31m ║\033[0m\n", domain)
	fmt.Println("\033[1;31m╚══════════════════════════════════════════════════════════════════════════════╝\033[0m")
	fmt.Println()

	// Group by category
	categories := make(map[string][]GoogleDork)
	categoryOrder := []string{}
	for _, d := range dorks {
		if _, exists := categories[d.Category]; !exists {
			categoryOrder = append(categoryOrder, d.Category)
		}
		categories[d.Category] = append(categories[d.Category], d)
	}

	for _, cat := range categoryOrder {
		items := categories[cat]
		fmt.Printf("\033[1;35m[●] Category: %s (%d dorks)\033[0m\n", cat, len(items))

		for i, item := range items {
			sevColor := "\033[1;32m" // INFO
			switch item.Severity {
			case "CRITICAL":
				sevColor = "\033[1;31m"
			case "HIGH":
				sevColor = "\033[1;33m"
			case "MEDIUM":
				sevColor = "\033[1;34m"
			}

			fmt.Printf("    ├── \033[1;37m[%d] %s\033[0m %s[%s]\033[0m (\033[36m%s\033[0m)\n", i+1, item.Description, sevColor, item.Severity, item.GHDBSection)
			fmt.Printf("    │   ├── Query      : \033[1;33m%s\033[0m\n", item.Query)
			fmt.Printf("    │   ├── Google     : \033[34m%s\033[0m\n", item.GoogleURL)
			fmt.Printf("    │   └── DorkSearch : \033[32m%s\033[0m\n", item.DorkSearchURL)
		}
		fmt.Println()
	}
	fmt.Printf("\033[1;32m[+] Successfully generated %d Exploit-DB GHDB & DorkSearch intelligence queries for %s\033[0m\n\n", len(dorks), domain)
}

// ExportDorksJSON outputs generated dorks formatted as a JSON string.
func ExportDorksJSON(dorks []GoogleDork) (string, error) {
	bytes, err := json.MarshalIndent(dorks, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// ExportDorksHTML writes a standalone, dark-themed, interactive HTML Dork Dashboard with 1-click links.
func ExportDorksHTML(domain string, dorks []GoogleDork, outputPath string) error {
	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NightfallLX - GHDB & DorkSearch OSINT Report (` + domain + `)</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-card: #21262d;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-red: #f85149;
            --accent-green: #3fb950;
            --accent-blue: #58a6ff;
            --accent-yellow: #d29922;
            --accent-purple: #bc8cff;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 30px 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #1f0707 0%, var(--bg-secondary) 100%);
            border: 1px solid #6e1c1c;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
        }
        .header h1 {
            margin: 0 0 10px 0;
            color: var(--accent-red);
            font-size: 26px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .header p {
            margin: 0;
            color: var(--text-secondary);
            font-size: 14px;
        }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .badge-critical { background: rgba(248, 81, 73, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }
        .badge-high { background: rgba(210, 153, 34, 0.2); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }
        .badge-medium { background: rgba(88, 166, 255, 0.2); color: var(--accent-blue); border: 1px solid var(--accent-blue); }
        .badge-info { background: rgba(63, 185, 80, 0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }
        .card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 16px;
            padding: 16px 20px;
            transition: transform 0.15s ease, border-color 0.15s ease;
        }
        .card:hover {
            border-color: #58a6ff;
            transform: translateY(-2px);
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .card-title {
            font-size: 16px;
            font-weight: 600;
            color: #ffffff;
        }
        .query-box {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 10px 14px;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
            font-size: 13px;
            color: #79c0ff;
            word-break: break-all;
            margin-bottom: 12px;
        }
        .btn-group {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            text-decoration: none;
            cursor: pointer;
            border: 1px solid transparent;
            transition: all 0.2s;
        }
        .btn-google { background: #1a73e8; color: #ffffff; }
        .btn-google:hover { background: #1557b0; }
        .btn-dorksearch { background: #238636; color: #ffffff; }
        .btn-dorksearch:hover { background: #2ea043; }
        .btn-bing { background: #008080; color: #ffffff; }
        .btn-bing:hover { background: #005959; }
        .meta-tag {
            font-size: 12px;
            color: var(--text-secondary);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔥 NightfallLX Exploit-DB GHDB & DorkSearch OSINT Dossier</h1>
            <p>Target Domain: <strong style="color:#ffffff;">` + domain + `</strong> | Total Intelligence Dorks: <strong style="color:var(--accent-red);">` + fmt.Sprintf("%d", len(dorks)) + `</strong> | Generated via Exploit-DB Google Hacking Database & DorkSearch API Matrix</p>
        </div>
`)

	for _, d := range dorks {
		badgeClass := "badge-info"
		switch d.Severity {
		case "CRITICAL":
			badgeClass = "badge-critical"
		case "HIGH":
			badgeClass = "badge-high"
		case "MEDIUM":
			badgeClass = "badge-medium"
		}

		sb.WriteString(`
        <div class="card">
            <div class="card-header">
                <span class="card-title">` + d.Description + `</span>
                <div>
                    <span class="meta-tag" style="margin-right:8px;">` + d.GHDBSection + `</span>
                    <span class="badge ` + badgeClass + `">` + d.Severity + `</span>
                </div>
            </div>
            <div class="query-box">` + d.Query + `</div>
            <div class="btn-group">
                <a href="` + d.GoogleURL + `" target="_blank" rel="noopener noreferrer" class="btn btn-google">🔍 Search on Google</a>
                <a href="` + d.DorkSearchURL + `" target="_blank" rel="noopener noreferrer" class="btn btn-dorksearch">⚡ Search on DorkSearch</a>
                <a href="` + d.BingURL + `" target="_blank" rel="noopener noreferrer" class="btn btn-bing">🌐 Search on Bing</a>
            </div>
        </div>`)
	}

	sb.WriteString(`
    </div>
</body>
</html>`)

	return os.WriteFile(outputPath, []byte(sb.String()), 0644)
}
