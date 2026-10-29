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
	QueryFmt    string // %s will be replaced with clean domain
	Severity    string
}

// masterDorkTemplates contains strictly curated, verified Google Hacking Database (GHDB) and DorkSearch queries.
// All boolean operators strictly adhere to Google search engine grammar: uppercase "OR" with parenthetical grouping "(...)".
var masterDorkTemplates = []dorkTemplate{
	// 1. Files Containing Passwords & Secrets (GHDB Category 9 & 2)
	{
		GHDBSection: "GHDB-9 (Files Containing Passwords)",
		Category:    "Secrets & Credentials",
		Description: "Exposed Environment & Database Configuration Files",
		QueryFmt:    `site:%s (filetype:env OR filetype:ini OR filetype:yml OR filetype:yaml OR filetype:conf) ("DB_PASSWORD" OR "SECRET_KEY" OR "api_key" OR "app_secret")`,
		Severity:    "CRITICAL",
	},
	{
		GHDBSection: "GHDB-9 (Files Containing Passwords)",
		Category:    "Secrets & Credentials",
		Description: "RSA/SSH Private Keys & SSL Certificates",
		QueryFmt:    `site:%s (filetype:pem OR filetype:key OR filetype:pkcs12 OR filetype:pfx OR filetype:crt) ("BEGIN RSA PRIVATE KEY" OR "BEGIN PRIVATE KEY" OR "BEGIN OPENSSH PRIVATE KEY")`,
		Severity:    "CRITICAL",
	},
	{
		GHDBSection: "GHDB-9 (Files Containing Passwords)",
		Category:    "Secrets & Credentials",
		Description: "CMS Database Credentials (wp-config, configuration.php)",
		QueryFmt:    `site:%s (inurl:wp-config.php OR inurl:configuration.php OR inurl:settings.py OR inurl:database.php) ("DB_NAME" OR "DB_PASSWORD" OR "AUTH_KEY" OR "SECURE_AUTH_KEY")`,
		Severity:    "CRITICAL",
	},
	{
		GHDBSection: "GHDB-9 (Files Containing Passwords)",
		Category:    "Secrets & Credentials",
		Description: "Cloud & OAuth Credentials / Tokens in Plaintext",
		QueryFmt:    `site:%s ("client_secret" OR "aws_secret_access_key" OR "access_token" OR "bearer") (filetype:json OR filetype:txt OR filetype:xml OR filetype:env)`,
		Severity:    "CRITICAL",
	},

	// 2. Sensitive Directories & Source Code Exposure (GHDB Category 3)
	{
		GHDBSection: "GHDB-3 (Sensitive Directories)",
		Category:    "Exposed Code & Version Control",
		Description: "Exposed Git / SVN Repositories & CI/CD Configs",
		QueryFmt:    `site:%s (inurl:".git" OR inurl:".svn" OR inurl:".env" OR inurl:".dockerignore" OR inurl:".gitlab-ci.yml")`,
		Severity:    "HIGH",
	},
	{
		GHDBSection: "GHDB-3 (Sensitive Directories)",
		Category:    "Exposed Code & Version Control",
		Description: "Directory Listing / Open Index of Folders",
		QueryFmt:    `site:%s (intitle:"index of /" OR intitle:"index of") ("parent directory" OR "size" OR "last modified")`,
		Severity:    "HIGH",
	},
	{
		GHDBSection: "GHDB-3 (Sensitive Directories)",
		Category:    "Exposed Code & Version Control",
		Description: "Software Manifests & Dependency Definitions",
		QueryFmt:    `site:%s (inurl:package.json OR inurl:composer.json OR inurl:pom.xml OR inurl:requirements.txt OR inurl:Pipfile OR inurl:build.gradle)`,
		Severity:    "MEDIUM",
	},
	{
		GHDBSection: "GHDB-3 (Sensitive Directories)",
		Category:    "Exposed Code & Version Control",
		Description: "Developer Source Backup Files & Editors Swaps",
		QueryFmt:    `site:%s (ext:bak OR ext:old OR ext:backup OR ext:swp OR ext:save OR ext:~ OR ext:orig OR ext:tmp)`,
		Severity:    "HIGH",
	},

	// 3. Pages Containing Login Portals (GHDB Category 12)
	{
		GHDBSection: "GHDB-12 (Login Portals)",
		Category:    "Admin & Portals",
		Description: "Administrative Access Panels & Dashboards",
		QueryFmt:    `site:%s (inurl:admin OR inurl:administrator OR inurl:cpanel OR inurl:dashboard OR inurl:controlpanel)`,
		Severity:    "MEDIUM",
	},
	{
		GHDBSection: "GHDB-12 (Login Portals)",
		Category:    "Admin & Portals",
		Description: "Authentication & User Login Endpoints",
		QueryFmt:    `site:%s (inurl:login OR inurl:signin OR inurl:auth OR inurl:sso OR inurl:wp-login.php)`,
		Severity:    "MEDIUM",
	},
	{
		GHDBSection: "GHDB-12 (Login Portals)",
		Category:    "Admin & Portals",
		Description: "Internal Employee & Corporate Single Sign-On (SSO)",
		QueryFmt:    `site:%s (intitle:"Sign In" OR intitle:"Admin Login" OR intitle:"Single Sign-On" OR intitle:"Okta" OR intitle:"Keycloak")`,
		Severity:    "INFO",
	},

	// 4. Database Files, SQL Backups & Dumps (GHDB Category 5)
	{
		GHDBSection: "GHDB-5 (Vulnerable Files)",
		Category:    "Database & Storage Dumps",
		Description: "Raw Database Dumps and SQL Export Files",
		QueryFmt:    `site:%s (filetype:sql OR filetype:db OR filetype:sqlite OR filetype:sqlite3 OR filetype:dump) ("INSERT INTO" OR "CREATE TABLE" OR "DATABASE")`,
		Severity:    "CRITICAL",
	},
	{
		GHDBSection: "GHDB-5 (Vulnerable Files)",
		Category:    "Database & Storage Dumps",
		Description: "Full Site or Database Archive Packages",
		QueryFmt:    `site:%s (filetype:tar OR filetype:tar.gz OR filetype:zip OR filetype:7z OR filetype:rar OR filetype:gz) ("backup" OR "dump" OR "db" OR "data")`,
		Severity:    "HIGH",
	},
	{
		GHDBSection: "GHDB-5 (Vulnerable Files)",
		Category:    "Database & Storage Dumps",
		Description: "Web Database Admin Tools (phpMyAdmin, Adminer)",
		QueryFmt:    `site:%s (inurl:phpmyadmin OR inurl:pma OR inurl:adminer OR inurl:dbadmin OR inurl:webadmin)`,
		Severity:    "HIGH",
	},

	// 5. Error Logs & Debug Information Disclosure (GHDB Category 7)
	{
		GHDBSection: "GHDB-7 (Error Messages)",
		Category:    "Logs & Debug Diagnostics",
		Description: "Application Runtime Error Logs & Stack Traces",
		QueryFmt:    `site:%s filetype:log ("error" OR "exception" OR "warning" OR "fatal" OR "traceback")`,
		Severity:    "HIGH",
	},
	{
		GHDBSection: "GHDB-7 (Error Messages)",
		Category:    "Logs & Debug Diagnostics",
		Description: "PHP Framework Debug Leaks & Warning Messages",
		QueryFmt:    `site:%s ("PHP Parse error" OR "PHP Fatal error" OR "Uncaught exception" OR "Warning: mysqli_")`,
		Severity:    "MEDIUM",
	},
	{
		GHDBSection: "GHDB-7 (Error Messages)",
		Category:    "Logs & Debug Diagnostics",
		Description: "Diagnostic & Information Disclosure Pages (phpinfo, server-status)",
		QueryFmt:    `site:%s (inurl:phpinfo.php OR inurl:info.php OR inurl:server-status OR inurl:server-info OR inurl:status.json)`,
		Severity:    "HIGH",
	},
	{
		GHDBSection: "GHDB-7 (Error Messages)",
		Category:    "Logs & Debug Diagnostics",
		Description: "Interactive Debuggers Exposed (Werkzeug, Django, Laravel Flare)",
		QueryFmt:    `site:%s ("Werkzeug powered" OR "Traceback (most recent call last)" OR "Whoops! There was an error" OR "Django Version" OR "Laravel Flare")`,
		Severity:    "CRITICAL",
	},

	// 6. Vulnerable Servers & Infrastructure (GHDB Category 6 & 11)
	{
		GHDBSection: "GHDB-6 (Vulnerable Servers)",
		Category:    "Infrastructure & DevOps",
		Description: "Server Status, Health & Metrics Endpoints",
		QueryFmt:    `site:%s (intitle:"Apache Status" OR intitle:"Nginx Status" OR intitle:"IIS Windows Server" OR intitle:"Metrics")`,
		Severity:    "MEDIUM",
	},
	{
		GHDBSection: "GHDB-11 (Network Data)",
		Category:    "Infrastructure & DevOps",
		Description: "CI/CD, Monitoring & Build Automation Portals",
		QueryFmt:    `site:%s (inurl:jenkins OR inurl:gitlab OR inurl:sonarqube OR inurl:kibana OR inurl:grafana OR inurl:prometheus)`,
		Severity:    "HIGH",
	},

	// 7. APIs, Microservices & Documentation (DorkSearch Category)
	{
		GHDBSection: "DorkSearch-API (API Recon)",
		Category:    "APIs & Microservices",
		Description: "Swagger / OpenAPI Interactive API Documentation",
		QueryFmt:    `site:%s (inurl:swagger OR inurl:swagger-ui OR inurl:swagger.json OR inurl:api-docs OR inurl:openapi.json)`,
		Severity:    "MEDIUM",
	},
	{
		GHDBSection: "DorkSearch-API (API Recon)",
		Category:    "APIs & Microservices",
		Description: "GraphQL Consoles & Interactive Playgrounds",
		QueryFmt:    `site:%s (inurl:graphql OR inurl:graphiql OR inurl:altair OR inurl:playground)`,
		Severity:    "MEDIUM",
	},
	{
		GHDBSection: "DorkSearch-API (API Recon)",
		Category:    "APIs & Microservices",
		Description: "REST API Endpoint Discovery (v1, v2, v3, rest)",
		QueryFmt:    `site:%s (inurl:"/api/v1" OR inurl:"/api/v2" OR inurl:"/rest" OR inurl:"/v1/api")`,
		Severity:    "INFO",
	},

	// 8. Third-Party Leaks & Cloud Buckets (DorkSearch & External GHDB)
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
		QueryFmt:    `site:github.com "%s" ("password" OR "secret" OR "api_key" OR "token" OR "credentials")`,
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

	// 9. Confidential Documents & PII (GHDB Category 8)
	{
		GHDBSection: "GHDB-8 (Sensitive Info)",
		Category:    "Documents & PII Leaks",
		Description: "Confidential / Internal Office Documents",
		QueryFmt:    `site:%s (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx) ("confidential" OR "internal use only" OR "strictly private" OR "not for public release")`,
		Severity:    "HIGH",
	},
	{
		GHDBSection: "GHDB-8 (Sensitive Info)",
		Category:    "Documents & PII Leaks",
		Description: "Exposed Customer / Employee PII in CSV or Excel",
		QueryFmt:    `site:%s (filetype:csv OR filetype:tsv OR filetype:xls OR filetype:xlsx) ("email" OR "password" OR "phone" OR "ssn" OR "salary")`,
		Severity:    "HIGH",
	},
}

// CleanDomain normalizes a domain string by stripping protocols, ports, paths, and redundant www prefixes.
func CleanDomain(raw string) string {
	clean := strings.TrimSpace(strings.ToLower(raw))
	clean = strings.TrimPrefix(clean, "http://")
	clean = strings.TrimPrefix(clean, "https://")
	if idx := strings.Index(clean, "/"); idx != -1 {
		clean = clean[:idx]
	}
	if idx := strings.Index(clean, ":"); idx != -1 {
		clean = clean[:idx]
	}
	clean = strings.TrimPrefix(clean, "www.")
	return clean
}

// GenerateDorks creates customized Exploit-DB GHDB and DorkSearch intelligence queries for the target.
func GenerateDorks(domain string) []GoogleDork {
	cleanDomain := CleanDomain(domain)
	if cleanDomain == "" {
		cleanDomain = domain
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
			DorkSearchURL: "https://duckduckgo.com/?q=" + encodedQuery,
			BingURL:       "https://www.bing.com/search?q=" + encodedQuery,
			DuckDuckGoURL: "https://duckduckgo.com/?q=" + encodedQuery,
		})
	}
	return dorks
}

// makeOSC8Link wraps text in an ANSI OSC 8 terminal clickable hyperlink.
func makeOSC8Link(targetURL, linkText string) string {
	return fmt.Sprintf("\033]8;;%s\033\\%s\033]8;;\033\\", targetURL, linkText)
}

// PrintDorksReport renders a comprehensive, categorized terminal view of GHDB & DorkSearch intelligence.
func PrintDorksReport(domain string, dorks []GoogleDork) {
	cleanDomain := CleanDomain(domain)
	fmt.Println()
	fmt.Println("\033[1;31m╔══════════════════════════════════════════════════════════════════════════════╗\033[0m")
	fmt.Println("\033[1;31m║   🔥 Exploit-DB GHDB & DorkSearch OSINT Reconnaissance Engine               ║\033[0m")
	fmt.Printf("\033[1;31m║   Target Domain : \033[1;37m%-58s\033[1;31m ║\033[0m\n", cleanDomain)
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
			fmt.Printf("    │   ├── %s    : \033[34m%s\033[0m\n", makeOSC8Link(item.GoogleURL, "[Google Search]"), item.GoogleURL)
			fmt.Printf("    │   ├── %s: \033[32m%s\033[0m\n", makeOSC8Link(item.DuckDuckGoURL, "[DuckDuckGo]   "), item.DuckDuckGoURL)
			fmt.Printf("    │   └── %s       : \033[36m%s\033[0m\n", makeOSC8Link(item.BingURL, "[Bing Search]  "), item.BingURL)
		}
		fmt.Println()
	}
	fmt.Printf("\033[1;32m[+] Successfully generated %d Exploit-DB GHDB & DorkSearch intelligence queries for %s\033[0m\n", len(dorks), cleanDomain)
	fmt.Printf("\033[33m[*] Hint: In modern terminals, you can Ctrl+Click (or Cmd+Click) any search link above to open directly in your browser.\033[0m\n\n")
}

// ExportDorksJSON outputs generated dorks formatted as a JSON string.
func ExportDorksJSON(dorks []GoogleDork) (string, error) {
	bytes, err := json.MarshalIndent(dorks, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// ExportDorksHTML writes a standalone, dark-themed, interactive HTML Dork Dashboard with 1-click links, live search, and copy buttons.
func ExportDorksHTML(domain string, dorks []GoogleDork, outputPath string) error {
	cleanDomain := CleanDomain(domain)
	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NightfallLX - GHDB & DorkSearch OSINT Report (` + cleanDomain + `)</title>
    <style>
        :root {
            --bg-primary: #0a0d12;
            --bg-secondary: #121820;
            --bg-card: #18222d;
            --border-color: #263342;
            --text-primary: #e6edf3;
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
            max-width: 1250px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #1c0808 0%, var(--bg-secondary) 100%);
            border: 1px solid #7a1d1d;
            border-radius: 10px;
            padding: 24px 28px;
            margin-bottom: 24px;
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.6);
        }
        .header h1 {
            margin: 0 0 10px 0;
            color: var(--accent-red);
            font-size: 26px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .header p {
            margin: 0;
            color: var(--text-secondary);
            font-size: 14px;
            line-height: 1.6;
        }
        .controls {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: center;
            margin-bottom: 24px;
            background: var(--bg-secondary);
            padding: 16px 20px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }
        .search-box {
            flex-grow: 1;
            min-width: 250px;
            padding: 10px 14px;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: #ffffff;
            font-size: 14px;
            outline: none;
            transition: border-color 0.2s;
        }
        .search-box:focus {
            border-color: var(--accent-blue);
        }
        .filter-btn {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 8px 14px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .filter-btn.active, .filter-btn:hover {
            background: var(--accent-red);
            color: #ffffff;
            border-color: var(--accent-red);
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
            padding: 18px 22px;
            transition: transform 0.15s ease, border-color 0.15s ease, box-shadow 0.15s ease;
        }
        .card:hover {
            border-color: var(--accent-blue);
            transform: translateY(-2px);
            box-shadow: 0 4px 14px rgba(0, 0, 0, 0.4);
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            flex-wrap: wrap;
            gap: 8px;
        }
        .card-title {
            font-size: 16px;
            font-weight: 600;
            color: #ffffff;
        }
        .query-container {
            position: relative;
            margin-bottom: 14px;
        }
        .query-box {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 12px 50px 12px 14px;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
            font-size: 13px;
            color: #79c0ff;
            word-break: break-all;
            line-height: 1.4;
        }
        .copy-btn {
            position: absolute;
            right: 8px;
            top: 50%;
            transform: translateY(-50%);
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 6px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            transition: all 0.2s;
        }
        .copy-btn:hover {
            color: #ffffff;
            border-color: var(--accent-blue);
            background: #1f2937;
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
            padding: 7px 14px;
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
        .btn-ddg { background: #de5833; color: #ffffff; }
        .btn-ddg:hover { background: #bf4724; }
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
            <p>Target Domain: <strong style="color:#ffffff;">` + cleanDomain + `</strong> | Total Dorks: <strong style="color:var(--accent-red);">` + fmt.Sprintf("%d", len(dorks)) + `</strong> | Compliant with Google Search Grammar, Boolean Scoping & GHDB Standards</p>
        </div>

        <div class="controls">
            <input type="text" id="searchInput" class="search-box" placeholder="🔎 Search dorks by keyword (e.g. passwords, git, s3, config)..." onkeyup="filterDorks()">
            <button class="filter-btn active" onclick="setFilter('ALL', this)">All</button>
            <button class="filter-btn" onclick="setFilter('CRITICAL', this)">Critical</button>
            <button class="filter-btn" onclick="setFilter('HIGH', this)">High</button>
            <button class="filter-btn" onclick="setFilter('Secrets & Credentials', this)">Secrets</button>
            <button class="filter-btn" onclick="setFilter('Admin & Portals', this)">Admin</button>
            <button class="filter-btn" onclick="setFilter('Cloud & 3rd-Party Leaks', this)">Cloud</button>
        </div>

        <div id="dorksContainer">
`)

	for i, d := range dorks {
		badgeClass := "badge-info"
		switch d.Severity {
		case "CRITICAL":
			badgeClass = "badge-critical"
		case "HIGH":
			badgeClass = "badge-high"
		case "MEDIUM":
			badgeClass = "badge-medium"
		}

		escapedQueryForAttr := strings.ReplaceAll(d.Query, `"`, `&quot;`)
		cardID := fmt.Sprintf("card-%d", i)

		sb.WriteString(`
        <div class="card" id="` + cardID + `" data-severity="` + d.Severity + `" data-category="` + d.Category + `" data-text="` + strings.ToLower(d.Description+" "+d.Query+" "+d.Category+" "+d.GHDBSection) + `">
            <div class="card-header">
                <span class="card-title">` + d.Description + `</span>
                <div>
                    <span class="meta-tag" style="margin-right:8px;">` + d.GHDBSection + `</span>
                    <span class="badge ` + badgeClass + `">` + d.Severity + `</span>
                </div>
            </div>
            <div class="query-container">
                <div class="query-box">` + d.Query + `</div>
                <button class="copy-btn" onclick="copyQuery('` + escapedQueryForAttr + `', this)">📋 Copy</button>
            </div>
            <div class="btn-group">
                <a href="` + d.GoogleURL + `" target="_blank" rel="noopener noreferrer" class="btn btn-google">🔍 Google Search</a>
                <a href="` + d.DuckDuckGoURL + `" target="_blank" rel="noopener noreferrer" class="btn btn-dorksearch">⚡ DuckDuckGo (Instant Dork)</a>
                <a href="` + d.BingURL + `" target="_blank" rel="noopener noreferrer" class="btn btn-bing">🌐 Bing Search</a>
                <a href="` + d.DuckDuckGoURL + `" target="_blank" rel="noopener noreferrer" class="btn btn-ddg">🦆 DuckDuckGo</a>
            </div>
        </div>`)
	}

	sb.WriteString(`
        </div>
    </div>

    <script>
        let currentFilter = 'ALL';

        function setFilter(filter, btn) {
            currentFilter = filter;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            filterDorks();
        }

        function filterDorks() {
            const query = document.getElementById('searchInput').value.toLowerCase().trim();
            const cards = document.querySelectorAll('.card');

            cards.forEach(card => {
                const text = card.getAttribute('data-text');
                const sev = card.getAttribute('data-severity');
                const cat = card.getAttribute('data-category');

                const matchesSearch = !query || text.includes(query);
                let matchesCategory = false;

                if (currentFilter === 'ALL') {
                    matchesCategory = true;
                } else if (currentFilter === 'CRITICAL' || currentFilter === 'HIGH') {
                    matchesCategory = (sev === currentFilter);
                } else {
                    matchesCategory = (cat === currentFilter);
                }

                if (matchesSearch && matchesCategory) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        }

        function copyQuery(text, btn) {
            navigator.clipboard.writeText(text).then(() => {
                const orig = btn.innerText;
                btn.innerText = '✅ Copied!';
                btn.style.color = '#3fb950';
                setTimeout(() => {
                    btn.innerText = orig;
                    btn.style.color = '';
                }, 1800);
            }).catch(err => {
                alert('Copy failed: ' + err);
            });
        }
    </script>
</body>
</html>`)

	return os.WriteFile(outputPath, []byte(sb.String()), 0644)
}
