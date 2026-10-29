package osint

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"strings"
	"time"
)

// ExportOSINTHTML generates a comprehensive, standalone dark-themed interactive HTML OSINT Dashboard.
func ExportOSINTHTML(rep *OSINTReport, outputPath string) error {
	cleanDomain := CleanDomain(rep.Domain)
	if cleanDomain == "" {
		cleanDomain = rep.Domain
	}

	var sb strings.Builder

	// Count statistics
	totalSubdomains := len(rep.Subdomains)
	if rep.DNSEnum != nil && len(rep.DNSEnum.Subdomains) > 0 {
		totalSubdomains += len(rep.DNSEnum.Subdomains)
	}
	totalAdminPortals := len(rep.AdminPortals)
	totalFindings := len(rep.Findings)
	totalDorks := len(rep.GoogleDorks)

	// Critical and High findings count
	critHighCount := 0
	for _, f := range rep.Findings {
		if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
			critHighCount++
		}
	}

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NightfallLX OSINT Dossier - ` + html.EscapeString(cleanDomain) + `</title>
    <style>
        :root {
            --bg-primary: #0a0e17;
            --bg-secondary: #111827;
            --bg-card: #1f2937;
            --border-color: #374151;
            --text-primary: #f9fafb;
            --text-secondary: #9ca3af;
            --accent-cyan: #06b6d4;
            --accent-red: #ef4444;
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --accent-purple: #8b5cf6;
            --accent-blue: #3b82f6;
        }
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 24px 20px;
            line-height: 1.5;
        }
        .container { max-width: 1300px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 100%);
            border: 1px solid #38bdf8;
            border-radius: 12px;
            padding: 24px 30px;
            margin-bottom: 24px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.5);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }
        .header-title h1 {
            margin: 0 0 6px 0;
            font-size: 26px;
            color: #38bdf8;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .header-title p { margin: 0; color: var(--text-secondary); font-size: 14px; }
        .target-badge {
            display: inline-block;
            background: rgba(56, 189, 248, 0.15);
            border: 1px solid #38bdf8;
            color: #ffffff;
            padding: 4px 12px;
            border-radius: 6px;
            font-weight: bold;
            font-size: 16px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .stat-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 18px 20px;
            text-align: center;
        }
        .stat-val { font-size: 28px; font-weight: bold; margin-bottom: 4px; }
        .stat-label { font-size: 13px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; }
        .section-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 22px 24px;
            margin-bottom: 24px;
        }
        .section-header {
            font-size: 18px;
            font-weight: bold;
            color: var(--accent-cyan);
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
        }
        .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(450px, 1fr)); gap: 16px; }
        .data-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
        .data-table th, .data-table td {
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        .data-table th { background: rgba(31, 41, 55, 0.6); color: var(--text-secondary); }
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .badge-critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
        .badge-high { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }
        .badge-medium { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }
        .badge-secure { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
        .badge-code200 { background: rgba(16, 185, 129, 0.2); color: #34d399; }
        .badge-code300 { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
        .badge-code400 { background: rgba(139, 92, 246, 0.2); color: #a78bfa; }
        .portal-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 14px;
        }
        .portal-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 14px 16px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .portal-url {
            color: #60a5fa;
            text-decoration: none;
            font-weight: bold;
            font-size: 14px;
            word-break: break-all;
        }
        .portal-url:hover { text-decoration: underline; color: #93c5fd; }
        .portal-meta { font-size: 12px; color: var(--text-secondary); }
        .dork-item {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 14px 16px;
            margin-bottom: 12px;
        }
        .dork-title { font-weight: bold; font-size: 14px; margin-bottom: 6px; display: flex; justify-content: space-between; }
        .dork-query {
            background: #090d16;
            border: 1px solid #1e293b;
            border-radius: 6px;
            padding: 8px 12px;
            font-family: monospace;
            font-size: 12px;
            color: #38bdf8;
            margin-bottom: 8px;
            word-break: break-all;
        }
        .btn-group { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 6px 12px;
            border-radius: 5px;
            font-size: 12px;
            font-weight: 600;
            text-decoration: none;
            cursor: pointer;
            border: none;
        }
        .btn-google { background: #1d4ed8; color: #ffffff; }
        .btn-google:hover { background: #2563eb; }
        .btn-ddg { background: #ea580c; color: #ffffff; }
        .btn-ddg:hover { background: #f97316; }
        .btn-bing { background: #0f766e; color: #ffffff; }
        .btn-bing:hover { background: #14b8a6; }
        .btn-copy { background: #374151; color: #e5e7eb; cursor: pointer; }
        .btn-copy:hover { background: #4b5563; color: #ffffff; }
        .search-box {
            width: 100%;
            padding: 10px 14px;
            background: #090d16;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: #ffffff;
            font-size: 14px;
            margin-bottom: 16px;
        }
        .search-box:focus { outline: none; border-color: var(--accent-cyan); }
        .footer { text-align: center; color: var(--text-secondary); font-size: 12px; margin-top: 30px; }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="header-title">
            <h1>🎯 NightfallLX Deep OSINT Dossier</h1>
            <p>Target: <span class="target-badge">` + html.EscapeString(cleanDomain) + `</span> | Generated: ` + time.Now().Format("2006-01-02 15:04:05 UTC") + ` | Scan Duration: ` + rep.Duration.Round(time.Millisecond).String() + `</p>
        </div>
    </div>

    <!-- Stats Bar -->
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-val" style="color:#38bdf8;">` + fmt.Sprintf("%d", totalSubdomains) + `</div>
            <div class="stat-label">Subdomains Discovered</div>
        </div>
        <div class="stat-card">
            <div class="stat-val" style="color:#ef4444;">` + fmt.Sprintf("%d", totalAdminPortals) + `</div>
            <div class="stat-label">Admin Panels / Portals</div>
        </div>
        <div class="stat-card">
            <div class="stat-val" style="color:#f59e0b;">` + fmt.Sprintf("%d", totalFindings) + `</div>
            <div class="stat-label">Security Findings</div>
        </div>
        <div class="stat-card">
            <div class="stat-val" style="color:#10b981;">` + fmt.Sprintf("%d", totalDorks) + `</div>
            <div class="stat-label">Exploit-DB GHDB Vectors</div>
        </div>
    </div>

    <!-- Infrastructure & Email Security -->
    <div class="grid-2">
        <div class="section-card">
            <div class="section-header">🌐 Infrastructure & Network Intelligence</div>
            <table class="data-table">
                <tr><th>Cloud / Hosting</th><td><strong style="color:#34d399;">` + html.EscapeString(rep.CloudProvider) + `</strong></td></tr>
                <tr><th>ASN / BGP Routing</th><td>` + html.EscapeString(rep.ASNInfo) + `</td></tr>
                <tr><th>Resolved IPs</th><td>` + html.EscapeString(strings.Join(rep.TargetIPs, ", ")) + `</td></tr>
                <tr><th>Name Servers</th><td>` + html.EscapeString(strings.Join(rep.NameServers, ", ")) + `</td></tr>
                <tr><th>Mail Servers</th><td>` + html.EscapeString(strings.Join(rep.MailServers, ", ")) + `</td></tr>
                <tr><th>CIDR Ranges</th><td>` + html.EscapeString(strings.Join(rep.CIDRRanges, ", ")) + `</td></tr>` + func() string {
		if rep.SOARecord != nil {
			soaRows := `<tr><th>Primary SOA NS</th><td><code>` + html.EscapeString(rep.SOARecord.PrimaryNS) + `</code></td></tr>`
			if rep.SOARecord.AdminEmail != "" {
				soaRows += `<tr><th>SOA Hostmaster</th><td><strong style="color:#fbbf24;">` + html.EscapeString(rep.SOARecord.AdminEmail) + `</strong></td></tr>`
			}
			return soaRows
		}
		return ""
	}() + `
            </table>
        </div>

        <div class="section-card">
            <div class="section-header">🛡️ Email Spoofing & Security Posture</div>
            <table class="data-table">
                <tr>
                    <th>SPF Record</th>
                    <td>` + func() string {
		if rep.SPFRecord == "" {
			return `<span class="badge badge-critical">[MISSING] Spoofing Vulnerable</span>`
		}
		return `<code>` + html.EscapeString(rep.SPFRecord) + `</code>`
	}() + `</td>
                </tr>
                <tr>
                    <th>DMARC Policy</th>
                    <td>` + func() string {
		switch rep.DMARCStatus {
		case DMARCMissing:
			return `<span class="badge badge-critical">[MISSING] Phishing / BEC Risk</span>`
		case DMARCWeak:
			return `<span class="badge badge-high">[WEAK] ` + html.EscapeString(rep.DMARCRecord) + `</span>`
		case DMARCSecure:
			return `<span class="badge badge-secure">[SECURE] ` + html.EscapeString(rep.DMARCRecord) + `</span>`
		default:
			return `<code>` + html.EscapeString(rep.DMARCRecord) + `</code>`
		}
	}() + `</td>
                </tr>
                <tr>
                    <th>Corporate Pattern</th>
                    <td>` + func() string {
		if rep.EmailPattern != "" {
			return `<strong>` + html.EscapeString(rep.EmailPattern) + `</strong>`
		}
		return `<em>None detected</em>`
	}() + `</td>
                </tr>
                <tr>
                    <th>Discovered Emails</th>
                    <td>` + fmt.Sprintf("%d corporate addresses identified", len(rep.Emails)) + `</td>
                </tr>
            </table>
        </div>
    </div>`)

	// Authoritative TXT Records
	if len(rep.TXTRecords) > 0 {
		sb.WriteString(`
    <div class="section-card">
        <div class="section-header">📜 Authoritative DNS TXT Records (` + fmt.Sprintf("%d", len(rep.TXTRecords)) + ` records)</div>
        <table class="data-table">
            <thead>
                <tr>
                    <th style="width: 50px;">#</th>
                    <th style="width: 180px;">Classification</th>
                    <th>Record Value / Token</th>
                </tr>
            </thead>
            <tbody>`)
		for i, txt := range rep.TXTRecords {
			badgeClass := "badge-medium"
			typeLabel := "Verification / Token"
			lower := strings.ToLower(txt)
			if strings.HasPrefix(lower, "v=spf1") {
				typeLabel = "SPF Policy"
				badgeClass = "badge-secure"
			} else if strings.HasPrefix(lower, "v=dmarc1") {
				typeLabel = "DMARC Policy"
				badgeClass = "badge-code400"
			} else if strings.Contains(lower, "google-site-verification") {
				typeLabel = "Google Workspace"
				badgeClass = "badge-medium"
			} else if strings.Contains(lower, "ms=") {
				typeLabel = "Microsoft 365"
				badgeClass = "badge-high"
			} else if strings.Contains(lower, "anthropic") {
				typeLabel = "Anthropic Claude"
				badgeClass = "badge-code300"
			}
			sb.WriteString(`
                <tr>
                    <td><strong>` + fmt.Sprintf("%d", i+1) + `</strong></td>
                    <td><span class="badge ` + badgeClass + `">` + html.EscapeString(typeLabel) + `</span></td>
                    <td><code style="color:#38bdf8; word-break: break-all;">` + html.EscapeString(txt) + `</code></td>
                </tr>`)
		}
		sb.WriteString(`
            </tbody>
        </table>
    </div>`)
	}

	// Automated DNS Enumeration Intelligence
	if rep.DNSEnum != nil {
		sb.WriteString(`
    <div class="section-card">
        <div class="section-header">⚡ Automated DNS Enumeration (` + html.EscapeString(rep.DNSEnum.EngineUsed) + `)</div>
        <div class="grid-2">
            <div>
                <strong style="color:var(--text-secondary); font-size:13px;">Zone Transfers (AXFR) Probes:</strong>
                <ul style="margin: 8px 0; padding-left: 20px; font-size:13px;">`)
		for _, z := range rep.DNSEnum.ZoneTransfers {
			statusColor := "#10b981"
			if z.Vulnerable {
				statusColor = "#ef4444"
			}
			sb.WriteString(`<li><code>` + html.EscapeString(z.Server) + `</code>: <strong style="color:` + statusColor + `;">` + html.EscapeString(z.Status) + `</strong></li>`)
		}
		sb.WriteString(`
                </ul>
            </div>
            <div>
                <strong style="color:var(--text-secondary); font-size:13px;">Discovered Class C Netranges:</strong>
                <div style="margin-top: 8px; display:flex; flex-wrap:wrap; gap:6px;">`)
		for _, netr := range rep.DNSEnum.ClassCNetranges {
			sb.WriteString(`<span class="badge badge-medium">` + html.EscapeString(netr) + `</span>`)
		}
		sb.WriteString(`
                </div>
            </div>
        </div>
    </div>`)
	}

	// Discovered Admin Panels
	if len(rep.AdminPortals) > 0 {
		sb.WriteString(`
    <div class="section-card">
        <div class="section-header">🔥 Discovered Admin Panels, Dashboards & Login Portals (` + fmt.Sprintf("%d", len(rep.AdminPortals)) + ` identified)</div>
        <div class="portal-grid">`)
		for _, p := range rep.AdminPortals {
			badgeClass := "badge-code200"
			if p.StatusCode >= 300 && p.StatusCode < 400 {
				badgeClass = "badge-code300"
			} else if p.StatusCode >= 400 {
				badgeClass = "badge-code400"
			}
			titleStr := p.Title
			if titleStr == "" {
				titleStr = "No Title"
			}
			authBadge := ""
			if p.HasLoginForm {
				authBadge = ` <span class="badge badge-critical">AUTH FORM</span>`
			}
			sb.WriteString(`
            <div class="portal-card">
                <div>
                    <span class="badge ` + badgeClass + `">` + fmt.Sprintf("%d", p.StatusCode) + `</span>
                    <strong style="margin-left:6px; color:#f3f4f6;">` + html.EscapeString(p.Type) + `</strong>` + authBadge + `
                </div>
                <a href="` + html.EscapeString(p.URL) + `" target="_blank" rel="noopener noreferrer" class="portal-url">` + html.EscapeString(p.URL) + `</a>
                <div class="portal-meta">Title: ` + html.EscapeString(titleStr) + `</div>
            </div>`)
		}
		sb.WriteString(`
        </div>
    </div>`)
	}

	// Security Findings
	if len(rep.Findings) > 0 {
		sb.WriteString(`
    <div class="section-card">
        <div class="section-header">⚠️ Passive OSINT Security Findings (` + fmt.Sprintf("%d", len(rep.Findings)) + ` issues)</div>
        <table class="data-table">
            <thead>
                <tr><th>Severity</th><th>Vulnerability</th><th>Evidence</th><th>Remediation</th></tr>
            </thead>
            <tbody>`)
		for _, f := range rep.Findings {
			badgeClass := "badge-medium"
			if f.Severity == "CRITICAL" {
				badgeClass = "badge-critical"
			} else if f.Severity == "HIGH" {
				badgeClass = "badge-high"
			}
			sb.WriteString(`
                <tr>
                    <td><span class="badge ` + badgeClass + `">` + f.Severity + `</span></td>
                    <td><strong>` + html.EscapeString(f.Title) + `</strong><br><small style="color:#9ca3af;">` + html.EscapeString(f.Description) + `</small></td>
                    <td><code>` + html.EscapeString(f.Evidence) + `</code></td>
                    <td style="color:#34d399;">` + html.EscapeString(f.Remediation) + `</td>
                </tr>`)
		}
		sb.WriteString(`
            </tbody>
        </table>
    </div>`)
	}

	// Subdomains Table
	if len(rep.Subdomains) > 0 {
		sb.WriteString(`
    <div class="section-card">
        <div class="section-header">🌐 Certificate Transparency & Discovered Subdomains (` + fmt.Sprintf("%d", len(rep.Subdomains)) + ` total)</div>
        <input type="text" id="subdomainSearch" class="search-box" placeholder="Filter subdomains by name or IP..." onkeyup="filterSubdomains()">
        <div style="max-height: 400px; overflow-y: auto;">
            <table class="data-table" id="subdomainsTable">
                <thead><tr><th>Subdomain</th><th>IP Address</th><th>Source</th><th>Takeover Risk</th></tr></thead>
                <tbody>`)
		for _, s := range rep.Subdomains {
			ipStr := "-"
			if len(s.IPs) > 0 {
				ipStr = strings.Join(s.IPs, ", ")
			}
			takeoverBadge := `<span style="color:#9ca3af;">Safe</span>`
			if s.Takeover != "" {
				takeoverBadge = `<span class="badge badge-critical">VULNERABLE: ` + html.EscapeString(s.Takeover) + `</span>`
			}
			sb.WriteString(`
                <tr>
                    <td><strong>` + html.EscapeString(s.Hostname) + `</strong></td>
                    <td>` + html.EscapeString(ipStr) + `</td>
                    <td><span style="color:#9ca3af;">` + html.EscapeString(s.Source) + `</span></td>
                    <td>` + takeoverBadge + `</td>
                </tr>`)
		}
		sb.WriteString(`
                </tbody>
            </table>
        </div>
    </div>`)
	}

	// Exploit-DB GHDB Intelligence Queries
	if len(rep.GoogleDorks) > 0 {
		sb.WriteString(`
    <div class="section-card">
        <div class="section-header">🔍 Exploit-DB GHDB & Live Dork Intelligence Vectors (` + fmt.Sprintf("%d", len(rep.GoogleDorks)) + ` queries)</div>
        <input type="text" id="dorkSearch" class="search-box" placeholder="Filter Google Dorks by keyword or category..." onkeyup="filterDorks()">
        <div id="dorksContainer">`)
		for _, d := range rep.GoogleDorks {
			badgeClass := "badge-medium"
			if d.Severity == "CRITICAL" {
				badgeClass = "badge-critical"
			} else if d.Severity == "HIGH" {
				badgeClass = "badge-high"
			}
			sb.WriteString(`
            <div class="dork-item">
                <div class="dork-title">
                    <span>` + html.EscapeString(d.Description) + ` <small style="color:#9ca3af;">(` + html.EscapeString(d.GHDBSection) + `)</small></span>
                    <span class="badge ` + badgeClass + `">` + d.Severity + `</span>
                </div>
                <div class="dork-query">` + html.EscapeString(d.Query) + `</div>
                <div class="btn-group">
                    <a href="` + html.EscapeString(d.GoogleURL) + `" target="_blank" rel="noopener noreferrer" class="btn btn-google">🔍 Google Search</a>
                    <a href="` + html.EscapeString(d.DuckDuckGoURL) + `" target="_blank" rel="noopener noreferrer" class="btn btn-ddg">⚡ DuckDuckGo (Instant)</a>
                    <a href="` + html.EscapeString(d.BingURL) + `" target="_blank" rel="noopener noreferrer" class="btn btn-bing">🌐 Bing Search</a>
                    <button class="btn btn-copy" onclick="copyDork(this, '` + strings.ReplaceAll(html.EscapeString(d.Query), "'", "\\'") + `')">📋 Copy Query</button>
                </div>
            </div>`)
		}
		sb.WriteString(`
        </div>
    </div>`)
	}

	sb.WriteString(`
    <div class="footer">
        Generated by <strong>NightfallLX (Go Edition v2.0)</strong> - Next-Generation Penetration Testing & OSINT Suite.
    </div>
</div>

<script>
function filterSubdomains() {
    const input = document.getElementById('subdomainSearch').value.toLowerCase();
    const rows = document.querySelectorAll('#subdomainsTable tbody tr');
    rows.forEach(r => {
        const text = r.innerText.toLowerCase();
        r.style.display = text.includes(input) ? '' : 'none';
    });
}

function filterDorks() {
    const input = document.getElementById('dorkSearch').value.toLowerCase();
    const items = document.querySelectorAll('#dorksContainer .dork-item');
    items.forEach(item => {
        const text = item.innerText.toLowerCase();
        item.style.display = text.includes(input) ? '' : 'none';
    });
}

function copyDork(btn, query) {
    navigator.clipboard.writeText(query).then(() => {
        const original = btn.innerText;
        btn.innerText = '✅ Copied!';
        setTimeout(() => btn.innerText = original, 1500);
    });
}
</script>
</body>
</html>`)

	return os.WriteFile(outputPath, []byte(sb.String()), 0644)
}

// ExportOSINTJSON serializes the full OSINTReport to a formatted JSON string.
func ExportOSINTJSON(rep *OSINTReport) (string, error) {
	bytes, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
