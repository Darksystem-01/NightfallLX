package reporters

import (
	"html/template"
	"os"
	"strings"
	"time"

	"nightfalllx/pkg/intel"
	"nightfalllx/pkg/modules"
	"nightfalllx/pkg/version"
)

type htmlFinding struct {
	*modules.Finding
	Index          int
	SeverityClass  string
	ConfidenceText string
	CurlCmd        string
}

type htmlReportData struct {
	Target     *modules.Target
	ScanDate   string
	Total      int
	Counts     map[string]int
	Findings   []htmlFinding
	Intel      *intel.IntelReport
	Version    string
	SevFilters []string
}

// WriteHTMLReport writes a dark-themed HTML report without intel metadata.
func WriteHTMLReport(target *modules.Target, findings []*modules.Finding, filePath string) error {
	return WriteHTMLReportWithIntel(target, findings, nil, filePath)
}

// WriteHTMLReportWithIntel writes a self-contained dark HTML report with a
// summary dashboard, severity filters, search, and expandable findings.
func WriteHTMLReportWithIntel(target *modules.Target, findings []*modules.Finding, intelRep *intel.IntelReport, filePath string) error {
	if findings == nil {
		findings = []*modules.Finding{}
	}
	counts := map[string]int{
		"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
	}
	items := make([]htmlFinding, 0, len(findings))
	for i, f := range findings {
		sev := strings.ToUpper(string(f.Severity))
		if _, ok := counts[sev]; !ok {
			sev = "INFO"
		}
		counts[sev]++
		items = append(items, htmlFinding{
			Finding:        f,
			Index:          i + 1,
			SeverityClass:  strings.ToLower(sev),
			ConfidenceText: formatConfidence(f),
			CurlCmd:        f.CurlCmd,
		})
	}

	data := htmlReportData{
		Target:     target,
		ScanDate:   time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Total:      len(findings),
		Counts:     counts,
		Findings:   items,
		Intel:      intelRep,
		Version:    version.Version,
		SevFilters: []string{"all", "critical", "high", "medium", "low", "info"},
	}

	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	return htmlTemplate.Execute(f, data)
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"lower": strings.ToLower,
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NightfallLX Report - {{.Target.URL}}</title>
<style>
:root{--bg:#080b12;--panel:#101624;--panel2:#151d2f;--text:#e6edf7;--muted:#8ea0bd;--line:#233047;--accent:#43d9ff;--critical:#ff4d6d;--high:#ff9f43;--medium:#ffd166;--low:#4cc9f0;--info:#8b9bb4}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 20% 0%,#13233a 0,#080b12 42%);color:var(--text);font:14px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1240px;margin:0 auto;padding:28px 20px 60px}
header{display:flex;justify-content:space-between;gap:20px;align-items:flex-start;flex-wrap:wrap;margin-bottom:26px}
h1{font-size:26px;margin:0 0 6px;letter-spacing:-.4px}h1 span{color:var(--accent)}
.muted{color:var(--muted)}.target{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--accent);word-break:break-all}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px;margin:18px 0 24px}
.card{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:14px;padding:16px;box-shadow:0 8px 24px rgba(0,0,0,.25)}
.card .n{font-size:28px;font-weight:800;line-height:1.1}.card .l{font-size:11px;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);margin-top:6px}
.critical .n{color:var(--critical)}.high .n{color:var(--high)}.medium .n{color:var(--medium)}.low .n{color:var(--low)}.info .n{color:var(--info)}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:8px 0 18px}
button,.chip{background:var(--panel);border:1px solid var(--line);color:var(--text);padding:8px 13px;border-radius:999px;cursor:pointer;font-size:12px;text-transform:uppercase;letter-spacing:.06em}
button.active{border-color:var(--accent);color:var(--accent);box-shadow:0 0 0 3px rgba(67,217,255,.10)}
input[type=search]{background:var(--panel);border:1px solid var(--line);color:var(--text);padding:10px 14px;border-radius:10px;min-width:260px;flex:1;outline:none}
input[type=search]:focus{border-color:var(--accent)}
details.finding{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);border-left:4px solid var(--info);border-radius:12px;margin:10px 0;overflow:hidden}
details.finding[open]{box-shadow:0 12px 34px rgba(0,0,0,.35)}
details.finding.sev-critical{border-left-color:var(--critical)}details.finding.sev-high{border-left-color:var(--high)}details.finding.sev-medium{border-left-color:var(--medium)}details.finding.sev-low{border-left-color:var(--low)}
summary{cursor:pointer;padding:14px 16px;display:flex;gap:12px;align-items:center;flex-wrap:wrap;list-style:none}
summary::-webkit-details-marker{display:none}summary:before{content:"▸";color:var(--accent);font-size:12px}details[open] summary:before{content:"▾"}
.title{font-weight:700;flex:1;min-width:240px}.badge{font-size:10px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;padding:5px 9px;border-radius:999px;background:#1b263b;color:var(--text)}
.sev-critical .badge{background:rgba(255,77,109,.16);color:var(--critical)}.sev-high .badge{background:rgba(255,159,67,.16);color:var(--high)}.sev-medium .badge{background:rgba(255,209,102,.16);color:var(--medium)}.sev-low .badge{background:rgba(76,201,240,.16);color:var(--low)}
.body{padding:0 18px 18px;border-top:1px solid var(--line)}
.kv{display:grid;grid-template-columns:180px 1fr;gap:8px 14px;margin:14px 0}.k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}
pre{background:#070a10;border:1px solid var(--line);border-radius:10px;padding:13px;overflow:auto;white-space:pre-wrap;word-break:break-word;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:#cfe3ff}
h2{font-size:18px;margin:30px 0 12px}h3{font-size:16px;margin:20px 0 8px}
table{width:100%;border-collapse:collapse;margin:10px 0 20px;font-size:13px}th,td{padding:10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}
.empty{color:var(--muted);padding:18px;border:1px dashed var(--line);border-radius:12px}
footer{margin-top:36px;color:var(--muted);font-size:12px;text-align:center}
.hidden{display:none!important}
@media(max-width:600px){.kv{grid-template-columns:1fr}.target{font-size:12px}}
</style>
</head>
<body><div class="wrap">
<header>
<div><h1>Nightfall<span>LX</span> Assessment Report</h1><div class="muted">Generated {{.ScanDate}} · v{{.Version}}</div></div>
<div class="muted" style="text-align:right">Target<br><span class="target">{{.Target.URL}}</span></div>
</header>

<section class="grid">
<div class="card"><div class="n">{{.Total}}</div><div class="l">Total Findings</div></div>
<div class="card critical"><div class="n">{{index .Counts "CRITICAL"}}</div><div class="l">Critical</div></div>
<div class="card high"><div class="n">{{index .Counts "HIGH"}}</div><div class="l">High</div></div>
<div class="card medium"><div class="n">{{index .Counts "MEDIUM"}}</div><div class="l">Medium</div></div>
<div class="card low"><div class="n">{{index .Counts "LOW"}}</div><div class="l">Low</div></div>
<div class="card info"><div class="n">{{index .Counts "INFO"}}</div><div class="l">Info</div></div>
</section>

<div class="toolbar">
{{range .SevFilters}}<button class="filter{{if eq . "all"}} active{{end}}" data-severity="{{.}}">{{.}}</button>{{end}}
<input type="search" id="search" placeholder="Filter findings by title, module, parameter, or CVE…">
</div>

<h2>Findings</h2>
<div id="findings">
{{if not .Findings}}<div class="empty">No confirmed findings were reported.</div>{{end}}
{{range .Findings}}
<details class="finding sev-{{.SeverityClass}}" data-severity="{{.SeverityClass}}">
<summary>
<span class="badge">{{.Severity}}</span>
<span class="title">{{.Index}}. {{.Title}}</span>
<span class="muted">{{.Module}}</span>
</summary>
<div class="body">
<div class="kv">
<div class="k">Confidence</div><div>{{.ConfidenceText}}</div>
<div class="k">Parameter</div><div><code>{{.Parameter}}</code></div>
<div class="k">URL</div><div class="target">{{.URL}}</div>
{{if .CWEID}}<div class="k">CWE</div><div><a href="https://cwe.mitre.org/data/definitions/{{.CWEID}}.html" target="_blank" rel="noopener">CWE-{{.CWEID}}</a></div>{{end}}
<div class="k">Payload</div><div><code>{{.Payload}}</code></div>
</div>
{{if .CurlCmd}}<h3>Reproduction command</h3><pre>{{.CurlCmd}}</pre>{{end}}
<h3>Analysis &amp; evidence</h3>{{if .Detail}}<pre>{{.Detail}}</pre>{{end}}{{if .Evidence}}<pre>{{.Evidence}}</pre>{{end}}
<h3>Remediation</h3><p>{{.Remediation}}</p>
</div>
</details>
{{end}}
</div>

{{if .Intel}}
<h2>Version-matched intel (not verified)</h2>
<p class="muted">{{.Intel.Disclaimer}}</p>
<table><thead><tr><th>Query</th><th>Source</th><th>CVE / EDB</th><th>Title</th><th>Reference</th></tr></thead><tbody>
{{range .Intel.Findings}}<tr><td>{{.Query}}</td><td>{{.Source}}</td><td>{{range $i, $c := .CVEs}}{{if $i}}, {{end}}{{$c}}{{end}}{{if not .CVEs}}{{.EDBID}}{{end}}</td><td>{{.Title}}</td><td>{{if .CVSS}}CVSS {{printf "%.1f" .CVSS}}{{else}}{{.LocalPath}}{{end}}</td></tr>{{end}}
</tbody></table>
{{end}}

<footer>NightfallLX v{{.Version}} · Authorized testing only · Generated reports may contain sensitive target metadata.</footer>
</div>
<script>
(function(){
  var active='all';
  var buttons=Array.prototype.slice.call(document.querySelectorAll('button.filter'));
  var search=document.getElementById('search');
  var findings=Array.prototype.slice.call(document.querySelectorAll('details.finding'));
  function apply(){
    var q=(search.value||'').toLowerCase().trim();
    findings.forEach(function(el){
      var sev=el.getAttribute('data-severity');
      var text=el.textContent.toLowerCase();
      var okSev=(active==='all'||sev===active);
      var okText=(!q||text.indexOf(q)!==-1);
      el.classList.toggle('hidden',!(okSev&&okText));
    });
  }
  buttons.forEach(function(btn){
    btn.addEventListener('click',function(){
      active=btn.getAttribute('data-severity');
      buttons.forEach(function(b){b.classList.toggle('active',b===btn);});
      apply();
    });
  });
  if(search){search.addEventListener('input',apply);}
})();
</script>
</body></html>`))
