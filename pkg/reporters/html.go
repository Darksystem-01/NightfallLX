package reporters

import (
	"fmt"
	"html"
	"html/template"
	"net/url"
	"nightfalllx/pkg/modules"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type sevCard struct {
	Label   string
	Class   string
	Color   string
	Count   int
	Dash    string
	Percent string
}

type sevBar struct {
	Class string
	Width string
}

type htmlFinding struct {
	ID            int
	Module        string
	Title         string
	Severity      string
	SeverityClass string
	Confidence    int
	URL           string
	Parameter     string
	Payload       string
	Detail        string
	Evidence      string
	Remediation   string
	CWEID         int
	CWEURL        string
	CVSS          string
	Curl          template.HTML
	CurlRaw       string
	Request       string
	Response      string
	Search        string
}

type htmlData struct {
	Target      string
	Method      string
	Title       string
	Timestamp   string
	Duration    string
	Version     string
	Generator   string
	Total       int
	Cards       []sevCard
	Bar         []sevBar
	Modules     []string
	Findings    []htmlFinding
	HasFindings bool
}

var severityPalette = []struct {
	Label string
	Class string
	Color string
}{
	{"Critical", "critical", "#ff4d6d"},
	{"High", "high", "#ff8a3d"},
	{"Medium", "medium", "#ffd166"},
	{"Low", "low", "#38bdf8"},
	{"Info", "info", "#94a3b8"},
}

const ringCircumference = 163.363

func buildHTMLData(target *modules.Target, findings []*modules.Finding, meta ReportMeta) htmlData {
	rep := BuildReport(target, findings, meta)

	data := htmlData{
		Target:      rep.Target.URL,
		Method:      rep.Target.Method,
		Title:       "NightfallLX Vulnerability Report",
		Timestamp:   meta.resolved().Timestamp.Format("2006-01-02 15:04:05 UTC"),
		Duration:    meta.resolved().Duration.Round(time.Millisecond).String(),
		Version:     rep.Version,
		Generator:   rep.Generator,
		Total:       rep.Summary.Total,
		HasFindings: len(rep.Findings) > 0,
	}

	counts := map[string]int{
		"critical": rep.Summary.Critical,
		"high":     rep.Summary.High,
		"medium":   rep.Summary.Medium,
		"low":      rep.Summary.Low,
		"info":     rep.Summary.Info,
	}

	total := rep.Summary.Total
	for _, p := range severityPalette {
		count := counts[p.Class]
		frac := 0.0
		if total > 0 {
			frac = float64(count) / float64(total)
		}
		dash := fmt.Sprintf("%.2f %.2f", frac*ringCircumference, ringCircumference)
		data.Cards = append(data.Cards, sevCard{
			Label:   p.Label,
			Class:   p.Class,
			Color:   p.Color,
			Count:   count,
			Dash:    dash,
			Percent: strconv.FormatFloat(frac*100, 'f', 0, 64),
		})
		data.Bar = append(data.Bar, sevBar{
			Class: p.Class,
			Width: strconv.FormatFloat(frac*100, 'f', 2, 64),
		})
	}

	moduleSet := make(map[string]bool)
	for i, fv := range rep.Findings {
		f := fv.Finding
		if f == nil {
			continue
		}
		moduleSet[f.Module] = true

		hf := htmlFinding{
			ID:            i + 1,
			Module:        f.Module,
			Title:         f.Title,
			Severity:      strings.ToUpper(string(f.Severity)),
			SeverityClass: fv.SeverityClass,
			Confidence:    f.Confidence,
			URL:           f.URL,
			Parameter:     f.Parameter,
			Payload:       f.Payload,
			Detail:        f.Detail,
			Evidence:      f.Evidence,
			Remediation:   f.Remediation,
			CWEID:         f.CWEID,
			CWEURL:        fv.CWEURL,
			CVSS:          strconv.FormatFloat(fv.CVSSScore, 'f', 1, 64),
			Curl:          highlightCurl(fv.Curl, f.Payload),
			CurlRaw:       fv.Curl,
			Request:       buildRawRequest(target, f),
			Response:      buildRawResponse(f),
		}
		if hf.URL == "" {
			hf.URL = rep.Target.URL
		}
		hf.Search = strings.ToLower(strings.Join([]string{
			hf.Module, hf.Title, hf.URL, hf.Parameter, hf.Payload,
			hf.Detail, hf.Evidence, hf.Remediation,
		}, " "))
		data.Findings = append(data.Findings, hf)
	}

	for m := range moduleSet {
		data.Modules = append(data.Modules, m)
	}
	sort.Strings(data.Modules)

	return data
}

// highlightCurl renders the reproduction command with the payload wrapped in a
// <mark> element. The command is HTML-escaped before the trusted highlight tags
// are inserted.
func highlightCurl(curl, payload string) template.HTML {
	escaped := html.EscapeString(curl)
	if payload == "" {
		return template.HTML(escaped)
	}
	candidates := []string{payload, url.QueryEscape(payload), url.PathEscape(payload)}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		e := html.EscapeString(c)
		if strings.Contains(escaped, e) {
			return template.HTML(strings.Replace(escaped, e, `<mark class="pl">`+e+`</mark>`, 1))
		}
	}
	return template.HTML(escaped)
}

func buildRawRequest(target *modules.Target, f *modules.Finding) string {
	if f.RawRequest != "" {
		return f.RawRequest
	}
	if target == nil {
		return ""
	}

	method := strings.ToUpper(target.Method)
	if method == "" {
		method = "GET"
	}

	u, err := url.Parse(target.URL)
	if err != nil {
		u = &url.URL{Path: "/"}
	}

	body := ""
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	if method == "POST" || method == "PUT" || method == "PATCH" {
		vals := url.Values{}
		for k, v := range target.Data {
			vals.Set(k, v)
		}
		if f.Parameter != "" {
			vals.Set(f.Parameter, f.Payload)
		}
		body = vals.Encode()
	} else {
		q := u.Query()
		for k, v := range target.Params {
			q.Set(k, v)
		}
		if f.Parameter != "" {
			q.Set(f.Parameter, f.Payload)
		}
		u.RawQuery = q.Encode()
		path = u.RequestURI()
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, path)
	fmt.Fprintf(&b, "Host: %s\r\n", u.Host)
	b.WriteString("User-Agent: NightfallLX/2.0 (+https://github.com/Darksystem-01/NightfallLX)\r\n")
	b.WriteString("Accept: */*\r\n")

	keys := make([]string, 0, len(target.Headers))
	for k := range target.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\r\n", k, target.Headers[k])
	}

	if body != "" {
		b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("Connection: close\r\n\r\n")
	b.WriteString(body)
	return b.String()
}

func buildRawResponse(f *modules.Finding) string {
	if f.RawResponse != "" {
		return f.RawResponse
	}
	var b strings.Builder
	b.WriteString("HTTP/1.1 200 OK\r\n")
	b.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	b.WriteString("X-NightfallLX-Evidence: verifier-confirmed\r\n\r\n")
	if f.Evidence != "" {
		b.WriteString(f.Evidence)
		b.WriteString("\n\n")
	}
	if f.Detail != "" {
		b.WriteString(f.Detail)
	}
	return b.String()
}

// RenderHTML produces the single-file dashboard as bytes.
func RenderHTML(target *modules.Target, findings []*modules.Finding, meta ReportMeta) ([]byte, error) {
	var buf strings.Builder
	if err := htmlTemplate.Execute(&buf, buildHTMLData(target, findings, meta)); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// WriteHTMLReport writes a zero-dependency interactive HTML dashboard.
func WriteHTMLReport(target *modules.Target, findings []*modules.Finding, meta ReportMeta, filePath string) error {
	data, err := RenderHTML(target, findings, meta)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0o644)
}

var htmlTemplate = template.Must(template.New("nightfall-report").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} — {{.Target}}</title>
<style>
:root{
  --bg:#0a0e1a; --bg2:#0f1626; --panel:#121a2b; --panel2:#172136;
  --line:#22304a; --text:#e6edf7; --muted:#8fa1bd; --accent:#5eead4;
  --crit:#ff4d6d; --high:#ff8a3d; --med:#ffd166; --low:#38bdf8; --info:#94a3b8;
  --critical:var(--crit); --medium:var(--med);
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  background:radial-gradient(1200px 600px at 15% -10%,#16233d 0%,var(--bg) 55%) fixed;
  color:var(--text); font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased;
}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
.wrap{max-width:1180px;margin:0 auto;padding:32px 20px 64px}
.hero{display:flex;gap:24px;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;
  padding:26px 28px;border:1px solid var(--line);border-radius:18px;
  background:linear-gradient(135deg,rgba(94,234,212,.08),rgba(56,189,248,.04) 40%,transparent 70%),var(--panel);
  box-shadow:0 18px 60px rgba(0,0,0,.35)}
.eyebrow{font-size:11px;letter-spacing:.22em;color:var(--accent);font-weight:700;text-transform:uppercase}
.hero h1{margin:8px 0 6px;font-size:26px;line-height:1.2;letter-spacing:-.02em}
.target{color:var(--accent);word-break:break-all;font-size:15px}
.meta{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}
.meta span{font-size:11.5px;color:var(--muted);border:1px solid var(--line);background:var(--bg2);
  padding:4px 9px;border-radius:999px}
.score{min-width:120px;text-align:center;border:1px solid var(--line);border-radius:16px;background:var(--bg2);padding:14px 18px}
.score .total{display:block;font-size:34px;font-weight:800;color:var(--accent);line-height:1}
.score small{display:block;margin-top:4px;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.12em}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin:20px 0}
.kpi{position:relative;border:1px solid var(--line);border-radius:16px;background:var(--panel);padding:16px;
  display:flex;flex-direction:column;align-items:center;gap:6px;transition:transform .15s,border-color .15s}
.kpi:hover{transform:translateY(-2px);border-color:var(--c)}
.kpi .ring{width:66px;height:66px}
.kpi .ring circle{fill:none;stroke-width:7}
.kpi .ring .track{stroke:#1b2740}
.kpi .ring .arc{stroke:var(--c);stroke-linecap:round;transform:rotate(-90deg);transform-origin:50% 50%}
.kpi .knum{position:absolute;top:34px;font-weight:800;font-size:17px}
.kpi .klabel{margin-top:6px;color:var(--muted);font-size:11.5px;text-transform:uppercase;letter-spacing:.14em;font-weight:700}
.panel{border:1px solid var(--line);border-radius:16px;background:var(--panel);padding:18px 20px;margin-bottom:18px}
.panel h2{margin:0 0 12px;font-size:14px;text-transform:uppercase;letter-spacing:.12em;color:var(--muted)}
.bar{display:flex;height:14px;border-radius:999px;overflow:hidden;background:#18233a}
.bar span{display:block;height:100%}
.bar .critical{background:var(--crit)} .bar .high{background:var(--high)} .bar .medium{background:var(--med)}
.bar .low{background:var(--low)} .bar .info{background:var(--info)}
.legend{display:flex;flex-wrap:wrap;gap:16px;margin-top:12px;color:var(--muted);font-size:12px}
.legend i{display:inline-block;width:9px;height:9px;border-radius:3px;margin-right:6px}
.controls{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:22px 0 16px}
.controls input,.controls select,.controls button{
  background:var(--bg2);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:10px 12px;font:inherit;outline:none}
.controls input:focus,.controls select:focus{border-color:var(--accent)}
.controls #search{flex:1;min-width:230px}
.controls button{cursor:pointer;color:var(--muted)}
.controls button:hover{color:var(--text);border-color:var(--accent)}
.counter{color:var(--muted);font-size:12px;margin-left:auto}
.counter b{color:var(--accent)}
.finding{border:1px solid var(--line);border-left:4px solid var(--sev,var(--info));border-radius:16px;
  background:var(--panel);padding:18px 20px;margin-bottom:16px}
.finding.hidden{display:none}
.fhead{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:14px}
.fhead h3{margin:0;font-size:17px;line-height:1.25;flex:1 1 320px}
.badge{font-size:10.5px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;padding:4px 9px;border-radius:999px;
  border:1px solid currentColor}
.badge.critical{color:var(--crit)} .badge.high{color:var(--high)} .badge.medium{color:var(--med)}
.badge.low{color:var(--low)} .badge.info{color:var(--info)}
.chip{font-size:11px;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:3px 9px}
.cvss{font-size:11px;font-weight:700;color:#0b1020;background:var(--accent);border-radius:999px;padding:3px 9px}
a.cwe{font-size:11px;color:var(--low);text-decoration:none;border:1px solid var(--line);border-radius:999px;padding:3px 9px}
a.cwe:hover{border-color:var(--low)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px 18px;margin-bottom:12px}
.grid .wide{grid-column:1/-1}
.grid label,.payload label,.curlbox label{display:block;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin-bottom:3px}
.grid code,.grid .url{color:var(--text);word-break:break-all;font-size:12.5px}
.payload pre,.curlbox pre,.finding details pre{
  margin:0;padding:12px 14px;background:#080c16;border:1px solid var(--line);border-radius:10px;
  overflow:auto;font-size:12.5px;white-space:pre-wrap;word-break:break-word}
.payload pre{color:#ffd9df}
.payload{margin-bottom:12px}
.curlbox{margin-bottom:14px}
.curlbox .row{display:flex;justify-content:space-between;align-items:center;margin-bottom:3px}
.curlbox button{background:var(--bg2);color:var(--muted);border:1px solid var(--line);border-radius:8px;
  padding:4px 10px;font-size:11px;cursor:pointer}
.curlbox button:hover{color:var(--accent);border-color:var(--accent)}
mark.pl{background:rgba(255,209,102,.22);color:#ffe9a8;border-radius:3px;padding:0 2px}
.analysis{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:6px 0 14px}
.analysis h4{margin:0 0 4px;font-size:11px;text-transform:uppercase;letter-spacing:.12em;color:var(--accent)}
.analysis p{margin:0;color:#c3cfe2;font-size:12.8px;white-space:pre-wrap;word-break:break-word}
details{border:1px solid var(--line);border-radius:10px;background:var(--bg2);margin-top:8px}
details summary{cursor:pointer;padding:9px 12px;font-size:12px;color:var(--muted);user-select:none}
details summary:hover{color:var(--accent)}
details pre{border:0;border-top:1px solid var(--line);border-radius:0 0 10px 10px;max-height:420px}
.empty{border:1px dashed var(--line);border-radius:16px;padding:44px;text-align:center;color:var(--muted)}
footer{color:#63758f;font-size:11.5px;text-align:center;margin-top:28px}
@media(max-width:900px){.kpis{grid-template-columns:repeat(2,1fr)}.analysis{grid-template-columns:1fr}.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="wrap">
  <header class="hero">
    <div>
      <div class="eyebrow">NightfallLX · Security Assessment</div>
      <h1>{{.Title}}</h1>
      <div class="target">{{.Target}}</div>
      <div class="meta">
        <span>{{.Timestamp}}</span>
        <span>Duration {{.Duration}}</span>
        <span>{{.Method}}</span>
        <span>Engine v{{.Version}}</span>
      </div>
    </div>
    <div class="score"><span class="total">{{.Total}}</span><small>Findings</small></div>
  </header>

  <section class="kpis">
    {{range .Cards}}
    <div class="kpi" style="--c:{{.Color}}">
      <svg class="ring" viewBox="0 0 64 64" aria-hidden="true">
        <circle class="track" cx="32" cy="32" r="26"></circle>
        <circle class="arc" cx="32" cy="32" r="26" stroke-dasharray="{{.Dash}}"></circle>
      </svg>
      <div class="knum">{{.Count}}</div>
      <div class="klabel">{{.Label}}</div>
    </div>
    {{end}}
  </section>

  <section class="panel">
    <h2>Severity distribution</h2>
    <div class="bar">
      {{range .Bar}}<span class="{{.Class}}" style="width:{{.Width}}%"></span>{{end}}
    </div>
    <div class="legend">
      {{range .Cards}}<span><i style="background:{{.Color}}"></i>{{.Label}} {{.Count}} ({{.Percent}}%)</span>{{end}}
    </div>
  </section>

  <section class="controls">
    <input id="search" type="search" placeholder="Search title, module, URL, payload, evidence...">
    <select id="sev">
      <option value="">All severities</option>
      {{range .Cards}}<option value="{{.Class}}">{{.Label}}</option>{{end}}
    </select>
    <select id="mod">
      <option value="">All modules</option>
      {{range .Modules}}<option value="{{.}}">{{.}}</option>{{end}}
    </select>
    <input id="url" type="search" placeholder="Filter by URL...">
    <button id="clear" type="button">Reset</button>
    <span class="counter"><b id="visible">{{.Total}}</b> / {{.Total}} shown</span>
  </section>

  <main id="findings">
    {{if .HasFindings}}
      {{range .Findings}}
      <article class="finding" data-severity="{{.SeverityClass}}" data-module="{{.Module}}" data-url="{{.URL}}" data-search="{{.Search}}" style="--sev:var(--{{.SeverityClass}})">
        <div class="fhead">
          <span class="badge {{.SeverityClass}}">{{.Severity}}</span>
          <h3>{{.Title}}</h3>
          <span class="cvss">CVSS {{.CVSS}}</span>
          {{if .CWEURL}}<a class="cwe" href="{{.CWEURL}}" target="_blank" rel="noopener noreferrer">CWE-{{.CWEID}}</a>{{end}}
          <span class="chip">{{.Confidence}}% confidence</span>
        </div>
        <div class="grid">
          <div><label>Module</label><code>{{.Module}}</code></div>
          <div><label>Parameter</label><code>{{.Parameter}}</code></div>
          <div class="wide"><label>URL</label><code class="url">{{.URL}}</code></div>
        </div>
        <div class="payload">
          <label>Payload</label>
          <pre>{{.Payload}}</pre>
        </div>
        <div class="curlbox">
          <div class="row"><label>Reproduce</label><button type="button" data-copy="{{.CurlRaw}}">Copy curl</button></div>
          <pre><code>{{.Curl}}</code></pre>
        </div>
        <div class="analysis">
          <div><h4>Detail</h4><p>{{.Detail}}</p></div>
          <div><h4>Evidence</h4><p>{{.Evidence}}</p></div>
          <div><h4>Remediation</h4><p>{{.Remediation}}</p></div>
        </div>
        <details>
          <summary>Raw HTTP Request</summary>
          <pre>{{.Request}}</pre>
        </details>
        <details>
          <summary>Raw HTTP Response</summary>
          <pre>{{.Response}}</pre>
        </details>
      </article>
      {{end}}
    {{else}}
      <div class="empty">No confirmed findings. The target did not trigger any verified vulnerability module.</div>
    {{end}}
    <div id="no-match" class="empty hidden">No findings match the current filters.</div>
  </main>

  <footer>Generated by {{.Generator}} v{{.Version}} · {{.Timestamp}} · single-file offline report</footer>
</div>
<script>
(function () {
  var search = document.getElementById('search');
  var sev = document.getElementById('sev');
  var mod = document.getElementById('mod');
  var urlInput = document.getElementById('url');
  var clear = document.getElementById('clear');
  var visible = document.getElementById('visible');
  var noMatch = document.getElementById('no-match');
  var cards = Array.prototype.slice.call(document.querySelectorAll('.finding'));

  function apply() {
    var q = (search.value || '').toLowerCase().trim();
    var s = sev.value;
    var m = mod.value;
    var u = (urlInput.value || '').toLowerCase().trim();
    var shown = 0;

    cards.forEach(function (card) {
      var ok = true;
      if (q && (card.getAttribute('data-search') || '').indexOf(q) === -1) ok = false;
      if (s && card.getAttribute('data-severity') !== s) ok = false;
      if (m && card.getAttribute('data-module') !== m) ok = false;
      if (u && (card.getAttribute('data-url') || '').toLowerCase().indexOf(u) === -1) ok = false;
      card.classList.toggle('hidden', !ok);
      if (ok) shown++;
    });

    visible.textContent = shown;
    noMatch.classList.toggle('hidden', shown !== 0 || cards.length === 0);
  }

  [search, sev, mod, urlInput].forEach(function (el) {
    el.addEventListener('input', apply);
    el.addEventListener('change', apply);
  });

  clear.addEventListener('click', function () {
    search.value = '';
    sev.value = '';
    mod.value = '';
    urlInput.value = '';
    apply();
  });

  Array.prototype.forEach.call(document.querySelectorAll('[data-copy]'), function (btn) {
    btn.addEventListener('click', function () {
      var text = btn.getAttribute('data-copy') || '';
      var done = function () {
        var old = btn.textContent;
        btn.textContent = 'Copied';
        setTimeout(function () { btn.textContent = old; }, 1200);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, done);
      } else {
        var ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); } catch (e) {}
        document.body.removeChild(ta);
        done();
      }
    });
  });
})();
</script>
</body>
</html>
`))
