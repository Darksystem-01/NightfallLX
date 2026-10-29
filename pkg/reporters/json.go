package reporters

import (
	"encoding/json"
	"fmt"
	"net/url"
	"nightfalllx/pkg/cvss"
	"nightfalllx/pkg/modules"
	"os"
	"strings"
	"time"
)

const (
	// GeneratorName is embedded in every report format.
	GeneratorName = "NightfallLX"
	// GeneratorVersion is the report generator version.
	GeneratorVersion = "2.0.0"
	// ReportSchemaVersion identifies the JSON report layout.
	ReportSchemaVersion = "1.0"
)

// ReportMeta carries scan-level metadata shared by all report writers.
type ReportMeta struct {
	Timestamp time.Time
	Duration  time.Duration
	Version   string
	Command   string
}

func (m ReportMeta) resolved() ReportMeta {
	if m.Timestamp.IsZero() {
		m.Timestamp = time.Now().UTC()
	} else {
		m.Timestamp = m.Timestamp.UTC()
	}
	if m.Version == "" {
		m.Version = GeneratorVersion
	}
	return m
}

// TargetInfo is the serialisable view of a scan target.
type TargetInfo struct {
	URL        string   `json:"url"`
	Method     string   `json:"method"`
	Host       string   `json:"host,omitempty"`
	Parameters []string `json:"parameters"`
}

// Summary aggregates findings by severity.
type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// FindingView enriches a module finding with computed report fields.
type FindingView struct {
	*modules.Finding
	CVSSScore     float64 `json:"cvss_score"`
	CVSSVector    string  `json:"cvss_vector,omitempty"`
	CWEURL        string  `json:"cwe_url,omitempty"`
	Curl          string  `json:"curl"`
	SeverityClass string  `json:"severity_class"`
}

// Report is the structured JSON report document.
type Report struct {
	SchemaVersion string        `json:"schema_version"`
	Generator     string        `json:"generator"`
	Version       string        `json:"version"`
	Timestamp     string        `json:"timestamp"`
	DurationMS    int64         `json:"duration_ms"`
	Duration      string        `json:"duration"`
	Command       string        `json:"command,omitempty"`
	Target        TargetInfo    `json:"target"`
	Summary       Summary       `json:"summary"`
	Findings      []FindingView `json:"findings"`
}

// CVSSForSeverity maps a qualitative severity to an indicative CVSS 3.1 base
// score. Modules that know the exact vector can override it via Finding.CVSS.
func CVSSForSeverity(s modules.Severity) float64 {
	switch strings.ToUpper(string(s)) {
	case "CRITICAL":
		return 9.8
	case "HIGH":
		return 8.1
	case "MEDIUM":
		return 5.3
	case "LOW":
		return 3.1
	default:
		return 0.0
	}
}

func findingCVSS(f *modules.Finding) float64 {
	if f == nil {
		return 0
	}
	if f.CVSS > 0 {
		return f.CVSS
	}
	if f.CVSSVector != "" {
		if res, err := cvss.CalculateVector(f.CVSSVector); err == nil {
			f.CVSS = res.BaseScore
			return res.BaseScore
		}
	}
	return CVSSForSeverity(f.Severity)
}

func findingCVSSVector(f *modules.Finding) string {
	if f == nil {
		return ""
	}
	if f.CVSSVector != "" {
		return f.CVSSVector
	}
	res := cvss.ClassifyFinding(f.Module, f.Title, f.CWEID)
	return res.VectorString
}

// SeverityClass returns a stable CSS/JSON-safe lowercase severity name.
func SeverityClass(s modules.Severity) string {
	v := strings.ToLower(string(s))
	switch v {
	case "critical", "high", "medium", "low", "info":
		return v
	default:
		return "info"
	}
}

func cweURL(cwe int) string {
	if cwe <= 0 {
		return ""
	}
	return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", cwe)
}

func summarize(findings []*modules.Finding) Summary {
	s := Summary{Total: len(findings)}
	for _, f := range findings {
		switch SeverityClass(f.Severity) {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		case "low":
			s.Low++
		default:
			s.Info++
		}
	}
	return s
}

func targetInfo(target *modules.Target) TargetInfo {
	info := TargetInfo{}
	if target == nil {
		return info
	}
	info.URL = target.URL
	info.Method = target.Method
	info.Parameters = target.Parameters()
	if u, err := url.Parse(target.URL); err == nil && u.Host != "" {
		info.Host = u.Host
	}
	return info
}

func buildFindingViews(target *modules.Target, findings []*modules.Finding) []FindingView {
	views := make([]FindingView, 0, len(findings))
	for _, f := range findings {
		if f == nil {
			continue
		}
		views = append(views, FindingView{
			Finding:       f,
			CVSSScore:     findingCVSS(f),
			CVSSVector:    findingCVSSVector(f),
			CWEURL:        cweURL(f.CWEID),
			Curl:          buildCurlFinding(target, f),
			SeverityClass: SeverityClass(f.Severity),
		})
	}
	return views
}

// BuildReport assembles the structured report model.
func BuildReport(target *modules.Target, findings []*modules.Finding, meta ReportMeta) Report {
	meta = meta.resolved()
	duration := meta.Duration
	if duration < 0 {
		duration = 0
	}
	return Report{
		SchemaVersion: ReportSchemaVersion,
		Generator:     GeneratorName,
		Version:       meta.Version,
		Timestamp:     meta.Timestamp.Format(time.RFC3339),
		DurationMS:    duration.Milliseconds(),
		Duration:      duration.Round(time.Millisecond).String(),
		Command:       meta.Command,
		Target:        targetInfo(target),
		Summary:       summarize(findings),
		Findings:      buildFindingViews(target, findings),
	}
}

// MarshalJSONReport renders the structured JSON report.
func MarshalJSONReport(target *modules.Target, findings []*modules.Finding, meta ReportMeta) ([]byte, error) {
	return json.MarshalIndent(BuildReport(target, findings, meta), "", "  ")
}

// WriteJSONReport writes a structured JSON report to filePath.
func WriteJSONReport(target *modules.Target, findings []*modules.Finding, meta ReportMeta, filePath string) error {
	data, err := MarshalJSONReport(target, findings, meta)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, append(data, '\n'), 0o644)
}
