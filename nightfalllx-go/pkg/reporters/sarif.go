package reporters

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"nightfalllx/pkg/modules"
	"os"
	"strconv"
	"strings"
	"time"
)

// SARIFSchema is the canonical OASIS SARIF 2.1.0 schema identifier.
const SARIFSchema = "https://json.schemastore.org/sarif-2.1.0.json"

// SARIF 2.1.0 document model (only the fields NightfallLX emits).

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
	Results     []sarifResult     `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name,omitempty"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      *sarifText     `json:"fullDescription,omitempty"`
	HelpURI              string         `json:"helpUri,omitempty"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           sarifRuleProps `json:"properties"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
	CWE              int      `json:"cwe,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	StartTimeUTC        string `json:"startTimeUtc"`
	EndTimeUTC          string `json:"endTimeUtc"`
}

type sarifResult struct {
	RuleID              string                 `json:"ruleId"`
	RuleIndex           int                    `json:"ruleIndex"`
	Level               string                 `json:"level"`
	Message             sarifText              `json:"message"`
	Locations           []sarifLocation        `json:"locations"`
	PartialFingerprints map[string]string      `json:"partialFingerprints,omitempty"`
	Properties          map[string]interface{} `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

func sarifLevel(s modules.Severity) string {
	switch SeverityClass(s) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func sanitizeRuleID(module string) string {
	module = strings.ToLower(strings.TrimSpace(module))
	if module == "" {
		module = "generic"
	}
	var b strings.Builder
	for _, r := range module {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return "nightfalllx/" + b.String()
}

func fingerprint(f *modules.Finding) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		f.Module, f.Title, f.URL, f.Parameter, f.Payload,
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}

// BuildSARIFJSON renders findings as an OASIS SARIF v2.1.0 document suitable
// for GitHub Code Scanning, GitLab DAST and DefectDojo ingestion.
func BuildSARIFJSON(target *modules.Target, findings []*modules.Finding, meta ReportMeta) ([]byte, error) {
	meta = meta.resolved()
	start := meta.Timestamp.Add(-meta.Duration)
	if meta.Duration < 0 {
		start = meta.Timestamp
	}

	ruleIndex := make(map[string]int)
	rules := make([]sarifRule, 0)
	results := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		if f == nil {
			continue
		}
		ruleID := sanitizeRuleID(f.Module)
		idx, ok := ruleIndex[ruleID]
		if !ok {
			cvss := findingCVSS(f)
			idx = len(rules)
			ruleIndex[ruleID] = idx
			tags := []string{"security", f.Module}
			if f.CWEID > 0 {
				tags = append(tags, fmt.Sprintf("CWE-%d", f.CWEID))
			}
			rules = append(rules, sarifRule{
				ID:               ruleID,
				Name:             f.Module,
				ShortDescription: sarifText{Text: f.Title},
				FullDescription:  &sarifText{Text: f.Detail},
				HelpURI:          cweURL(f.CWEID),
				DefaultConfiguration: sarifConfig{
					Level: sarifLevel(f.Severity),
				},
				Properties: sarifRuleProps{
					Tags:             tags,
					SecuritySeverity: strconv.FormatFloat(cvss, 'f', 1, 64),
					CWE:              f.CWEID,
				},
			})
		}

		artifact := f.URL
		if artifact == "" && target != nil {
			artifact = target.URL
		}

		props := map[string]interface{}{
			"module":     f.Module,
			"severity":   string(f.Severity),
			"confidence": f.Confidence,
			"cvss":       findingCVSS(f),
			"parameter":  f.Parameter,
			"payload":    f.Payload,
		}
		if f.CWEID > 0 {
			props["cwe"] = f.CWEID
		}

		results = append(results, sarifResult{
			RuleID:    ruleID,
			RuleIndex: idx,
			Level:     sarifLevel(f.Severity),
			Message:   sarifText{Text: fmt.Sprintf("%s (parameter=%s, confidence=%d%%)", f.Title, f.Parameter, f.Confidence)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: artifact},
				},
			}},
			PartialFingerprints: map[string]string{
				"primaryLocationLineHash": fingerprint(f),
			},
			Properties: props,
		})
	}

	doc := sarifLog{
		Schema:  SARIFSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           GeneratorName,
				Version:        meta.Version,
				InformationURI: "https://github.com/Darksystem-01/NightfallLX",
				Rules:          rules,
			}},
			Invocations: []sarifInvocation{{
				ExecutionSuccessful: true,
				StartTimeUTC:        start.Format(time.RFC3339),
				EndTimeUTC:          meta.Timestamp.Format(time.RFC3339),
			}},
			Results: results,
		}},
	}

	return json.MarshalIndent(doc, "", "  ")
}

// WriteSARIFReport writes a SARIF v2.1.0 report to filePath.
func WriteSARIFReport(target *modules.Target, findings []*modules.Finding, meta ReportMeta, filePath string) error {
	data, err := BuildSARIFJSON(target, findings, meta)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, append(data, '\n'), 0o644)
}
