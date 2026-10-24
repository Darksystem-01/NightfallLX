package reporters

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"nightfalllx/pkg/intel"
	"nightfalllx/pkg/modules"
	"nightfalllx/pkg/version"
)

// SARIF 2.1.0 structures (only the fields NightfallLX emits).
type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	InformationURI  string      `json:"informationUri,omitempty"`
	Rules           []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name,omitempty"`
	ShortDescription sarifMessage           `json:"shortDescription"`
	FullDescription  *sarifMessage          `json:"fullDescription,omitempty"`
	HelpURI          string                 `json:"helpUri,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID     string                 `json:"ruleId"`
	RuleIndex  int                    `json:"ruleIndex"`
	Level      string                 `json:"level"`
	Message    sarifMessage           `json:"message"`
	Locations  []sarifLocation        `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// WriteSARIFReport writes findings as SARIF 2.1.0 without intel metadata.
func WriteSARIFReport(target *modules.Target, findings []*modules.Finding, filePath string) error {
	return WriteSARIFReportWithIntel(target, findings, nil, filePath)
}

// WriteSARIFReportWithIntel writes a SARIF 2.1.0 log suitable for GitHub
// Advanced Security, VS Code SARIF Viewer, and other SARIF consumers.
func WriteSARIFReportWithIntel(target *modules.Target, findings []*modules.Finding, intelRep *intel.IntelReport, filePath string) error {
	if findings == nil {
		findings = []*modules.Finding{}
	}

	driver := sarifDriver{
		Name:            "NightfallLX",
		Version:         version.Version,
		SemanticVersion: version.Version,
		InformationURI:  "https://github.com/Darksystem-01/NightfallLX",
	}
	ruleIndex := make(map[string]int)
	var rules []sarifRule
	addRule := func(id, name, short, help string, props map[string]interface{}) int {
		if idx, ok := ruleIndex[id]; ok {
			return idx
		}
		idx := len(rules)
		ruleIndex[id] = idx
		rules = append(rules, sarifRule{
			ID:               id,
			Name:             name,
			ShortDescription: sarifMessage{Text: short},
			HelpURI:          help,
			Properties:       props,
		})
		return idx
	}

	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		ruleID := sarifRuleID(f)
		idx := addRule(ruleID, f.Module, f.Title,
			"https://github.com/Darksystem-01/NightfallLX",
			map[string]interface{}{
				"tags":     []string{"security", "web", string(f.Severity)},
				"severity": string(f.Severity),
				"cwe":      f.CWEID,
			})
		props := map[string]interface{}{
			"module":           f.Module,
			"severity":         string(f.Severity),
			"confidence":       f.Confidence,
			"confidence_level": string(f.ConfidenceLevel),
			"parameter":        f.Parameter,
			"payload":          f.Payload,
			"remediation":      f.Remediation,
		}
		if f.Evidence != "" {
			props["evidence"] = f.Evidence
		}
		results = append(results, sarifResult{
			RuleID:    ruleID,
			RuleIndex: idx,
			Level:     sarifLevel(f.Severity),
			Message:   sarifMessage{Text: f.Title + " (" + f.URL + ")"},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.URL},
					Region:           sarifRegion{StartLine: 1},
				},
			}},
			Properties: props,
		})
	}

	if intelRep != nil {
		for _, item := range intelRep.Findings {
			if item == nil {
				continue
			}
			ruleID := "nightfalllx/intel/" + sanitizeRuleComponent(item.Source)
			idx := addRule(ruleID, "intel/"+item.Source, "Version-matched public vulnerability reference",
				"https://github.com/Darksystem-01/NightfallLX",
				map[string]interface{}{"tags": []string{"security", "intel", "unverified"}})
			props := map[string]interface{}{
				"query":      item.Query,
				"source":     item.Source,
				"cves":       item.CVEs,
				"edb_id":     item.EDBID,
				"cvss":       item.CVSS,
				"local_path": item.LocalPath,
				"unverified": true,
			}
			results = append(results, sarifResult{
				RuleID:    ruleID,
				RuleIndex: idx,
				Level:     "note",
				Message:   sarifMessage{Text: item.Title},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: target.URL},
						Region:           sarifRegion{StartLine: 1},
					},
				}},
				Properties: props,
			})
		}
	}

	driver.Rules = rules
	report := sarifReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: driver},
			Results: results,
		}},
	}

	bytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, bytes, 0644)
}

func sarifRuleID(f *modules.Finding) string {
	module := sanitizeRuleComponent(f.Module)
	if f.CWEID > 0 {
		return fmt.Sprintf("nightfalllx/%s/cwe-%d", module, f.CWEID)
	}
	return "nightfalllx/" + module
}

func sanitizeRuleComponent(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "unknown"
	}
	return out
}

func sarifLevel(sev modules.Severity) string {
	switch sev {
	case modules.SeverityCritical, modules.SeverityHigh:
		return "error"
	case modules.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
