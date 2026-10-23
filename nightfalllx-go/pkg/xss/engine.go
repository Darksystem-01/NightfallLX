package xss

import (
	"fmt"
	"nightfalllx/pkg/client"
	"strings"
)

// EngineConfig configures the native Go XSS testing engine.
type EngineConfig struct {
	EnableDOM         bool
	EnableDOMBrowser  bool
	EnableForms       bool
	EnableStored      bool
	MaxVectorsPerParam int
	FuzzMode          bool
}

// DefaultEngineConfig returns sensible defaults for fast and comprehensive testing.
func DefaultEngineConfig() *EngineConfig {
	return &EngineConfig{
		EnableDOM:          true,
		EnableDOMBrowser:   false,
		EnableForms:        false,
		EnableStored:       false,
		MaxVectorsPerParam: 15,
		FuzzMode:           false,
	}
}

// Engine implements intelligent reflection context analysis, character probing, and harmless test vector evaluation.
type Engine struct {
	Config  *EngineConfig
	Vectors []*Vector
}

// NewEngine initializes the XSS engine with embedded vectors.
func NewEngine(cfg *EngineConfig) *Engine {
	if cfg == nil {
		cfg = DefaultEngineConfig()
	}
	if cfg.MaxVectorsPerParam <= 0 {
		cfg.MaxVectorsPerParam = 15
	}
	return &Engine{
		Config:  cfg,
		Vectors: LoadVectors(),
	}
}

// ScanTarget runs comprehensive XSS analysis on a target endpoint.
func (e *Engine) ScanTarget(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding

	// 1. Baseline Request
	var baselineResp *client.Response
	var err error
	if strings.ToUpper(target.Method) == "POST" {
		baselineResp, err = c.Post(target.URL, target.Data)
	} else {
		baselineResp, err = c.Get(target.BuildURLWithParam("", ""))
	}
	if err != nil {
		return nil, fmt.Errorf("baseline request failed: %w", err)
	}

	// 2. DOM Analysis on Baseline HTML
	if e.Config.EnableDOM && baselineResp != nil && baselineResp.Body != "" {
		domFindings := AnalyzeHTMLDOM(baselineResp.Body, target.URL, c)
		for _, df := range domFindings {
			f := &Finding{
				Title:           fmt.Sprintf("DOM XSS Source-to-Sink: %s -> %s", df.Source, df.Sink),
				Severity:        "MEDIUM",
				Confidence:      80,
				ConfidenceLevel: "probable",
				URL:             target.URL,
				Parameter:       df.Source,
				Payload:         df.Snippet,
				Detail:          fmt.Sprintf("Static DOM analysis detected tainted data flow from source '%s' to sink '%s' in %s (line %d).", df.Source, df.Sink, df.ScriptFile, df.LineNumber),
				Evidence:        df.Snippet,
				Remediation:     "Sanitize untrusted inputs from DOM sources using DOMPurify before assigning to HTML sinks.",
				CWEID:           79,
			}
			findings = append(findings, f)
		}

		if e.Config.EnableDOMBrowser {
			installed, binPath := CheckBrowserDOM()
			if !installed {
				// Record note that browser check was skipped gracefully
				fmt.Println("    [-] Notice: Chromium/Chrome not found on PATH. Headless DOM browser validation skipped.")
			} else {
				fmt.Printf("    [+] Headless browser available at %s for DOM validation.\n", binPath)
			}
		}
	}

	// 3. Form Parsing & Stored XSS
	if e.Config.EnableForms && baselineResp != nil && baselineResp.Body != "" {
		forms := ParseForms(baselineResp.Body, target.URL)
		if e.Config.EnableStored && len(forms) > 0 {
			storedList, errStored := CheckStoredXSS(forms, []string{target.URL}, c)
			if errStored == nil {
				for _, sf := range storedList {
					conf := "probable"
					score := 80
					if sf.Confidence == "confirmed" {
						conf = "confirmed"
						score = 100
					}
					f := &Finding{
						Title:           "Stored Cross-Site Scripting (Persistent Reflection)",
						Severity:        "HIGH",
						Confidence:      score,
						ConfidenceLevel: conf,
						URL:             sf.FoundAtURL,
						Parameter:       sf.Parameter,
						Payload:         sf.Canary,
						Detail:          sf.Detail,
						Evidence:        sf.Proof,
						Remediation:     "Store data in a clean format and apply context-aware HTML output encoding upon rendering.",
						CWEID:           79,
					}
					findings = append(findings, f)
				}
			}
		}
	}

	// 4. Reflected Parameter Analysis
	params := target.Parameters()
	for _, param := range params {
		paramFindings := e.testParameter(param, target, c)
		findings = append(findings, paramFindings...)
	}

	return findings, nil
}

// BuildVectorWithCanary embeds the unique canary token into the test vector payload.
func BuildVectorWithCanary(basePayload, canary string) string {
	if strings.Contains(basePayload, "alert(1)") {
		return strings.ReplaceAll(basePayload, "alert(1)", "alert("+canary+")")
	}
	if strings.Contains(basePayload, "(1)") {
		return strings.ReplaceAll(basePayload, "(1)", "("+canary+")")
	}
	return basePayload + canary
}

func (e *Engine) testParameter(param string, target *Target, c *client.Client) []*Finding {
	var findings []*Finding

	// Step 4.1: Reflection Check with unique canary
	canary := RandomToken("lxref", 8)
	resp, err := e.sendParam(target, param, canary, c)
	if err != nil || resp == nil {
		return findings
	}

	reflections := FindReflections(resp.Body, canary)
	if len(reflections) == 0 {
		return findings // Parameter does not reflect in response
	}

	// Determine primary reflection context
	primaryContext := reflections[0].Context

	// Step 4.2: Character Probing
	probe, _ := SendProbe(param, target, c)

	// Step 4.3: Filter & Prioritize Vectors
	candidateVectors := FilterVectorsByProbe(e.Vectors, probe)
	candidateVectors = FilterVectorsByContext(candidateVectors, primaryContext)

	if len(candidateVectors) > e.Config.MaxVectorsPerParam {
		candidateVectors = candidateVectors[:e.Config.MaxVectorsPerParam]
	}

	var confirmedFinding *Finding
	var probableFinding *Finding
	var possibleFinding *Finding

	// Step 4.4: Inject Test Vectors
	for _, vec := range candidateVectors {
		canary := RandomToken("lxc", 12)
		payload := BuildVectorWithCanary(vec.Payload, canary)

		vecResp, errVec := e.sendParam(target, param, payload, c)
		if errVec != nil || vecResp == nil {
			continue
		}

		// A4 Confidence Evaluation:
		// 1. Confirmed only if:
		// (a) the canary appears in the response, and
		// (b) CheckExecutableNode(body, canary) is true.
		if strings.Contains(vecResp.Body, canary) {
			isExec, proof := CheckExecutableNode(vecResp.Body, canary)
			if isExec {
				confirmedFinding = &Finding{
					Title:           fmt.Sprintf("Confirmed Reflected XSS (%s)", vec.Category),
					Severity:        "HIGH",
					Confidence:      100,
					ConfidenceLevel: "confirmed",
					URL:             target.URL,
					Parameter:       param,
					Payload:         payload,
					Detail:          fmt.Sprintf("The parameter was confirmed vulnerable to Reflected Cross-Site Scripting. The injected vector executed in context '%s'.", primaryContext),
					Evidence:        proof,
					Remediation:     "Implement context-aware HTML entity encoding or Content Security Policy (CSP).",
					CWEID:           79,
				}
				break // Confirmed found, no need to probe further for this parameter
			}
		}

		// 2. Probable: string is reflected unescaped in dangerous context
		if strings.Contains(vecResp.Body, payload) && probableFinding == nil {
			if reflections[0].IsDangerous {
				probableFinding = &Finding{
					Title:           fmt.Sprintf("Probable Reflected XSS (%s)", vec.Category),
					Severity:        "MEDIUM",
					Confidence:      80,
					ConfidenceLevel: "probable",
					URL:             target.URL,
					Parameter:       param,
					Payload:         payload,
					Detail:          fmt.Sprintf("The vector was reflected unescaped in dangerous context '%s', but parser did not verify active node execution.", primaryContext),
					Evidence:        extractSnippet(vecResp.Body, payload, 40),
					Remediation:     "Sanitize and encode all reflected parameters using context-appropriate HTML encoders.",
					CWEID:           79,
				}
			}
		}
	}

	if confirmedFinding != nil {
		findings = append(findings, confirmedFinding)
		return findings
	}

	if probableFinding != nil {
		findings = append(findings, probableFinding)
		return findings
	}

	// 3. Possible: only partial survival of special characters
	if probe != nil && len(probe.SurvivingChars) >= 2 && possibleFinding == nil {
		var surviving []string
		for ch := range probe.SurvivingChars {
			surviving = append(surviving, string(ch))
		}
		possibleFinding = &Finding{
			Title:           "Possible XSS Filter Anomaly (Special Characters Reflected)",
			Severity:        "LOW",
			Confidence:      50,
			ConfidenceLevel: "possible",
			URL:             target.URL,
			Parameter:       param,
			Payload:         BuildProbePayload("lxprobe"),
			Detail:          fmt.Sprintf("Parameter reflects in %s with surviving special characters: [%s].", primaryContext, strings.Join(surviving, " ")),
			Evidence:        fmt.Sprintf("Surviving characters: %v", surviving),
			Remediation:     "Ensure special characters (<, >, \", ', `) are strictly HTML-entity encoded.",
			CWEID:           79,
		}
		findings = append(findings, possibleFinding)
	}

	return findings
}

func (e *Engine) sendParam(target *Target, param, val string, c *client.Client) (*client.Response, error) {
	if target.IsJSON && target.RawJSON != "" {
		body := strings.ReplaceAll(target.RawJSON, `"`+param+`": ""`, `"`+param+`": "`+val+`"`)
		if body == target.RawJSON {
			body = strings.ReplaceAll(target.RawJSON, param, val)
		}
		headers := copyHeaders(target.Headers)
		headers["Content-Type"] = "application/json"
		return c.DoCustom("POST", target.URL, headers, body)
	}

	if strings.ToUpper(target.Method) == "POST" {
		data := copyParams(target.Data)
		data[param] = val
		return c.Post(target.URL, data)
	}

	reqURL := target.BuildURLWithParam(param, val)
	return c.Get(reqURL)
}

