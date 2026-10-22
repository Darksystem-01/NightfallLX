package xss

import (
	"bufio"
	"net/url"
	"nightfalllx/pkg/client"
	"os/exec"
	"regexp"
	"strings"
)

// DOMFinding records an identified source-to-sink flow in JavaScript code.
type DOMFinding struct {
	Source     string `json:"source"`
	Sink       string `json:"sink"`
	Variable   string `json:"variable,omitempty"`
	LineNumber int    `json:"line_number"`
	Snippet    string `json:"snippet"`
	ScriptFile string `json:"script_file"` // "inline" or remote script URL
	Confidence string `json:"confidence"`  // "probable"
}

var (
	// Known DOM XSS Sources
	domSources = []string{
		"location.hash",
		"location.search",
		"location.href",
		"window.location",
		"document.URL",
		"document.documentURI",
		"document.baseURI",
		"document.referrer",
		"window.name",
		"event.data",
		"e.data",
	}

	// Known DOM XSS Sinks
	domSinks = []string{
		".innerHTML",
		".outerHTML",
		".insertAdjacentHTML",
		"document.write",
		"document.writeln",
		"eval(",
		"setTimeout(",
		"setInterval(",
		"location.href",
		"location.assign(",
		"location.replace(",
		".html(",
		".append(",
		".prepend(",
	}

	// Pattern for variable assignment: (var|let|const|)\s*([a-zA-Z0-9_$]+)\s*=\s*(.*)
	assignRegex = regexp.MustCompile(`(?:var|let|const)?\s*([a-zA-Z0-9_$]+)\s*=\s*([^;]+)`)
	scriptSrcRegex = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	inlineScriptRegex = regexp.MustCompile(`(?is)<script(?:\s+[^>]*)?>(.*?)</script>`)
)

// AnalyzeDOMScript scans JavaScript source code for intra-file source-to-sink data flow.
func AnalyzeDOMScript(jsContent, scriptOrigin string) []*DOMFinding {
	var findings []*DOMFinding
	if jsContent == "" {
		return findings
	}

	scanner := bufio.NewScanner(strings.NewReader(jsContent))
	lineNum := 0

	// Map of tracked variable name -> source name
	trackedVars := make(map[string]string)

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") {
			continue
		}

		// 1. Direct Source to Sink in the same line
		for _, src := range domSources {
			if strings.Contains(line, src) {
				for _, sink := range domSinks {
					if strings.Contains(line, sink) {
						findings = append(findings, &DOMFinding{
							Source:     src,
							Sink:       sink,
							LineNumber: lineNum,
							Snippet:    line,
							ScriptFile: scriptOrigin,
							Confidence: "probable",
						})
					}
				}
			}
		}

		// 2. Intra-file Variable Assignment Tracking: var x = source
		matches := assignRegex.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			if len(m) >= 3 {
				varName := strings.TrimSpace(m[1])
				rhs := m[2]
				for _, src := range domSources {
					if strings.Contains(rhs, src) {
						trackedVars[varName] = src
					}
				}
			}
		}

		// 3. Tracked Variable to Sink
		for varName, src := range trackedVars {
			for _, sink := range domSinks {
				// Check if sink appears with the tracked variable in the line
				if strings.Contains(line, sink) && containsIdentifier(line, varName) {
					// Verify we haven't already recorded this exact line
					alreadyRecorded := false
					for _, f := range findings {
						if f.LineNumber == lineNum && f.ScriptFile == scriptOrigin && f.Sink == sink {
							alreadyRecorded = true
							break
						}
					}
					if !alreadyRecorded {
						findings = append(findings, &DOMFinding{
							Source:     src,
							Sink:       sink,
							Variable:   varName,
							LineNumber: lineNum,
							Snippet:    line,
							ScriptFile: scriptOrigin,
							Confidence: "probable",
						})
					}
				}
			}
		}
	}

	return findings
}

func containsIdentifier(line, ident string) bool {
	// Simple identifier boundary check
	pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(ident) + `\b`)
	return pattern.MatchString(line)
}

// AnalyzeHTMLDOM scans all inline <script> blocks and same-origin external scripts in the HTML page.
func AnalyzeHTMLDOM(pageHTML, pageURL string, c *client.Client) []*DOMFinding {
	var allFindings []*DOMFinding

	// 1. Inline scripts
	inlineMatches := inlineScriptRegex.FindAllStringSubmatch(pageHTML, -1)
	for _, m := range inlineMatches {
		if len(m) >= 2 && strings.TrimSpace(m[1]) != "" {
			f := AnalyzeDOMScript(m[1], "inline <script>")
			allFindings = append(allFindings, f...)
		}
	}

	// 2. Same-origin external scripts
	if c != nil && pageURL != "" {
		parsedBase, err := url.Parse(pageURL)
		if err == nil {
			srcMatches := scriptSrcRegex.FindAllStringSubmatch(pageHTML, -1)
			for _, sm := range srcMatches {
				if len(sm) >= 2 {
					scriptPath := sm[1]
					scriptURL, errResolve := parsedBase.Parse(scriptPath)
					if errResolve != nil {
						continue
					}
					// Only fetch same-origin scripts
					if scriptURL.Host == parsedBase.Host {
						resp, errGet := c.Get(scriptURL.String())
						if errGet == nil && resp.StatusCode == 200 {
							f := AnalyzeDOMScript(resp.Body, scriptURL.String())
							allFindings = append(allFindings, f...)
						}
					}
				}
			}
		}
	}

	return allFindings
}

// CheckBrowserDOM checks whether Chromium or Chrome is installed for headless DOM validation.
func CheckBrowserDOM() (bool, string) {
	for _, bin := range []string{"chromium", "chromium-browser", "google-chrome", "chrome"} {
		if path, err := exec.LookPath(bin); err == nil {
			return true, path
		}
	}
	return false, ""
}
