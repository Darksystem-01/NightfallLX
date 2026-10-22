package xss

import (
	"embed"
	"strings"
	"sync"
)

//go:embed vectors/*.txt
var vectorFS embed.FS

// Vector represents a single test vector with its category and character requirements.
type Vector struct {
	Payload       string      `json:"payload"`
	Category      string      `json:"category"`
	RequiredChars string      `json:"required_chars"`
	ContextHint   ContextType `json:"context_hint"`
}

var (
	corpus     []*Vector
	corpusOnce sync.Once
)

// ComputeRequiredChars extracts the distinct special characters present in the payload.
func ComputeRequiredChars(payload string) string {
	var chars []rune
	seen := make(map[rune]bool)
	for _, ch := range payload {
		if strings.ContainsRune(ProbeCharacters, ch) && !seen[ch] {
			seen[ch] = true
			chars = append(chars, ch)
		}
	}
	return string(chars)
}

// InferContextHint maps category or payload characteristics to an expected context.
func InferContextHint(category, payload string) ContextType {
	switch category {
	case "html_tag", "svg", "math":
		return ContextHTMLText
	case "attribute_context":
		return ContextAttributeQuoted
	case "js_string_context":
		return ContextJSStringSingle
	case "js_template_context":
		return ContextJSTemplate
	case "url_scheme":
		return ContextURLAttribute
	case "combined_context":
		return ContextAttributeQuoted
	default:
		return ContextUnknown
	}
}

// LoadVectors loads and parses the embedded vector files.
func LoadVectors() []*Vector {
	corpusOnce.Do(func() {
		files, err := vectorFS.ReadDir("vectors")
		if err != nil {
			return
		}

		for _, file := range files {
			if !strings.HasSuffix(file.Name(), ".txt") {
				continue
			}
			catName := strings.TrimSuffix(file.Name(), ".txt")
			data, err := vectorFS.ReadFile("vectors/" + file.Name())
			if err != nil {
				continue
			}

			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				vec := &Vector{
					Payload:       line,
					Category:      catName,
					RequiredChars: ComputeRequiredChars(line),
					ContextHint:   InferContextHint(catName, line),
				}
				corpus = append(corpus, vec)
			}
		}
	})
	return corpus
}

// FilterVectorsByProbe filters out vectors whose required characters failed to survive probing.
func FilterVectorsByProbe(vectors []*Vector, probe *ProbeResult) []*Vector {
	if probe == nil || len(probe.SurvivingChars) == 0 {
		return vectors
	}
	var filtered []*Vector
	for _, v := range vectors {
		if probe.SupportsVector(v.RequiredChars) {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

// FilterVectorsByContext prioritizes vectors matching the identified reflection context.
func FilterVectorsByContext(vectors []*Vector, ctx ContextType) []*Vector {
	var prioritized []*Vector
	var rest []*Vector

	for _, v := range vectors {
		if v.ContextHint == ctx {
			prioritized = append(prioritized, v)
		} else {
			rest = append(rest, v)
		}
	}

	return append(prioritized, rest...)
}
