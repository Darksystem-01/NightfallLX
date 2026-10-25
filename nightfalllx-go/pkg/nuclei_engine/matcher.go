package nuclei_engine

import (
	"nightfalllx/pkg/client"
	"regexp"
	"strings"
)

// EvaluateMatcher checks if an HTTP response satisfies a NucleiMatcher.
func EvaluateMatcher(m *NucleiMatcher, resp *client.Response) bool {
	var targetText string
	part := strings.ToLower(m.Part)
	if part == "" || part == "body" {
		targetText = resp.Body
	} else if part == "header" {
		var hdrs []string
		for k, v := range resp.Headers {
			hdrs = append(hdrs, k+": "+strings.Join(v, ", "))
		}
		targetText = strings.Join(hdrs, "\r\n")
	} else { // "all"
		targetText = resp.Body
		for k, v := range resp.Headers {
			targetText += "\r\n" + k + ": " + strings.Join(v, ", ")
		}
	}

	match := false

	switch strings.ToLower(m.Type) {
	case "status":
		for _, s := range m.Status {
			if resp.StatusCode == s {
				match = true
				break
			}
		}

	case "word":
		cond := strings.ToLower(m.Condition)
		if cond == "and" {
			match = true
			for _, w := range m.Words {
				if m.CaseInsensitive {
					if !strings.Contains(strings.ToLower(targetText), strings.ToLower(w)) {
						match = false
						break
					}
				} else {
					if !strings.Contains(targetText, w) {
						match = false
						break
					}
				}
			}
		} else { // "or" / default
			for _, w := range m.Words {
				if m.CaseInsensitive {
					if strings.Contains(strings.ToLower(targetText), strings.ToLower(w)) {
						match = true
						break
					}
				} else {
					if strings.Contains(targetText, w) {
						match = true
						break
					}
				}
			}
		}

	case "regex":
		cond := strings.ToLower(m.Condition)
		if cond == "and" {
			match = true
			for _, pattern := range m.Regex {
				flags := ""
				if m.CaseInsensitive {
					flags = "(?i)"
				}
				re, err := regexp.Compile(flags + pattern)
				if err != nil || !re.MatchString(targetText) {
					match = false
					break
				}
			}
		} else {
			for _, pattern := range m.Regex {
				flags := ""
				if m.CaseInsensitive {
					flags = "(?i)"
				}
				re, err := regexp.Compile(flags + pattern)
				if err == nil && re.MatchString(targetText) {
					match = true
					break
				}
			}
		}
	}

	if m.Negative {
		return !match
	}
	return match
}
