package xss

import (
	"bytes"
	"fmt"
	"golang.org/x/net/html"
	"regexp"
	"strings"
)

// ContextType represents the HTML/JS reflection context.
type ContextType string

const (
	ContextHTMLText          ContextType = "html-text"
	ContextAttributeQuoted   ContextType = "attribute-quoted"
	ContextAttributeUnquoted ContextType = "attribute-unquoted"
	ContextJSStringSingle    ContextType = "js-string-single"
	ContextJSStringDouble    ContextType = "js-string-double"
	ContextJSTemplate        ContextType = "js-template"
	ContextJSRaw             ContextType = "js-raw"
	ContextURLAttribute      ContextType = "url-attribute"
	ContextHTMLComment       ContextType = "html-comment"
	ContextTagName           ContextType = "tag-name"
	ContextUnknown           ContextType = "unknown"
)

// Reflection holds the classified context and node details for a reflected marker.
type Reflection struct {
	Marker      string      `json:"marker"`
	Context     ContextType `json:"context"`
	TagName     string      `json:"tag_name,omitempty"`
	AttrName    string      `json:"attr_name,omitempty"`
	AttrQuote   string      `json:"attr_quote,omitempty"` // "'", "\"", or ""
	Snippet     string      `json:"snippet"`
	LineNumber  int         `json:"line_number"`
	IsDangerous bool        `json:"is_dangerous"`
}

var (
	urlAttributes = map[string]bool{
		"href":       true,
		"src":        true,
		"action":     true,
		"formaction": true,
		"data":       true,
		"poster":     true,
		"background": true,
	}

	eventHandlerRegex = regexp.MustCompile(`(?i)^on[a-z]+`)
	jsProtocolRegex   = regexp.MustCompile(`(?i)^\s*javascript:`)
)

// FindReflections parses HTML with golang.org/x/net/html and finds all occurrences of the marker.
func FindReflections(body string, marker string) []*Reflection {
	var reflections []*Reflection
	if marker == "" || !strings.Contains(body, marker) {
		return reflections
	}

	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		// Fallback to text scanning if parser fails completely
		return fallbackReflections(body, marker)
	}

	var walk func(n *html.Node, inScript bool)
	walk = func(n *html.Node, inScript bool) {
		if n == nil {
			return
		}

		currentInScript := inScript || (n.Type == html.ElementNode && strings.EqualFold(n.Data, "script"))

		switch n.Type {
		case html.ElementNode:
			// Check if tag name contains marker
			if strings.Contains(n.Data, marker) {
				reflections = append(reflections, &Reflection{
					Marker:      marker,
					Context:     ContextTagName,
					TagName:     n.Data,
					Snippet:     fmt.Sprintf("<%s>", n.Data),
					IsDangerous: true,
				})
			}

			// Check attributes
			for _, attr := range n.Attr {
				if strings.Contains(attr.Val, marker) {
					ref := classifyAttribute(body, n.Data, attr.Key, attr.Val, marker)
					reflections = append(reflections, ref)
				}
			}

		case html.TextNode:
			if strings.Contains(n.Data, marker) {
				if currentInScript {
					// Inside a <script> tag
					jsRef := classifyJSContext(n.Data, marker)
					reflections = append(reflections, jsRef)
				} else {
					// Normal HTML text
					snip := extractSnippet(n.Data, marker, 40)
					parentTag := ""
					if n.Parent != nil {
						parentTag = n.Parent.Data
					}
					reflections = append(reflections, &Reflection{
						Marker:      marker,
						Context:     ContextHTMLText,
						TagName:     parentTag,
						Snippet:     snip,
						IsDangerous: false,
					})
				}
			}

		case html.CommentNode:
			if strings.Contains(n.Data, marker) {
				reflections = append(reflections, &Reflection{
					Marker:      marker,
					Context:     ContextHTMLComment,
					Snippet:     fmt.Sprintf("<!--%s-->", extractSnippet(n.Data, marker, 40)),
					IsDangerous: false,
				})
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, currentInScript)
		}
	}

	walk(doc, false)
	return reflections
}

func classifyAttribute(rawHTML, tagName, attrKey, attrVal, marker string) *Reflection {
	lowerKey := strings.ToLower(attrKey)
	snip := fmt.Sprintf("%s=\"%s\"", attrKey, extractSnippet(attrVal, marker, 30))

	// Determine quote style in raw HTML
	// Match key=... in raw text
	attrPattern := regexp.MustCompile(fmt.Sprintf(`(?i)%s\s*=\s*(['"]?)([^'"\s>]*)`, regexp.QuoteMeta(attrKey)))
	quoteStyle := "\""
	match := attrPattern.FindStringSubmatch(rawHTML)
	if len(match) > 1 && match[1] != "" {
		quoteStyle = match[1]
	}

	ctx := ContextAttributeQuoted
	if quoteStyle == "" {
		ctx = ContextAttributeUnquoted
	}

	if urlAttributes[lowerKey] {
		ctx = ContextURLAttribute
	}

	return &Reflection{
		Marker:      marker,
		Context:     ctx,
		TagName:     tagName,
		AttrName:    attrKey,
		AttrQuote:   quoteStyle,
		Snippet:     snip,
		IsDangerous: true,
	}
}

func classifyJSContext(scriptBody, marker string) *Reflection {
	idx := strings.Index(scriptBody, marker)
	if idx == -1 {
		return &Reflection{Marker: marker, Context: ContextJSRaw, Snippet: marker}
	}

	// Scan preceding characters to check string quoting
	before := scriptBody[:idx]
	singleQuotes := 0
	doubleQuotes := 0
	backticks := 0
	escaped := false

	for i := 0; i < len(before); i++ {
		ch := before[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		switch ch {
		case '\'':
			if doubleQuotes%2 == 0 && backticks%2 == 0 {
				singleQuotes++
			}
		case '"':
			if singleQuotes%2 == 0 && backticks%2 == 0 {
				doubleQuotes++
			}
		case '`':
			if singleQuotes%2 == 0 && doubleQuotes%2 == 0 {
				backticks++
			}
		}
	}

	snip := extractSnippet(scriptBody, marker, 40)

	if backticks%2 != 0 {
		return &Reflection{
			Marker:      marker,
			Context:     ContextJSTemplate,
			TagName:     "script",
			Snippet:     snip,
			IsDangerous: true,
		}
	}
	if singleQuotes%2 != 0 {
		return &Reflection{
			Marker:      marker,
			Context:     ContextJSStringSingle,
			TagName:     "script",
			AttrQuote:   "'",
			Snippet:     snip,
			IsDangerous: true,
		}
	}
	if doubleQuotes%2 != 0 {
		return &Reflection{
			Marker:      marker,
			Context:     ContextJSStringDouble,
			TagName:     "script",
			AttrQuote:   "\"",
			Snippet:     snip,
			IsDangerous: true,
		}
	}

	return &Reflection{
		Marker:      marker,
		Context:     ContextJSRaw,
		TagName:     "script",
		Snippet:     snip,
		IsDangerous: true,
	}
}

func extractSnippet(str, needle string, radius int) string {
	idx := strings.Index(str, needle)
	if idx == -1 {
		if len(str) > radius*2 {
			return str[:radius*2] + "..."
		}
		return str
	}
	start := idx - radius
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + radius
	if end > len(str) {
		end = len(str)
	}
	res := str[start:end]
	res = strings.ReplaceAll(res, "\n", " ")
	res = strings.ReplaceAll(res, "\r", "")
	return strings.TrimSpace(res)
}

func fallbackReflections(body, marker string) []*Reflection {
	var list []*Reflection
	idx := 0
	for {
		pos := strings.Index(body[idx:], marker)
		if pos == -1 {
			break
		}
		realPos := idx + pos
		snip := extractSnippet(body[realPos:], marker, 30)
		list = append(list, &Reflection{
			Marker:      marker,
			Context:     ContextUnknown,
			Snippet:     snip,
			IsDangerous: false,
		})
		idx = realPos + len(marker)
	}
	return list
}

// CheckExecutableNode scans parsed HTML to find any confirmed executable XSS sinks containing the marker/payload.
// Confirmed means:
// 1. An event handler attribute (e.g. onerror, onload, onclick) whose value contains the unescaped payload or marker.
// 2. A <script> node whose unescaped body contains the payload or marker in executable position.
// 3. An active URL attribute (href, src, action) starting with javascript: (after whitespace/casing normalization) containing the payload.
func CheckExecutableNode(body string, marker string) (bool, string) {
	if marker == "" || !strings.Contains(body, marker) {
		return false, ""
	}

	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return false, ""
	}

	var confirmed bool
	var proof string

	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if confirmed || n == nil {
			return
		}

		if n.Type == html.ElementNode {
			// 1. Check all attributes for event handlers or javascript: URLs
			for _, attr := range n.Attr {
				// Event handler attribute like onload, onerror, onmouseover, ontoggle, etc.
				if eventHandlerRegex.MatchString(attr.Key) && strings.Contains(attr.Val, marker) {
					confirmed = true
					proof = fmt.Sprintf("<%s %s=%q>", n.Data, attr.Key, attr.Val)
					return
				}

				// URL attribute with javascript: scheme
				if urlAttributes[strings.ToLower(attr.Key)] {
					trimmed := strings.TrimSpace(attr.Val)
					if jsProtocolRegex.MatchString(trimmed) && strings.Contains(trimmed, marker) {
						confirmed = true
						proof = fmt.Sprintf("<%s %s=%q>", n.Data, attr.Key, attr.Val)
						return
					}
				}
			}

			// 2. Check <script> tags for active execution
			if strings.EqualFold(n.Data, "script") {
				var scriptBuf bytes.Buffer
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					if c.Type == html.TextNode {
						scriptBuf.WriteString(c.Data)
					}
				}
				sBody := scriptBuf.String()
				if strings.Contains(sBody, marker) {
					// Verify it is not inside an innocuous comment or completely escaped string
					jsRef := classifyJSContext(sBody, marker)
					if jsRef.Context == ContextJSRaw || jsRef.Context == ContextJSTemplate {
						confirmed = true
						proof = fmt.Sprintf("<script>%s</script>", extractSnippet(sBody, marker, 50))
						return
					}
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}

	walk(doc)
	return confirmed, proof
}
