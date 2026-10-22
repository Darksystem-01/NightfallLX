package modules

import (
	"encoding/json"
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/oast"
	"regexp"
	"strconv"
	"strings"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

type ConfidenceLevel string

const (
	ConfidenceConfirmed ConfidenceLevel = "confirmed"
	ConfidenceProbable  ConfidenceLevel = "probable"
	ConfidencePossible  ConfidenceLevel = "possible"
)

// Finding represents a verified security vulnerability.
type Finding struct {
	Module          string          `json:"module"`
	Title           string          `json:"title"`
	Severity        Severity        `json:"severity"`
	Confidence      int             `json:"confidence"`
	ConfidenceLevel ConfidenceLevel `json:"confidence_level"`
	URL             string          `json:"url"`
	Parameter       string          `json:"parameter"`
	Payload         string          `json:"payload"`
	Detail          string          `json:"detail"`
	Evidence        string          `json:"evidence"`
	Remediation     string          `json:"remediation"`
	CWEID           int             `json:"cwe_id"`
	CurlCmd         string          `json:"curl_cmd,omitempty"`
}

// SetConfidence sets the confidence level and synchronizes the legacy percentage value.
func (f *Finding) SetConfidence(level ConfidenceLevel) {
	f.ConfidenceLevel = level
	switch level {
	case ConfidenceConfirmed:
		f.Confidence = 100
	case ConfidenceProbable:
		f.Confidence = 80
	case ConfidencePossible:
		f.Confidence = 50
	default:
		f.ConfidenceLevel = ConfidencePossible
		f.Confidence = 50
	}
}

// Target holds target URL parameters, JSON state, and metadata.
type Target struct {
	URL        string
	Method     string
	Params     map[string]string
	Data       map[string]string
	Headers    map[string]string
	Cookie2    string
	Headers2   map[string]string
	IsJSON     bool
	RawJSON    string
	JSONLeaves map[string]interface{}
	OAST       *oast.Server
}

// Parameters returns a list of testable parameter names.
func (t *Target) Parameters() []string {
	if t.IsJSON && len(t.JSONLeaves) > 0 {
		var keys []string
		for k := range t.JSONLeaves {
			keys = append(keys, k)
		}
		return keys
	}
	var keys []string
	if strings.ToUpper(t.Method) == "POST" && len(t.Data) > 0 {
		for k := range t.Data {
			keys = append(keys, k)
		}
	} else {
		for k := range t.Params {
			keys = append(keys, k)
		}
	}
	return keys
}

// BuildURLWithParam builds a full GET URL with injected parameter.
func (t *Target) BuildURLWithParam(param, value string) string {
	u, err := url.Parse(t.URL)
	if err != nil {
		return t.URL
	}
	q := u.Query()
	for k, v := range t.Params {
		q.Set(k, v)
	}
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// BuildURLWithRawParam builds a full GET URL where the parameter value is not re-encoded (essential for CRLF %0d%0a).
func (t *Target) BuildURLWithRawParam(param, rawValue string) string {
	u, err := url.Parse(t.URL)
	if err != nil {
		return t.URL
	}
	var pairs []string
	for k, v := range t.Params {
		if k != param {
			pairs = append(pairs, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	pairs = append(pairs, url.QueryEscape(param)+"="+rawValue)
	u.RawQuery = strings.Join(pairs, "&")
	return u.String()
}

// BuildDataWithParam builds POST urlencoded body with injected parameter.
func (t *Target) BuildDataWithParam(param, value string) string {
	vals := url.Values{}
	for k, v := range t.Data {
		vals.Set(k, v)
	}
	vals.Set(param, value)
	return vals.Encode()
}

// BuildDataWithRawParam builds POST body where param value is inserted raw.
func (t *Target) BuildDataWithRawParam(param, rawValue string) string {
	var pairs []string
	for k, v := range t.Data {
		if k != param {
			pairs = append(pairs, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	pairs = append(pairs, url.QueryEscape(param)+"="+rawValue)
	return strings.Join(pairs, "&")
}

// BuildBodyWithParam builds either a JSON body or form body depending on target content type.
func (t *Target) BuildBodyWithParam(param, value string) string {
	if t.IsJSON && t.RawJSON != "" {
		res, err := SetJSONLeaf(t.RawJSON, param, value)
		if err == nil {
			return res
		}
	}
	return t.BuildDataWithParam(param, value)
}

// ParseJSONBody parses a JSON body and populates JSONLeaves.
func (t *Target) ParseJSONBody(raw string) error {
	t.RawJSON = raw
	t.IsJSON = true
	var root interface{}
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		return err
	}
	leaves := make(map[string]interface{})
	walkJSON("", root, leaves)
	t.JSONLeaves = leaves
	return nil
}

func walkJSON(prefix string, val interface{}, leaves map[string]interface{}) {
	switch v := val.(type) {
	case map[string]interface{}:
		for k, child := range v {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			walkJSON(p, child, leaves)
		}
	case []interface{}:
		for i, child := range v {
			p := fmt.Sprintf("%s[%d]", prefix, i)
			walkJSON(p, child, leaves)
		}
	default:
		if prefix != "" {
			leaves[prefix] = v
		}
	}
}

var arrayIndexRegex = regexp.MustCompile(`^([^\[]+)\[(\d+)\]$`)

// SetJSONLeaf updates a specific leaf path in a JSON string with type preservation.
func SetJSONLeaf(rawJSON, leafPath, payload string) (string, error) {
	var root interface{}
	if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
		return rawJSON, err
	}

	parts := strings.Split(leafPath, ".")
	if err := mutateJSONNode(root, parts, payload); err != nil {
		return rawJSON, err
	}

	out, err := json.Marshal(root)
	if err != nil {
		return rawJSON, err
	}
	return string(out), nil
}

func mutateJSONNode(current interface{}, parts []string, payload string) error {
	if len(parts) == 0 {
		return nil
	}
	head := parts[0]
	rest := parts[1:]

	// Check if head contains array indexing like "items[0]"
	if matches := arrayIndexRegex.FindStringSubmatch(head); len(matches) == 3 {
		key := matches[1]
		idx, _ := strconv.Atoi(matches[2])

		m, ok := current.(map[string]interface{})
		if !ok {
			return fmt.Errorf("expected map at %s", key)
		}
		arrVal, exists := m[key]
		if !exists {
			return fmt.Errorf("key %s not found", key)
		}
		arr, ok := arrVal.([]interface{})
		if !ok || idx < 0 || idx >= len(arr) {
			return fmt.Errorf("invalid array index %d for %s", idx, key)
		}

		if len(rest) == 0 {
			arr[idx] = preserveType(arr[idx], payload)
			return nil
		}
		return mutateJSONNode(arr[idx], rest, payload)
	}

	m, ok := current.(map[string]interface{})
	if !ok {
		return fmt.Errorf("expected map for part %s", head)
	}

	if len(rest) == 0 {
		origVal := m[head]
		m[head] = preserveType(origVal, payload)
		return nil
	}

	child, exists := m[head]
	if !exists {
		return fmt.Errorf("key %s not found", head)
	}
	return mutateJSONNode(child, rest, payload)
}

func preserveType(original interface{}, payload string) interface{} {
	switch original.(type) {
	case float64:
		if num, err := strconv.ParseFloat(payload, 64); err == nil {
			return num
		}
	case int:
		if num, err := strconv.Atoi(payload); err == nil {
			return num
		}
	case bool:
		if b, err := strconv.ParseBool(payload); err == nil {
			return b
		}
	}
	return payload
}

// Module is the interface implemented by each vulnerability detector.
type Module interface {
	Name() string
	Description() string
	Run(target *Target, c *client.Client) ([]*Finding, error)
}

// Similarity calculates Sorensen-Dice coefficient between two strings (0.0 to 1.0).
func Similarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}
	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}
	if len(s1) > 10000 {
		s1 = s1[:10000]
	}
	if len(s2) > 10000 {
		s2 = s2[:10000]
	}

	bigrams := make(map[string]int)
	for i := 0; i < len(s1)-1; i++ {
		bigrams[s1[i:i+2]]++
	}

	intersection := 0
	for i := 0; i < len(s2)-1; i++ {
		bg := s2[i : i+2]
		if count := bigrams[bg]; count > 0 {
			intersection++
			bigrams[bg]--
		}
	}

	total := (len(s1) - 1) + (len(s2) - 1)
	if total == 0 {
		return 0.0
	}
	return float64(2*intersection) / float64(total)
}
