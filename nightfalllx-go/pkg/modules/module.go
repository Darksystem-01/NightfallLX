package modules

import (
	"math"
	"net/url"
	"nightfalllx/pkg/client"
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

// Finding represents a verified security vulnerability.
type Finding struct {
	Module      string   `json:"module"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Confidence  int      `json:"confidence"`
	URL         string   `json:"url"`
	Parameter   string   `json:"parameter"`
	Payload     string   `json:"payload"`
	Detail      string   `json:"detail"`
	Evidence    string   `json:"evidence"`
	Remediation string   `json:"remediation"`
	CWEID       int      `json:"cwe_id"`
	CVSS        float64  `json:"cvss,omitempty"`
	RawRequest  string   `json:"raw_request,omitempty"`
	RawResponse string   `json:"raw_response,omitempty"`
}

// Target holds target URL parameters and metadata.
type Target struct {
	URL      string
	Method   string
	Params   map[string]string
	Data     map[string]string
	Headers  map[string]string
	Cookie2  string
	Headers2 map[string]string
}

// Parameters returns a list of testable parameter names.
func (t *Target) Parameters() []string {
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

// BuildDataWithParam builds POST urlencoded body with injected parameter.
func (t *Target) BuildDataWithParam(param, value string) string {
	vals := url.Values{}
	for k, v := range t.Data {
		vals.Set(k, v)
	}
	vals.Set(param, value)
	return vals.Encode()
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
	// Truncate to first 10,000 characters for efficiency
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
		return 1.0
	}
	return math.Round((2.0*float64(intersection)/float64(total))*1000) / 1000
}
