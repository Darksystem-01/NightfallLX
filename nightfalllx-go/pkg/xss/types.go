package xss

import "net/url"

// Target defines the target parameters and request data for XSS scanning.
type Target struct {
	URL     string
	Method  string
	Params  map[string]string
	Data    map[string]string
	Headers map[string]string
	IsJSON  bool
	RawJSON string
}

// Parameters returns all testable parameter names.
func (t *Target) Parameters() []string {
	var keys []string
	if t.Method == "POST" && len(t.Data) > 0 {
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
	if param != "" {
		q.Set(param, value)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Finding represents an identified XSS vulnerability or DOM flow.
type Finding struct {
	Title           string `json:"title"`
	Severity        string `json:"severity"`
	Confidence      int    `json:"confidence"`
	ConfidenceLevel string `json:"confidence_level"`
	URL             string `json:"url"`
	Parameter       string `json:"parameter"`
	Payload         string `json:"payload"`
	Detail          string `json:"detail"`
	Evidence        string `json:"evidence"`
	Remediation     string `json:"remediation"`
	CWEID           int    `json:"cwe_id"`
}
