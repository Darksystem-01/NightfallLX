package modules

import (
	"bufio"
	"math"
	"net/url"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/cvss"
	"os"
	"regexp"
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
	CVSSVector  string   `json:"cvss_vector,omitempty"`
	RawRequest  string   `json:"raw_request,omitempty"`
	RawResponse string   `json:"raw_response,omitempty"`
}

// NormalizeCVSS ensures that CVSS and CVSSVector are populated according to
// the official FIRST.ORG CVSS v3.1 specification, and infers them automatically if absent.
func (f *Finding) NormalizeCVSS() {
	if f == nil {
		return
	}
	if f.CVSSVector != "" {
		res, err := cvss.CalculateVector(f.CVSSVector)
		if err == nil {
			f.CVSS = res.BaseScore
			f.CVSSVector = res.VectorString
			if f.Severity == "" {
				f.Severity = Severity(res.Severity)
			}
			return
		}
	}

	// Auto-classify based on module, title, and CWE
	res := cvss.ClassifyFinding(f.Module, f.Title, f.CWEID)
	if f.CVSS == 0 {
		f.CVSS = res.BaseScore
	}
	if f.CVSSVector == "" {
		f.CVSSVector = res.VectorString
	}
	if f.Severity == "" {
		if f.CVSS == 0 {
			f.Severity = SeverityInfo
		} else {
			f.Severity = Severity(res.Severity)
		}
	}
}

// AlignSeverityToCVSS strictly synchronizes the qualitative Severity with the official
// CVSS 3.1 score threshold (None: 0.0, Low: 0.1-3.9, Medium: 4.0-6.9, High: 7.0-8.9, Critical: 9.0-10.0).
func (f *Finding) AlignSeverityToCVSS() {
	if f == nil {
		return
	}
	f.NormalizeCVSS()
	if f.Severity != SeverityInfo {
		f.Severity = Severity(cvss.SeverityRating(f.CVSS))
	}
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
	Wordlist string
}

// ReadWordlistLines reads custom wordlist lines from a file path.
func ReadWordlistLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
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

// BuildURLWithParam builds a full GET URL with injected parameter (supporting both query parameters and RESTful path parameters).
func (t *Target) BuildURLWithParam(param, value string) string {
	u, err := url.Parse(t.URL)
	if err != nil {
		return t.URL
	}

	// If param is a RESTful path parameter (e.g. /ticket/4211 -> /ticket/4200)
	origVal, existsInParams := t.Params[param]
	if existsInParams && origVal != "" {
		pathPattern := "/" + param + "/" + origVal
		if strings.Contains(u.Path, pathPattern) {
			u.Path = strings.Replace(u.Path, pathPattern, "/"+param+"/"+value, 1)
			return u.String()
		}
		if strings.HasSuffix(u.Path, "/"+origVal) {
			u.Path = strings.TrimSuffix(u.Path, "/"+origVal) + "/" + value
			return u.String()
		}
	}

	q := u.Query()
	for k, v := range t.Params {
		if !strings.Contains(u.Path, "/"+k+"/") && !strings.HasSuffix(u.Path, "/"+v) {
			q.Set(k, v)
		}
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

var (
	inputNameRegex  = regexp.MustCompile(`(?i)<(?:input|textarea|select)[^>]+name=["']([^"']+)["']`)
	linkParamRegex  = regexp.MustCompile(`(?i)(?:href|src)=["'][^"']*\?([a-zA-Z0-9_\-]+)=`)
	csrfFilterRegex = regexp.MustCompile(`(?i)(csrf|xsrf|_token|nonce|authenticity|captcha)`)
)

// ExtractParametersFromHTML crawls the HTML body and extracts usable form/URL query parameters.
func ExtractParametersFromHTML(htmlBody string) []string {
	seen := make(map[string]bool)
	var params []string

	// 1. Form inputs, textareas, selects
	for _, m := range inputNameRegex.FindAllStringSubmatch(htmlBody, -1) {
		if len(m) > 1 {
			name := strings.TrimSpace(m[1])
			if name == "" || seen[name] || csrfFilterRegex.MatchString(name) {
				continue
			}
			seen[name] = true
			params = append(params, name)
		}
	}

	// 2. Parameters in links / hrefs
	for _, m := range linkParamRegex.FindAllStringSubmatch(htmlBody, -1) {
		if len(m) > 1 {
			name := strings.TrimSpace(m[1])
			if name == "" || seen[name] || csrfFilterRegex.MatchString(name) {
				continue
			}
			seen[name] = true
			params = append(params, name)
		}
	}

	return params
}

// HTMLForm represents a parsed HTML form with its action, method, and default input field values.
type HTMLForm struct {
	Action string
	Method string
	Fields map[string]string
}

// ExtractFormsFromHTML parses all HTML forms with their method, action, and fields.
func ExtractFormsFromHTML(baseURL, htmlBody string) []*HTMLForm {
	var forms []*HTMLForm
	formRegex := regexp.MustCompile(`(?is)<form([^>]*)>(.*?)</form>`)
	actionRegex := regexp.MustCompile(`(?i)action=["']?([^"' >]*)["']?`)
	methodRegex := regexp.MustCompile(`(?i)method=["']?([^"' >]*)["']?`)
	inputRegex := regexp.MustCompile(`(?i)<(?:input|textarea|select)[^>]+name=["']?([^"' >]+)["']?[^>]*>`)
	valRegex := regexp.MustCompile(`(?i)value=["']?([^"']*)["']?`)
	textareaContentRegex := regexp.MustCompile(`(?is)<textarea[^>]+name=["']?([^"' >]+)["']?[^>]*>(.*?)</textarea>`)

	for _, fm := range formRegex.FindAllStringSubmatch(htmlBody, -1) {
		if len(fm) < 3 {
			continue
		}
		formTagAttrs := fm[1]
		formContent := fm[2]

		fMethod := "GET"
		if mMatch := methodRegex.FindStringSubmatch(formTagAttrs); len(mMatch) > 1 {
			if strings.ToUpper(strings.TrimSpace(mMatch[1])) == "POST" {
				fMethod = "POST"
			}
		}

		fAction := baseURL
		if aMatch := actionRegex.FindStringSubmatch(formTagAttrs); len(aMatch) > 1 {
			act := strings.TrimSpace(aMatch[1])
			if act != "" && act != "#" {
				if strings.HasPrefix(act, "http://") || strings.HasPrefix(act, "https://") {
					fAction = act
				} else {
					baseU, bErr := url.Parse(baseURL)
					if bErr == nil {
						relU, rErr := url.Parse(act)
						if rErr == nil {
							fAction = baseU.ResolveReference(relU).String()
						}
					}
				}
			}
		}

		fields := make(map[string]string)
		for _, inp := range inputRegex.FindAllStringSubmatch(formContent, -1) {
			if len(inp) > 1 {
				name := strings.TrimSpace(inp[1])
				if name != "" && !csrfFilterRegex.MatchString(name) {
					val := "test"
					if vMatch := valRegex.FindStringSubmatch(inp[0]); len(vMatch) > 1 {
						if vMatch[1] != "" {
							val = vMatch[1]
						}
					}
					fields[name] = val
				}
			}
		}

		for _, ta := range textareaContentRegex.FindAllStringSubmatch(formContent, -1) {
			if len(ta) > 2 {
				name := strings.TrimSpace(ta[1])
				content := strings.TrimSpace(ta[2])
				if name != "" && !csrfFilterRegex.MatchString(name) {
					if content != "" {
						fields[name] = content
					} else {
						fields[name] = "test"
					}
				}
			}
		}

		if len(fields) > 0 {
			forms = append(forms, &HTMLForm{
				Action: fAction,
				Method: fMethod,
				Fields: fields,
			})
		}
	}

	return forms
}
