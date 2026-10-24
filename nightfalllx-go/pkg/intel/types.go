package intel

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	ErrSearchsploitNotFound = errors.New("searchsploit binary not found on PATH")
	ErrInvalidQuery         = errors.New("invalid query: only alphanumeric, space, dot, underscore, and hyphen allowed; leading hyphen forbidden; max 64 characters")

	cveRegex        = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)
	validQueryRegex = regexp.MustCompile(`^[a-zA-Z0-9._ -]{1,64}$`)
)

// ProductVersion represents a detected software technology and version.
type ProductVersion struct {
	Product string `json:"product"`
	Version string `json:"version"`
	Source  string `json:"source"` // "tech.go", "Server", "X-Powered-By", "meta-generator", "flag"
}

// IntelFinding contains public reference metadata from local searchsploit index or NVD.
type IntelFinding struct {
	Query     string   `json:"query"`
	Source    string   `json:"source"` // "searchsploit" or "nvd"
	Title     string   `json:"title"`
	EDBID     string   `json:"edb_id,omitempty"`
	CVEs      []string `json:"cves,omitempty"`
	LocalPath string   `json:"local_path,omitempty"` // Local path only; NEVER opened or executed
	Type      string   `json:"type,omitempty"`
	Platform  string   `json:"platform,omitempty"`
	Date      string   `json:"date,omitempty"`
	CVSS      float64  `json:"cvss,omitempty"`
}

// IntelReport contains the aggregate version-matched reference findings.
type IntelReport struct {
	Target                string          `json:"target"`
	Queries               []string        `json:"queries"`
	Findings              []*IntelFinding `json:"findings"`
	SearchsploitAvailable bool            `json:"searchsploit_available"`
	InstallHint           string          `json:"install_hint,omitempty"`
	Disclaimer            string          `json:"disclaimer"`
}

// ValidateQuery enforces strict character set and length constraints to prevent argument injection.
func ValidateQuery(q string) (string, error) {
	trimmed := strings.TrimSpace(q)
	if trimmed == "" {
		return "", fmt.Errorf("%w: query is empty", ErrInvalidQuery)
	}
	if strings.HasPrefix(trimmed, "-") {
		return "", fmt.Errorf("%w: leading hyphen not permitted", ErrInvalidQuery)
	}
	if len(trimmed) > 64 {
		return "", fmt.Errorf("%w: length %d exceeds max 64", ErrInvalidQuery, len(trimmed))
	}
	if !validQueryRegex.MatchString(trimmed) {
		return "", fmt.Errorf("%w: contains disallowed characters", ErrInvalidQuery)
	}
	return trimmed, nil
}

// ExtractCVEs parses unique CVE identifiers from strings.
func ExtractCVEs(text string) []string {
	matches := cveRegex.FindAllString(text, -1)
	var unique []string
	seen := make(map[string]bool)
	for _, m := range matches {
		upper := strings.ToUpper(m)
		if !seen[upper] {
			seen[upper] = true
			unique = append(unique, upper)
		}
	}
	return unique
}
