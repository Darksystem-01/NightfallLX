package osint

import "time"

// DMARCSeverity indicates email security posture.
type DMARCSeverity string

const (
	DMARCNone    DMARCSeverity = "NONE"
	DMARCWeak    DMARCSeverity = "WEAK"
	DMARCSecure  DMARCSeverity = "SECURE"
	DMARCMissing DMARCSeverity = "MISSING"
)

// OSINTFinding represents a security issue discovered purely via passive OSINT.
type OSINTFinding struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"` // "HIGH", "MEDIUM", "LOW", "INFO"
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
}

// SubdomainResult holds a discovered subdomain and resolved details.
type SubdomainResult struct {
	Hostname string   `json:"hostname"`
	Source   string   `json:"source"`
	IPs      []string `json:"ips,omitempty"`
	CNAME    string   `json:"cname,omitempty"`
	Takeover string   `json:"takeover_risk,omitempty"`
}

// GoogleDork holds a targeted Exploit-DB GHDB / DorkSearch reconnaissance query.
type GoogleDork struct {
	Category      string `json:"category"`
	Description   string `json:"description"`
	Query         string `json:"query"`
	Severity      string `json:"severity"` // "CRITICAL", "HIGH", "MEDIUM", "INFO"
	GHDBSection   string `json:"ghdb_section"`
	GoogleURL     string `json:"google_url"`
	DorkSearchURL string `json:"dorksearch_url"`
	BingURL       string `json:"bing_url"`
}

// OSINTReport encapsulates all passive intelligence gathered on the target domain.
type OSINTReport struct {
	Domain             string            `json:"domain"`
	TargetIPs          []string          `json:"target_ips"`
	CloudProvider      string            `json:"cloud_provider"`
	NameServers        []string          `json:"name_servers"`
	MailServers        []string          `json:"mail_servers"`
	SPFRecord          string            `json:"spf_record"`
	DMARCRecord        string            `json:"dmarc_record"`
	DMARCStatus        DMARCSeverity     `json:"dmarc_status"`
	Subdomains         []SubdomainResult `json:"subdomains"`
	SensitiveEndpoints []string          `json:"sensitive_endpoints"`
	SecurityTxt        string            `json:"security_txt,omitempty"`
	Findings           []OSINTFinding    `json:"findings"`
	GoogleDorks        []GoogleDork      `json:"google_dorks,omitempty"`
	Duration           time.Duration     `json:"duration"`
}

// Config defines execution parameters for OSINT reconnaissance.
type Config struct {
	Domain        string
	Timeout       time.Duration
	FetchArchive  bool
	CheckTakeover bool
	IncludeDorks  bool
}
