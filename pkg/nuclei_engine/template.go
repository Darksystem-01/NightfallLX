package nuclei_engine

// NucleiTemplate defines the top-level Nuclei YAML template format.
type NucleiTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        string   `yaml:"name"`
		Author      string   `yaml:"author"`
		Severity    string   `yaml:"severity"`
		Description string   `yaml:"description"`
		Tags        string   `yaml:"tags"`
		Reference   []string `yaml:"reference"`
		CVSS        float64  `yaml:"cvss-metrics"`
		Remediation string   `yaml:"remediation"`
	} `yaml:"info"`
	HTTP []NucleiHTTPRequest `yaml:"http"`
}

// NucleiHTTPRequest models an HTTP request definition.
type NucleiHTTPRequest struct {
	Method           string            `yaml:"method"`
	Path             []string          `yaml:"path"`
	Headers          map[string]string `yaml:"headers"`
	Body             string            `yaml:"body"`
	MatchersCondition string           `yaml:"matchers-condition"` // "and" | "or"
	Matchers         []NucleiMatcher   `yaml:"matchers"`
	Extractors       []NucleiExtractor `yaml:"extractors"`
}

// NucleiMatcher defines match conditions on HTTP responses.
type NucleiMatcher struct {
	Type            string   `yaml:"type"` // "word", "status", "regex", "binary"
	Words           []string `yaml:"words"`
	Regex           []string `yaml:"regex"`
	Status          []int    `yaml:"status"`
	Part            string   `yaml:"part"`      // "body", "header", "all"
	Condition       string   `yaml:"condition"` // "and" | "or"
	Negative        bool     `yaml:"negative"`
	CaseInsensitive bool     `yaml:"case-insensitive"`
}

// NucleiExtractor extracts tokens or values from responses.
type NucleiExtractor struct {
	Type  string   `yaml:"type"` // "regex", "kval"
	Name  string   `yaml:"name"`
	Regex []string `yaml:"regex"`
	Part  string   `yaml:"part"`
	Group int      `yaml:"group"`
}
