package nuclei_engine

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"nightfalllx/pkg/client"
	"nightfalllx/pkg/modules"
)

// NucleiRunnerConfig configures the execution of Nuclei.
type NucleiRunnerConfig struct {
	TargetURL      string
	BinaryPath     string
	TemplatesPath  string
	Tags           string
	Severity       string
	Concurrency    int
	TimeoutSec     int
	Engine         string // "auto", "official", "internal"
	CustomArgs     string // Custom raw arguments to pass directly to official nuclei
	Proxy          string
	Headers        map[string]string
	Client         *client.Client
	OnFinding      func(finding *modules.Finding)
}

// OfficialNucleiFinding represents a single JSONL item from official Nuclei.
type OfficialNucleiFinding struct {
	TemplateID   string `json:"template-id"`
	TemplatePath string `json:"template-path"`
	TemplateURL  string `json:"template-url"`
	Info         struct {
		Name           string      `json:"name"`
		Author         interface{} `json:"author"`
		Tags           interface{} `json:"tags"`
		Description    string      `json:"description"`
		Reference      interface{} `json:"reference"`
		Severity       string      `json:"severity"`
		Classification struct {
			CVEID      []string    `json:"cve-id"`
			CWEID      []string    `json:"cwe-id"`
			CVSSScore  float64     `json:"cvss-score"`
			CVSSMetric string      `json:"cvss-metrics"`
		} `json:"classification"`
	} `json:"info"`
	MatcherName      string   `json:"matcher-name"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	Port             string   `json:"port"`
	Scheme           string   `json:"scheme"`
	URL              string   `json:"url"`
	MatchedAt        string   `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results"`
	CurlCommand      string   `json:"curl-command"`
	Request          string   `json:"request,omitempty"`
	Response         string   `json:"response,omitempty"`
	IP               string   `json:"ip"`
	Timestamp        string   `json:"timestamp"`
}

// FindNucleiBinary looks for the official nuclei binary on the system.
func FindNucleiBinary() (string, error) {
	// 1. Check PATH
	if p, err := exec.LookPath("nuclei"); err == nil {
		return p, nil
	}

	// 2. Check common paths
	homeDir, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(homeDir, "go", "bin", "nuclei"),
		"/home/cyborg/go/bin/nuclei",
		"/usr/local/bin/nuclei",
		"/usr/bin/nuclei",
		"/snap/bin/nuclei",
		"/opt/nuclei/nuclei",
	}

	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			if fi.Mode()&0111 != 0 {
				return c, nil
			}
		}
	}

	return "", fmt.Errorf("nuclei binary not found")
}

// FindTemplatesDir locates official or installed Nuclei templates.
func FindTemplatesDir() (string, error) {
	homeDir, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(homeDir, "Pentesting", "nuclei-templates"),
		"/home/cyborg/Pentesting/nuclei-templates",
		filepath.Join(homeDir, "tools", "nuclei-templates"),
		"/home/cyborg/tools/nuclei-templates",
		filepath.Join(homeDir, "nuclei-templates"),
		"/home/cyborg/nuclei-templates",
		filepath.Join(homeDir, ".local", "nuclei-templates"),
		"./nuclei-templates",
		"/usr/share/nuclei-templates",
		"/root/nuclei-templates",
	}

	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			// Verify it actually contains templates
			if _, err := os.Stat(filepath.Join(c, "http")); err == nil {
				return c, nil
			}
			if _, err := os.Stat(filepath.Join(c, "cves.json")); err == nil {
				return c, nil
			}
			if _, err := os.Stat(filepath.Join(c, "cloud")); err == nil {
				return c, nil
			}
		}
	}

	return "", fmt.Errorf("nuclei-templates directory not found")
}

// SeverityColorBadge returns formatted terminal badge for a given severity.
func SeverityColorBadge(sev string) string {
	sev = strings.ToUpper(strings.TrimSpace(sev))
	switch sev {
	case "CRITICAL":
		return "\033[1;97;41m CRITICAL \033[0m"
	case "HIGH":
		return "\033[1;31m[HIGH]\033[0m"
	case "MEDIUM":
		return "\033[1;33m[MEDIUM]\033[0m"
	case "LOW":
		return "\033[1;34m[LOW]\033[0m"
	case "INFO":
		return "\033[1;36m[INFO]\033[0m"
	default:
		return fmt.Sprintf("[%s]", sev)
	}
}

// RunOfficialNuclei executes the official Nuclei binary with streaming real-time findings.
func RunOfficialNuclei(cfg NucleiRunnerConfig) ([]*modules.Finding, error) {
	binPath := cfg.BinaryPath
	if binPath == "" {
		var err error
		binPath, err = FindNucleiBinary()
		if err != nil {
			return nil, err
		}
	}

	tmplPath := cfg.TemplatesPath
	if tmplPath == "" {
		var err error
		tmplPath, err = FindTemplatesDir()
		if err != nil {
			return nil, err
		}
	}

	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 35
	}

	timeoutSec := cfg.TimeoutSec
	if timeoutSec <= 0 {
		timeoutSec = 5
	}

	tags := cfg.Tags
	if strings.ToLower(strings.TrimSpace(tags)) == "all" {
		tags = ""
	} else if tags == "" && cfg.TemplatesPath == "" && cfg.CustomArgs == "" {
		tags = "cve,misconfig,exposure"
	}

	args := []string{
		"-target", cfg.TargetURL,
		"-t", tmplPath,
		"-c", strconv.Itoa(concurrency),
		"-timeout", strconv.Itoa(timeoutSec),
		"-retries", "1",
		"-jsonl",
		"-silent",
		"-duc",
	}

	if tags != "" {
		args = append(args, "-tags", tags)
	}
	if cfg.Severity != "" {
		args = append(args, "-severity", cfg.Severity)
	}
	if cfg.Proxy != "" {
		args = append(args, "-proxy", cfg.Proxy)
	}
	for k, v := range cfg.Headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", k, v))
	}
	if cfg.CustomArgs != "" {
		args = append(args, strings.Fields(cfg.CustomArgs)...)
	}

	cmd := exec.Command(binPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start nuclei process: %w", err)
	}

	var findings []*modules.Finding
	scanner := bufio.NewScanner(stdout)
	// Buffer up to 1MB per line
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var item OfficialNucleiFinding
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			continue
		}

		if item.TemplateID == "" {
			continue
		}

		finding := convertOfficialToFinding(&item)
		findings = append(findings, finding)

		// Real-time terminal output
		badge := SeverityColorBadge(item.Info.Severity)
		targetEndpoint := item.MatchedAt
		if targetEndpoint == "" {
			targetEndpoint = item.URL
		}

		fmt.Printf("  %s \033[1m[%s]\033[0m %s\n", badge, item.TemplateID, item.Info.Name)
		fmt.Printf("         \033[90mURL:\033[0m %s\n", targetEndpoint)
		if len(item.Info.Classification.CVEID) > 0 {
			fmt.Printf("         \033[1;31mCVE:\033[0m %s\n", strings.Join(item.Info.Classification.CVEID, ", "))
		}
		if item.CurlCommand != "" {
			fmt.Printf("         \033[90mPoC:\033[0m %s\n", item.CurlCommand)
		}

		if cfg.OnFinding != nil {
			cfg.OnFinding(finding)
		}
	}

	_ = cmd.Wait()
	return findings, nil
}

func convertOfficialToFinding(item *OfficialNucleiFinding) *modules.Finding {
	sevStr := strings.ToUpper(strings.TrimSpace(item.Info.Severity))
	var sev modules.Severity
	switch sevStr {
	case "CRITICAL":
		sev = modules.SeverityCritical
	case "HIGH":
		sev = modules.SeverityHigh
	case "MEDIUM":
		sev = modules.SeverityMedium
	case "LOW":
		sev = modules.SeverityLow
	default:
		sev = modules.SeverityInfo
	}

	targetEndpoint := item.MatchedAt
	if targetEndpoint == "" {
		targetEndpoint = item.URL
	}

	evidence := item.CurlCommand
	if len(item.ExtractedResults) > 0 {
		evidence = fmt.Sprintf("Extracted: %s | PoC: %s", strings.Join(item.ExtractedResults, ", "), item.CurlCommand)
	}

	detail := item.Info.Description
	if len(item.Info.Classification.CVEID) > 0 {
		detail += fmt.Sprintf(" (CVEs: %s)", strings.Join(item.Info.Classification.CVEID, ", "))
	}

	cweID := 200
	if len(item.Info.Classification.CWEID) > 0 {
		// Parse first CWE number if possible
		rawCWE := strings.ToLower(item.Info.Classification.CWEID[0])
		rawCWE = strings.TrimPrefix(rawCWE, "cwe-")
		if n, err := strconv.Atoi(rawCWE); err == nil {
			cweID = n
		}
	}

	cvss := item.Info.Classification.CVSSScore
	cvssVector := item.Info.Classification.CVSSMetric
	if cvss == 0 {
		switch sev {
		case modules.SeverityCritical:
			cvss = 9.8
			if cvssVector == "" {
				cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
			}
		case modules.SeverityHigh:
			cvss = 7.5
			if cvssVector == "" {
				cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
			}
		case modules.SeverityMedium:
			cvss = 5.3
			if cvssVector == "" {
				cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
			}
		case modules.SeverityLow:
			cvss = 3.1
			if cvssVector == "" {
				cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
			}
		default:
			cvss = 0.0
		}
	}

	remediation := "Review official CVE / advisory documentation for this template ID and patch affected software."
	var refs []string
	if item.Info.Reference != nil {
		switch r := item.Info.Reference.(type) {
		case string:
			if r != "" {
				refs = append(refs, r)
			}
		case []interface{}:
			for _, refItem := range r {
				if s, ok := refItem.(string); ok && s != "" {
					refs = append(refs, s)
				}
			}
		}
	}
	if len(refs) > 0 {
		remediation += " References: " + strings.Join(refs, ", ")
	}

	f := &modules.Finding{
		Module:      "nuclei",
		Title:       fmt.Sprintf("[%s] %s", item.TemplateID, item.Info.Name),
		Severity:    sev,
		Confidence:  98,
		URL:         targetEndpoint,
		Parameter:   "template",
		Payload:     item.TemplateID,
		Detail:      detail,
		Evidence:    evidence,
		Remediation: remediation,
		CWEID:       cweID,
		CVSS:        cvss,
		CVSSVector:  cvssVector,
		RawRequest:  item.Request,
		RawResponse: item.Response,
	}
	f.NormalizeCVSS()
	return f
}

// RunSmartNuclei coordinates high-speed execution using the optimal engine.
func RunSmartNuclei(cfg NucleiRunnerConfig) ([]*modules.Finding, error) {
	useOfficial := false
	if cfg.Engine == "official" {
		useOfficial = true
	} else if cfg.Engine != "internal" {
		if _, err := FindNucleiBinary(); err == nil {
			useOfficial = true
		}
	}

	if useOfficial {
		fmt.Printf("\033[1;36m[*] High-Speed Official Nuclei Engine Active\033[0m (Concurrency: %d, Timeout: %ds)\n",
			cfg.Concurrency, cfg.TimeoutSec)
		return RunOfficialNuclei(cfg)
	}

	// Fallback to pure-Go Parallel Engine
	fmt.Printf("\033[1;33m[*] High-Performance Built-in Pure-Go Nuclei Engine Active\033[0m\n")
	tmplPath := cfg.TemplatesPath
	if tmplPath == "" {
		var err error
		tmplPath, err = FindTemplatesDir()
		if err != nil {
			return nil, fmt.Errorf("no templates available: %w", err)
		}
	}

	var tmpls []*NucleiTemplate
	fi, err := os.Stat(tmplPath)
	if err != nil {
		return nil, fmt.Errorf("cannot stat templates path: %w", err)
	}

	if fi.IsDir() {
		tmpls, err = LoadTemplatesFromDir(tmplPath, cfg.Tags)
	} else {
		single, sErr := LoadTemplateFromFile(tmplPath)
		if sErr == nil && single != nil {
			tmpls = []*NucleiTemplate{single}
		}
		err = sErr
	}

	if err != nil || len(tmpls) == 0 {
		return nil, fmt.Errorf("no matching templates found in %s", tmplPath)
	}

	fmt.Printf("\033[1;32m[+] Loaded %d template(s). Executing concurrently against %s ...\033[0m\n\n", len(tmpls), cfg.TargetURL)

	c := cfg.Client
	if c == nil {
		c = client.NewClient(cfg.Proxy, time.Duration(cfg.TimeoutSec)*time.Second, false, "", cfg.Headers)
	}

	executor := NewExecutor(c, tmpls)
	var findings []*modules.Finding
	var mu sync.Mutex

	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 30
	}

	executor.ExecuteParallel(tmpls, cfg.TargetURL, concurrency, func(res *TemplateResult) {
		finding := res.ToFinding()
		mu.Lock()
		findings = append(findings, finding)
		mu.Unlock()

		badge := SeverityColorBadge(res.Severity)
		fmt.Printf("  %s \033[1m[%s]\033[0m %s\n", badge, res.TemplateID, res.TemplateName)
		fmt.Printf("         \033[90mURL:\033[0m %s\n", res.MatchedAt)
		if res.CurlCommand != "" {
			fmt.Printf("         \033[90mPoC:\033[0m %s\n", res.CurlCommand)
		}

		if cfg.OnFinding != nil {
			cfg.OnFinding(finding)
		}
	})

	return findings, nil
}

// InferTagsFromTech maps detected technologies to Nuclei template tags.
func InferTagsFromTech(technologies []string) string {
	var tags []string
	seen := make(map[string]bool)

	addTag := func(t string) {
		if !seen[t] {
			seen[t] = true
			tags = append(tags, t)
		}
	}

	for _, tech := range technologies {
		lower := strings.ToLower(tech)
		switch {
		case strings.Contains(lower, "apache"):
			addTag("apache")
		case strings.Contains(lower, "nginx"):
			addTag("nginx")
		case strings.Contains(lower, "iis"):
			addTag("iis")
		case strings.Contains(lower, "caddy"):
			addTag("caddy")
		case strings.Contains(lower, "litespeed"):
			addTag("litespeed")
		case strings.Contains(lower, "php"):
			addTag("php")
		case strings.Contains(lower, "wordpress"):
			addTag("wordpress")
			addTag("wp-plugin")
		case strings.Contains(lower, "joomla"):
			addTag("joomla")
		case strings.Contains(lower, "drupal"):
			addTag("drupal")
		case strings.Contains(lower, "laravel"):
			addTag("laravel")
		case strings.Contains(lower, "symfony"):
			addTag("symfony")
		case strings.Contains(lower, "spring"):
			addTag("spring")
			addTag("springboot")
		case strings.Contains(lower, "tomcat"):
			addTag("tomcat")
		case strings.Contains(lower, "jenkins"):
			addTag("jenkins")
		case strings.Contains(lower, "grafana"):
			addTag("grafana")
		case strings.Contains(lower, "django"):
			addTag("django")
		case strings.Contains(lower, "flask"):
			addTag("flask")
		case strings.Contains(lower, "fastapi"):
			addTag("fastapi")
		case strings.Contains(lower, "rails") || strings.Contains(lower, "ruby"):
			addTag("rails")
			addTag("ruby")
		case strings.Contains(lower, "asp.net") || strings.Contains(lower, "dotnet"):
			addTag("aspnet")
			addTag("dotnet")
		case strings.Contains(lower, "node") || strings.Contains(lower, "express"):
			addTag("nodejs")
			addTag("express")
		case strings.Contains(lower, "next"):
			addTag("nextjs")
		case strings.Contains(lower, "react"):
			addTag("react")
		case strings.Contains(lower, "vue"):
			addTag("vue")
		case strings.Contains(lower, "angular"):
			addTag("angular")
		case strings.Contains(lower, "graphql"):
			addTag("graphql")
		case strings.Contains(lower, "redis"):
			addTag("redis")
		case strings.Contains(lower, "mongo"):
			addTag("mongodb")
		case strings.Contains(lower, "mysql"):
			addTag("mysql")
		case strings.Contains(lower, "postgres"):
			addTag("postgres")
		case strings.Contains(lower, "docker"):
			addTag("docker")
		case strings.Contains(lower, "k8s") || strings.Contains(lower, "kube"):
			addTag("kubernetes")
		case strings.Contains(lower, "kibana") || strings.Contains(lower, "elastic"):
			addTag("elasticsearch")
			addTag("kibana")
		case strings.Contains(lower, "gitlab"):
			addTag("gitlab")
		case strings.Contains(lower, "gitea"):
			addTag("gitea")
		case strings.Contains(lower, "keycloak"):
			addTag("keycloak")
		}
	}

	return strings.Join(tags, ",")
}

// NucleiModule implements the standard modules.Module interface for full scan integration.
type NucleiModule struct {
	TemplatesPath string
	Tags          string
	Severity      string
	Concurrency   int
	TimeoutSec    int
	CustomArgs    string
}

func NewNucleiModule() *NucleiModule {
	return &NucleiModule{
		Concurrency: 35,
		TimeoutSec:  10,
	}
}

func (m *NucleiModule) Name() string {
	return "nuclei"
}

func (m *NucleiModule) Description() string {
	return "Next-Gen Nuclei Template Vulnerability & Misconfiguration Scanner"
}

func (m *NucleiModule) Run(target *modules.Target, c *client.Client) ([]*modules.Finding, error) {
	effectiveTags := m.Tags
	if effectiveTags == "" && m.TemplatesPath == "" && m.CustomArgs == "" {
		effectiveTags = "cve,misconfig,exposure"
	}
	cfg := NucleiRunnerConfig{
		TargetURL:     target.URL,
		TemplatesPath: m.TemplatesPath,
		Tags:          effectiveTags,
		Severity:      m.Severity,
		Concurrency:   m.Concurrency,
		TimeoutSec:    m.TimeoutSec,
		CustomArgs:    m.CustomArgs,
		Headers:       target.Headers,
		Client:        c,
	}
	return RunSmartNuclei(cfg)
}
