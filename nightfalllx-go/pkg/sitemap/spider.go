package sitemap

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// DiscoveredEndpoint contains info about a discovered URL
type DiscoveredEndpoint struct {
	URL        string            `json:"url"`
	Path       string            `json:"path"`
	Method     string            `json:"method"`
	StatusCode int               `json:"status_code"`
	Parameters []string          `json:"parameters"`
	Type       string            `json:"type"` // "page", "api", "script", "style", "form"
	Forms      []FormInfo        `json:"forms,omitempty"`
}

// FormInfo holds discovered HTML form metadata
type FormInfo struct {
	Action string   `json:"action"`
	Method string   `json:"method"`
	Inputs []string `json:"inputs"`
}

// SiteMap holds the complete tree of discovered URLs
type SiteMap struct {
	TargetHost string                        `json:"target_host"`
	BaseURL    string                        `json:"base_url"`
	Endpoints  map[string]*DiscoveredEndpoint `json:"endpoints"`
	TotalURLs  int                           `json:"total_urls"`
}

// Spider crawls target site to map its architecture
type Spider struct {
	BaseURL    *url.URL
	MaxDepth   int
	MaxURLs    int
	Timeout    time.Duration
	Visited    map[string]bool
	SiteMap    *SiteMap
	HTTPClient *http.Client
	mu         sync.Mutex
}

var (
	hrefRegex   = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'>\s#]+)["']`)
	inputRegex  = regexp.MustCompile(`(?i)<input[^>]+name\s*=\s*["']([^"']+)["']`)
	formTagRegex = regexp.MustCompile(`(?is)<form([^>]*)>(.*?)</form>`)
	actionAttrRegex = regexp.MustCompile(`(?i)action\s*=\s*["']([^"']*)["']`)
	methodAttrRegex = regexp.MustCompile(`(?i)method\s*=\s*["']([^"']*)["']`)
)

// NewSpider creates a new recursive site crawler
func NewSpider(targetURL string, maxDepth, maxURLs int) (*Spider, error) {
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	if maxDepth <= 0 {
		maxDepth = 3
	}
	if maxURLs <= 0 {
		maxURLs = 50
	}

	return &Spider{
		BaseURL:  parsed,
		MaxDepth: maxDepth,
		MaxURLs:  maxURLs,
		Timeout:  10 * time.Second,
		Visited:  make(map[string]bool),
		SiteMap: &SiteMap{
			TargetHost: parsed.Host,
			BaseURL:    targetURL,
			Endpoints:  make(map[string]*DiscoveredEndpoint),
		},
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}, nil
}

// Crawl performs recursive spidering and builds the site map
func (s *Spider) Crawl() *SiteMap {
	fmt.Printf("\n\033[1;34m[*] Spanning Web Crawler & Full Site Mapper on: %s (Depth: %d, Max: %d)\033[0m\n", s.BaseURL.String(), s.MaxDepth, s.MaxURLs)
	s.crawlURL(s.BaseURL.String(), 0)
	s.SiteMap.TotalURLs = len(s.SiteMap.Endpoints)
	return s.SiteMap
}

func (s *Spider) crawlURL(target string, depth int) {
	if depth > s.MaxDepth {
		return
	}

	s.mu.Lock()
	if len(s.SiteMap.Endpoints) >= s.MaxURLs || s.Visited[target] {
		s.mu.Unlock()
		return
	}
	s.Visited[target] = true
	s.mu.Unlock()

	parsedTarget, err := url.Parse(target)
	if err != nil || parsedTarget.Host != s.BaseURL.Host {
		return
	}

	resp, err := s.HTTPClient.Get(target)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes := make([]byte, 128*1024) // Read up to 128KB
	n, _ := resp.Body.Read(bodyBytes)
	bodyStr := string(bodyBytes[:n])

	// Parameters
	var params []string
	for k := range parsedTarget.Query() {
		params = append(params, k)
	}
	sort.Strings(params)

	endpointType := "page"
	lowerPath := strings.ToLower(parsedTarget.Path)
	if strings.HasSuffix(lowerPath, ".js") {
		endpointType = "script"
	} else if strings.HasSuffix(lowerPath, ".css") {
		endpointType = "style"
	} else if strings.Contains(lowerPath, "/api/") || strings.HasSuffix(lowerPath, ".json") {
		endpointType = "api"
	}

	// Extract forms
	var forms []FormInfo
	formMatches := formTagRegex.FindAllStringSubmatch(bodyStr, -1)
	for _, fm := range formMatches {
		formAttrs := fm[1]
		formInner := fm[2]
		action := ""
		if act := actionAttrRegex.FindStringSubmatch(formAttrs); len(act) > 1 {
			action = act[1]
		}
		method := "GET"
		if met := methodAttrRegex.FindStringSubmatch(formAttrs); len(met) > 1 {
			method = strings.ToUpper(met[1])
		}
		var inputs []string
		inMatches := inputRegex.FindAllStringSubmatch(formInner, -1)
		for _, in := range inMatches {
			if len(in) > 1 {
				inputs = append(inputs, in[1])
			}
		}
		forms = append(forms, FormInfo{Action: action, Method: method, Inputs: inputs})
	}

	endpoint := &DiscoveredEndpoint{
		URL:        target,
		Path:       parsedTarget.Path,
		Method:     "GET",
		StatusCode: resp.StatusCode,
		Parameters: params,
		Type:       endpointType,
		Forms:      forms,
	}

	s.mu.Lock()
	s.SiteMap.Endpoints[target] = endpoint
	s.mu.Unlock()

	// Extract internal links for next hop
	matches := hrefRegex.FindAllStringSubmatch(bodyStr, -1)
	var discoveredNext []string

	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		link := strings.TrimSpace(m[1])
		if strings.HasPrefix(link, "javascript:") || strings.HasPrefix(link, "mailto:") || strings.HasPrefix(link, "tel:") {
			continue
		}

		resolvedURL := s.resolveURL(parsedTarget, link)
		if resolvedURL != nil && resolvedURL.Host == s.BaseURL.Host {
			s.mu.Lock()
			if !s.Visited[resolvedURL.String()] && len(s.SiteMap.Endpoints) < s.MaxURLs {
				discoveredNext = append(discoveredNext, resolvedURL.String())
			}
			s.mu.Unlock()
		}
	}

	// Recursively crawl discovered links
	for _, nextURL := range discoveredNext {
		s.crawlURL(nextURL, depth+1)
	}
}

func (s *Spider) resolveURL(base *url.URL, ref string) *url.URL {
	refURL, err := url.Parse(ref)
	if err != nil {
		return nil
	}
	return base.ResolveReference(refURL)
}

// PrintSiteMap renders a structured ASCII Tree and attack vectors table
func PrintSiteMap(sm *SiteMap) {
	fmt.Printf("\n\033[1;35m┌──────────────────────────────────────────────────────────────────────────────────┐\033[0m\n")
	fmt.Printf("\033[1;35m│ 🗺️   NightfallLX Full Web Application Architecture & Attack Surface Map           │\033[0m\n")
	fmt.Printf("\033[1;35m│ Target Root : %-66s │\033[0m\n", sm.BaseURL)
	fmt.Printf("\033[1;35m│ Total Nodes : %-66d │\033[0m\n", sm.TotalURLs)
	fmt.Printf("\033[1;35m├──────────────────────────────────────────────────────────────────────────────────┤\033[0m\n")

	// Group endpoints by directory hierarchy
	var urls []string
	for u := range sm.Endpoints {
		urls = append(urls, u)
	}
	sort.Strings(urls)

	fmt.Printf("\033[1;33m[+] Discovered URL Tree & Endpoints (%d):\033[0m\n", len(urls))
	for _, u := range urls {
		ep := sm.Endpoints[u]
		parsed, _ := url.Parse(u)
		path := parsed.Path
		if path == "" {
			path = "/"
		}
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}

		statusColor := "\033[1;32m"
		if ep.StatusCode >= 300 && ep.StatusCode < 400 {
			statusColor = "\033[1;33m"
		} else if ep.StatusCode >= 400 {
			statusColor = "\033[1;31m"
		}

		fmt.Printf("    ├── %s[%d]\033[0m \033[1;37m%-45s\033[0m (%s)\n", statusColor, ep.StatusCode, path, ep.Type)
	}
	fmt.Println()

	// Parameters Discovered (Attack Surface)
	var allParams []string
	paramMap := make(map[string][]string)
	for _, ep := range sm.Endpoints {
		for _, p := range ep.Parameters {
			paramMap[p] = append(paramMap[p], ep.Path)
			if !contains(allParams, p) {
				allParams = append(allParams, p)
			}
		}
		for _, f := range ep.Forms {
			for _, in := range f.Inputs {
				paramMap[in] = append(paramMap[in], f.Action+" ("+f.Method+")")
				if !contains(allParams, in) {
					allParams = append(allParams, in)
				}
			}
		}
	}

	sort.Strings(allParams)
	if len(allParams) > 0 {
		fmt.Printf("\033[1;33m[🎯] Discovered Attack Surface Input Parameters (%d):\033[0m\n", len(allParams))
		for _, p := range allParams {
			endpoints := paramMap[p]
			fmt.Printf("    ├── Param: \033[1;32m%-15s\033[0m -> Endpoints: %s\n", p, strings.Join(unique(endpoints), ", "))
		}
		fmt.Println()
	}

	fmt.Printf("\033[1;35m└──────────────────────────────────────────────────────────────────────────────────┘\033[0m\n\n")
}

func contains(arr []string, v string) bool {
	for _, a := range arr {
		if a == v {
			return true
		}
	}
	return false
}

func unique(arr []string) []string {
	m := make(map[string]bool)
	var res []string
	for _, a := range arr {
		if !m[a] {
			m[a] = true
			res = append(res, a)
		}
	}
	return res
}
