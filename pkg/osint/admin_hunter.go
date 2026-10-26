package osint

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Curated high-probability admin and authentication probe paths
var defaultAdminPaths = []string{
	// CMS & Web Frameworks
	"/wp-login.php",
	"/wp-admin/",
	"/administrator/",
	"/admin/",
	"/admin/login",
	"/admin/login.php",
	"/admin/dashboard",
	"/login",
	"/login.php",
	"/signin",
	"/user/login",
	"/auth/login",
	"/portal/",
	"/portal/login",

	// Control Panels & Hosting
	"/cpanel",
	"/whm",
	"/webmail",
	"/controlpanel/",
	"/panel/",
	"/management/",
	"/manager/html",

	// Database Administration
	"/phpmyadmin/",
	"/pma/",
	"/adminer.php",
	"/dbadmin/",

	// DevOps, Infrastructure & Monitoring
	"/grafana/login",
	"/jenkins/login",
	"/gitlab/users/sign_in",
	"/kibana/",

	// Identity, SSO & Auth
	"/auth/admin/",
	"/auth/realms/master/",
	"/oauth/login",
	"/idp/login",
	"/sso/login",

	// API & Swagger docs
	"/api/admin",
	"/swagger-ui/index.html",
	"/swagger/index.html",
}

// adminSubdomainKeywords detects administrative subdomains from certificate transparency
var adminSubdomainKeywords = []string{
	"admin", "portal", "auth", "sso", "login", "cpanel", "dashboard",
	"panel", "manage", "vpn", "idp", "keycloak", "kibana", "grafana",
	"webmail", "whm", "pma", "phpmyadmin",
}

var (
	titleRegex     = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	passwordRegex  = regexp.MustCompile(`(?i)<input[^>]+type=["']?password["']?`)
	loginFormRegex = regexp.MustCompile(`(?i)<form[^>]+(action|id|name)=["']?[^"']*(login|signin|auth)[^"']*["']?`)
)

// classifyPortal determines the type and category of the discovered management portal.
func classifyPortal(targetURL, title, body string) string {
	lowerURL := strings.ToLower(targetURL)
	lowerTitle := strings.ToLower(title)
	lowerBody := strings.ToLower(body)

	if strings.Contains(lowerURL, "wp-login") || strings.Contains(lowerURL, "wp-admin") || strings.Contains(lowerTitle, "wordpress") {
		return "WordPress CMS Admin"
	}
	if strings.Contains(lowerURL, "phpmyadmin") || strings.Contains(lowerURL, "adminer") || strings.Contains(lowerTitle, "phpmyadmin") || strings.Contains(lowerTitle, "adminer") {
		return "Database Console"
	}
	if strings.Contains(lowerURL, "cpanel") || strings.Contains(lowerURL, "whm") || strings.Contains(lowerTitle, "cpanel") {
		return "Hosting Control Panel"
	}
	if strings.Contains(lowerURL, "grafana") || strings.Contains(lowerTitle, "grafana") {
		return "Grafana Metrics Console"
	}
	if strings.Contains(lowerURL, "jenkins") || strings.Contains(lowerTitle, "jenkins") {
		return "Jenkins CI/CD Portal"
	}
	if strings.Contains(lowerURL, "kibana") || strings.Contains(lowerTitle, "kibana") {
		return "Kibana Search Console"
	}
	if strings.Contains(lowerURL, "gitlab") || strings.Contains(lowerTitle, "gitlab") {
		return "GitLab Management Portal"
	}
	if strings.Contains(lowerURL, "keycloak") || strings.Contains(lowerTitle, "keycloak") || strings.Contains(lowerBody, "keycloak") {
		return "Keycloak IAM Portal"
	}
	if strings.Contains(lowerURL, "sso") || strings.Contains(lowerTitle, "single sign-on") || strings.Contains(lowerTitle, "okta") || strings.Contains(lowerTitle, "sign in") {
		return "SSO / Identity Provider"
	}
	if strings.Contains(lowerURL, "swagger") || strings.Contains(lowerTitle, "swagger") {
		return "Swagger / OpenAPI Docs"
	}
	if strings.Contains(lowerTitle, "admin") || strings.Contains(lowerURL, "admin") {
		return "Administrative Portal"
	}
	return "Authentication Endpoint"
}

// probeEndpoint actively checks a given endpoint for administrative characteristics.
func probeEndpoint(client *http.Client, endpointURL, source string) *AdminPortal {
	req, err := http.NewRequest("GET", endpointURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// High interest status codes
	if resp.StatusCode != http.StatusOK &&
		resp.StatusCode != http.StatusUnauthorized &&
		resp.StatusCode != http.StatusForbidden &&
		resp.StatusCode != http.StatusFound &&
		resp.StatusCode != http.StatusMovedPermanently &&
		resp.StatusCode != http.StatusTemporaryRedirect {
		return nil
	}

	redirectLocation := resp.Header.Get("Location")

	// Read small snippet to extract title and form elements
	buf := make([]byte, 8192)
	n, _ := io.ReadFull(resp.Body, buf)
	bodySnippet := string(buf[:n])

	title := ""
	if matches := titleRegex.FindStringSubmatch(bodySnippet); len(matches) > 1 {
		title = strings.TrimSpace(matches[1])
	}

	hasPassword := passwordRegex.MatchString(bodySnippet)
	hasLoginForm := hasPassword || loginFormRegex.MatchString(bodySnippet)

	// Filter out generic 404/not found masquerading as 200 OK
	lowerTitle := strings.ToLower(title)
	if strings.Contains(lowerTitle, "not found") || strings.Contains(lowerTitle, "page not found") || strings.Contains(lowerTitle, "404") {
		return nil
	}

	portalType := classifyPortal(endpointURL, title, bodySnippet)

	return &AdminPortal{
		URL:          endpointURL,
		Type:         portalType,
		StatusCode:   resp.StatusCode,
		Title:        title,
		Source:       source,
		HasLoginForm: hasLoginForm,
		RedirectURL:  redirectLocation,
	}
}

// CleanHost preserves custom ports if specified (e.g. host:8080) for active network probes.
func CleanHost(raw string) string {
	clean := strings.TrimSpace(strings.ToLower(raw))
	clean = strings.TrimPrefix(clean, "http://")
	clean = strings.TrimPrefix(clean, "https://")
	if idx := strings.Index(clean, "/"); idx != -1 {
		clean = clean[:idx]
	}
	clean = strings.TrimPrefix(clean, "www.")
	return clean
}

// HuntAdminPortals executes active and passive discovery of admin panels and authentication portals.
func HuntAdminPortals(domain string, certSubdomains []string, waybackURLs []string, timeout time.Duration) []AdminPortal {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	cleanHost := CleanHost(domain)
	if cleanHost == "" {
		cleanHost = domain
	}

	// Fast HTTP client with TLS skip verify (for corporate self-signed / staging admin panels)
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   4 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't auto-redirect, record Location
		},
	}

	var results []AdminPortal
	var mu sync.Mutex
	seen := make(map[string]bool)

	addResult := func(p *AdminPortal) {
		if p == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if !seen[p.URL] {
			seen[p.URL] = true
			results = append(results, *p)
		}
	}

	targetsToProbe := []string{}

	// 1. Root domain HTTP & HTTPS: rapid preflight check to only probe live schemes
	activeSchemes := []string{}
	schemesToCheck := []string{"https", "http"}
	if strings.HasPrefix(strings.ToLower(domain), "http://") {
		schemesToCheck = []string{"http", "https"}
	}

	preflightClient := &http.Client{
		Transport: tr,
		Timeout:   1500 * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, s := range schemesToCheck {
		testURL := fmt.Sprintf("%s://%s/", s, cleanHost)
		if resp, err := preflightClient.Get(testURL); err == nil {
			resp.Body.Close()
			activeSchemes = append(activeSchemes, s)
		}
	}
	if len(activeSchemes) == 0 {
		activeSchemes = schemesToCheck
	}

	for _, scheme := range activeSchemes {
		baseURL := fmt.Sprintf("%s://%s", scheme, cleanHost)
		for _, path := range defaultAdminPaths {
			targetsToProbe = append(targetsToProbe, baseURL+path)
		}
	}

	// 2. Discover admin-related subdomains from Certificate Transparency
	adminSubs := []string{}
	for _, sub := range certSubdomains {
		subLower := strings.ToLower(sub)
		for _, kw := range adminSubdomainKeywords {
			if strings.HasPrefix(subLower, kw+".") || strings.Contains(subLower, "-"+kw) || strings.Contains(subLower, kw+"-") {
				adminSubs = append(adminSubs, sub)
				break
			}
		}
	}

	// Add discovered admin subdomains
	for _, sub := range adminSubs {
		for _, scheme := range activeSchemes {
			targetsToProbe = append(targetsToProbe, fmt.Sprintf("%s://%s", scheme, sub))
			targetsToProbe = append(targetsToProbe, fmt.Sprintf("%s://%s/login", scheme, sub))
			targetsToProbe = append(targetsToProbe, fmt.Sprintf("%s://%s/admin", scheme, sub))
		}
	}

	// 3. Filter Wayback URLs for historical admin and login portals
	for _, rawURL := range waybackURLs {
		lower := strings.ToLower(rawURL)
		if strings.Contains(lower, "/admin") || strings.Contains(lower, "/login") ||
			strings.Contains(lower, "/cpanel") || strings.Contains(lower, "/portal") ||
			strings.Contains(lower, "/signin") || strings.Contains(lower, "/dashboard") {
			targetsToProbe = append(targetsToProbe, rawURL)
		}
	}

	// Limit total probe queue to 80 to maintain blistering fast speed
	if len(targetsToProbe) > 80 {
		targetsToProbe = targetsToProbe[:80]
	}

	// Concurrent probe worker pool
	var wg sync.WaitGroup
	sem := make(chan struct{}, 15) // 15 concurrent threads

	for _, targetURL := range targetsToProbe {
		u := targetURL
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			source := "Active Probe"
			if strings.Contains(endpoint, "web.archive.org") {
				source = "Wayback Archive"
			}
			res := probeEndpoint(client, endpoint, source)
			if res != nil {
				addResult(res)
			}
		}(u)
	}

	wg.Wait()
	return results
}

// PrintAdminReport prints a dedicated, high-impact terminal view of discovered admin portals.
func PrintAdminReport(portals []AdminPortal, domain string) {
	fmt.Println()
	fmt.Println("\033[1;31m╔══════════════════════════════════════════════════════════════════════════════╗\033[0m")
	fmt.Println("\033[1;31m║   🛡️  NightfallLX High-Precision Admin Panel & Login Portal Hunter           ║\033[0m")
	fmt.Printf("\033[1;31m║   Target Domain : \033[1;37m%-58s\033[1;31m ║\033[0m\n", domain)
	fmt.Println("\033[1;31m╚══════════════════════════════════════════════════════════════════════════════╝\033[0m")
	fmt.Println()

	if len(portals) == 0 {
		fmt.Println("\033[33m[-] No active admin panels or login endpoints directly exposed on tested paths.\033[0m")
		fmt.Println("\033[36m[*] Pro Tip: Run `nightfalllx -domain " + domain + " -dorks` to check Google Dorks for obfuscated admin URLs.\033[0m\n")
		return
	}

	fmt.Printf("\033[1;32m[+] Discovered %d Admin & Authentication Portals:\033[0m\n\n", len(portals))

	for i, p := range portals {
		statusColor := "\033[1;32m" // 200 OK
		switch p.StatusCode {
		case 301, 302, 307, 308:
			statusColor = "\033[1;33m" // Yellow redirect
		case 401, 403:
			statusColor = "\033[1;35m" // Magenta restricted
		}

		loginTag := ""
		if p.HasLoginForm {
			loginTag = " \033[1;31m[PASSWORD FORM DETECTED]\033[0m"
		}

		fmt.Printf("  \033[1;37m[%d]\033[0m %s[%d %s]\033[0m \033[1;36m%-25s\033[0m%s\n",
			i+1, statusColor, p.StatusCode, http.StatusText(p.StatusCode), p.Type, loginTag)
		fmt.Printf("      ├── URL         : \033[1;34m%s\033[0m\n", p.URL)
		if p.Title != "" {
			fmt.Printf("      ├── Page Title  : \033[37m%s\033[0m\n", p.Title)
		}
		if p.RedirectURL != "" {
			fmt.Printf("      ├── Redirects To: \033[33m%s\033[0m\n", p.RedirectURL)
		}
		fmt.Printf("      └── Source      : \033[32m%s\033[0m\n\n", p.Source)
	}
}
