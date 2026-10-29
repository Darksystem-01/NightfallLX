package osint

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
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

// defaultAdminSubdomainPrefixes is the built-in fallback wordlist when SecLists is unavailable
var defaultAdminSubdomainPrefixes = []string{
	"admin", "git", "panel", "cms", "back", "backoffice", "cpanel",
	"grafana", "vpn", "auth", "sso", "portal", "webmail",
	"dashboard", "cloud", "minio",
}

// seclistsWordlistPaths are known SecLists paths, tried in order (shorter wordlist first for speed)
var seclistsWordlistPaths = []string{
	"/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
	"/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
	"/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt",
	"/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
}

// loadSubdomainWordlist loads from SecLists if available; falls back to built-in list
func loadSubdomainWordlist() []string {
	for _, wlPath := range seclistsWordlistPaths {
		data, err := os.ReadFile(wlPath)
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		cleaned := make([]string, 0, len(lines))
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") {
				cleaned = append(cleaned, l)
			}
		}
		fmt.Printf("[+] Admin Subdomain Wordlist: %s (%d words)\n", wlPath, len(cleaned))
		return cleaned
	}
	// SecLists not found -> use built-in compact list
	return defaultAdminSubdomainPrefixes
}

// adminSubdomainKeywords detects administrative subdomains from certificate transparency

var adminSubdomainKeywords = []string{
	"admin", "portal", "auth", "sso", "login", "cpanel", "dashboard",
	"panel", "manage", "vpn", "idp", "keycloak", "kibana", "grafana",
	"webmail", "whm", "pma", "phpmyadmin", "git", "gitlab", "gitea", "minio", "airflow",
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

	// 1. Definite technology identification by title, body or signatures
	if strings.Contains(lowerTitle, "gitea") || strings.Contains(lowerBody, "gitea") {
		return "Gitea Source Code Management"
	}
	if strings.Contains(lowerTitle, "gitlab") || strings.Contains(lowerBody, "gitlab") {
		return "GitLab Management Portal"
	}
	if strings.Contains(lowerTitle, "jenkins") || strings.Contains(lowerBody, "jenkins") {
		return "Jenkins CI/CD Portal"
	}
	if strings.Contains(lowerTitle, "grafana") || strings.Contains(lowerBody, "grafana-app") {
		return "Grafana Metrics Console"
	}
	if strings.Contains(lowerTitle, "kibana") || strings.Contains(lowerBody, "kibana") {
		return "Kibana Search Console"
	}
	if strings.Contains(lowerTitle, "wordpress") || strings.Contains(lowerBody, "wp-submit") || strings.Contains(lowerBody, "user_login") {
		return "WordPress CMS Admin"
	}
	if strings.Contains(lowerTitle, "phpmyadmin") || strings.Contains(lowerTitle, "adminer") || strings.Contains(lowerBody, "pma_username") {
		return "Database Console"
	}
	if strings.Contains(lowerTitle, "cpanel") || strings.Contains(lowerTitle, "whm") || strings.Contains(lowerBody, "cpanel") || strings.Contains(lowerBody, "cpsession") {
		return "Hosting Control Panel"
	}
	if strings.Contains(lowerTitle, "keycloak") || strings.Contains(lowerBody, "keycloak") {
		return "Keycloak IAM Portal"
	}
	if strings.Contains(lowerTitle, "swagger") || strings.Contains(lowerTitle, "openapi") || strings.Contains(lowerBody, "swagger-ui") {
		return "Swagger / OpenAPI Docs"
	}
	if strings.Contains(lowerTitle, "single sign-on") || strings.Contains(lowerTitle, "okta") || strings.Contains(lowerTitle, "sso") {
		return "SSO / Identity Provider"
	}
	if strings.Contains(lowerTitle, "airflow") || strings.Contains(lowerBody, "airflow") {
		return "Apache Airflow Portal"
	}
	if strings.Contains(lowerTitle, "minio") || strings.Contains(lowerBody, "minio") {
		return "MinIO Object Console"
	}
	if strings.Contains(lowerTitle, "dashboard") {
		return "Internal Dashboard Portal"
	}

	// 2. Fallbacks if only URL has technology hint but verified in response
	if strings.Contains(lowerURL, "wp-login") || strings.Contains(lowerURL, "wp-admin") {
		return "WordPress CMS Admin"
	}
	if strings.Contains(lowerURL, "phpmyadmin") || strings.Contains(lowerURL, "adminer") {
		return "Database Console"
	}
	if strings.Contains(lowerURL, "cpanel") || strings.Contains(lowerURL, "whm") {
		return "Hosting Control Panel"
	}
	if strings.Contains(lowerURL, "grafana") {
		return "Grafana Metrics Console"
	}
	if strings.Contains(lowerURL, "jenkins") {
		return "Jenkins CI/CD Portal"
	}
	if strings.Contains(lowerURL, "kibana") {
		return "Kibana Search Console"
	}
	if strings.Contains(lowerURL, "gitlab") {
		return "GitLab Management Portal"
	}
	if strings.Contains(lowerURL, "swagger") {
		return "Swagger / OpenAPI Docs"
	}
	if strings.Contains(lowerURL, "sso") {
		return "SSO / Identity Provider"
	}
	if strings.Contains(lowerTitle, "admin") || strings.Contains(lowerURL, "admin") {
		return "Administrative Portal"
	}
	return "Authentication Endpoint"
}

// probeEndpoint actively checks a given endpoint for administrative characteristics.
func probeEndpoint(client *http.Client, endpointURL, source string, phpBlocked bool) *AdminPortal {
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

	// 1. HTTP 401 Unauthorized with WWW-Authenticate Basic Realm -> Authentic portal
	if resp.StatusCode == http.StatusUnauthorized {
		realm := resp.Header.Get("WWW-Authenticate")
		title := "Protected Portal"
		if realm != "" {
			title = realm
		}
		portalType := "Protected Administrative Portal"
		if strings.Contains(strings.ToLower(endpointURL), "grafana") {
			portalType = "Grafana Metrics Console"
		}
		return &AdminPortal{
			URL:          endpointURL,
			Type:         portalType,
			StatusCode:   resp.StatusCode,
			Title:        title,
			Source:       source,
			HasLoginForm: true,
		}
	}

	redirectLocation := resp.Header.Get("Location")

	// 2. Handle Redirects (301, 302, 307, 308): Eliminate False Positives
	if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound ||
		resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == 308 {
		if redirectLocation == "" {
			return nil
		}

		targetParsed, errT := url.Parse(endpointURL)
		destParsed, errD := url.Parse(redirectLocation)
		if errT != nil || errD != nil {
			return nil
		}
		finalURL := targetParsed.ResolveReference(destParsed)

		// Discard pure HTTP -> HTTPS redirect of the same path
		if targetParsed.Scheme == "http" && finalURL.Scheme == "https" &&
			strings.TrimSuffix(targetParsed.Path, "/") == strings.TrimSuffix(finalURL.Path, "/") {
			return nil
		}

		// Discard catch-all redirects to homepage or language roots
		finalPath := strings.TrimRight(finalURL.Path, "/")
		if finalPath == "" || finalPath == "/uz" || finalPath == "/ru" || finalPath == "/en" ||
			finalPath == "/home" || finalPath == "/main" || strings.Contains(finalPath, "404") {
			return nil
		}

		// Follow redirect once to inspect final landing page
		followReq, errF := http.NewRequest("GET", finalURL.String(), nil)
		if errF != nil {
			return nil
		}
		followReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
		followResp, errFDo := client.Do(followReq)
		if errFDo != nil {
			return nil
		}
		defer followResp.Body.Close()

		if followResp.StatusCode == http.StatusNotFound {
			return nil
		}

		if followResp.StatusCode == http.StatusUnauthorized {
			realm := followResp.Header.Get("WWW-Authenticate")
			return &AdminPortal{
				URL:          endpointURL,
				Type:         "Protected Administrative Portal",
				StatusCode:   resp.StatusCode,
				Title:        realm,
				Source:       source,
				HasLoginForm: true,
				RedirectURL:  finalURL.String(),
			}
		}

		buf := make([]byte, 8192)
		n, _ := io.ReadFull(followResp.Body, buf)
		bodySnip := string(buf[:n])

		title := ""
		if matches := titleRegex.FindStringSubmatch(bodySnip); len(matches) > 1 {
			title = strings.TrimSpace(matches[1])
		}
		lowTitle := strings.ToLower(title)
		lowBody := strings.ToLower(bodySnip)

		// Check soft 404
		if strings.Contains(lowTitle, "not found") || strings.Contains(lowTitle, "404") ||
			strings.Contains(lowTitle, "bunday sahifa") || strings.Contains(lowBody, "adashib qoldingiz") ||
			strings.Contains(lowTitle, "страница не найдена") {
			return nil
		}

		hasPwd := passwordRegex.MatchString(bodySnip)
		hasForm := hasPwd || loginFormRegex.MatchString(bodySnip)

		if hasForm || strings.Contains(lowTitle, "login") || strings.Contains(lowTitle, "admin") ||
			strings.Contains(lowTitle, "sign in") || strings.Contains(lowTitle, "dashboard") ||
			strings.Contains(lowTitle, "gitea") || strings.Contains(lowTitle, "grafana") ||
			followResp.StatusCode == http.StatusForbidden {
			portalType := classifyPortal(finalURL.String(), title, bodySnip)
			return &AdminPortal{
				URL:          endpointURL,
				Type:         portalType,
				StatusCode:   resp.StatusCode,
				Title:        title,
				Source:       source,
				HasLoginForm: hasForm,
				RedirectURL:  finalURL.String(),
			}
		}
		return nil
	}

	// 3. Read response body snippet
	buf := make([]byte, 8192)
	n, _ := io.ReadFull(resp.Body, buf)
	bodySnippet := string(buf[:n])

	title := ""
	if matches := titleRegex.FindStringSubmatch(bodySnippet); len(matches) > 1 {
		title = strings.TrimSpace(matches[1])
	}

	hasPassword := passwordRegex.MatchString(bodySnippet)
	hasLoginForm := hasPassword || loginFormRegex.MatchString(bodySnippet)

	// Filter out generic soft 404s
	lowerTitle := strings.ToLower(title)
	lowerBody := strings.ToLower(bodySnippet)
	if strings.Contains(lowerTitle, "not found") || strings.Contains(lowerTitle, "page not found") ||
		strings.Contains(lowerTitle, "404") || strings.Contains(lowerTitle, "bunday sahifa") ||
		strings.Contains(lowerBody, "adashib qoldingiz") || strings.Contains(lowerTitle, "страница не найдена") {
		return nil
	}

	// Handle 403 Forbidden: check if it is caused by blanket server rules (.php blocked)
	if resp.StatusCode == http.StatusForbidden {
		lowerURL := strings.ToLower(endpointURL)
		if strings.HasSuffix(lowerURL, ".php") && phpBlocked {
			return nil // Filter out false positive: server rejects all .php files indiscriminately
		}
		// Generic 403 web server pages with no admin relevance -> discard
		if !strings.Contains(lowerURL, "admin") && !strings.Contains(lowerURL, "login") &&
			!strings.Contains(lowerURL, "dashboard") && !strings.Contains(lowerURL, "cpanel") &&
			!strings.Contains(lowerTitle, "admin") && !strings.Contains(lowerTitle, "access") {
			return nil
		}
	}

	portalType := classifyPortal(endpointURL, title, bodySnippet)
	if resp.StatusCode == http.StatusForbidden && portalType == "WordPress CMS Admin" && !strings.Contains(lowerTitle, "wordpress") {
		portalType = "Access Restricted Endpoint (403)"
	}

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
			return http.ErrUseLastResponse
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

	// 1. Gather candidate administrative subdomains from SecLists (or built-in fallback)
	candidateHosts := make(map[string]bool)
	subdomainWordlist := loadSubdomainWordlist()

	// DNS-resolve wordlist entries concurrently - only probe ones that actually resolve
	var hostWg sync.WaitGroup
	var hostMu sync.Mutex
	// Skip generic non-admin prefixes (www, mail, ftp, ns*, smtp, pop*, imap, cdn, etc.)
	skipPrefixes := map[string]bool{
		"www": true, "mail": true, "ftp": true, "smtp": true,
		"pop": true, "pop3": true, "imap": true, "ns": true,
		"ns1": true, "ns2": true, "ns3": true, "ns4": true,
		"cdn": true, "cdn2": true, "static": true, "assets": true,
		"img": true, "images": true, "blog": true, "shop": true,
		"store": true, "news": true, "autodiscover": true,
		"autoconfig": true, "irc": true, "chat": true, "forum": true,
	}
	for _, prefix := range subdomainWordlist {
		prefix = strings.TrimSpace(prefix)
		if prefix == "" || skipPrefixes[strings.ToLower(prefix)] {
			continue
		}
		candidateSub := fmt.Sprintf("%s.%s", prefix, cleanHost)
		hostWg.Add(1)
		go func(sub string) {
			defer hostWg.Done()
			if _, err := net.LookupHost(sub); err == nil {
				hostMu.Lock()
				candidateHosts[sub] = true
				hostMu.Unlock()
			}
		}(candidateSub)
	}

	// Add certificate transparency subdomains matching keywords
	for _, sub := range certSubdomains {
		subLower := strings.ToLower(sub)
		for _, kw := range adminSubdomainKeywords {
			if strings.HasPrefix(subLower, kw+".") || strings.Contains(subLower, "-"+kw) || strings.Contains(subLower, kw+"-") {
				candidateHosts[sub] = true
				break
			}
		}
	}
	hostWg.Wait()

	// 2. Preflight scheme check for root domain
	rootSchemes := []string{}
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
			if s == "http" && (resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound) {
				loc := resp.Header.Get("Location")
				if strings.HasPrefix(strings.ToLower(loc), "https://") {
					continue
				}
			}
			rootSchemes = append(rootSchemes, s)
		}
	}
	if len(rootSchemes) == 0 {
		rootSchemes = []string{"https"}
	}

	// 3. Calibrate root domain: test if .php files are globally blocked with 403
	phpBlocked := false
	testPHPURL := fmt.Sprintf("%s://%s/nightfalllx_calib_%d.php", rootSchemes[0], cleanHost, time.Now().UnixNano()%10000)
	if respPHP, errPHP := preflightClient.Get(testPHPURL); errPHP == nil {
		respPHP.Body.Close()
		if respPHP.StatusCode == http.StatusForbidden {
			phpBlocked = true
		}
	}

	type probeTask struct {
		url        string
		source     string
		phpBlocked bool
	}

	tasks := []probeTask{}

	// A. High-Priority: Discovered Admin Subdomains
	for sub := range candidateHosts {
		tasks = append(tasks, probeTask{
			url:        fmt.Sprintf("https://%s/", sub),
			source:     "Admin Subdomain",
			phpBlocked: false,
		})
		tasks = append(tasks, probeTask{
			url:        fmt.Sprintf("https://%s/login", sub),
			source:     "Admin Subdomain",
			phpBlocked: false,
		})
	}

	// B. Root Domain Admin Paths
	for _, scheme := range rootSchemes {
		baseURL := fmt.Sprintf("%s://%s", scheme, cleanHost)
		for _, path := range defaultAdminPaths {
			tasks = append(tasks, probeTask{
				url:        baseURL + path,
				source:     "Active Probe",
				phpBlocked: phpBlocked,
			})
		}
	}

	// C. Historical Wayback Admin URLs
	for _, rawURL := range waybackURLs {
		lower := strings.ToLower(rawURL)
		if strings.Contains(lower, "/admin") || strings.Contains(lower, "/login") ||
			strings.Contains(lower, "/cpanel") || strings.Contains(lower, "/portal") ||
			strings.Contains(lower, "/signin") || strings.Contains(lower, "/dashboard") {
			tasks = append(tasks, probeTask{
				url:        rawURL,
				source:     "Wayback Archive",
				phpBlocked: phpBlocked,
			})
		}
	}

	if len(tasks) > 120 {
		tasks = tasks[:120]
	}

	// Concurrent probe worker pool
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for _, task := range tasks {
		t := task
		wg.Add(1)
		go func(pt probeTask) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res := probeEndpoint(client, pt.url, pt.source, pt.phpBlocked)
			if res != nil {
				addResult(res)
			}
		}(t)
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
