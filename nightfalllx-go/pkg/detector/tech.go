package detector

import (
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"regexp"
	"strings"
)

// Category classifies the type of technology.
type Category string

const (
	CatServer         Category = "Web Server"
	CatCDN            Category = "CDN & Proxy"
	CatLanguage       Category = "Programming Language"
	CatFramework      Category = "Web Framework"
	CatTemplateEngine Category = "Template Engine"
	CatCMS            Category = "CMS & Site Builder"
	CatFrontend       Category = "Frontend Library"
	CatOS             Category = "Operating System"
	CatSecurity       Category = "Security & Headers"
)

// Technology represents an identified technology with version and confidence.
type Technology struct {
	Category   Category `json:"category"`
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	Confidence int      `json:"confidence"` // 0-100%
	Evidence   string   `json:"evidence"`
}

// TechReport contains the complete scan results.
type TechReport struct {
	URL          string        `json:"url"`
	RedirectURL  string        `json:"redirect_url,omitempty"`
	Technologies []*Technology `json:"technologies"`
	Headers      []string      `json:"headers"`
	MissingSec   []string      `json:"missing_security_headers"`
}

// TechDetector runs deep Wappalyzer-grade fingerprinting.
type TechDetector struct{}

func NewTechDetector() *TechDetector {
	return &TechDetector{}
}

// Regex patterns for exact version extractions
var (
	rePHPVersion       = regexp.MustCompile(`(?i)php[/ _-]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reApacheVersion    = regexp.MustCompile(`(?i)apache[/ _-]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reNginxVersion     = regexp.MustCompile(`(?i)nginx[/ _-]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reIISVersion       = regexp.MustCompile(`(?i)microsoft-iis[/ _-]?([0-9]+\.[0-9]+)`)
	reOpenSSLVersion   = regexp.MustCompile(`(?i)openssl[/ _-]?([0-9]+\.[0-9]+(?:\.[0-9]+[a-z]*)?)`)
	rePythonVersion    = regexp.MustCompile(`(?i)python[/ _-]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reNodeVersion      = regexp.MustCompile(`(?i)node\.?js[/ _-]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reWordPressVersion = regexp.MustCompile(`(?i)wordpress[/ _-]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reDrupalVersion    = regexp.MustCompile(`(?i)drupal[/ _-]?([0-9]+(?:\.[0-9]+)?)`)
	reJoomlaVersion    = regexp.MustCompile(`(?i)joomla!?[/ _-]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reJQueryVersion    = regexp.MustCompile(`(?i)jquery[/ _-]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reBootstrapVersion = regexp.MustCompile(`(?i)bootstrap[/ _-]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reVueVersion       = regexp.MustCompile(`(?i)vue(?:\.js)?[/ _-]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reReactVersion     = regexp.MustCompile(`(?i)react(?:\.js)?[/ _-]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reNextVersion      = regexp.MustCompile(`(?i)next\.js[/ _-]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reCoreJSVersion    = regexp.MustCompile(`(?i)core-js(?:-bundle)?[/ @-]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
)

func (d *TechDetector) Detect(targetURL string, c *client.Client) (*TechReport, error) {
	report := &TechReport{
		URL: targetURL,
	}

	foundMap := make(map[string]*Technology)
	addTech := func(cat Category, name, ver string, conf int, ev string) {
		key := string(cat) + ":" + strings.ToLower(name)
		if existing, ok := foundMap[key]; ok {
			if ver != "" && existing.Version == "" {
				existing.Version = ver
			}
			if conf > existing.Confidence {
				existing.Confidence = conf
			}
			return
		}
		tech := &Technology{
			Category:   cat,
			Name:       name,
			Version:    ver,
			Confidence: conf,
			Evidence:   ev,
		}
		foundMap[key] = tech
		report.Technologies = append(report.Technologies, tech)
	}

	// 1. Follow Redirects to inspect both initial hop and landing page
	currentURL := targetURL
	var allResponses []*client.Response

	for hop := 0; hop < 6; hop++ {
		resp, err := c.Request("GET", currentURL, "", nil)
		if err != nil {
			if hop == 0 {
				return nil, fmt.Errorf("connection failed: %w", err)
			}
			break
		}
		allResponses = append(allResponses, resp)

		// Check for redirect
		if resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.Location != "" {
			loc := resp.Location
			if !strings.HasPrefix(loc, "http://") && !strings.HasPrefix(loc, "https://") {
				baseU, err := url.Parse(currentURL)
				if err == nil {
					relU, err := url.Parse(loc)
					if err == nil {
						loc = baseU.ResolveReference(relU).String()
					}
				}
			}
			currentURL = loc
		} else {
			break
		}
	}

	if currentURL != targetURL {
		report.RedirectURL = currentURL
	}

	if len(allResponses) == 0 {
		return nil, fmt.Errorf("no response received from %s", targetURL)
	}

	// 2. Iterate through all responses in chain (Redirects + Final Page)
	finalResp := allResponses[len(allResponses)-1]

	for _, resp := range allResponses {
		serverHeader := resp.Headers.Get("Server")
		xPoweredBy := resp.Headers.Get("X-Powered-By")
		setCookie := strings.Join(resp.Headers.Values("Set-Cookie"), " ; ")
		viaHeader := resp.Headers.Get("Via")
		serverTiming := resp.Headers.Get("Server-Timing")
		linkHeader := resp.Headers.Get("Link")

		if serverHeader != "" {
			report.Headers = append(report.Headers, "Server: "+serverHeader)
		}

		// --- Cloudflare ---
		if strings.Contains(strings.ToLower(serverHeader), "cloudflare") || resp.Headers.Get("CF-Ray") != "" || resp.Headers.Get("cf-cache-status") != "" {
			addTech(CatCDN, "Cloudflare", "", 100, "Header CF-Ray / Server: cloudflare")
		}

		// --- Wix.com & Pepyaka ---
		if strings.Contains(strings.ToLower(serverHeader), "pepyaka") {
			addTech(CatServer, "Pepyaka (Wix Server)", "", 100, "Server: Pepyaka")
			addTech(CatCMS, "Wix.com Website Builder", "", 100, "Pepyaka implies Wix infrastructure")
		}
		if resp.Headers.Get("X-Wix-Request-Id") != "" || resp.Headers.Get("X-Wix-Cache-Control") != "" || resp.Headers.Get("X-Meta-Site-Id") != "" {
			addTech(CatCMS, "Wix.com Website Builder", "", 100, "Header X-Wix-Request-Id / X-Meta-Site-Id")
		}

		// --- Varnish Cache ---
		if strings.Contains(strings.ToLower(viaHeader), "varnish") || strings.Contains(strings.ToLower(serverTiming), "varnish") || strings.Contains(strings.ToLower(resp.Headers.Get("X-Cache")), "varnish") {
			addTech(CatCDN, "Varnish Cache", "", 95, "Header Via / Server-Timing: varnish")
		}

		// --- Fastly ---
		if resp.Headers.Get("X-Served-By") != "" && strings.Contains(resp.Headers.Get("X-Served-By"), "cache-") {
			addTech(CatCDN, "Fastly", "", 95, "Header X-Served-By: cache-")
		}

		// --- AWS CloudFront ---
		if resp.Headers.Get("X-Amz-Cf-Id") != "" || strings.Contains(strings.ToLower(viaHeader), "cloudfront") {
			addTech(CatCDN, "AWS CloudFront", "", 100, "Header X-Amz-Cf-Id / CloudFront")
		}

		// --- Akamai ---
		if resp.Headers.Get("X-Akamai-Transformed") != "" {
			addTech(CatCDN, "Akamai Edge", "", 100, "Header X-Akamai-Transformed")
		}

		// --- Web Servers & Operating Systems ---
		if serverHeader != "" {
			if m := reApacheVersion.FindStringSubmatch(serverHeader); len(m) > 1 {
				addTech(CatServer, "Apache HTTP Server", m[1], 100, "Server: "+serverHeader)
			} else if strings.Contains(strings.ToLower(serverHeader), "apache") {
				addTech(CatServer, "Apache HTTP Server", "", 95, "Server: "+serverHeader)
			}

			if m := reNginxVersion.FindStringSubmatch(serverHeader); len(m) > 1 {
				addTech(CatServer, "Nginx", m[1], 100, "Server: "+serverHeader)
			} else if strings.Contains(strings.ToLower(serverHeader), "nginx") {
				addTech(CatServer, "Nginx", "", 95, "Server: "+serverHeader)
			}

			if m := reIISVersion.FindStringSubmatch(serverHeader); len(m) > 1 {
				addTech(CatServer, "Microsoft IIS", m[1], 100, "Server: "+serverHeader)
				addTech(CatOS, "Windows Server", "", 90, "IIS implies Windows")
			} else if strings.Contains(strings.ToLower(serverHeader), "iis") {
				addTech(CatServer, "Microsoft IIS", "", 95, "Server: "+serverHeader)
				addTech(CatOS, "Windows Server", "", 85, "IIS implies Windows")
			}

			if strings.Contains(strings.ToLower(serverHeader), "litespeed") {
				addTech(CatServer, "LiteSpeed", "", 95, "Server: "+serverHeader)
			}
			if strings.Contains(strings.ToLower(serverHeader), "openresty") {
				addTech(CatServer, "OpenResty", "", 95, "Server: "+serverHeader)
			}
			if strings.Contains(strings.ToLower(serverHeader), "caddy") {
				addTech(CatServer, "Caddy", "", 95, "Server: "+serverHeader)
			}
			if m := reOpenSSLVersion.FindStringSubmatch(serverHeader); len(m) > 1 {
				addTech(CatSecurity, "OpenSSL", m[1], 100, "Server: "+serverHeader)
			}

			serverLower := strings.ToLower(serverHeader)
			if strings.Contains(serverLower, "ubuntu") {
				addTech(CatOS, "Ubuntu Linux", "", 100, "Server: "+serverHeader)
			} else if strings.Contains(serverLower, "debian") {
				addTech(CatOS, "Debian Linux", "", 100, "Server: "+serverHeader)
			} else if strings.Contains(serverLower, "centos") {
				addTech(CatOS, "CentOS Linux", "", 100, "Server: "+serverHeader)
			} else if strings.Contains(serverLower, "alpine") {
				addTech(CatOS, "Alpine Linux", "", 100, "Server: "+serverHeader)
			} else if strings.Contains(serverLower, "freebsd") {
				addTech(CatOS, "FreeBSD", "", 100, "Server: "+serverHeader)
			} else if strings.Contains(serverLower, "unix") || strings.Contains(serverLower, "linux") {
				addTech(CatOS, "Linux / POSIX", "", 85, "Server: "+serverHeader)
			}
		}

		// --- Languages & Frameworks via X-Powered-By ---
		if xPoweredBy != "" {
			report.Headers = append(report.Headers, "X-Powered-By: "+xPoweredBy)
			if m := rePHPVersion.FindStringSubmatch(xPoweredBy); len(m) > 1 {
				addTech(CatLanguage, "PHP", m[1], 100, "X-Powered-By: "+xPoweredBy)
			} else if strings.Contains(strings.ToLower(xPoweredBy), "php") {
				addTech(CatLanguage, "PHP", "", 95, "X-Powered-By: "+xPoweredBy)
			}
			if strings.Contains(strings.ToLower(xPoweredBy), "express") {
				addTech(CatFramework, "Express.js", "", 95, "X-Powered-By: "+xPoweredBy)
				addTech(CatLanguage, "Node.js (JavaScript)", "", 95, "Express.js framework")
			}
			if strings.Contains(strings.ToLower(xPoweredBy), "next.js") {
				addTech(CatFramework, "Next.js (React)", "", 100, "X-Powered-By: "+xPoweredBy)
			}
			if strings.Contains(strings.ToLower(xPoweredBy), "asp.net") {
				addTech(CatFramework, "ASP.NET", "", 95, "X-Powered-By: "+xPoweredBy)
				addTech(CatLanguage, "C# / .NET", "", 95, "ASP.NET framework")
			}
		}

		// --- Cookie Analysis ---
		cookieLower := strings.ToLower(setCookie)
		if strings.Contains(cookieLower, "phpsessid") {
			addTech(CatLanguage, "PHP", "", 95, "Cookie: PHPSESSID")
		}
		if strings.Contains(cookieLower, "laravel_session") {
			addTech(CatFramework, "Laravel", "", 100, "Cookie: laravel_session")
			addTech(CatLanguage, "PHP", "", 100, "Laravel framework")
			addTech(CatTemplateEngine, "Blade", "", 90, "Default Laravel template engine")
		}
		if strings.Contains(cookieLower, "symfony") {
			addTech(CatFramework, "Symfony", "", 95, "Cookie: symfony")
			addTech(CatTemplateEngine, "Twig", "", 90, "Default Symfony template engine")
		}
		if strings.Contains(cookieLower, "csrftoken") || strings.Contains(cookieLower, "django") {
			addTech(CatFramework, "Django", "", 95, "Cookie: csrftoken / django")
			addTech(CatLanguage, "Python", "", 95, "Django framework")
			addTech(CatTemplateEngine, "Django Template / Jinja2", "", 90, "Default Django template engine")
		}
		if strings.Contains(cookieLower, "connect.sid") {
			addTech(CatFramework, "Express.js", "", 90, "Cookie: connect.sid")
			addTech(CatLanguage, "Node.js (JavaScript)", "", 90, "Express session")
		}
		if strings.Contains(cookieLower, "jsessionid") {
			addTech(CatLanguage, "Java", "", 95, "Cookie: JSESSIONID")
			addTech(CatFramework, "Java Servlet / Spring", "", 85, "JSESSIONID standard")
		}
		if strings.Contains(cookieLower, "asp.net_sessionid") || strings.Contains(cookieLower, "aspsessionid") {
			addTech(CatFramework, "ASP.NET", "", 95, "Cookie: ASPSESSIONID")
			addTech(CatLanguage, "C# / .NET", "", 95, "ASP.NET session")
		}
		if strings.Contains(cookieLower, "_rails_session") || strings.Contains(cookieLower, "rack.session") {
			addTech(CatFramework, "Ruby on Rails", "", 95, "Cookie: rails_session")
			addTech(CatLanguage, "Ruby", "", 95, "Rails framework")
			addTech(CatTemplateEngine, "ERB (Embedded Ruby)", "", 90, "Default Rails template engine")
		}

		// --- Link Header CDN analysis ---
		if strings.Contains(linkHeader, "parastorage.com") || strings.Contains(linkHeader, "wixstatic.com") {
			addTech(CatCMS, "Wix.com Website Builder", "", 100, "Link header / Wix CDN")
			addTech(CatCDN, "Wix Static CDN (Parastorage)", "", 100, "Link preconnect: parastorage.com")
		}
	}

	// 3. Inspect Landing Page HTML Body
	body := finalResp.Body
	bodyLower := strings.ToLower(body)

	// --- Wix.com Site Builder ---
	if strings.Contains(bodyLower, "wix.com website builder") || strings.Contains(bodyLower, "wixdesktopviewport") ||
		strings.Contains(bodyLower, "static.wixstatic.com") || strings.Contains(bodyLower, "static.parastorage.com") {
		addTech(CatCMS, "Wix.com Website Builder", "", 100, "Meta generator / Wix static assets")
		addTech(CatCDN, "Wix Static CDN (Parastorage)", "", 100, "Asset origin: parastorage.com")
	}

	// --- Shopify ---
	if strings.Contains(bodyLower, "cdn.shopify.com") || strings.Contains(bodyLower, "shopify.theme") {
		addTech(CatCMS, "Shopify", "", 100, "Asset origin: cdn.shopify.com")
		addTech(CatTemplateEngine, "Liquid", "", 90, "Default Shopify template engine")
	}

	// --- Webflow ---
	if strings.Contains(bodyLower, "content=\"webflow\"") || strings.Contains(bodyLower, "webflow.js") {
		addTech(CatCMS, "Webflow", "", 100, "Meta generator: Webflow")
	}

	// --- WordPress ---
	if strings.Contains(bodyLower, "wp-content") || strings.Contains(bodyLower, "wp-includes") {
		ver := ""
		if m := reWordPressVersion.FindStringSubmatch(body); len(m) > 1 {
			ver = m[1]
		}
		addTech(CatCMS, "WordPress", ver, 100, "HTML artifact: wp-content")
		addTech(CatLanguage, "PHP", "", 100, "WordPress is built on PHP")
	}

	// --- Drupal & Joomla ---
	if strings.Contains(bodyLower, "drupal") || strings.Contains(bodyLower, "/sites/default/files") {
		ver := ""
		if m := reDrupalVersion.FindStringSubmatch(body); len(m) > 1 {
			ver = m[1]
		}
		addTech(CatCMS, "Drupal", ver, 95, "HTML artifact: Drupal files")
		addTech(CatLanguage, "PHP", "", 95, "Drupal is built on PHP")
	}
	if strings.Contains(bodyLower, "joomla") {
		ver := ""
		if m := reJoomlaVersion.FindStringSubmatch(body); len(m) > 1 {
			ver = m[1]
		}
		addTech(CatCMS, "Joomla!", ver, 95, "HTML artifact: Joomla")
		addTech(CatLanguage, "PHP", "", 95, "Joomla is built on PHP")
	}

	// --- Frontend Libraries & JavaScript Bundles ---
	if m := reCoreJSVersion.FindStringSubmatch(body); len(m) > 1 {
		addTech(CatFrontend, "Core-js", m[1], 100, "Script core-js-bundle@"+m[1])
	}
	if strings.Contains(bodyLower, "@formatjs/intl-segmenter") {
		addTech(CatFrontend, "FormatJS Polyfill", "", 95, "Polyfill script: @formatjs")
	}
	if strings.Contains(bodyLower, "react") || strings.Contains(bodyLower, "_reactroot") || strings.Contains(bodyLower, "data-reactid") {
		ver := ""
		if m := reReactVersion.FindStringSubmatch(body); len(m) > 1 {
			ver = m[1]
		}
		addTech(CatFrontend, "React", ver, 95, "React DOM / attribute signatures")
	}
	if strings.Contains(bodyLower, "vue") || strings.Contains(bodyLower, "data-v-") || strings.Contains(bodyLower, "v-bind") {
		ver := ""
		if m := reVueVersion.FindStringSubmatch(body); len(m) > 1 {
			ver = m[1]
		}
		addTech(CatFrontend, "Vue.js", ver, 95, "Vue.js DOM scoped attributes (data-v-)")
	}
	if strings.Contains(bodyLower, "ng-app") || strings.Contains(bodyLower, "ng-controller") || strings.Contains(bodyLower, "ng-version") {
		addTech(CatFrontend, "Angular", "", 95, "Angular ng- attributes")
	}
	if strings.Contains(bodyLower, "_next/static") {
		ver := ""
		if m := reNextVersion.FindStringSubmatch(body); len(m) > 1 {
			ver = m[1]
		}
		addTech(CatFramework, "Next.js", ver, 100, "Next.js static assets directory")
		addTech(CatFrontend, "React", "", 100, "Next.js uses React")
	}
	if strings.Contains(bodyLower, "jquery") {
		ver := ""
		if m := reJQueryVersion.FindStringSubmatch(body); len(m) > 1 {
			ver = m[1]
		}
		addTech(CatFrontend, "jQuery", ver, 90, "jQuery script reference")
	}
	if strings.Contains(bodyLower, "bootstrap") {
		ver := ""
		if m := reBootstrapVersion.FindStringSubmatch(body); len(m) > 1 {
			ver = m[1]
		}
		addTech(CatFrontend, "Bootstrap", ver, 90, "Bootstrap CSS/JS reference")
	}
	if strings.Contains(bodyLower, "tailwind") {
		addTech(CatFrontend, "Tailwind CSS", "", 85, "Tailwind CSS classes / stylesheet")
	}

	// --- Template Engines ---
	if strings.Contains(bodyLower, "twig") || strings.Contains(bodyLower, "twig_error") {
		addTech(CatTemplateEngine, "Twig", "", 95, "Twig error / signature in body")
	}
	if strings.Contains(bodyLower, "jinja2") || strings.Contains(bodyLower, "jinja2.exceptions") {
		addTech(CatTemplateEngine, "Jinja2", "", 95, "Jinja2 error / signature in body")
	}
	if strings.Contains(bodyLower, "smarty") || strings.Contains(bodyLower, "$smarty") {
		addTech(CatTemplateEngine, "Smarty", "", 95, "Smarty signature in body")
	}
	if strings.Contains(bodyLower, "thymeleaf") {
		addTech(CatTemplateEngine, "Thymeleaf", "", 95, "Thymeleaf signature in body")
	}

	// 4. Active Probing for Exact PHP Version via Easter Egg query if not already found
	phpTechKey := string(CatLanguage) + ":php"
	if foundMap[phpTechKey] == nil || foundMap[phpTechKey].Version == "" {
		u, err := url.Parse(targetURL)
		if err == nil {
			eggURL := fmt.Sprintf("%s://%s/?=PHPB8B5F2A0-3C92-11d3-A360-006008902CFF", u.Scheme, u.Host)
			eggResp, err := c.Request("GET", eggURL, "", nil)
			if err == nil && eggResp != nil {
				if m := rePHPVersion.FindStringSubmatch(eggResp.Body); len(m) > 1 {
					addTech(CatLanguage, "PHP", m[1], 100, "PHP Easter Egg Credits: "+eggURL)
				}
			}
		}
	}

	// 5. Audit Security Headers on landing page
	checkSecHeader := func(headerName, desc string) {
		if finalResp.Headers.Get(headerName) == "" {
			report.MissingSec = append(report.MissingSec, fmt.Sprintf("%s (%s)", headerName, desc))
		}
	}
	checkSecHeader("Content-Security-Policy", "Prevents XSS & data injection")
	checkSecHeader("Strict-Transport-Security", "Forces HTTPS connections")
	checkSecHeader("X-Frame-Options", "Prevents Clickjacking attacks")
	checkSecHeader("X-Content-Type-Options", "Prevents MIME-sniffing")
	checkSecHeader("Referrer-Policy", "Controls referrer leakage")

	return report, nil
}

// PrintReport outputs an executive, color-coded Technology and Fingerprint box.
func PrintReport(r *TechReport) {
	fmt.Println("\n\033[1;36m┌──────────────────────────────────────────────────────────────────────────────────┐\033[0m")
	fmt.Printf("\033[1;36m│\033[0m \033[1;37m🎯 NightfallLX Deep Technology & Version Discovery Engine\033[0m                        \033[1;36m│\033[0m\n")
	fmt.Printf("\033[1;36m│\033[0m Target: \033[1;33m%-73s\033[0m \033[1;36m│\033[0m\n", r.URL)
	if r.RedirectURL != "" {
		fmt.Printf("\033[1;36m│\033[0m Followed Redirect -> \033[1;32m%-60s\033[0m \033[1;36m│\033[0m\n", r.RedirectURL)
	}
	fmt.Println("\033[1;36m├──────────────────────────┬─────────────────────────────┬──────────┬──────────────┤\033[0m")
	fmt.Println("\033[1;36m│\033[0m \033[1mCategory\033[0m                 \033[1;36m│\033[0m \033[1mTechnology Name\033[0m             \033[1;36m│\033[0m \033[1mVersion\033[0m  \033[1;36m│\033[0m \033[1mConfidence\033[0m   \033[1;36m│\033[0m")
	fmt.Println("\033[1;36m├──────────────────────────┼─────────────────────────────┼──────────┼──────────────┤\033[0m")

	if len(r.Technologies) == 0 {
		fmt.Println("\033[1;36m│\033[0m \033[33mNo unique technology signatures detected (Hardened/Generic web service)\033[0m         \033[1;36m│\033[0m")
	} else {
		for _, t := range r.Technologies {
			verStr := t.Version
			if verStr == "" {
				verStr = "\033[90m(hidden)\033[0m"
			} else {
				verStr = "\033[1;32m" + verStr + "\033[0m"
			}
			confStr := fmt.Sprintf("\033[36m%3d%%\033[0m", t.Confidence)
			fmt.Printf("\033[1;36m│\033[0m %-24s \033[1;36m│\033[0m \033[1m%-27s\033[0m \033[1;36m│\033[0m %-17s\033[1;36m│\033[0m %-21s\033[1;36m│\033[0m\n",
				t.Category, t.Name, verStr, confStr)
		}
	}
	fmt.Println("\033[1;36m└──────────────────────────┴─────────────────────────────┴──────────┴──────────────┘\033[0m")

	if len(r.MissingSec) > 0 {
		fmt.Println("\n\033[1;33m⚠️  Missing Defensive Security Headers:\033[0m")
		for _, s := range r.MissingSec {
			fmt.Printf("   \033[31m[-] %s\033[0m\n", s)
		}
	}
	fmt.Println()
}
