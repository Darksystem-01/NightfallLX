package osint

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

var emailRegex = regexp.MustCompile(`(?i)[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// EmailDossier encapsulates discovered corporate emails and format patterns.
type EmailDossier struct {
	Domain       string   `json:"domain"`
	Emails       []string `json:"emails"`
	Pattern      string   `json:"pattern,omitempty"` // e.g. "{first}.{last}@domain.com"
	TotalFound   int      `json:"total_found"`
	SampleFormat string   `json:"sample_format,omitempty"`
}

// detectEmailPattern infers corporate email syntax from harvested addresses.
func detectEmailPattern(emails []string, domain string) (string, string) {
	if len(emails) == 0 {
		return "", ""
	}

	cleanDomain := strings.ToLower(domain)
	dotCount := 0
	underCount := 0
	hyphenCount := 0
	shortCount := 0 // single initial (e.g. jdoe)

	samples := []string{}
	for _, em := range emails {
		parts := strings.Split(strings.ToLower(em), "@")
		if len(parts) != 2 || parts[1] != cleanDomain {
			continue
		}
		user := parts[0]
		samples = append(samples, em)

		if strings.Contains(user, ".") {
			dotCount++
		} else if strings.Contains(user, "_") {
			underCount++
		} else if strings.Contains(user, "-") {
			hyphenCount++
		} else if len(user) > 3 {
			shortCount++
		}
	}

	sample := ""
	if len(samples) > 0 {
		sample = samples[0]
	}

	total := len(samples)
	if total == 0 {
		return "", ""
	}

	if dotCount > total/3 {
		return "{first}.{last}@" + cleanDomain, sample
	}
	if underCount > total/3 {
		return "{first}_{last}@" + cleanDomain, sample
	}
	if hyphenCount > total/3 {
		return "{first}-{last}@" + cleanDomain, sample
	}
	if shortCount > total/3 {
		return "{f}{last}@" + cleanDomain, sample
	}

	return "{username}@" + cleanDomain, sample
}

// HarvestEmails discovers public corporate email addresses from archive URLs and metadata.
func HarvestEmails(domain string, waybackURLs []string, secTxt string, timeout time.Duration) *EmailDossier {
	cleanDomain := CleanDomain(domain)
	if cleanDomain == "" {
		cleanDomain = domain
	}

	emailSet := make(map[string]bool)

	// 1. Extract from security.txt
	if secTxt != "" {
		matches := emailRegex.FindAllString(secTxt, -1)
		for _, m := range matches {
			mClean := strings.ToLower(strings.TrimSpace(m))
			if strings.HasSuffix(mClean, "@"+cleanDomain) || strings.HasSuffix(mClean, "."+cleanDomain) {
				emailSet[mClean] = true
			}
		}
	}

	// 2. Extract from Wayback URLs (e.g. mailto: links, user contact paths)
	for _, raw := range waybackURLs {
		if strings.Contains(raw, "@") {
			// URL decode
			decoded, err := url.QueryUnescape(raw)
			if err != nil {
				decoded = raw
			}
			matches := emailRegex.FindAllString(decoded, -1)
			for _, m := range matches {
				mClean := strings.ToLower(strings.TrimSpace(m))
				// Filter out bogus binary or image extensions mistakenly matched
				if strings.HasSuffix(mClean, ".png") || strings.HasSuffix(mClean, ".jpg") ||
					strings.HasSuffix(mClean, ".svg") || strings.HasSuffix(mClean, ".webp") {
					continue
				}
				if strings.HasSuffix(mClean, "@"+cleanDomain) || strings.HasSuffix(mClean, "."+cleanDomain) {
					emailSet[mClean] = true
				}
			}
		}
	}

	var emailList []string
	for em := range emailSet {
		emailList = append(emailList, em)
	}
	sort.Strings(emailList)

	pattern, sample := detectEmailPattern(emailList, cleanDomain)

	return &EmailDossier{
		Domain:       cleanDomain,
		Emails:       emailList,
		Pattern:      pattern,
		TotalFound:   len(emailList),
		SampleFormat: sample,
	}
}

// PrintEmailReport renders harvested email intelligence and corporate patterns.
func PrintEmailReport(dossier *EmailDossier) {
	fmt.Println()
	fmt.Println("\033[1;36m╔══════════════════════════════════════════════════════════════════════════════╗\033[0m")
	fmt.Println("\033[1;36m║   📧  NightfallLX Corporate Email Intelligence & Pattern Hunter              ║\033[0m")
	fmt.Printf("\033[1;36m║   Target Domain : \033[1;37m%-58s\033[1;36m ║\033[0m\n", dossier.Domain)
	fmt.Println("\033[1;36m╚══════════════════════════════════════════════════════════════════════════════╝\033[0m")
	fmt.Println()

	if dossier.TotalFound == 0 {
		fmt.Printf("\033[33m[-] No public email addresses discovered for @%s in passive archives.\033[0m\n", dossier.Domain)
		fmt.Printf("\033[36m[*] Pro Tip: Run `nightfalllx -domain %s -dorks` to inspect GHDB PII and contact dorks.\033[0m\n\n", dossier.Domain)
		return
	}

	fmt.Printf("\033[1;32m[+] Discovered %d Corporate Email Addresses:\033[0m\n", dossier.TotalFound)
	if dossier.Pattern != "" {
		fmt.Printf("    ├── \033[1;35mInferred Pattern : \033[1;37m%s\033[0m (Example: %s)\n", dossier.Pattern, dossier.SampleFormat)
	}

	limit := 15
	if len(dossier.Emails) < limit {
		limit = len(dossier.Emails)
	}
	for i := 0; i < limit; i++ {
		fmt.Printf("    ├── [%d] \033[33m%s\033[0m\n", i+1, dossier.Emails[i])
	}
	if len(dossier.Emails) > limit {
		fmt.Printf("    └── ... and %d more corporate addresses.\n", len(dossier.Emails)-limit)
	}
	fmt.Println()
}
