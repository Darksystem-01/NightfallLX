package wordlists

import (
	"testing"
)

func TestEmbeddedWordlists(t *testing.T) {
	categories := []string{
		"ssrf", "sqli", "ssti", "xxe", "xss",
		"parameters", "lfi", "cmdi", "directories", "subdomains",
	}

	for _, cat := range categories {
		list := GetWordlist(cat, "")
		if len(list) == 0 {
			t.Errorf("Expected non-empty wordlist for category %s, got 0", cat)
		} else {
			t.Logf("Category %-12s has %d entries", cat, len(list))
		}
	}
}
