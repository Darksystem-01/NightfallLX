package secrets

import (
	"strings"
	"testing"
)

func TestScanString(t *testing.T) {
	scanner := NewSecretScanner()

	sample := `
		// Config
		const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
		const awsKey = "AKIAIOSFODNN7EXAMPLE";
		const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG48g_d1i_example";
	`

	findings := scanner.ScanString(sample, "http://target.local/app.js")
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}

	hasGitHub := false
	hasAWS := false
	for _, f := range findings {
		if strings.Contains(f.Pattern, "GitHub") {
			hasGitHub = true
		}
		if strings.Contains(f.Pattern, "AWS") {
			hasAWS = true
		}
	}

	if !hasGitHub || !hasAWS {
		t.Errorf("missing expected findings: github=%v, aws=%v", hasGitHub, hasAWS)
	}
}

func TestRedact(t *testing.T) {
	val := "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
	red := Redact(val)
	if !strings.HasPrefix(red, "ghp_") || !strings.HasSuffix(red, "wxyz") || !strings.Contains(red, "...") {
		t.Errorf("unexpected redacted format: %s", red)
	}
}

func TestShannon(t *testing.T) {
	lowEntropy := Shannon("aaaaaaaaaaaaaaaaaaaa")
	highEntropy := Shannon("a8#fK9!mQ2$zP5&vL1*x")
	if highEntropy <= lowEntropy {
		t.Errorf("expected high entropy (%f) > low entropy (%f)", highEntropy, lowEntropy)
	}
}
