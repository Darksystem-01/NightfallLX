package cvss

import (
	"testing"
)

func TestOfficialFIRSTVectors(t *testing.T) {
	tests := []struct {
		name         string
		vector       string
		wantScore    float64
		wantSeverity string
	}{
		// FIRST.ORG reference test vectors
		{
			name:         "Reference 1 - Maximum Impact",
			vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantScore:    9.8,
			wantSeverity: "CRITICAL",
		},
		{
			name:         "Reference 2 - Denial of Service Only",
			vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			wantScore:    7.5,
			wantSeverity: "HIGH",
		},
		{
			name:         "Reference 3 - User Interaction Required Confidentiality",
			vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
			wantScore:    6.5,
			wantSeverity: "MEDIUM",
		},
		{
			name:         "Reference 4 - High Complexity Confidentiality",
			vector:       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
			wantScore:    5.9,
			wantSeverity: "MEDIUM",
		},

		// Scope Changed vectors
		{
			name:         "Reflected XSS (Scope Changed)",
			vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
			wantScore:    6.1,
			wantSeverity: "MEDIUM",
		},
		{
			name:         "SSRF to Cloud Metadata (Scope Changed)",
			vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
			wantScore:    8.6,
			wantSeverity: "HIGH",
		},

		// Megacorpone / Audit findings vectors
		{
			name:         "F-01 DNS Zone Transfer (AXFR)",
			vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			wantScore:    7.5,
			wantSeverity: "HIGH",
		},
		{
			name:         "F-02 Missing SPF Record",
			vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
			wantScore:    5.3,
			wantSeverity: "MEDIUM",
		},
		{
			name:         "F-03 Missing DMARC Record",
			vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
			wantScore:    6.5,
			wantSeverity: "MEDIUM",
		},
		{
			name:         "F-04 Directory Listing Enabled",
			vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
			wantScore:    5.3,
			wantSeverity: "MEDIUM",
		},
		{
			name:         "F-05 Missing Security Headers (Overall)",
			vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
			wantScore:    5.4,
			wantSeverity: "MEDIUM",
		},
		{
			name:         "F-05.1 Missing CSP",
			vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
			wantScore:    5.4,
			wantSeverity: "MEDIUM",
		},
		{
			name:         "F-05.2 Missing X-Frame-Options",
			vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
			wantScore:    4.3,
			wantSeverity: "MEDIUM",
		},
		{
			name:         "F-05.3 Missing X-Content-Type-Options",
			vector:       "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
			wantScore:    3.1,
			wantSeverity: "LOW",
		},
		{
			name:         "F-05.4 Missing Referrer-Policy",
			vector:       "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
			wantScore:    3.1,
			wantSeverity: "LOW",
		},
		{
			name:         "F-06 Missing HSTS Header",
			vector:       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
			wantScore:    5.9,
			wantSeverity: "MEDIUM",
		},
		{
			name:         "F-07 Apache Version Disclosure",
			vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
			wantScore:    5.3,
			wantSeverity: "MEDIUM",
		},
		{
			name:         "F-08 Outdated jQuery 1.11.0",
			vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
			wantScore:    5.4,
			wantSeverity: "MEDIUM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := CalculateVector(tt.vector)
			if err != nil {
				t.Fatalf("CalculateVector(%q) unexpected error: %v", tt.vector, err)
			}
			if res.BaseScore != tt.wantScore {
				t.Errorf("Score = %v, want %v (Vector: %s)", res.BaseScore, tt.wantScore, tt.vector)
			}
			if res.Severity != tt.wantSeverity {
				t.Errorf("Severity = %s, want %s (Vector: %s)", res.Severity, tt.wantSeverity, tt.vector)
			}
		})
	}
}

func TestRoundupPrecision(t *testing.T) {
	cases := []struct {
		input float64
		want  float64
	}{
		{0.0, 0.0},
		{7.48224, 7.5},
		{5.816366, 5.9},
		{4.0, 4.0},
		{4.000001, 4.0}, // rounding threshold
		{4.00009, 4.1},  // rounding up
		{9.80000, 9.8},
		{10.0, 10.0},
	}

	for _, c := range cases {
		got := Roundup(c.input)
		if got != c.want {
			t.Errorf("Roundup(%v) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestMalformedVectorErrors(t *testing.T) {
	badVectors := []string{
		"",
		"INVALID",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", // missing A
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // invalid AV
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:INVALID/C:H/I:H/A:H", // invalid S
	}

	for _, bv := range badVectors {
		_, err := CalculateVector(bv)
		if err == nil {
			t.Errorf("Expected error for bad vector %q, got nil", bv)
		}
	}
}

func TestClassifyFinding(t *testing.T) {
	resSQLi := ClassifyFinding("sqli", "SQL Injection", 89)
	if resSQLi.BaseScore != 9.8 || resSQLi.Severity != "CRITICAL" {
		t.Errorf("Classify SQLi: got %v %s, want 9.8 CRITICAL", resSQLi.BaseScore, resSQLi.Severity)
	}

	resAXFR := ClassifyFinding("osint", "DNS zone transfer (AXFR)", 200)
	if resAXFR.BaseScore != 7.5 || resAXFR.Severity != "HIGH" {
		t.Errorf("Classify AXFR: got %v %s, want 7.5 HIGH", resAXFR.BaseScore, resAXFR.Severity)
	}

	resHSTS := ClassifyFinding("headers", "HSTS Header Missing", 693)
	if resHSTS.BaseScore != 5.9 || resHSTS.Severity != "MEDIUM" {
		t.Errorf("Classify HSTS: got %v %s, want 5.9 MEDIUM", resHSTS.BaseScore, resHSTS.Severity)
	}
}
