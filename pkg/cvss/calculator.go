package cvss

import (
	"fmt"
	"math"
	"strings"
)

const (
	ExploitabilityCoefficient = 8.22
	ScopeCoefficient          = 1.08
)

// Roundup implements the exact FIRST.ORG CVSS v3.1 integer-based rounding specification.
// It rounds up its parameter to 1 decimal place using integer arithmetic to eliminate
// IEEE-754 floating-point inaccuracies.
func Roundup(input float64) float64 {
	if input <= 0.0 {
		return 0.0
	}
	intInput := int64(math.Round(input * 100000.0))
	if intInput%10000 == 0 {
		return float64(intInput) / 100000.0
	}
	return float64((intInput/10000)+1) / 10.0
}

// SeverityRating maps a CVSS 3.1 score to its official qualitative rating string.
// Ratings: 0.0: NONE, 0.1-3.9: LOW, 4.0-6.9: MEDIUM, 7.0-8.9: HIGH, 9.0-10.0: CRITICAL.
func SeverityRating(score float64) string {
	rounded := Roundup(score)
	if rounded == 0.0 {
		return "NONE"
	} else if rounded <= 3.9 {
		return "LOW"
	} else if rounded <= 6.9 {
		return "MEDIUM"
	} else if rounded <= 8.9 {
		return "HIGH"
	}
	return "CRITICAL"
}

// Calculate computes the official CVSS v3.1 Base Score and sub-scores for a validated Vector.
func Calculate(v Vector) (ScoreResult, error) {
	var avWeight float64
	switch v.AV {
	case AVNetwork:
		avWeight = 0.85
	case AVAdjacent:
		avWeight = 0.62
	case AVLocal:
		avWeight = 0.55
	case AVPhysical:
		avWeight = 0.20
	default:
		return ScoreResult{}, fmt.Errorf("invalid AV metric: %q (expected N, A, L, P)", v.AV)
	}

	var acWeight float64
	switch v.AC {
	case ACLow:
		acWeight = 0.77
	case ACHigh:
		acWeight = 0.44
	default:
		return ScoreResult{}, fmt.Errorf("invalid AC metric: %q (expected L, H)", v.AC)
	}

	var prWeight float64
	switch v.S {
	case ScopeUnchanged:
		switch v.PR {
		case PRNone:
			prWeight = 0.85
		case PRLow:
			prWeight = 0.62
		case PRHigh:
			prWeight = 0.27
		default:
			return ScoreResult{}, fmt.Errorf("invalid PR metric for Scope Unchanged: %q", v.PR)
		}
	case ScopeChanged:
		switch v.PR {
		case PRNone:
			prWeight = 0.85
		case PRLow:
			prWeight = 0.68
		case PRHigh:
			prWeight = 0.50
		default:
			return ScoreResult{}, fmt.Errorf("invalid PR metric for Scope Changed: %q", v.PR)
		}
	default:
		return ScoreResult{}, fmt.Errorf("invalid Scope metric: %q (expected U, C)", v.S)
	}

	var uiWeight float64
	switch v.UI {
	case UINone:
		uiWeight = 0.85
	case UIRequired:
		uiWeight = 0.62
	default:
		return ScoreResult{}, fmt.Errorf("invalid UI metric: %q (expected N, R)", v.UI)
	}

	impactWeight := func(m ImpactMetric, name string) (float64, error) {
		switch m {
		case ImpactNone:
			return 0.0, nil
		case ImpactLow:
			return 0.22, nil
		case ImpactHigh:
			return 0.56, nil
		default:
			return 0.0, fmt.Errorf("invalid %s impact metric: %q (expected N, L, H)", name, m)
		}
	}

	cWeight, err := impactWeight(v.C, "Confidentiality")
	if err != nil {
		return ScoreResult{}, err
	}
	iWeight, err := impactWeight(v.I, "Integrity")
	if err != nil {
		return ScoreResult{}, err
	}
	aWeight, err := impactWeight(v.A, "Availability")
	if err != nil {
		return ScoreResult{}, err
	}

	// 1. Calculate ISS (Impact Sub-Score)
	iss := 1.0 - ((1.0 - cWeight) * (1.0 - iWeight) * (1.0 - aWeight))

	// 2. Calculate Impact
	var impact float64
	if v.S == ScopeUnchanged {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15.0)
	}

	// 3. Calculate Exploitability
	exploitability := ExploitabilityCoefficient * avWeight * acWeight * prWeight * uiWeight

	// 4. Calculate Base Score
	var baseScore float64
	if impact <= 0.0 {
		baseScore = 0.0
	} else if v.S == ScopeUnchanged {
		baseScore = Roundup(math.Min(impact+exploitability, 10.0))
	} else {
		baseScore = Roundup(math.Min(ScopeCoefficient*(impact+exploitability), 10.0))
	}

	canonicalVector := fmt.Sprintf("CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s",
		v.AV, v.AC, v.PR, v.UI, v.S, v.C, v.I, v.A)

	return ScoreResult{
		VectorString:   canonicalVector,
		BaseScore:      baseScore,
		Severity:       SeverityRating(baseScore),
		Impact:         impact,
		Exploitability: exploitability,
		ISS:            iss,
	}, nil
}

// ParseVector parses a CVSS v3.1 vector string into a structured Vector.
// Supports both full format ("CVSS:3.1/AV:N/AC:L/...") and metric-only format ("AV:N/AC:L/...").
func ParseVector(vectorStr string) (Vector, error) {
	clean := strings.TrimSpace(vectorStr)
	clean = strings.TrimPrefix(clean, "CVSS:3.1/")
	clean = strings.TrimPrefix(clean, "CVSS:3.0/")

	parts := strings.Split(clean, "/")
	metrics := make(map[string]string)

	for _, p := range parts {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			metrics[strings.ToUpper(strings.TrimSpace(kv[0]))] = strings.ToUpper(strings.TrimSpace(kv[1]))
		}
	}

	required := []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
	for _, req := range required {
		if _, ok := metrics[req]; !ok {
			return Vector{}, fmt.Errorf("missing required CVSS 3.1 metric %s in vector %q", req, vectorStr)
		}
	}

	v := Vector{
		AV: AttackVector(metrics["AV"]),
		AC: AttackComplexity(metrics["AC"]),
		PR: PrivilegesRequired(metrics["PR"]),
		UI: UserInteraction(metrics["UI"]),
		S:  Scope(metrics["S"]),
		C:  ImpactMetric(metrics["C"]),
		I:  ImpactMetric(metrics["I"]),
		A:  ImpactMetric(metrics["A"]),
	}

	return v, nil
}

// CalculateVector parses a vector string and computes its CVSS v3.1 Base Score and severity rating.
func CalculateVector(vectorStr string) (ScoreResult, error) {
	v, err := ParseVector(vectorStr)
	if err != nil {
		return ScoreResult{}, err
	}
	return Calculate(v)
}
