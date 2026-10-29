package cvss

// AttackVector represents CVSS 3.1 AV metric.
type AttackVector string

const (
	AVNetwork  AttackVector = "N"
	AVAdjacent AttackVector = "A"
	AVLocal    AttackVector = "L"
	AVPhysical AttackVector = "P"
)

// AttackComplexity represents CVSS 3.1 AC metric.
type AttackComplexity string

const (
	ACLow  AttackComplexity = "L"
	ACHigh AttackComplexity = "H"
)

// PrivilegesRequired represents CVSS 3.1 PR metric.
type PrivilegesRequired string

const (
	PRNone PrivilegesRequired = "N"
	PRLow  PrivilegesRequired = "L"
	PRHigh PrivilegesRequired = "H"
)

// UserInteraction represents CVSS 3.1 UI metric.
type UserInteraction string

const (
	UINone     UserInteraction = "N"
	UIRequired UserInteraction = "R"
)

// Scope represents CVSS 3.1 S metric.
type Scope string

const (
	ScopeUnchanged Scope = "U"
	ScopeChanged   Scope = "C"
)

// ImpactMetric represents CVSS 3.1 C, I, A metrics.
type ImpactMetric string

const (
	ImpactNone ImpactMetric = "N"
	ImpactLow  ImpactMetric = "L"
	ImpactHigh ImpactMetric = "H"
)

// Vector represents the complete CVSS v3.1 Base Metrics set.
type Vector struct {
	AV AttackVector       `json:"av"`
	AC AttackComplexity   `json:"ac"`
	PR PrivilegesRequired `json:"pr"`
	UI UserInteraction    `json:"ui"`
	S  Scope              `json:"s"`
	C  ImpactMetric       `json:"c"`
	I  ImpactMetric       `json:"i"`
	A  ImpactMetric       `json:"a"`
}

// ScoreResult holds all computed values according to the FIRST.ORG specification.
type ScoreResult struct {
	VectorString   string  `json:"vector_string"`
	BaseScore      float64 `json:"base_score"`
	Severity       string  `json:"severity"`
	Impact         float64 `json:"impact"`
	Exploitability float64 `json:"exploitability"`
	ISS            float64 `json:"iss"`
}
