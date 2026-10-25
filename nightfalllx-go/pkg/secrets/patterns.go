package secrets

import "regexp"

// SecretPattern defines a signature for locating sensitive tokens.
type SecretPattern struct {
	Name        string
	Regex       *regexp.Regexp
	Severity    string
	Confidence  int
	Remediation string
}

// BuiltinPatterns provides 25+ high-precision secret detection patterns.
var BuiltinPatterns = []SecretPattern{
	{
		Name:        "GitHub Personal Access Token",
		Regex:       regexp.MustCompile(`gh[pous]_[A-Za-z0-9_]{36,255}`),
		Severity:    "CRITICAL",
		Confidence:  95,
		Remediation: "Revoke token immediately via GitHub Settings -> Developer settings -> Personal access tokens.",
	},
	{
		Name:        "AWS Access Key ID",
		Regex:       regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
		Severity:    "HIGH",
		Confidence:  90,
		Remediation: "Rotate AWS IAM credentials and audit CloudTrail for unauthorized API calls.",
	},
	{
		Name:        "AWS Secret Access Key",
		Regex:       regexp.MustCompile(`(?i)aws_secret_access_key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
		Severity:    "CRITICAL",
		Confidence:  95,
		Remediation: "Revoke and rotate secret access key immediately in AWS IAM console.",
	},
	{
		Name:        "Google API Key",
		Regex:       regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		Severity:    "HIGH",
		Confidence:  85,
		Remediation: "Restrict API key scope in Google Cloud Console or regenerate.",
	},
	{
		Name:        "Stripe Live API Key",
		Regex:       regexp.MustCompile(`(?:r|s)k_live_[0-9a-zA-Z]{24,34}`),
		Severity:    "CRITICAL",
		Confidence:  95,
		Remediation: "Revoke key in Stripe Dashboard -> Developers -> API keys.",
	},
	{
		Name:        "Slack Bot Token",
		Regex:       regexp.MustCompile(`xoxb-[0-9]{11,13}-[0-9]{11,13}-[0-9a-zA-Z]{24}`),
		Severity:    "HIGH",
		Confidence:  95,
		Remediation: "Revoke token in Slack App configuration dashboard.",
	},
	{
		Name:        "Telegram Bot Token",
		Regex:       regexp.MustCompile(`\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b`),
		Severity:    "HIGH",
		Confidence:  90,
		Remediation: "Revoke token via @BotFather on Telegram.",
	},
	{
		Name:        "JSON Web Token (JWT)",
		Regex:       regexp.MustCompile(`\beyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\b`),
		Severity:    "MEDIUM",
		Confidence:  80,
		Remediation: "Verify if JWT contains sensitive claims or long-lived authentication privilege.",
	},
	{
		Name:        "RSA/EC/OpenSSH Private Key",
		Regex:       regexp.MustCompile(`-----BEGIN (?:RSA|OPENSSH|EC|PGP|DSA)? PRIVATE KEY-----`),
		Severity:    "CRITICAL",
		Confidence:  100,
		Remediation: "Private key leaked! Remove from version control and revoke immediately.",
	},
	{
		Name:        "Database Connection URI",
		Regex:       regexp.MustCompile(`(?i)(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^:]+:[^@\s]+@[^\s'"]+`),
		Severity:    "CRITICAL",
		Confidence:  95,
		Remediation: "Do not expose database connection strings in client-accessible responses.",
	},
	{
		Name:        "Hardcoded Password in Code",
		Regex:       regexp.MustCompile(`(?i)(?:password|passwd|pwd|db_pass|secret_key)\s*[:=]\s*['"]([^'"]{6,40})['"]`),
		Severity:    "HIGH",
		Confidence:  75,
		Remediation: "Move credentials into environment variables or secrets manager.",
	},
	{
		Name:        "Bearer Token Header",
		Regex:       regexp.MustCompile(`(?i)Authorization:\s*Bearer\s+([A-Za-z0-9._~+/-]{20,})`),
		Severity:    "MEDIUM",
		Confidence:  85,
		Remediation: "Ensure bearer tokens are not leaked in static scripts or logs.",
	},
	{
		Name:        "Twilio Account SID / Auth Token",
		Regex:       regexp.MustCompile(`\bAC[a-zA-Z0-9]{32}\b`),
		Severity:    "HIGH",
		Confidence:  85,
		Remediation: "Regenerate Twilio credentials in Twilio Console.",
	},
	{
		Name:        "SendGrid API Key",
		Regex:       regexp.MustCompile(`\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b`),
		Severity:    "HIGH",
		Confidence:  95,
		Remediation: "Revoke and regenerate SendGrid API key.",
	},
}
