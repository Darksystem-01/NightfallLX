package modules

import (
	"fmt"
	"nightfalllx/pkg/client"
	"regexp"
	"sort"
	"strings"
	"time"
)

type SQLiModule struct {
	DefaultDelay int
}

func NewSQLiModule() *SQLiModule {
	return &SQLiModule{
		DefaultDelay: 3,
	}
}

func (m *SQLiModule) Name() string {
	return "sqli"
}

func (m *SQLiModule) Description() string {
	return "Differential boolean-based, error-based & dual-scaling time-based SQL injection detector"
}

var (
	// Comprehensive DBMS Error Regex covering MySQL, PostgreSQL, MSSQL, Oracle, SQLite, Informix, Sybase, MariaDB
	sqlErrorRegex = regexp.MustCompile(`(?i)(you have an error in your sql syntax|error in your sql syntax|SQL syntax.*MySQL|Warning.*mysql_|valid MySQL result|MySqlClient\.|PostgreSQL.*ERROR|Warning.*\Wpg_|valid PostgreSQL result|Npgsql\.|Driver.*SQL[\-\_\ ]*Server|OLE DB.*SQL Server|\bORA\-[0-9]{4,5}|Oracle error|SQLite/JDBCDriver|SQLite.Exception|System.Data.SQLite.SQLiteException|syntax error near|Microsoft Access Database Engine|JET Database Engine|ODBC Microsoft Access Driver|CLI Driver.*DB2|DB2 SQL error|Informix ODBC Driver|Sybase message|SQLSTATE\[)`)

	/*
	CATEGORY: Boolean Differential SQLi Vector Pairs (50+ pairs)
	Sources: OWASP Testing Guide, SQLi Reference Manuals, PortSwigger SQLi Cheat Sheet.
	Contexts:
	- Unquoted numeric literals
	- Single quote string literals with comment variations (-- -, #, /*)
	- Double quote string literals
	- Single and double parentheses enclosures
	- DBMS-specific boolean syntax (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
	*/
	sqliPairs = [][2]string{
		// 1. Numeric / Integer Context (No quotes)
		{"%s AND 1=1", "%s AND 1=2"},
		{"%s AND 73=73", "%s AND 73=74"},
		{"%s AND 2>1", "%s AND 2<1"},
		{"%s AND 10=10", "%s AND 10=20"},
		{"%s AND 100=100", "%s AND 100=200"},
		{"%s AND (1=1)", "%s AND (1=2)"},
		{"%s AND ((1=1))", "%s AND ((1=2))"},
		{"%s AND 1=1-- -", "%s AND 1=2-- -"},
		{"%s AND 1=1#", "%s AND 1=2#"},

		// 2. Single Quote Context ('... AND '1'='1')
		{"%s' AND '1'='1", "%s' AND '1'='2"},
		{"%s' AND 'a'='a", "%s' AND 'a'='b"},
		{"%s' AND 'x'='x", "%s' AND 'x'='y"},
		{"%s' AND 1=1-- -", "%s' AND 1=2-- -"},
		{"%s' AND 77=77-- -", "%s' AND 77=78-- -"},
		{"%s' AND 1=1#", "%s' AND 1=2#"},
		{"%s' AND 1=1/*", "%s' AND 1=2/*"},
		{"%s' AND '1'=(SELECT '1')-- -", "%s' AND '1'=(SELECT '2')-- -"},
		{"%s' AND 1=1 AND 'a'='a", "%s' AND 1=2 AND 'a'='a"},

		// 3. Double Quote Context ("... AND "1"="1")
		{"%s\" AND \"1\"=\"1", "%s\" AND \"1\"=\"2"},
		{"%s\" AND \"a\"=\"a", "%s\" AND \"a\"=\"b"},
		{"%s\" AND 1=1-- -", "%s\" AND 1=2-- -"},
		{"%s\" AND 77=77-- -", "%s\" AND 77=78-- -"},
		{"%s\" AND 1=1#", "%s\" AND 1=2#"},
		{"%s\" AND 1=1/*", "%s\" AND 1=2/*"},
		{"%s\" AND \"1\"=(SELECT \"1\")-- -", "%s\" AND \"1\"=(SELECT \"2\")-- -"},

		// 4. Single Parenthesis Context (') ...')
		{"%s') AND ('1'='1", "%s') AND ('1'='2"},
		{"%s') AND 1=1-- -", "%s') AND 1=2-- -"},
		{"%s') AND 77=77-- -", "%s') AND 77=78-- -"},
		{"%s') AND 1=1#", "%s') AND 1=2#"},
		{"%s') AND 1=1/*", "%s') AND 1=2/*"},
		{"%s\") AND (\"1\"=\"1", "%s\") AND (\"1\"=\"2"},
		{"%s\") AND 1=1-- -", "%s\") AND 1=2-- -"},
		{"%s\") AND 1=1#", "%s\") AND 1=2#"},

		// 5. Double Parentheses Context (')) ...'))
		{"%s')) AND (('1'='1", "%s')) AND (('1'='2"},
		{"%s')) AND 1=1-- -", "%s')) AND 1=2-- -"},
		{"%s')) AND 1=1#", "%s')) AND 1=2#"},
		{"%s\")) AND ((\"1\"=\"1", "%s\")) AND ((\"1\"=\"2"},
		{"%s\")) AND 1=1-- -", "%s\")) AND 1=2-- -"},
		{"%s\")) AND 1=1#", "%s\")) AND 1=2#"},

		// 6. MySQL Specific Operators
		{"%s' AND (SELECT 1)=1-- -", "%s' AND (SELECT 1)=2-- -"},
		{"%s' AND (SELECT 123)=(SELECT 123)-- -", "%s' AND (SELECT 123)=(SELECT 456)-- -"},
		{"%s' AND LENGTH('test')=4-- -", "%s' AND LENGTH('test')=5-- -"},
		{"%s' AND ASCII('a')=97-- -", "%s' AND ASCII('a')=98-- -"},

		// 7. PostgreSQL Specific Operators
		{"%s' AND 1::int=1--", "%s' AND 1::int=2--"},
		{"%s' AND '1'::text='1'--", "%s' AND '1'::text='2'--"},
		{"%s' AND (SELECT 1::int)=1--", "%s' AND (SELECT 1::int)=2--"},

		// 8. MSSQL Specific Operators
		{"%s' AND 1=(SELECT 1)--", "%s' AND 1=(SELECT 2)--"},
		{"%s' AND @@SPID=@@SPID--", "%s' AND @@SPID=@@SPID+1--"},
		{"%s' AND LEN('test')=4--", "%s' AND LEN('test')=5--"},

		// 9. Oracle Specific Operators (DUAL table)
		{"%s' AND 1=(SELECT 1 FROM DUAL)--", "%s' AND 1=(SELECT 2 FROM DUAL)--"},
		{"%s' AND (SELECT COUNT(*) FROM DUAL)=1--", "%s' AND (SELECT COUNT(*) FROM DUAL)=0--"},

		// 10. SQLite Specific Operators
		{"%s' AND (SELECT 1)=1--", "%s' AND (SELECT 1)=2--"},
		{"%s' AND sqlite_version()=sqlite_version()--", "%s' AND sqlite_version()='none'--"},
		{"%s' AND length('test')=4--", "%s' AND length('test')=5--"},
	}
)

type timeContext struct {
	Prefix string
	Suffix string
}

var timeContexts = []timeContext{
	{"", ""},
	{"'", " AND '1'='1"},
	{"'", "-- -"},
	{"\"", " AND \"1\"=\"1"},
	{"\"", "-- -"},
	{"')", " AND ('1'='1"},
	{"')", "-- -"},
}

type timeTemplate struct {
	DB   string
	Expr func(delay int) string
}

var dbTimeGenerators = []timeTemplate{
	{"MySQL", func(d int) string { return fmt.Sprintf("AND (SELECT SLEEP(%d))", d) }},
	{"PostgreSQL", func(d int) string { return fmt.Sprintf("AND (SELECT pg_sleep(%d))", d) }},
	{"MSSQL", func(d int) string { return fmt.Sprintf("; WAITFOR DELAY '0:0:%d'--", d) }},
	{"SQLite", func(d int) string {
		// Heavy calculation for SQLite
		return fmt.Sprintf("AND (SELECT count(*) FROM (SELECT 1 UNION SELECT 2) a, (SELECT 1 UNION SELECT 2) b, (SELECT 1 UNION SELECT 2) c) > 0")
	}},
}

func (m *SQLiModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	for _, param := range target.Parameters() {
		origVal := target.Params[param]
		if isPost && !target.IsJSON {
			origVal = target.Data[param]
		}
		if origVal == "" {
			origVal = "1"
		}

		headers := map[string]string{}
		if target.IsJSON {
			headers["Content-Type"] = "application/json"
		}

		// 1. Error-based & Boolean Differential Checks
		var baseResp *client.Response
		var err error
		if isPost {
			baseResp, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, origVal), headers)
		} else {
			baseResp, err = c.Request("GET", target.BuildURLWithParam(param, origVal), "", nil)
		}
		if err != nil || baseResp == nil || baseResp.StatusCode >= 500 {
			continue
		}

		foundForParam := false
		for _, pair := range sqliPairs {
			truePayload := fmt.Sprintf(pair[0], origVal)
			falsePayload := fmt.Sprintf(pair[1], origVal)

			var trueResp, falseResp *client.Response
			if isPost {
				trueResp, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, truePayload), headers)
				if err != nil {
					continue
				}
				falseResp, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, falsePayload), headers)
				if err != nil {
					continue
				}
			} else {
				trueResp, err = c.Request("GET", target.BuildURLWithParam(param, truePayload), "", nil)
				if err != nil {
					continue
				}
				falseResp, err = c.Request("GET", target.BuildURLWithParam(param, falsePayload), "", nil)
				if err != nil {
					continue
				}
			}

			// Error-based check
			if sqlErrorRegex.MatchString(falseResp.Body) || sqlErrorRegex.MatchString(trueResp.Body) {
				evidence := sqlErrorRegex.FindString(falseResp.Body)
				if evidence == "" {
					evidence = sqlErrorRegex.FindString(trueResp.Body)
				}
				f := &Finding{
					Module:      m.Name(),
					Title:       "SQL Injection (Error-Based)",
					Severity:    SeverityCritical,
					URL:         target.URL,
					Parameter:   param,
					Payload:     falsePayload,
					Detail:      fmt.Sprintf("Database error signature detected in response to payload: %s", falsePayload),
					Evidence:    fmt.Sprintf("Matched database error pattern: %s", evidence),
					Remediation: "Use parameterized prepared statements and bind variables for all database queries.",
					CWEID:       89,
				}
				f.SetConfidence(ConfidenceConfirmed)
				findings = append(findings, f)
				foundForParam = true
				break
			}

			// Boolean differential check
			if trueResp.StatusCode == baseResp.StatusCode && falseResp.StatusCode != baseResp.StatusCode {
				f := &Finding{
					Module:      m.Name(),
					Title:       "SQL Injection (Boolean-Based Blind)",
					Severity:    SeverityCritical,
					URL:         target.URL,
					Parameter:   param,
					Payload:     truePayload,
					Detail:      fmt.Sprintf("Status differential observed: TRUE=%d vs FALSE=%d (Baseline=%d).", trueResp.StatusCode, falseResp.StatusCode, baseResp.StatusCode),
					Evidence:    fmt.Sprintf("TRUE Status: %d, FALSE Status: %d", trueResp.StatusCode, falseResp.StatusCode),
					Remediation: "Use parameterized queries with prepared statements.",
					CWEID:       89,
				}
				f.SetConfidence(ConfidenceConfirmed)
				findings = append(findings, f)
				foundForParam = true
				break
			}

			if trueResp.StatusCode == 200 && falseResp.StatusCode == 200 {
				simTrue := Similarity(baseResp.Body, trueResp.Body)
				simFalse := Similarity(baseResp.Body, falseResp.Body)
				if simTrue > 0.95 && simFalse < 0.85 {
					f := &Finding{
						Module:      m.Name(),
						Title:       "SQL Injection (Boolean-Based Differential Content)",
						Severity:    SeverityCritical,
						URL:         target.URL,
						Parameter:   param,
						Payload:     truePayload,
						Detail:      fmt.Sprintf("Significant body difference between TRUE (sim=%.2f) and FALSE (sim=%.2f) queries.", simTrue, simFalse),
						Evidence:    fmt.Sprintf("Similarity to baseline: TRUE=%.2f, FALSE=%.2f", simTrue, simFalse),
						Remediation: "Use parameterized queries with prepared statements.",
						CWEID:       89,
					}
					f.SetConfidence(ConfidenceConfirmed)
					findings = append(findings, f)
					foundForParam = true
					break
				}
			}
		}

		if foundForParam {
			continue
		}

		// 2. Time-Based Dual-Scaling Injection Check
		// Baseline timing: median of 3 requests
		durations := make([]time.Duration, 3)
		for i := 0; i < 3; i++ {
			t0 := time.Now()
			if isPost {
				_, _ = c.Request("POST", target.URL, target.BuildBodyWithParam(param, origVal), headers)
			} else {
				_, _ = c.Request("GET", target.BuildURLWithParam(param, origVal), "", nil)
			}
			durations[i] = time.Since(t0)
		}
		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		medianBaseline := durations[1]

		// If server is very jittery or > 2.5s baseline, skip time-based
		if medianBaseline > 2500*time.Millisecond {
			continue
		}

		delay1 := m.DefaultDelay
		if delay1 <= 0 {
			delay1 = 3
		}
		delay2 := delay1 + 3 // e.g. 3s then 6s

		for _, tmpl := range dbTimeGenerators {
			if foundForParam {
				break
			}
			for _, ctx := range timeContexts {
				expr1 := tmpl.Expr(delay1)
				payload1 := fmt.Sprintf("%s%s %s%s", origVal, ctx.Prefix, expr1, ctx.Suffix)

				t0 := time.Now()
				var p1Err error
				if isPost {
					_, p1Err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, payload1), headers)
				} else {
					_, p1Err = c.Request("GET", target.BuildURLWithParam(param, payload1), "", nil)
				}
				dur1 := time.Since(t0)
				if p1Err != nil {
					continue
				}

				minThreshold1 := medianBaseline + time.Duration(delay1)*time.Second - 400*time.Millisecond
				if dur1 >= minThreshold1 {
					// First delay hit! Validate second scaling delay (delay2) to rule out network latency spikes
					expr2 := tmpl.Expr(delay2)
					payload2 := fmt.Sprintf("%s%s %s%s", origVal, ctx.Prefix, expr2, ctx.Suffix)

					t1 := time.Now()
					var p2Err error
					if isPost {
						_, p2Err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, payload2), headers)
					} else {
						_, p2Err = c.Request("GET", target.BuildURLWithParam(param, payload2), "", nil)
					}
					dur2 := time.Since(t1)
					if p2Err != nil {
						continue
					}

					minThreshold2 := medianBaseline + time.Duration(delay2)*time.Second - 400*time.Millisecond
					if dur2 >= minThreshold2 && dur2 > dur1+time.Duration(delay2-delay1-1)*time.Second {
						// Scaling confirmed!
						f := &Finding{
							Module:      m.Name(),
							Title:       fmt.Sprintf("SQL Injection (Time-Based Blind - %s Confirmed)", tmpl.DB),
							Severity:    SeverityCritical,
							URL:         target.URL,
							Parameter:   param,
							Payload:     payload1,
							Detail:      fmt.Sprintf("Time-based SQL injection confirmed via dual delay scaling (%ds -> %v, %ds -> %v; baseline=%v).", delay1, dur1, delay2, dur2, medianBaseline),
							Evidence:    fmt.Sprintf("Baseline: %v | %ds probe: %v | %ds probe: %v", medianBaseline, delay1, dur1, delay2, dur2),
							Remediation: "Ensure all database calls use parameterized SQL queries (e.g. database/sql with ? or $ placeholders).",
							CWEID:       89,
						}
						f.SetConfidence(ConfidenceConfirmed)
						findings = append(findings, f)
						foundForParam = true
						break
					} else {
						// Single anomaly without clean scaling -> mark possible
						f := &Finding{
							Module:      m.Name(),
							Title:       fmt.Sprintf("Potential SQL Injection (Time-Based Anomaly - %s)", tmpl.DB),
							Severity:    SeverityMedium,
							URL:         target.URL,
							Parameter:   param,
							Payload:     payload1,
							Detail:      fmt.Sprintf("Response delay observed for %ds probe (%v vs baseline %v), but secondary %ds scaling probe did not correlate cleanly.", delay1, dur1, medianBaseline, delay2),
							Evidence:    fmt.Sprintf("Baseline: %v, Delay1: %v, Delay2: %v", medianBaseline, dur1, dur2),
							Remediation: "Audit backend SQL query construction for parameter.",
							CWEID:       89,
						}
						f.SetConfidence(ConfidencePossible)
						findings = append(findings, f)
						foundForParam = true
						break
					}
				}
			}
		}
	}

	return findings, nil
}
