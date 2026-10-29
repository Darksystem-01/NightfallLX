package modules

import (
	"fmt"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/wordlists"
	"strings"
	"time"
)

type SQLiModule struct{}

func NewSQLiModule() *SQLiModule {
	return &SQLiModule{}
}

func (m *SQLiModule) Name() string {
	return "sqli"
}

func (m *SQLiModule) Description() string {
	return "Differential boolean-based, error-based, and time-based blind SQL injection detector"
}

func (m *SQLiModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	for _, param := range target.Parameters() {
		origVal := target.Params[param]
		if isPost {
			origVal = target.Data[param]
		}
		if origVal == "" {
			origVal = "1"
		}

		// ── Step 1: Baseline Request & Latency ─────────────────────────────
		startBase := time.Now()
		var baseResp *client.Response
		var err error
		if isPost {
			baseResp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, origVal), nil)
		} else {
			baseResp, err = c.Request("GET", target.BuildURLWithParam(param, origVal), "", nil)
		}
		baseLatency := time.Since(startBase)

		if err != nil || baseResp == nil || baseResp.StatusCode >= 500 {
			continue
		}

		// Ensure baseline does not already disclose database syntax errors (eliminates false positives on docs/blogs)
		baselineHasSQLError := wordlists.SQLErrorRegex.MatchString(baseResp.Body)

		// ── Step 2: Error-Based SQL Injection ──────────────────────────────
		if !baselineHasSQLError {
			errorProbes := []string{"'", "\"", "')", "\")", "';-- -"}
			for _, extraProbe := range wordlists.GetWordlist("sqli", target.Wordlist) {
				if len(errorProbes) >= 15 {
					break
				}
				errorProbes = append(errorProbes, extraProbe)
			}
			confirmedError := false
			for _, probe := range errorProbes {
				probePayload := origVal + probe
				var probeResp *client.Response
				if isPost {
					probeResp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, probePayload), nil)
				} else {
					probeResp, err = c.Request("GET", target.BuildURLWithParam(param, probePayload), "", nil)
				}

				if err == nil && probeResp != nil && probeResp.Body != "" && wordlists.SQLErrorRegex.MatchString(probeResp.Body) {
					evidence := wordlists.SQLErrorRegex.FindString(probeResp.Body)
					findings = append(findings, &Finding{
						Module:      m.Name(),
						Title:       "SQL Injection (Error-Based)",
						Severity:    SeverityCritical,
						Confidence:  100,
						URL:         target.URL,
						Parameter:   param,
						Payload:     probePayload,
						Detail:      fmt.Sprintf("Confirmed SQL syntax error disclosed via injected delimiter '%s'. Matched database signature: '%s'", probe, evidence),
						Evidence:    evidence,
						Remediation: "Use parameterized queries (prepared statements) for all database operations.",
						CWEID:       89,
					})
					confirmedError = true
					break
				}
			}
			if confirmedError {
				continue
			}
		}

		// ── Step 3: Boolean-Based Blind SQL Injection ──────────────────────
		confirmedBoolean := false
		for _, pair := range wordlists.SQLBooleanPairs {
			truePayload := fmt.Sprintf(pair[0], origVal)
			falsePayload := fmt.Sprintf(pair[1], origVal)

			var trueResp, falseResp *client.Response
			if isPost {
				trueResp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, truePayload), nil)
				if err != nil {
					continue
				}
				falseResp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, falsePayload), nil)
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

			// Also check error disclosure during boolean pairing
			if !baselineHasSQLError && (wordlists.SQLErrorRegex.MatchString(falseResp.Body) || wordlists.SQLErrorRegex.MatchString(trueResp.Body)) {
				evidence := wordlists.SQLErrorRegex.FindString(falseResp.Body)
				if evidence == "" {
					evidence = wordlists.SQLErrorRegex.FindString(trueResp.Body)
				}
				findings = append(findings, &Finding{
					Module:      m.Name(),
					Title:       "SQL Injection (Error-Based via Boolean Pair)",
					Severity:    SeverityCritical,
					Confidence:  100,
					URL:         target.URL,
					Parameter:   param,
					Payload:     falsePayload,
					Detail:      fmt.Sprintf("Database engine syntax error disclosed: '%s'", evidence),
					Evidence:    evidence,
					Remediation: "Use parameterized queries (prepared statements) for all database operations.",
					CWEID:       89,
				})
				confirmedBoolean = true
				break
			}

			// Eliminate WAF block False Positives (403, 429, 5xx)
			if trueResp.StatusCode == 403 || falseResp.StatusCode == 403 ||
				trueResp.StatusCode == 429 || falseResp.StatusCode == 429 ||
				trueResp.StatusCode >= 500 || falseResp.StatusCode >= 500 {
				continue
			}

			trueSim := Similarity(baseResp.Body, trueResp.Body)
			falseSim := Similarity(baseResp.Body, falseResp.Body)
			separation := trueSim - falseSim

			if trueSim >= 0.88 && falseSim <= 0.82 && separation >= 0.10 {
				findings = append(findings, &Finding{
					Module:      m.Name(),
					Title:       "SQL Injection (Boolean-based Blind)",
					Severity:    SeverityHigh,
					Confidence:  100,
					URL:         target.URL,
					Parameter:   param,
					Payload:     fmt.Sprintf("%s vs %s", truePayload, falsePayload),
					Detail:      fmt.Sprintf("Boolean differential verified: true similarity=%.3f, false similarity=%.3f, separation=%.3f", trueSim, falseSim, separation),
					Evidence:    fmt.Sprintf("True response bytes: %d, False response bytes: %d", trueResp.Bytes, falseResp.Bytes),
					Remediation: "Use parameterized queries (prepared statements) for all database operations.",
					CWEID:       89,
				})
				confirmedBoolean = true
				break
			}
		}

		if confirmedBoolean {
			continue
		}

		// ── Step 4: Time-Based Blind SQL Injection (Multi-Stage Latency Differential) ──
		sleepDelay := 3 * time.Second
		for _, tmpl := range wordlists.SQLTimeSleepTemplates {
			sPayload := fmt.Sprintf(tmpl, origVal, 3)
			start := time.Now()
			var sErr error
			if isPost {
				_, sErr = c.Request("POST", target.URL, target.BuildDataWithParam(param, sPayload), nil)
			} else {
				_, sErr = c.Request("GET", target.BuildURLWithParam(param, sPayload), "", nil)
			}
			if sErr != nil {
				continue
			}
			sLatency := time.Since(start)

			// If delayed by at least 80% of sleep duration
			if sLatency >= baseLatency+(sleepDelay*8/10) {
				// Secondary probe: sleep 0 (must be fast, eliminates network latency jitter)
				fastPayload := fmt.Sprintf(tmpl, origVal, 0)
				startFast := time.Now()
				if isPost {
					_, _ = c.Request("POST", target.URL, target.BuildDataWithParam(param, fastPayload), nil)
				} else {
					_, _ = c.Request("GET", target.BuildURLWithParam(param, fastPayload), "", nil)
				}
				fastLatency := time.Since(startFast)

				// Tertiary probe: sleep 4 (must scale proportionally)
				confirmPayload := fmt.Sprintf(tmpl, origVal, 4)
				startConfirm := time.Now()
				if isPost {
					_, _ = c.Request("POST", target.URL, target.BuildDataWithParam(param, confirmPayload), nil)
				} else {
					_, _ = c.Request("GET", target.BuildURLWithParam(param, confirmPayload), "", nil)
				}
				confirmLatency := time.Since(startConfirm)

				// Differential assertion: sleep 0 < 1.8s and sleep 4 >= 3.2s
				if fastLatency < 1800*time.Millisecond && confirmLatency >= 3200*time.Millisecond {
					findings = append(findings, &Finding{
						Module:      m.Name(),
						Title:       "SQL Injection (Time-based Blind)",
						Severity:    SeverityCritical,
						Confidence:  95,
						URL:         target.URL,
						Parameter:   param,
						Payload:     sPayload,
						Detail:      fmt.Sprintf("Confirmed time-based SQL execution (sleep 0: %v, sleep 3: %v, sleep 4: %v).", fastLatency.Round(time.Millisecond), sLatency.Round(time.Millisecond), confirmLatency.Round(time.Millisecond)),
						Evidence:    fmt.Sprintf("Proportional sleep delay verified: base=%v, sleep3=%v, sleep4=%v", baseLatency.Round(time.Millisecond), sLatency.Round(time.Millisecond), confirmLatency.Round(time.Millisecond)),
						Remediation: "Use parameterized queries (prepared statements) for all database operations.",
						CWEID:       89,
					})
					break
				}
			}
		}
	}

	return findings, nil
}
