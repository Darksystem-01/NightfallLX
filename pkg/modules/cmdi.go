package modules

import (
	"fmt"
	"math/rand"
	"nightfalllx/pkg/client"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type CMDiModule struct{}

func NewCMDiModule() *CMDiModule {
	return &CMDiModule{}
}

func (m *CMDiModule) Name() string {
	return "cmdi"
}

func (m *CMDiModule) Description() string {
	return "Harmless OS Command Injection verification (canary arithmetic, safe id probes, and differential timing)"
}

var (
	// Matches standard Linux/Unix uid output: uid=1000(user) gid=1000(user)
	idPattern = regexp.MustCompile(`uid=\d+\([a-zA-Z0-9_\-.]+\)\s+gid=\d+`)
	// Matches standard Windows whoami output: DOMAIN\user or NT AUTHORITY\SYSTEM
	winUserPattern = regexp.MustCompile(`(?i)(?:nt authority\\(?:system|network service|local service)|[a-zA-Z0-9_\-]+\\[a-zA-Z0-9_\-]+)`)
)

func (m *CMDiModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
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
		var baseErr error
		if isPost {
			baseResp, baseErr = c.Request("POST", target.URL, target.BuildDataWithParam(param, origVal), nil)
		} else {
			baseResp, baseErr = c.Request("GET", target.BuildURLWithParam(param, origVal), "", nil)
		}
		baseLatency := time.Since(startBase)
		baseBody := ""
		if baseErr == nil && baseResp != nil {
			baseBody = baseResp.Body
		}

		// Check if baseline already has idPattern to prevent false positives on documentation pages
		baselineHasID := idPattern.MatchString(baseBody)

		// ── Step 2: In-band Canary Arithmetic Probe (Zero False Positive) ──
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		n1 := 10000 + r.Intn(40000)
		n2 := 10000 + r.Intn(40000)
		expectedSum := n1 + n2
		canaryPrefix := "nflx_"
		expectedToken := fmt.Sprintf("%s%d", canaryPrefix, expectedSum)
		calcExpr := fmt.Sprintf("%d+%d", n1, n2)

		// Ensure baseline does not coincidentally contain our token
		if !strings.Contains(baseBody, expectedToken) {
			canaryTemplates := []string{
				"; echo " + canaryPrefix + "$(( " + calcExpr + " ))",
				"| echo " + canaryPrefix + "$(( " + calcExpr + " ))",
				"&& echo " + canaryPrefix + "$(( " + calcExpr + " ))",
				"\necho " + canaryPrefix + "$(( " + calcExpr + " ))",
				"'; echo " + canaryPrefix + "$(( " + calcExpr + " )); #",
				"\"; echo " + canaryPrefix + "$(( " + calcExpr + " )); #",
				"$(echo " + canaryPrefix + "$(( " + calcExpr + " )))",
				"`echo " + canaryPrefix + "$(( " + calcExpr + " ))`",
				"& set /a " + strconv.Itoa(expectedSum) + " &",
			}

			confirmedCanary := false
			for _, payload := range canaryTemplates {
				var resp *client.Response
				var err error
				if isPost {
					resp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, payload), nil)
				} else {
					resp, err = c.Request("GET", target.BuildURLWithParam(param, payload), "", nil)
				}
				if err != nil || resp == nil || resp.Body == "" {
					continue
				}

				if strings.Contains(resp.Body, expectedToken) {
					findings = append(findings, &Finding{
						Module:      m.Name(),
						Title:       "OS Command Injection (Deterministic Arithmetic Canary)",
						Severity:    SeverityCritical,
						Confidence:  100,
						URL:         target.URL,
						Parameter:   param,
						Payload:     payload,
						Detail:      fmt.Sprintf("Confirmed arbitrary command execution via dynamic arithmetic canary: '%s' evaluated to '%s'.", calcExpr, expectedToken),
						Evidence:    fmt.Sprintf("Discovered evaluated arithmetic token '%s' in HTTP response body.", expectedToken),
						Remediation: "Avoid shell execution with user-controlled input. Use parameterized APIs (e.g. execFile) without shell invocation.",
						CWEID:       78,
					})
					confirmedCanary = true
					break
				}
			}

			if confirmedCanary {
				continue
			}
		}

		// ── Step 3: Fallback Safe System Identity Probe (id) ──────────────
		if !baselineHasID {
			idProbes := []string{
				"; id",
				"| id",
				"&& id",
				"\nid",
				"'; id; #",
				"\"; id; #",
				"$(id)",
				"`id`",
				"& whoami &",
				"| whoami",
			}

			confirmedID := false
			for _, payload := range idProbes {
				var resp *client.Response
				var err error
				if isPost {
					resp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, payload), nil)
				} else {
					resp, err = c.Request("GET", target.BuildURLWithParam(param, payload), "", nil)
				}
				if err != nil || resp == nil || resp.Body == "" {
					continue
				}

				if idPattern.MatchString(resp.Body) || winUserPattern.MatchString(resp.Body) {
					matchedUser := idPattern.FindString(resp.Body)
					if matchedUser == "" {
						matchedUser = winUserPattern.FindString(resp.Body)
					}
					findings = append(findings, &Finding{
						Module:      m.Name(),
						Title:       "OS Command Injection (Safe System Info)",
						Severity:    SeverityCritical,
						Confidence:  100,
						URL:         target.URL,
						Parameter:   param,
						Payload:     payload,
						Detail:      fmt.Sprintf("Confirmed arbitrary command execution using harmless probe '%s'. Matched system identity: '%s'.", payload, matchedUser),
						Evidence:    fmt.Sprintf("Matched system identity: %s", matchedUser),
						Remediation: "Avoid shell execution with request-controlled inputs. Use safe system APIs without shell invocation.",
						CWEID:       78,
					})
					confirmedID = true
					break
				}
			}

			if confirmedID {
				continue
			}
		}

		// ── Step 4: Multi-stage Differential Blind Timing Probe ────────────
		sleepDelay := 3 * time.Second
		sleepTemplates := []string{
			"; sleep %d",
			"| sleep %d",
			"&& sleep %d",
			"'; sleep %d; #",
			"\"; sleep %d; #",
		}

		for _, tmpl := range sleepTemplates {
			sPayload := fmt.Sprintf(tmpl, 3)
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
				// Secondary probe: sleep 0 (must be fast, eliminates network lag)
				fastPayload := fmt.Sprintf(tmpl, 0)
				startFast := time.Now()
				if isPost {
					_, _ = c.Request("POST", target.URL, target.BuildDataWithParam(param, fastPayload), nil)
				} else {
					_, _ = c.Request("GET", target.BuildURLWithParam(param, fastPayload), "", nil)
				}
				fastLatency := time.Since(startFast)

				// Tertiary probe: sleep 4 (must scale proportionally)
				confirmPayload := fmt.Sprintf(tmpl, 4)
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
						Title:       "Blind OS Command Injection (Time-based)",
						Severity:    SeverityCritical,
						Confidence:  95,
						URL:         target.URL,
						Parameter:   param,
						Payload:     sPayload,
						Detail:      fmt.Sprintf("Confirmed time-based command execution (sleep 0: %v, sleep 3: %v, sleep 4: %v).", fastLatency.Round(time.Millisecond), sLatency.Round(time.Millisecond), confirmLatency.Round(time.Millisecond)),
						Evidence:    fmt.Sprintf("Proportional sleep delay verified: base=%v, sleep3=%v, sleep4=%v", baseLatency.Round(time.Millisecond), sLatency.Round(time.Millisecond), confirmLatency.Round(time.Millisecond)),
						Remediation: "Avoid system shell invocation; use parameterized APIs.",
						CWEID:       78,
					})
					break
				}
			}
		}
	}

	return findings, nil
}
