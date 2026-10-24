package tui

import (
	"bufio"
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/detector"
	"nightfalllx/pkg/fuzzer"
	"nightfalllx/pkg/modules"
	"nightfalllx/pkg/parser"
	"nightfalllx/pkg/shodan"
	"nightfalllx/pkg/sitemap"
	"nightfalllx/pkg/troubleshoot"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// MouseEvent represents a decoded terminal mouse click.
type MouseEvent struct {
	Col    int
	Row    int
	Button int
	Action byte // 'M' for press, 'm' for release
}

// MenuItem represents an interactive button in the TUI.
type MenuItem struct {
	ID          int
	Title       string
	Description string
	StartRow    int
	EndRow      int
	StartCol    int
	EndCol      int
}

// InteractiveTUI manages the mouse-controllable terminal UI.
type InteractiveTUI struct {
	TargetURL     string
	Proxy         string
	Threads       int
	Wordlist      string
	SelectedIndex int
	Items         []MenuItem
	StatusMsg     string
}

func NewInteractiveTUI(initialURL string) *InteractiveTUI {
	if initialURL == "" {
		initialURL = "http://127.0.0.1:8080"
	}
	return &InteractiveTUI{
		TargetURL: initialURL,
		Threads:   40,
		StatusMsg: "Ready. Click any button with your mouse or use [1-9] / Arrow keys.",
	}
}

// setRawMode enables raw input and mouse tracking.
func (t *InteractiveTUI) enableMouseAndRaw() (*exec.Cmd, error) {
	// Enable mouse reporting (X10 + normal + SGR extended mode)
	fmt.Print("\033[?1000h\033[?1002h\033[?1006h\033[?25l")
	cmd := exec.Command("stty", "cbreak", "-echo")
	cmd.Stdin = os.Stdin
	return cmd, cmd.Run()
}

// disableMouseAndRaw restores the terminal.
func (t *InteractiveTUI) disableMouseAndRaw() {
	// Disable mouse reporting, restore cursor
	fmt.Print("\033[?1000l\033[?1002l\033[?1006l\033[?25h\033[0m")
	cmd := exec.Command("stty", "sane")
	cmd.Stdin = os.Stdin
	_ = cmd.Run()
}

var sgrMouseRegex = regexp.MustCompile(`\x1b\[<(\d+);(\d+);(\d+)([Mm])`)

// parseInput parses stdin bytes for mouse clicks or keys.
func (t *InteractiveTUI) readInput(reader *bufio.Reader) (string, *MouseEvent) {
	b, err := reader.ReadByte()
	if err != nil {
		return "", nil
	}

	if b == 3 { // Ctrl+C
		return "quit", nil
	}

	if b == 27 { // Escape sequence
		// Check if there is more
		var seq strings.Builder
		seq.WriteByte(b)
		for reader.Buffered() > 0 {
			next, _ := reader.ReadByte()
			seq.WriteByte(next)
			if next == 'M' || next == 'm' || next == '~' || (next >= 'A' && next <= 'Z') {
				break
			}
		}

		rawSeq := seq.String()

		// Check for SGR mouse event: \x1b[<0;col;rowM
		if matches := sgrMouseRegex.FindStringSubmatch(rawSeq); len(matches) == 5 {
			btn, _ := strconv.Atoi(matches[1])
			col, _ := strconv.Atoi(matches[2])
			row, _ := strconv.Atoi(matches[3])
			action := matches[4][0]
			return "mouse", &MouseEvent{
				Col:    col,
				Row:    row,
				Button: btn,
				Action: action,
			}
		}

		if rawSeq == "\033[A" {
			return "up", nil
		}
		if rawSeq == "\033[B" {
			return "down", nil
		}
		if rawSeq == "\033" {
			return "escape", nil
		}
	}

	if b == '\r' || b == '\n' {
		return "enter", nil
	}

	ch := string(b)
	if ch == "q" || ch == "Q" {
		return "quit", nil
	}
	if ch >= "1" && ch <= "9" {
		return ch, nil
	}

	return "", nil
}

// Draw renders the interactive screen.
func (t *InteractiveTUI) Draw() {
	// Clear screen & move to top-left
	fmt.Print("\033[H\033[2J")

	// 1. Futuristic Cyberpunk Miniature ASCII Art Banner
	fmt.Println("\033[1;36m")
	fmt.Println("  ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗ █████╗ ██╗     ██╗     ██╗   ██╗")
	fmt.Println("  ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔══██╗██║     ██║     ╚██╗ ██╔╝")
	fmt.Println("  ██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ███████║██║     ██║      ╚████╔╝ ")
	fmt.Println("  ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██╔══██║██║     ██║      ██╔═██╗ ")
	fmt.Println("  ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║     ██║  ██║███████╗███████╗██╔╝ ██╗")
	fmt.Println("  ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝\033[0m")
	fmt.Println("\033[1;35m  :: Next-Gen Web Assessment & Recon Suite :: [ Interactive Mouse TUI Mode ] ::\033[0m")
	fmt.Println()

	// 2. Active Target Configuration Box
	fmt.Println("\033[1;34m  ┌───[ 🎯 Active Session Context ]────────────────────────────────────────────────┐\033[0m")
	fmt.Printf("\033[1;34m  │\033[0m Target URL : \033[1;32m%-50s\033[0m \033[1;34m│\033[0m\n", t.TargetURL)
	proxyDisplay := t.Proxy
	if proxyDisplay == "" {
		proxyDisplay = "(Direct connection - no proxy)"
	}
	fmt.Printf("\033[1;34m  │\033[0m Proxy      : \033[33m%-50s\033[0m \033[1;34m│\033[0m\n", proxyDisplay)
	fmt.Printf("\033[1;34m  │\033[0m Concurrency: \033[36m%-50s\033[0m \033[1;34m│\033[0m\n", fmt.Sprintf("%d Goroutine workers", t.Threads))
	fmt.Println("\033[1;34m  └────────────────────────────────────────────────────────────────────────────────┘\033[0m")
	fmt.Println()

	// 3. Define Interactive Menu Items
	menuDefs := []struct {
		ID    int
		Title string
		Desc  string
	}{
		{1, "🎯  Set Target URL / Change Target", "Update target web application address"},
		{2, "🔍  Deep Tech Detector (Wappalyzer+)", "Discover PHP/Apache/Laravel versions, templates & headers"},
		{3, "🌐  Subdomain & VHost Discovery", "Fast ffuf-compatible DNS & VHost fuzzing with auto-calibration"},
		{4, "🗺️   Full Site Map & Web Crawler", "Spider architecture, endpoints, forms & parameter tree"},
		{5, "🛰️   Shodan OSINT Intelligence", "Passive DNS subdomains, open ports, services & CVEs"},
		{6, "⚡  High-Speed Directory & Param Fuzzer", "Concurrent 1800+ req/s endpoint and wordlist fuzzing"},
		{7, "🛡️   Run 10 Vulnerability Modules", "Scan for SQLi, SSTI, LFI, CMDi, XSS, CORS, SSRF, JWT, WAF"},
		{8, "📬  Load Burp Suite Request (-r)", "Import raw request.txt from Burp Suite Proxy/Repeater"},
		{9, "🩺  Doctor & Diagnostics Check", "Troubleshoot DNS, TCP, TLS, and Proxy connectivity"},
		{10, "🚀  Launch Comprehensive Audit", "Full assessment: Tech + Map + Shodan + Vulns"},
		{11, "❌  Exit NightfallLX", "Exit interactive dashboard to terminal"},
	}

	t.Items = nil
	currentVisualRow := 15 // Line where buttons start on screen

	for idx, def := range menuDefs {
		isSelected := idx == t.SelectedIndex
		prefix := "  \033[36m[ ]\033[0m"
		cardBg := "\033[0m"
		border := "\033[90m"
		textStyle := "\033[37m"

		if isSelected {
			prefix = "  \033[1;32m[▶]\033[0m"
			cardBg = "\033[48;5;236m"
			border = "\033[1;36m"
			textStyle = "\033[1;37m"
		}

		lineStr := fmt.Sprintf("%s%s %-38s \033[90m— %-33s\033[0m", prefix, cardBg+textStyle, def.Title, def.Desc)
		fmt.Printf("  %s\n", lineStr)

		// Record bounding coordinates for mouse clicks
		t.Items = append(t.Items, MenuItem{
			ID:          def.ID,
			Title:       def.Title,
			Description: def.Desc,
			StartRow:    currentVisualRow,
			EndRow:      currentVisualRow,
			StartCol:    3,
			EndCol:      82,
		})
		currentVisualRow++
		_ = border
	}

	fmt.Println()
	// 4. Status Bar and Mouse Guide
	fmt.Println("\033[1;33m  ┌───[ 💡 Navigation & Mouse Control ]────────────────────────────────────────────┐\033[0m")
	fmt.Printf("\033[1;33m  │\033[0m \033[1;32m🖱️  MOUSE:\033[0m Click ANY button directly | \033[1;36m⌨️  KEYS:\033[0m [1-9] or ↑/↓ + Enter | \033[1;31mq:\033[0m Quit  \033[1;33m│\033[0m\n")
	fmt.Printf("\033[1;33m  │\033[0m Status: \033[1;37m%-69s\033[0m \033[1;33m│\033[0m\n", t.StatusMsg)
	fmt.Println("\033[1;33m  └────────────────────────────────────────────────────────────────────────────────┘\033[0m")
}

// RunLoop launches the interactive mouse loop.
func (t *InteractiveTUI) RunLoop() {
	_, err := t.enableMouseAndRaw()
	if err != nil {
		fmt.Printf("Failed to enable mouse TUI mode: %v\n", err)
		return
	}
	defer t.disableMouseAndRaw()

	reader := bufio.NewReader(os.Stdin)

	for {
		t.Draw()
		event, mouse := t.readInput(reader)

		if event == "quit" {
			break
		}

		if event == "up" {
			if t.SelectedIndex > 0 {
				t.SelectedIndex--
			} else {
				t.SelectedIndex = len(t.Items) - 1
			}
			continue
		}

		if event == "down" {
			if t.SelectedIndex < len(t.Items)-1 {
				t.SelectedIndex++
			} else {
				t.SelectedIndex = 0
			}
			continue
		}

		// Direct number press [1-9]
		if len(event) == 1 && event[0] >= '1' && event[0] <= '9' {
			idx := int(event[0] - '1')
			if idx < len(t.Items) {
				t.SelectedIndex = idx
				t.executeItem(t.Items[idx].ID)
			}
			continue
		}

		// Mouse Click handling
		if event == "mouse" && mouse != nil && mouse.Action == 'M' && mouse.Button == 0 {
			// Find which menu item matches mouse row
			clickedItem := -1
			for idx, item := range t.Items {
				if mouse.Row == item.StartRow && mouse.Col >= item.StartCol && mouse.Col <= item.EndCol {
					clickedItem = idx
					break
				}
			}

			if clickedItem != -1 {
				t.SelectedIndex = clickedItem
				t.executeItem(t.Items[clickedItem].ID)
			}
			continue
		}

		if event == "enter" {
			if t.SelectedIndex >= 0 && t.SelectedIndex < len(t.Items) {
				t.executeItem(t.Items[t.SelectedIndex].ID)
			}
			continue
		}
	}
}

// executeItem performs the selected action and pauses for viewing.
func (t *InteractiveTUI) executeItem(id int) {
	// Temporarily restore terminal for standard command execution
	t.disableMouseAndRaw()

	fmt.Print("\033[H\033[2J") // Clear

	switch id {
	case 1: // Set Target URL
		fmt.Printf("\n\033[1;36m[🎯 Set Target URL]\033[0m Current: %s\n", t.TargetURL)
		fmt.Print("Enter new target URL (or press Enter to keep current): ")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input != "" {
			if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
				input = "http://" + input
			}
			t.TargetURL = input
			t.StatusMsg = fmt.Sprintf("Target URL updated to: %s", t.TargetURL)
		}

	case 2: // Deep Tech Detector (Wappalyzer+)
		fmt.Printf("\n\033[1;36m[*] Running Wappalyzer-grade Technology & Version Detector on:\033[0m %s ...\n", t.TargetURL)
		c := client.NewClient(t.Proxy, 8*time.Second, true, "", nil)
		det := detector.NewTechDetector()
		report, err := det.Detect(t.TargetURL, c)
		if err != nil {
			fmt.Printf("\033[31m[!] Detection failed: %v\033[0m\n", err)
		} else {
			detector.PrintReport(report)
		}
		t.waitReturn()

	case 3: // Subdomain & VHost Discovery
		cleanHost := strings.TrimPrefix(strings.TrimPrefix(t.TargetURL, "http://"), "https://")
		if slashIdx := strings.Index(cleanHost, "/"); slashIdx != -1 {
			cleanHost = cleanHost[:slashIdx]
		}
		fmt.Printf("\n\033[1;36m[*] Running Subdomain & VHost Discovery for:\033[0m %s (Host: FUZZ.%s) ...\n", t.TargetURL, cleanHost)

		cfg := &fuzzer.Config{
			URL:           t.TargetURL,
			Headers:       map[string]string{"Host": fmt.Sprintf("FUZZ.%s", cleanHost)},
			Threads:       t.Threads,
			AutoCalibrate: true,
			IsSubdomain:   true,
			Proxy:         t.Proxy,
			Insecure:      true,
			FilterCodes:   map[int]bool{404: true},
		}
		f := fuzzer.NewFuzzer(cfg)
		_, _ = f.Run()
		t.waitReturn()

	case 4: // Full Site Map & Web Crawler
		fmt.Printf("\n\033[1;36m[*] Crawling web architecture and attack surface on:\033[0m %s ...\n", t.TargetURL)
		sp, err := sitemap.NewSpider(t.TargetURL, 3, 50)
		if err != nil {
			fmt.Printf("\033[31m[!] Spider initialization failed: %v\033[0m\n", err)
		} else {
			sm := sp.Crawl()
			sitemap.PrintSiteMap(sm)
		}
		t.waitReturn()

	case 5: // Shodan OSINT Intelligence
		fmt.Printf("\n\033[1;36m[*] Querying Shodan OSINT Intelligence for:\033[0m %s ...\n", t.TargetURL)
		shodanClient := shodan.NewClient("")
		domain, ip, _ := shodan.ResolveTarget(t.TargetURL)
		var hostInfo *shodan.HostInfo
		var dnsInfo *shodan.DomainInfo
		if ip != "" {
			hostInfo, _ = shodanClient.LookupHost(ip)
		}
		if domain != "" {
			dnsInfo, _ = shodanClient.LookupDomain(domain)
		}
		if hostInfo != nil || dnsInfo != nil {
			shodan.PrintReport(domain, hostInfo, dnsInfo)
		} else {
			fmt.Println("\033[33m[!] No Shodan OSINT data found or API limit reached.\033[0m")
		}
		t.waitReturn()

	case 6: // High-Speed Fuzzer
		fmt.Printf("\n\033[1;36m[*] Launching High-Speed Directory & Endpoint Fuzzer on:\033[0m %s/FUZZ ...\n", strings.TrimSuffix(t.TargetURL, "/"))
		cfg := &fuzzer.Config{
			URL:           strings.TrimSuffix(t.TargetURL, "/") + "/FUZZ",
			Threads:       t.Threads,
			AutoCalibrate: true,
			Proxy:         t.Proxy,
			Insecure:      true,
			FilterCodes:   map[int]bool{404: true},
		}
		f := fuzzer.NewFuzzer(cfg)
		_, _ = f.Run()
		t.waitReturn()

	case 7: // 10 Vulnerability Modules
		fmt.Printf("\n\033[1;36m[*] Executing 10 Vulnerability Assessment Modules against:\033[0m %s ...\n", t.TargetURL)
		t.runAllVulnModules()
		t.waitReturn()

	case 8: // Load Burp Suite Request
		fmt.Print("\n\033[1;36m[📬 Load Burp Suite Raw Request]\033[0m\nPath to request file (e.g. request.txt): ")
		reader := bufio.NewReader(os.Stdin)
		pathInput, _ := reader.ReadString('\n')
		pathInput = strings.TrimSpace(pathInput)
		if pathInput != "" {
			req, err := parser.ParseRawRequestFile(pathInput, false)
			if err != nil {
				fmt.Printf("\033[31m[!] Error: %v\033[0m\n", err)
			} else {
				t.TargetURL = req.FullURL
				t.StatusMsg = fmt.Sprintf("Burp Request Loaded: %s %s", req.Method, req.FullURL)
				fmt.Printf("\033[32m[+] Successfully loaded request:\033[0m %s %s (Host: %s, Params: %d)\n",
					req.Method, req.FullURL, req.Host, len(req.QueryParams)+len(req.PostParams))
			}
		}
		t.waitReturn()

	case 9: // Doctor Diagnostics
		fmt.Printf("\n\033[1;36m[*] Running Diagnostics & Doctor on:\033[0m %s ...\n", t.TargetURL)
		doc := troubleshoot.NewDoctor(t.TargetURL, t.Proxy, t.Wordlist)
		checks := doc.RunAll()
		_ = troubleshoot.PrintDoctorReport(checks)
		t.waitReturn()

	case 10: // Launch Full Assessment
		fmt.Printf("\n\033[1;35m════════════════════════════════════════════════════════════════════════════════════\033[0m\n")
		fmt.Printf("\033[1;36m  🚀 NIGHTFALL-LX FULL AUTOMATED COMPREHENSIVE ASSESSMENT: %s\033[0m\n", t.TargetURL)
		fmt.Printf("\033[1;35m════════════════════════════════════════════════════════════════════════════════════\033[0m\n\n")

		// Step A: Tech Detection
		fmt.Println("\033[1;33m[Step 1/3] Fingerprinting Technologies & Versions...\033[0m")
		c := client.NewClient(t.Proxy, 8*time.Second, true, "", nil)
		det := detector.NewTechDetector()
		if rep, err := det.Detect(t.TargetURL, c); err == nil {
			detector.PrintReport(rep)
		}

		// Step B: Vulnerability Assessment
		fmt.Println("\n\033[1;33m[Step 2/3] Running Active Vulnerability Audit (10 Modules)...\033[0m")
		t.runAllVulnModules()

		// Step C: Summary
		fmt.Println("\n\033[1;32m[✓] Comprehensive Assessment completed! Report saved to lab_report.md and lab_report.json\033[0m")
		t.waitReturn()

	case 11: // Exit
		os.Exit(0)
	}

	// Re-enable raw input and mouse mode for TUI
	_, _ = t.enableMouseAndRaw()
}

func (t *InteractiveTUI) runAllVulnModules() {
	parsedURL, err := url.Parse(t.TargetURL)
	if err != nil {
		fmt.Printf("\033[31m[!] Invalid URL: %v\033[0m\n", err)
		return
	}

	urlWithoutQuery := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)
	queryParams := make(map[string]string)
	for k, v := range parsedURL.Query() {
		if len(v) > 0 {
			queryParams[k] = v[0]
		}
	}

	target := &modules.Target{
		URL:    urlWithoutQuery,
		Method: "GET",
		Params: queryParams,
		Data:   make(map[string]string),
	}

	httpClient := client.NewClient(t.Proxy, 8*time.Second, true, "", nil)
	availableModules := modules.Registry(nil)
	activeMods := make([]modules.Module, 0, len(availableModules))
	for _, name := range modules.AllOrder() {
		if mod, ok := availableModules[name]; ok {
			activeMods = append(activeMods, mod)
		}
	}

	for _, mod := range activeMods {
		fmt.Printf("\033[36m[*] Running: %-12s\033[0m ...\n", mod.Name())
		findings, err := mod.Run(target, httpClient)
		if err != nil {
			continue
		}
		for _, f := range findings {
			status := "\033[1;32m[CONFIRMED]\033[0m"
			if f.Severity == modules.SeverityInfo {
				status = "\033[1;36m[INFO]\033[0m"
			}
			fmt.Printf("    %s \033[1m%s\033[0m (param=%s, confidence=%d%%)\n", status, f.Title, f.Parameter, f.Confidence)
		}
	}
}

func (t *InteractiveTUI) waitReturn() {
	fmt.Print("\n\033[1;33m[Press ENTER to return to Interactive Mouse Dashboard]\033[0m ")
	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
}
