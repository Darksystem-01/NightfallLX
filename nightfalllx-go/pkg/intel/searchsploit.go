package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type searchsploitOutput struct {
	Search         string                   `json:"SEARCH"`
	DBPathExploit  string                   `json:"DB_PATH_EXPLOIT"`
	ResultsExploit []searchsploitResultItem `json:"RESULTS_EXPLOIT"`
}

type searchsploitResultItem struct {
	Title         string `json:"Title"`
	EDBID         string `json:"EDB-ID"`
	DatePublished string `json:"Date_Published"`
	Author        string `json:"Author"`
	Type          string `json:"Type"`
	Platform      string `json:"Platform"`
	Codes         string `json:"Codes"`
	Path          string `json:"Path"`
}

// SearchsploitClient manages lookups against the local Exploit-DB searchsploit index.
type SearchsploitClient struct {
	BinPath string
	Timeout time.Duration
}

// NewSearchsploitClient creates a new SearchsploitClient.
func NewSearchsploitClient() *SearchsploitClient {
	bin, err := exec.LookPath("searchsploit")
	if err != nil {
		bin = ""
	}
	return &SearchsploitClient{
		BinPath: bin,
		Timeout: 30 * time.Second,
	}
}

// IsAvailable checks if the searchsploit binary is executable.
func (c *SearchsploitClient) IsAvailable() bool {
	return c.BinPath != ""
}

// Lookup queries the searchsploit index safely using exec.Command with argument slices.
// It parses the JSON output and extracts metadata only.
// SAFETY: Files listed in searchsploit are NEVER opened, read, copied, or executed.
func (c *SearchsploitClient) Lookup(product, version string) ([]*IntelFinding, error) {
	if !c.IsAvailable() {
		return nil, ErrSearchsploitNotFound
	}

	query := strings.TrimSpace(product + " " + version)
	validQuery, err := ValidateQuery(query)
	if err != nil {
		return nil, err
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Never use a shell string; use exec.CommandContext with explicit argument slice and "--"
	cmd := exec.CommandContext(ctx, c.BinPath, "--json", "--", validQuery)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Even if searchsploit exits with non-zero on 0 matches, inspect stdout for JSON
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("searchsploit execution failed: %w (stderr: %s)", err, stderr.String())
		}
	}

	var parsed searchsploitOutput
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse searchsploit JSON output: %w", err)
	}

	var findings []*IntelFinding
	for _, item := range parsed.ResultsExploit {
		cves := ExtractCVEs(item.Title + " " + item.Codes)

		findings = append(findings, &IntelFinding{
			Query:     validQuery,
			Source:    "searchsploit",
			Title:     item.Title,
			EDBID:     item.EDBID,
			CVEs:      cves,
			LocalPath: item.Path, // Informational only; not opened or executed
			Type:      item.Type,
			Platform:  item.Platform,
			Date:      item.DatePublished,
		})
	}

	return findings, nil
}
