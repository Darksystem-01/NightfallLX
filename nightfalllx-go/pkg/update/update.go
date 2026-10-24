package update

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"nightfalllx/pkg/version"
)

// Result describes the latest published release.
type Result struct {
	CurrentVersion  string
	LatestVersion   string
	URL             string
	UpdateAvailable bool
}

// Client checks the GitHub releases API for a newer NightfallLX version.
type Client struct {
	BaseURL    string
	Repository string
	HTTPClient *http.Client
}

// NewClient creates an update checker with a short timeout.
func NewClient() *Client {
	return &Client{
		BaseURL:    "https://api.github.com",
		Repository: version.Repository,
		HTTPClient: &http.Client{Timeout: 4 * time.Second},
	}
}

type releaseResponse struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

// Check queries GitHub and reports whether a newer semantic version exists.
func (c *Client) Check(ctx context.Context) (*Result, error) {
	if c == nil {
		return nil, fmt.Errorf("update client is nil")
	}
	base := strings.TrimRight(c.BaseURL, "/")
	repo := strings.Trim(c.Repository, "/")
	if base == "" || repo == "" {
		return nil, fmt.Errorf("update endpoint is not configured")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", version.UserAgent)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	var release releaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}
	latest := strings.TrimSpace(release.TagName)
	if latest == "" {
		return nil, fmt.Errorf("GitHub release did not include a tag")
	}

	return &Result{
		CurrentVersion:  version.Version,
		LatestVersion:   latest,
		URL:             release.HTMLURL,
		UpdateAvailable: CompareVersions(latest, version.Version) > 0,
	}, nil
}

// CompareVersions compares dotted numeric versions. It returns 1 when left is newer.
func CompareVersions(left, right string) int {
	leftParts := numericParts(left)
	rightParts := numericParts(right)
	max := len(leftParts)
	if len(rightParts) > max {
		max = len(rightParts)
	}
	for i := 0; i < max; i++ {
		var l, r int
		if i < len(leftParts) {
			l = leftParts[i]
		}
		if i < len(rightParts) {
			r = rightParts[i]
		}
		if l > r {
			return 1
		}
		if l < r {
			return -1
		}
	}
	return 0
}

func numericParts(v string) []int {
	v = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(v), "v"))
	var parts []int
	for _, field := range strings.FieldsFunc(v, func(r rune) bool {
		return r < '0' || r > '9'
	}) {
		var n int
		for _, ch := range field {
			n = n*10 + int(ch-'0')
		}
		parts = append(parts, n)
	}
	return parts
}
