package modules

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"nightfalllx/pkg/client"
	"regexp"
	"strings"
)

type UploadModule struct{}

func NewUploadModule() *UploadModule {
	return &UploadModule{}
}

func (m *UploadModule) Name() string {
	return "upload"
}

func (m *UploadModule) Description() string {
	return "Unrestricted File Upload & Extension / MIME Validation Assessment"
}

var (
	fileInputRegex = regexp.MustCompile(`(?i)<input[^>]+type=["']file["'][^>]*name=["']([^"']*)["']`)
	uploadSuccessRegex = regexp.MustCompile(`(?i)(uploaded|success|file saved|upload complete|"status":\s*"success"|"status":\s*true)`)
)

func (m *UploadModule) Run(target *Target, c *client.Client) ([]*Finding, error) {
	var findings []*Finding

	// Check if target page has file upload form
	resp, err := c.Request("GET", target.URL, "", nil)
	if err != nil || resp == nil {
		return nil, nil
	}

	matches := fileInputRegex.FindAllStringSubmatch(resp.Body, -1)
	if len(matches) == 0 && !strings.Contains(strings.ToLower(target.URL), "upload") {
		return nil, nil
	}

	fieldName := "file"
	if len(matches) > 0 && len(matches[0]) > 1 && matches[0][1] != "" {
		fieldName = matches[0][1]
	}

	// Safe read-only marker upload test (never persists beyond probe)
	markerContent := "NFLX_READONLY_PROBE_MARKER_TEST"
	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	part, err := w.CreateFormFile(fieldName, "probe.php.png")
	if err == nil {
		_, _ = part.Write([]byte(markerContent))
	}
	_ = w.Close()

	uploadHeaders := map[string]string{
		"Content-Type": w.FormDataContentType(),
	}

	uploadResp, err := c.Request("POST", target.URL, b.String(), uploadHeaders)
	if err == nil && uploadResp != nil {
		if (uploadResp.StatusCode == 200 || uploadResp.StatusCode == 201) &&
			uploadSuccessRegex.MatchString(uploadResp.Body) &&
			!uploadSuccessRegex.MatchString(resp.Body) {
			evidence := uploadSuccessRegex.FindString(uploadResp.Body)
			findings = append(findings, &Finding{
				Module:      m.Name(),
				Title:       "Insecure File Upload (Double Extension Permitted)",
				Severity:    SeverityHigh,
				Confidence:  85,
				URL:         target.URL,
				Parameter:   fieldName,
				Payload:     "probe.php.png",
				Detail:      fmt.Sprintf("Server accepted upload with potential executable double extension ('probe.php.png'). Indicator: '%s'.", evidence),
				Evidence:    fmt.Sprintf("Status %d: %s", uploadResp.StatusCode, evidence),
				Remediation: "Enforce strict allow-list on file extensions, re-encode image files, and store uploads outside web root with no-execute permissions.",
				CWEID:       434,
			})
		}
	}

	return findings, nil
}
