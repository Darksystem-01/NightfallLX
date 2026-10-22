package modules

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"mime/multipart"
	"net/url"
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
	return "Unrestricted File Upload & Extension / MIME Validation Assessment (Opt-in)"
}

var (
	fileInputRegex = regexp.MustCompile(`(?i)<input[^>]+type=["']file["'][^>]*name=["']([^"']*)["']`)
	filePathRegex  = regexp.MustCompile(`(?i)["'](/?[a-zA-Z0-9_.\-/]+(?:uploads?|files?|images?|static)[a-zA-Z0-9_.\-/]*(?:probe[a-zA-Z0-9_.\-]*\.(?:php|png|txt))?)["']`)
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

	// Unique non-destructive marker probe (safe read-only probe)
	tokenBytes := make([]byte, 8)
	_, _ = rand.Read(tokenBytes)
	markerID := hex.EncodeToString(tokenBytes)
	markerContent := "NFLX_PROBE_MARKER_" + markerID
	probeFileName := "probe.php.png"

	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	part, err := w.CreateFormFile(fieldName, probeFileName)
	if err == nil {
		_, _ = part.Write([]byte(markerContent))
	}
	_ = w.Close()

	uploadHeaders := map[string]string{
		"Content-Type": w.FormDataContentType(),
	}

	uploadResp, err := c.Request("POST", target.URL, b.String(), uploadHeaders)
	if err != nil || uploadResp == nil {
		return nil, nil
	}

	if uploadResp.StatusCode != 200 && uploadResp.StatusCode != 201 {
		return nil, nil
	}

	// Try to find the uploaded path from response body
	var detectedPath string
	candidates := filePathRegex.FindAllStringSubmatch(uploadResp.Body, -1)
	for _, cMatch := range candidates {
		if len(cMatch) > 1 && cMatch[1] != "" {
			detectedPath = cMatch[1]
			break
		}
	}
	if detectedPath == "" {
		// Common standard upload paths to verify
		detectedPath = "/uploads/" + probeFileName
	}

	// Confirm success deterministically by GET-ing the uploaded file path to check for our marker
	targetParsed, _ := url.Parse(target.URL)
	var checkURL string
	if targetParsed != nil {
		rel, err := url.Parse(detectedPath)
		if err == nil {
			checkURL = targetParsed.ResolveReference(rel).String()
		}
	}
	if checkURL == "" {
		checkURL = target.URL + "/" + detectedPath
	}

	getResp, getErr := c.Request("GET", checkURL, "", nil)
	if getErr == nil && getResp != nil && getResp.StatusCode == 200 && strings.Contains(getResp.Body, markerContent) {
		finding := &Finding{
			Module:      m.Name(),
			Title:       "Insecure File Upload (Double Extension Permitted & Verified)",
			Severity:    SeverityCritical,
			URL:         target.URL,
			Parameter:   fieldName,
			Payload:     probeFileName,
			Detail:      fmt.Sprintf("Server accepted upload with double extension ('%s') and the file was confirmed accessible via GET at %s with marker verification.", probeFileName, checkURL),
			Evidence:    fmt.Sprintf("Marker confirmed in GET %s: %s", checkURL, markerContent),
			Remediation: "Enforce strict allow-list on file extensions, re-encode image files, and store uploads outside web root with no-execute permissions.",
			CWEID:       434,
		}
		finding.SetConfidence(ConfidenceConfirmed)
		findings = append(findings, finding)
	} else if strings.Contains(uploadResp.Body, probeFileName) {
		// File name reflected in response without direct content verification -> mark as possible
		finding := &Finding{
			Module:      m.Name(),
			Title:       "Potential Insecure File Upload (Double Extension Accepted)",
			Severity:    SeverityMedium,
			URL:         target.URL,
			Parameter:   fieldName,
			Payload:     probeFileName,
			Detail:      fmt.Sprintf("Server accepted upload with potential executable double extension ('%s'), but marker could not be verified via GET.", probeFileName),
			Evidence:    fmt.Sprintf("Status %d with uploaded filename reflected in response.", uploadResp.StatusCode),
			Remediation: "Enforce strict allow-list on file extensions and store uploads outside web root.",
			CWEID:       434,
		}
		finding.SetConfidence(ConfidencePossible)
		findings = append(findings, finding)
	}

	return findings, nil
}
