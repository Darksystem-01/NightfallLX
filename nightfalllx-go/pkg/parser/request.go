package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"net/url"
	"nightfalllx/pkg/modules"
	"os"
	"strings"
)

// RawRequest represents a parsed Burp Suite HTTP request.
type RawRequest struct {
	Method       string
	Path         string
	HTTPVersion  string
	Host         string
	Scheme       string
	FullURL      string
	Headers      map[string]string
	Cookie       string
	Body         string
	QueryParams  map[string]string
	PostParams   map[string]string
	HasFuzzPoint bool
}

// ParseRawRequest parses raw HTTP request bytes into a RawRequest struct.
func ParseRawRequest(data []byte, isHTTPS bool) (*RawRequest, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty raw request data")
	}

	// Normalize line endings to \n
	normalized := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	
	// Split headers and body
	var headerBytes, bodyBytes []byte
	splitIdx := bytes.Index(normalized, []byte("\n\n"))
	if splitIdx != -1 {
		headerBytes = normalized[:splitIdx]
		bodyBytes = normalized[splitIdx+2:]
	} else {
		headerBytes = normalized
		bodyBytes = nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(headerBytes))
	if !scanner.Scan() {
		return nil, fmt.Errorf("failed to read request line")
	}

	// 1. Parse Request-Line (e.g. "POST /login.php?action=auth HTTP/1.1")
	reqLine := strings.TrimSpace(scanner.Text())
	parts := strings.Split(reqLine, " ")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request line format: %q", reqLine)
	}

	method := strings.ToUpper(parts[0])
	rawPath := parts[1]
	httpVersion := "HTTP/1.1"
	if len(parts) >= 3 {
		httpVersion = parts[2]
	}

	// 2. Parse Headers
	headers := make(map[string]string)
	var hostHeader, cookieHeader string

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue
		}

		k := strings.TrimSpace(line[:colonIdx])
		v := strings.TrimSpace(line[colonIdx+1:])

		if strings.EqualFold(k, "Host") {
			hostHeader = v
		} else if strings.EqualFold(k, "Cookie") {
			cookieHeader = v
		}
		headers[k] = v
	}

	// Determine Scheme
	scheme := "http"
	if isHTTPS || strings.HasSuffix(hostHeader, ":443") {
		scheme = "https"
	}

	// Check if path is full absolute URL (e.g., in proxy format)
	var finalURL string
	var queryParams = make(map[string]string)
	var cleanPath string

	if strings.HasPrefix(rawPath, "http://") || strings.HasPrefix(rawPath, "https://") {
		finalURL = rawPath
		if u, err := url.Parse(rawPath); err == nil {
			scheme = u.Scheme
			hostHeader = u.Host
			cleanPath = u.Path
			for qk, qv := range u.Query() {
				if len(qv) > 0 {
					queryParams[qk] = qv[0]
				}
			}
		}
	} else {
		// Normal path format
		cleanPath = rawPath
		if qIdx := strings.Index(rawPath, "?"); qIdx != -1 {
			cleanPath = rawPath[:qIdx]
			queryString := rawPath[qIdx+1:]
			if vals, err := url.ParseQuery(queryString); err == nil {
				for qk, qv := range vals {
					if len(qv) > 0 {
						queryParams[qk] = qv[0]
					}
				}
			}
		}
		if hostHeader != "" {
			finalURL = fmt.Sprintf("%s://%s%s", scheme, hostHeader, rawPath)
		} else {
			finalURL = rawPath
		}
	}

	bodyStr := string(bodyBytes)

	// 3. Parse Body Parameters (if application/x-www-form-urlencoded or plain key=value)
	postParams := make(map[string]string)
	if bodyStr != "" {
		if vals, err := url.ParseQuery(bodyStr); err == nil && len(vals) > 0 {
			for pk, pv := range vals {
				if len(pv) > 0 {
					postParams[pk] = pv[0]
				}
			}
		}
	}

	// 4. Check for FUZZ or * injection points
	hasFuzz := strings.Contains(finalURL, "FUZZ") || strings.Contains(finalURL, "*") ||
		strings.Contains(bodyStr, "FUZZ") || strings.Contains(bodyStr, "*")
	for _, v := range headers {
		if strings.Contains(v, "FUZZ") || strings.Contains(v, "*") {
			hasFuzz = true
			break
		}
	}

	return &RawRequest{
		Method:       method,
		Path:         cleanPath,
		HTTPVersion:  httpVersion,
		Host:         hostHeader,
		Scheme:       scheme,
		FullURL:      finalURL,
		Headers:      headers,
		Cookie:       cookieHeader,
		Body:         bodyStr,
		QueryParams:  queryParams,
		PostParams:   postParams,
		HasFuzzPoint: hasFuzz,
	}, nil
}

// ParseRawRequestFile reads a file and parses it as a RawRequest.
func ParseRawRequestFile(filePath string, isHTTPS bool) (*RawRequest, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("could not read request file %s: %w", filePath, err)
	}
	return ParseRawRequest(data, isHTTPS)
}

// ToTarget converts a parsed RawRequest into a Target struct for vulnerability assessment modules.
func (r *RawRequest) ToTarget() *modules.Target {
	baseURL := r.FullURL
	if qIdx := strings.Index(baseURL, "?"); qIdx != -1 {
		baseURL = baseURL[:qIdx]
	}

	return &modules.Target{
		URL:     baseURL,
		Method:  r.Method,
		Params:  r.QueryParams,
		Data:    r.PostParams,
		Headers: r.Headers,
	}
}
