package xss

import (
	"fmt"
	"net/url"
	"nightfalllx/pkg/client"
	"regexp"
	"strings"
	"golang.org/x/net/html"
)

// HTMLForm represents a parsed HTML <form>.
type HTMLForm struct {
	Action    string            `json:"action"`
	Method    string            `json:"method"`
	Inputs    map[string]string `json:"inputs"`
	CSRFField string            `json:"csrf_field,omitempty"`
	OriginURL string            `json:"origin_url"`
}

var csrfNames = []string{
	"csrf", "token", "_token", "authenticity_token", "nonce", "xsrf", "form_key", "security_token",
}

// ParseForms extracts all <form> elements and their inputs from HTML.
func ParseForms(pageHTML, pageURL string) []*HTMLForm {
	var forms []*HTMLForm

	doc, err := html.Parse(strings.NewReader(pageHTML))
	if err != nil {
		return forms
	}

	base, _ := url.Parse(pageURL)

	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n == nil {
			return
		}

		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "form") {
			form := &HTMLForm{
				Method:    "GET",
				Inputs:    make(map[string]string),
				OriginURL: pageURL,
			}

			for _, a := range n.Attr {
				if strings.EqualFold(a.Key, "action") {
					actionVal := strings.TrimSpace(a.Val)
					if base != nil && actionVal != "" {
						if resolved, errRes := base.Parse(actionVal); errRes == nil {
							form.Action = resolved.String()
						} else {
							form.Action = actionVal
						}
					} else if actionVal != "" {
						form.Action = actionVal
					} else {
						form.Action = pageURL
					}
				} else if strings.EqualFold(a.Key, "method") {
					form.Method = strings.ToUpper(strings.TrimSpace(a.Val))
				}
			}
			if form.Action == "" {
				form.Action = pageURL
			}

			// Traverse form children to extract <input>, <textarea>, <button>, <select>
			var extractInputs func(child *html.Node)
			extractInputs = func(child *html.Node) {
				if child == nil {
					return
				}
				if child.Type == html.ElementNode {
					tag := strings.ToLower(child.Data)
					if tag == "input" || tag == "textarea" || tag == "select" || tag == "button" {
						var name, val, iType string
						for _, a := range child.Attr {
							switch strings.ToLower(a.Key) {
							case "name":
								name = strings.TrimSpace(a.Val)
							case "value":
								val = a.Val
							case "type":
								iType = strings.ToLower(strings.TrimSpace(a.Val))
							}
						}
						if name != "" {
							form.Inputs[name] = val
							// Detect CSRF tokens
							if iType == "hidden" || form.CSRFField == "" {
								for _, cName := range csrfNames {
									if strings.Contains(strings.ToLower(name), cName) {
										form.CSRFField = name
										break
									}
								}
							}
						}
					}
				}
				for c := child.FirstChild; c != nil; c = c.NextSibling {
					extractInputs(c)
				}
			}

			extractInputs(n)
			forms = append(forms, form)
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}

	walk(doc)
	return forms
}

// RefreshCSRFToken re-fetches OriginURL to obtain an updated CSRF token before form submission.
func RefreshCSRFToken(form *HTMLForm, c *client.Client) error {
	if form.CSRFField == "" || form.OriginURL == "" || c == nil {
		return nil
	}

	resp, err := c.Get(form.OriginURL)
	if err != nil {
		return err
	}

	latestForms := ParseForms(resp.Body, form.OriginURL)
	for _, lf := range latestForms {
		if lf.Action == form.Action || len(latestForms) == 1 {
			if latestVal, ok := lf.Inputs[form.CSRFField]; ok && latestVal != "" {
				form.Inputs[form.CSRFField] = latestVal
				return nil
			}
		}
	}

	// Fallback regex scan for the csrf token
	tokenPattern := regexp.MustCompile(fmt.Sprintf(`(?i)name=["']%s["'][^>]*value=["']([^"']+)["']`, regexp.QuoteMeta(form.CSRFField)))
	m := tokenPattern.FindStringSubmatch(resp.Body)
	if len(m) > 1 {
		form.Inputs[form.CSRFField] = m[1]
		return nil
	}

	return nil
}

// SubmitForm executes an HTTP request submitting the form with an injected payload in the given parameter.
func SubmitForm(form *HTMLForm, testParam, payload string, c *client.Client) (*client.Response, error) {
	if form.CSRFField != "" && testParam != form.CSRFField {
		_ = RefreshCSRFToken(form, c)
	}

	data := make(map[string]string)
	for k, v := range form.Inputs {
		data[k] = v
	}
	data[testParam] = payload

	if form.Method == "POST" {
		return c.Post(form.Action, data)
	}

	// GET Form
	u, err := url.Parse(form.Action)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	for k, v := range data {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return c.Get(u.String())
}

// StoredFinding records a confirmed or probable stored XSS indicator.
type StoredFinding struct {
	FormAction string `json:"form_action"`
	Parameter  string `json:"parameter"`
	Canary     string `json:"canary"`
	FoundAtURL string `json:"found_at_url"`
	Confidence string `json:"confidence"`
	Proof      string `json:"proof"`
	Detail     string `json:"detail"`
}

// CheckStoredXSS submits a unique canary into each form parameter and checks crawled URLs to identify persistent reflection.
func CheckStoredXSS(forms []*HTMLForm, crawlURLs []string, c *client.Client) ([]*StoredFinding, error) {
	var findings []*StoredFinding

	for _, form := range forms {
		for param := range form.Inputs {
			if param == form.CSRFField {
				continue
			}

			canary := RandomToken("lxst", 8)
			payload := fmt.Sprintf("<script>/*%s*/alert(1)</script>", canary)

			// Submit payload
			_, err := SubmitForm(form, param, payload, c)
			if err != nil {
				continue
			}

			// Scan the form's origin page and crawl URLs for the canary
			checkTargets := append([]string{form.OriginURL, form.Action}, crawlURLs...)
			checkedMap := make(map[string]bool)

			for _, targetURL := range checkTargets {
				if targetURL == "" || checkedMap[targetURL] {
					continue
				}
				checkedMap[targetURL] = true

				resp, errGet := c.Get(targetURL)
				if errGet != nil {
					continue
				}

				if strings.Contains(resp.Body, canary) {
					isExec, proof := CheckExecutableNode(resp.Body, canary)
					confidence := "probable"
					if isExec {
						confidence = "confirmed"
					}

					findings = append(findings, &StoredFinding{
						FormAction: form.Action,
						Parameter:  param,
						Canary:     canary,
						FoundAtURL: targetURL,
						Confidence: confidence,
						Proof:      proof,
						Detail:     fmt.Sprintf("Stored XSS canary %s submitted via %s was stored and reflected at %s. Note: The test marker remains on the target.", canary, form.Action, targetURL),
					})
					break // Once found for this parameter, continue to next parameter
				}
			}
		}
	}

	return findings, nil
}
