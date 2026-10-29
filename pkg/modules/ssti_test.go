package modules

import (
	"net/http"
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"strings"
	"testing"
	"time"
)

func TestExtractFormsFromHTML(t *testing.T) {
	htmlSample := `
	<html>
	<body>
	<h2>NoteCraft</h2>
	<form method="POST" action="/preview">
		<input type="text" name="subject" value="Hi {{ first_name }}">
		<textarea name="body">Welcome to {{ company }}.</textarea>
		<button type="submit">Preview Note</button>
	</form>
	</body>
	</html>
	`

	forms := ExtractFormsFromHTML("http://cms.discover.hard/", htmlSample)
	if len(forms) == 0 {
		t.Fatalf("expected at least 1 form extracted, got 0")
	}

	form := forms[0]
	if form.Method != "POST" {
		t.Fatalf("expected POST method, got %s", form.Method)
	}
	if form.Action != "http://cms.discover.hard/preview" {
		t.Fatalf("expected http://cms.discover.hard/preview, got %s", form.Action)
	}
	if _, ok := form.Fields["subject"]; !ok {
		t.Fatalf("expected 'subject' field in form")
	}
	if _, ok := form.Fields["body"]; !ok {
		t.Fatalf("expected 'body' field in form")
	}
	if form.Fields["body"] != "Welcome to {{ company }}." {
		t.Fatalf("expected textarea body content, got %s", form.Fields["body"])
	}
}

func TestSSTIModule_NoteCraftSimulation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			_ = r.ParseForm()
			subject := r.Form.Get("subject")
			body := r.Form.Get("body")

			render := func(s string) string {
				s = strings.ReplaceAll(s, "{{7*7}}", "49")
				s = strings.ReplaceAll(s, "{{ 7*7 }}", "49")
				s = strings.ReplaceAll(s, "{{7*8}}", "56")
				s = strings.ReplaceAll(s, "{{ 7*8 }}", "56")
				return s
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><div class='preview'>Subject: " + render(subject) + "<br>Body: " + render(body) + "</div></html>"))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
		<form method="POST" action="">
			<input type="text" name="subject" value="Hi user">
			<textarea name="body">Welcome note</textarea>
			<button type="submit">Preview</button>
		</form>
		`))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL,
		Method: "POST",
		Data:   map[string]string{"subject": "Hi user", "body": "Welcome note"},
		Params: map[string]string{"subject": "Hi user", "body": "Welcome note"},
	}

	mod := NewSSTIModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("expected SSTI finding for NoteCraft simulation, got 0")
	}

	if !strings.Contains(findings[0].Title, "Server-Side Template Injection") {
		t.Fatalf("expected SSTI title, got %s", findings[0].Title)
	}
}
