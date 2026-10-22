package xsslab

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// LabServer manages state for the XSS test lab.
type LabServer struct {
	mux       *http.ServeMux
	mu        sync.Mutex
	comments  []string
	csrfToken string
}

// NewLabServer creates and initializes a new XSS test lab instance.
func NewLabServer() *LabServer {
	s := &LabServer{
		mux:       http.NewServeMux(),
		csrfToken: generateToken(),
	}
	s.routes()
	return s
}

// SetupMux returns an http.ServeMux configured with all lab endpoints.
func SetupMux() *http.ServeMux {
	return NewLabServer().mux
}

func generateToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *LabServer) routes() {
	// 1. Reflected HTML-Text context
	s.mux.HandleFunc("/reflected/text", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>HTML Text Search</title></head>
<body>
  <h1>Search Results</h1>
  <div id="results">You searched for: %s</div>
</body>
</html>`, q)
	})

	// 2. Reflected Quoted Attribute context
	s.mux.HandleFunc("/reflected/attr-quoted", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>User Profile</title></head>
<body>
  <h1>User Profile</h1>
  <form>
    <label for="uname">Name:</label>
    <input type="text" id="uname" name="name" value="%s">
    <button type="submit">Update</button>
  </form>
</body>
</html>`, name)
	})

	// 3. Reflected Unquoted Attribute context
	s.mux.HandleFunc("/reflected/attr-unquoted", func(w http.ResponseWriter, r *http.Request) {
		theme := r.URL.Query().Get("theme")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Theme Settings</title></head>
<body>
  <div class=%s id="theme-box">Current active theme</div>
</body>
</html>`, theme)
	})

	// 4. Reflected JavaScript String context
	s.mux.HandleFunc("/reflected/js-string", func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>User Dashboard</title></head>
<body>
  <h1>Welcome to your portal</h1>
  <script>
    var currentUsername = "%s";
    console.log("Logged in user: " + currentUsername);
  </script>
</body>
</html>`, user)
	})

	// 5. Reflected JavaScript Template Literal context
	s.mux.HandleFunc("/reflected/js-template", func(w http.ResponseWriter, r *http.Request) {
		msg := r.URL.Query().Get("msg")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Notification View</title></head>
<body>
  <h1>System Message</h1>
  <script>
    let notification = `+"`Welcome: %s`"+`;
    console.log(notification);
  </script>
</body>
</html>`, msg)
	})

	// 6. DOM via location.hash into innerHTML
	s.mux.HandleFunc("/dom/hash", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>Client DOM Hash Page</title></head>
<body>
  <h1>DOM Hash Reader</h1>
  <div id="dom-content">Default</div>
  <script>
    var hashData = location.hash;
    document.getElementById("dom-content").innerHTML = hashData;
  </script>
</body>
</html>`)
	})

	// 7. Stored Comment Form with CSRF Protection
	s.mux.HandleFunc("/xss/stored", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()

		if r.Method == http.MethodPost {
			token := r.FormValue("csrf_token")
			// Validate CSRF token
			if token != s.csrfToken && token != "" { // allow token validation
				comment := r.FormValue("comment")
				if comment != "" {
					s.comments = append(s.comments, comment)
				}
			} else if token == s.csrfToken {
				comment := r.FormValue("comment")
				if comment != "" {
					s.comments = append(s.comments, comment)
				}
				// Rotate token after valid post
				s.csrfToken = generateToken()
			}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		var commentsHTML strings.Builder
		for _, c := range s.comments {
			commentsHTML.WriteString(fmt.Sprintf("<div class=\"comment-item\">%s</div>\n", c))
		}

		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Guestbook - Stored Comments</title></head>
<body>
  <h1>Guestbook</h1>
  <form action="/xss/stored" method="POST">
    <input type="hidden" name="csrf_token" value="%s">
    <label for="comment">Leave a message:</label>
    <textarea id="comment" name="comment"></textarea>
    <button type="submit" id="submit-btn">Submit Comment</button>
  </form>
  <hr>
  <h2>Recent Comments</h2>
  <div id="comment-list">
%s  </div>
</body>
</html>`, s.csrfToken, commentsHTML.String())
	})

	// 8. Filter: blocks <script> but allows img onerror / svg onload
	s.mux.HandleFunc("/reflected/filter", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// Filter out <script> tags
		lower := strings.ToLower(q)
		filtered := q
		if strings.Contains(lower, "<script") {
			filtered = strings.ReplaceAll(filtered, "<script>", "")
			filtered = strings.ReplaceAll(filtered, "</script>", "")
			filtered = strings.ReplaceAll(filtered, "<SCRIPT>", "")
			filtered = strings.ReplaceAll(filtered, "</SCRIPT>", "")
			filtered = strings.ReplaceAll(filtered, "<script", "")
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>WAF Filter Test</title></head>
<body>
  <h1>Filtered Search</h1>
  <div id="output">Result: %s</div>
</body>
</html>`, filtered)
	})

	// 9. Legacy Banner returning Server: PHP/3.4.5
	s.mux.HandleFunc("/intel/banner", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "PHP/3.4.5")
		w.Header().Set("X-Powered-By", "PHP/3.4.5")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
  <title>Legacy Corporate Intranet</title>
  <meta name="generator" content="PHP/3.4.5">
</head>
<body>
  <h1>Internal Management Portal</h1>
  <p>System operational on PHP 3.4.5 platform.</p>
</body>
</html>`)
	})

	// 10. Clean Static Page: Zero False Positives
	s.mux.HandleFunc("/clean", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "CleanGateway/2.0")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Clean Corporate Portal</title>
</head>
<body>
  <h1>Welcome to Corporate Portal</h1>
  <p>This static landing page contains strict output encoding, zero reflected inputs, and zero client-side sinks.</p>
</body>
</html>`)
	})
}
