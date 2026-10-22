package testdata

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var sleepRegex = regexp.MustCompile(`(?i)(?:SLEEP|pg_sleep)\((\d+)\)`)

func SetupLabMux() *http.ServeMux {
	mux := http.NewServeMux()

	// 1. LFI
	mux.HandleFunc("/vuln/lfi", func(w http.ResponseWriter, r *http.Request) {
		f := r.URL.Query().Get("file")
		if strings.Contains(f, "etc/passwd") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("File not found"))
	})

	// 2. Error-based SQLi
	mux.HandleFunc("/vuln/sqli", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") || strings.Contains(id, "\"") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Database Error: You have an error in your SQL syntax near '' at line 1"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Product details for ID: " + id))
	})

	// 3. JSON SQLi
	mux.HandleFunc("/vuln/json_sqli", func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		body := buf.String()
		if strings.Contains(body, "'") || strings.Contains(body, "AND 1=2") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"syntax error near '1=2' in MySQL statement"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user":{"id":1,"status":"active"}}`))
	})

	// 4. Time-based SQLi
	mux.HandleFunc("/vuln/time_sqli", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		matches := sleepRegex.FindStringSubmatch(id)
		if len(matches) > 1 {
			seconds, _ := strconv.Atoi(matches[1])
			if seconds > 0 && seconds <= 10 {
				time.Sleep(time.Duration(seconds) * time.Second)
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Time record returned."))
	})

	// 5. OAST SSRF (Dispatches HTTP callback)
	mux.HandleFunc("/vuln/oast_ssrf", func(w http.ResponseWriter, r *http.Request) {
		dest := r.URL.Query().Get("url")
		if dest != "" {
			go func() {
				resp, err := http.Get(dest)
				if err == nil {
					_ = resp.Body.Close()
				}
			}()
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Callback dispatched."))
	})

	// 6. GraphQL Introspection
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sBody := string(body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(sBody, "__schema") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User","kind":"OBJECT"}]}}}`))
			return
		}
		if strings.Contains(sBody, "__typename") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":{"__typename":"Query"}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"hello":"world"}}`))
	})

	// 7. JWT alg:none
	mux.HandleFunc("/vuln/jwt", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized"))
			return
		}
		if strings.Contains(auth, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("admin privileges granted via alg:none"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden token"))
	})

	// 8. Parameter Discovery (exact 3 hidden params)
	mux.HandleFunc("/vuln/params", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var found []string
		for _, p := range []string{"admin_key", "debug_mode", "secret_flag"} {
			if q.Get(p) != "" {
				found = append(found, p)
			}
		}
		if len(found) > 0 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("SPECIAL DEBUG OUTPUT REVEALED BY: %s (ANOMALOUS BYTES)", strings.Join(found, ","))))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Standard public landing page without parameters."))
	})

	// 9. Login & Cookie Session
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		u := r.FormValue("user")
		p := r.FormValue("pass")
		if u == "admin" && p == "cyberpass" {
			http.SetCookie(w, &http.Cookie{
				Name:  "sessionid",
				Value: "valid_session_9988",
				Path:  "/",
			})
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"success"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"status":"fail"}`))
	})

	mux.HandleFunc("/protected/profile", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sessionid")
		if err != nil || c.Value != "valid_session_9988" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized access"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome to authenticated admin profile!"))
	})

	// 10. Clean Static Page
	mux.HandleFunc("/clean/page", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Server", "secure-gateway")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!DOCTYPE html><html><body><h1>Safe Static Site</h1><p>No vulnerabilities here.</p></body></html>"))
	})

	// Fuzz endpoint
	mux.HandleFunc("/fuzz/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	return mux
}
