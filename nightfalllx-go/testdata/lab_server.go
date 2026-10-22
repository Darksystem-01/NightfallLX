package main

import (
	"fmt"
	"net/http"
	"strings"
)

func main() {
	http.HandleFunc("/vuln/lfi", func(w http.ResponseWriter, r *http.Request) {
		f := r.URL.Query().Get("file")
		if strings.Contains(f, "etc/passwd") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("File not found"))
	})

	http.HandleFunc("/vuln/sqli", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") || strings.Contains(id, "\"") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Database Error: You have an error in your SQL syntax near '' at line 1"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Product details for ID: " + id))
	})

	http.HandleFunc("/clean/page", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Server", "secure-gateway")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!DOCTYPE html><html><body><h1>Welcome to Safe Static Site</h1><p>No vulnerabilities here.</p></body></html>"))
	})

	http.HandleFunc("/fuzz/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	fmt.Println("Local test lab listening on http://127.0.0.1:48123")
	http.ListenAndServe("127.0.0.1:48123", nil)
}
