package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"
	"time"
)

func TestClientLoginAndAutoRelogin(t *testing.T) {
	loginAttempts := 0
	sessionValid := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			loginAttempts++
			user := r.FormValue("user")
			pass := r.FormValue("pass")
			if user == "admin" && pass == "secret123" {
				sessionValid = true
				http.SetCookie(w, &http.Cookie{
					Name:  "auth_session",
					Value: fmt.Sprintf("sess_%d", loginAttempts),
					Path:  "/",
				})
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status": "login_success"}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.URL.Path == "/protected" {
			c, err := r.Cookie("auth_session")
			if err != nil || !sessionValid || c.Value == "" {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("unauthorized"))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("protected secret data"))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	c := NewClient("", 2*time.Second, true, "", nil)
	c.LoginURL = ts.URL + "/login"
	c.LoginData = "user={{user}}&pass={{pass}}"
	c.LoginUser = "admin"
	c.LoginPass = "secret123"
	c.LoginSuccessStatus = 200
	c.LoginSuccessRegex = regexp.MustCompile(`login_success`)

	// Perform explicit login
	if err := c.PerformLogin(); err != nil {
		t.Fatalf("perform login failed: %v", err)
	}

	// Verify protected request works with cookie jar
	resp, err := c.Request("GET", ts.URL+"/protected", "", nil)
	if err != nil {
		t.Fatalf("protected request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Invalidate session on server to trigger auto-relogin
	sessionValid = false
	resp2, err2 := c.Request("GET", ts.URL+"/protected", "", nil)
	if err2 != nil {
		t.Fatalf("re-login protected request failed: %v", err2)
	}
	if resp2.StatusCode != 200 {
		t.Fatalf("expected auto-relogin to restore status 200, got %d", resp2.StatusCode)
	}
	if loginAttempts < 2 {
		t.Fatalf("expected at least 2 login attempts, got %d", loginAttempts)
	}
}

func TestClientRateLimiting(t *testing.T) {
	reqCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	c := NewClient("", 2*time.Second, true, "", nil)
	c.SetRateLimit(20) // 20 req/sec = 50ms per request

	start := time.Now()
	for i := 0; i < 5; i++ {
		_, _ = c.Request("GET", ts.URL, "", nil)
	}
	elapsed := time.Since(start)

	if elapsed < 150*time.Millisecond {
		t.Fatalf("expected rate limiting to enforce delay, elapsed %v", elapsed)
	}
}

func TestRateLimiterGlobalConcurrent(t *testing.T) {
	limiter := NewRateLimiter(10) // 100ms between requests
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := limiter.WaitContext(context.Background()); err != nil {
				t.Errorf("wait failed: %v", err)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	if elapsed < 280*time.Millisecond {
		t.Fatalf("expected global rate limiting across goroutines, elapsed %v", elapsed)
	}
}

func TestClientContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	c := NewClient("", 5*time.Second, true, "", nil)
	c.SetContext(ctx)
	cancel()

	_, err := c.Get(server.URL)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
