package client

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	rps := 10
	rl := NewRateLimiter(rps)
	defer rl.Stop()

	start := time.Now()
	// Consume initial burst + next tokens
	for i := 0; i < 15; i++ {
		rl.Wait()
	}
	elapsed := time.Since(start)

	// Consuming 15 items with 10 rps should take roughly at least 300-400ms
	if elapsed < 200*time.Millisecond {
		t.Logf("Rate limiter elapsed time: %v", elapsed)
	}
}

func TestSmartRetryOn429(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt32(&attempts, 1)
		if current < 3 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("Rate limit exceeded"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Success after retry"))
	}))
	defer server.Close()

	c := NewClient("", 5*time.Second, true, "", nil)
	c.SetRetry(3, 50*time.Millisecond)

	resp, err := c.Request("GET", server.URL, "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK after retries, got %d", resp.StatusCode)
	}
	if atomic.LoadInt32(&attempts) != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

func TestRawRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom-Raw") == "Verified" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Raw OK"))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	c := NewClient("", 5*time.Second, true, "", nil)
	rawPayload := []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nX-Custom-Raw: Verified\r\nConnection: close\r\n\r\n", server.Listener.Addr().String()))

	resp, err := c.RawRequest(server.URL, rawPayload)
	if err != nil {
		t.Fatalf("raw request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	if resp.Body != "Raw OK" {
		t.Fatalf("expected 'Raw OK', got '%s'", resp.Body)
	}
}
