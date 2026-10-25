package fuzzer

import (
	"testing"
	"time"
)

func TestAdaptiveDefaults(t *testing.T) {
	a := NewAdaptiveController(AdaptiveConfig{MaxConcurrency: 8, MinConcurrency: 2})
	if a.Limit() != 8 {
		t.Fatalf("initial limit = %d, want 8", a.Limit())
	}
	if a.Penalty() != 0 {
		t.Fatalf("initial penalty = %v, want 0", a.Penalty())
	}

	// Min > Max must be clamped.
	b := NewAdaptiveController(AdaptiveConfig{MaxConcurrency: 2, MinConcurrency: 10})
	if b.Limit() != 2 {
		t.Fatalf("clamped limit = %d, want 2", b.Limit())
	}
}

func TestAdaptiveBackoffOn429(t *testing.T) {
	a := NewAdaptiveController(AdaptiveConfig{
		MaxConcurrency: 8,
		MinConcurrency: 2,
		BackoffBase:    10 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
	})

	a.Observe(429)
	if a.Limit() != 4 {
		t.Fatalf("limit after 429 = %d, want 4", a.Limit())
	}
	if a.Penalty() != 10*time.Millisecond {
		t.Fatalf("penalty = %v, want 10ms", a.Penalty())
	}

	a.Observe(429)
	if a.Limit() != 2 {
		t.Fatalf("limit after second 429 = %d, want 2", a.Limit())
	}
	if a.Penalty() != 20*time.Millisecond {
		t.Fatalf("penalty = %v, want 20ms", a.Penalty())
	}

	// Never below the floor, penalty capped.
	for i := 0; i < 10; i++ {
		a.Observe(429)
	}
	if a.Limit() != 2 {
		t.Fatalf("limit floor violated: %d", a.Limit())
	}
	if a.Penalty() > 100*time.Millisecond {
		t.Fatalf("penalty cap violated: %v", a.Penalty())
	}
}

func TestAdaptiveForbiddenThreshold(t *testing.T) {
	a := NewAdaptiveController(AdaptiveConfig{
		MaxConcurrency:     16,
		MinConcurrency:     1,
		BackoffBase:        5 * time.Millisecond,
		MaxBackoff:         50 * time.Millisecond,
		ForbiddenThreshold: 3,
	})

	// Two 403s must not trip the breaker.
	a.Observe(403)
	a.Observe(403)
	if a.Limit() != 16 {
		t.Fatalf("limit changed too early: %d", a.Limit())
	}

	a.Observe(403)
	if a.Limit() != 8 {
		t.Fatalf("limit after threshold = %d, want 8", a.Limit())
	}
	if a.Penalty() != 5*time.Millisecond {
		t.Fatalf("penalty after 403 = %v", a.Penalty())
	}
}

func TestAdaptiveRecovery(t *testing.T) {
	a := NewAdaptiveController(AdaptiveConfig{
		MaxConcurrency: 8,
		MinConcurrency: 1,
		BackoffBase:    8 * time.Millisecond,
		MaxBackoff:     64 * time.Millisecond,
	})

	a.Observe(429) // limit 4, penalty 8ms
	for i := 0; i < recoverySuccesses; i++ {
		a.Observe(200)
	}
	if a.Limit() != 5 {
		t.Fatalf("limit after recovery = %d, want 5", a.Limit())
	}
	if a.Penalty() != 4*time.Millisecond {
		t.Fatalf("penalty after recovery = %v, want 4ms", a.Penalty())
	}
}

func TestAdaptiveUserAgentRotation(t *testing.T) {
	a := NewAdaptiveController(AdaptiveConfig{MaxConcurrency: 4, RotateUserAgents: true})

	seen := make(map[string]bool)
	for i := 0; i < len(BrowserUserAgents); i++ {
		ua := a.UserAgent()
		if ua == "" {
			t.Fatal("empty user agent")
		}
		seen[ua] = true
	}
	if len(seen) != len(BrowserUserAgents) {
		t.Fatalf("rotation repeated too early: %d unique", len(seen))
	}

	off := NewAdaptiveController(AdaptiveConfig{MaxConcurrency: 4})
	if off.UserAgent() != "" {
		t.Fatal("UA returned while rotation disabled")
	}
}

func TestAdaptiveAcquireBlocksAtLimit(t *testing.T) {
	a := NewAdaptiveController(AdaptiveConfig{MaxConcurrency: 1, MinConcurrency: 1})

	a.Acquire()
	acquired := make(chan struct{})
	go func() {
		a.Acquire()
		close(acquired)
	}()

	select {
	case <-acquired:
		t.Fatal("second Acquire bypassed the concurrency limit")
	case <-time.After(60 * time.Millisecond):
	}

	a.Release()
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("Acquire stayed blocked after Release")
	}
	a.Release()
}

func TestFuzzerAdaptiveIntegration(t *testing.T) {
	cfg := &Config{
		URL:                "http://127.0.0.1:1/FUZZ",
		Wordlist:           []string{"a"},
		Threads:            2,
		Adaptive:           true,
		AdaptiveJitter:     time.Millisecond,
		RotateUserAgent:    true,
		AdaptiveMinThreads: 1,
	}
	f := NewFuzzer(cfg)
	if f.adaptive == nil {
		t.Fatal("adaptive controller not initialised")
	}
	if f.adaptive.Limit() != 2 {
		t.Fatalf("limit = %d, want 2", f.adaptive.Limit())
	}
}
