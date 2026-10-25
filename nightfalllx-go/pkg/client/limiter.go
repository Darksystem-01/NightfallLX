package client

import (
	"sync"
	"time"
)

// RateLimiter enforces a maximum request rate per second using a token bucket.
type RateLimiter struct {
	rate    int
	ch      chan struct{}
	ticker  *time.Ticker
	stopCh  chan struct{}
	stopped bool
	mu      sync.Mutex
}

// NewRateLimiter initializes a RateLimiter with the given requests per second.
// If rate <= 0, returns nil (unlimited).
func NewRateLimiter(rate int) *RateLimiter {
	if rate <= 0 {
		return nil
	}

	burst := rate
	if burst > 100 {
		burst = 100
	}
	if burst < 1 {
		burst = 1
	}

	ch := make(chan struct{}, burst)
	for i := 0; i < burst; i++ {
		ch <- struct{}{}
	}

	interval := time.Second / time.Duration(rate)
	if interval < time.Microsecond {
		interval = time.Microsecond
	}

	ticker := time.NewTicker(interval)
	stopCh := make(chan struct{})

	rl := &RateLimiter{
		rate:   rate,
		ch:     ch,
		ticker: ticker,
		stopCh: stopCh,
	}

	go func() {
		for {
			select {
			case <-ticker.C:
				select {
				case rl.ch <- struct{}{}:
				default:
				}
			case <-stopCh:
				ticker.Stop()
				return
			}
		}
	}()

	return rl
}

// Wait blocks until a token is available or does nothing if rl is nil.
func (rl *RateLimiter) Wait() {
	if rl == nil {
		return
	}
	<-rl.ch
}

// Stop terminates the background ticker goroutine.
func (rl *RateLimiter) Stop() {
	if rl == nil {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if !rl.stopped {
		rl.stopped = true
		close(rl.stopCh)
	}
}
