package fuzzer

import (
	"math/rand"
	"sync"
	"time"
)

// AdaptiveConfig tunes the WAF-aware adaptive controller.
type AdaptiveConfig struct {
	// MaxConcurrency is the initial number of in-flight requests (usually the
	// configured thread count).
	MaxConcurrency int
	// MinConcurrency is the floor the controller will never shrink below.
	MinConcurrency int
	// BackoffBase is the first exponential backoff delay.
	BackoffBase time.Duration
	// MaxBackoff caps the exponential delay.
	MaxBackoff time.Duration
	// Jitter adds a random delay in [0, Jitter) to every request to break
	// behavioural rate-limit fingerprints.
	Jitter time.Duration
	// ForbiddenThreshold is how many consecutive 403s trigger a backoff.
	ForbiddenThreshold int
	// RotateUserAgents enables browser User-Agent rotation.
	RotateUserAgents bool
}

// AdaptiveState is a point-in-time snapshot of the controller.
type AdaptiveState struct {
	Concurrency int           `json:"concurrency"`
	InFlight    int           `json:"in_flight"`
	Penalty     time.Duration `json:"penalty"`
	Requests    int64         `json:"requests"`
	RateLimited int64         `json:"rate_limited"`
	Forbidden   int64         `json:"forbidden"`
	Reductions  int64         `json:"reductions"`
}

// BrowserUserAgents are realistic, current desktop and mobile fingerprints used
// to rotate the scanner identity.
var BrowserUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
}

const recoverySuccesses = 10

// AdaptiveController throttles concurrency and injects delay/identity changes
// in response to WAF rate limiting and blocking.
type AdaptiveController struct {
	cfg  AdaptiveConfig
	mu   sync.Mutex
	cond *sync.Cond

	limit           int
	inFlight        int
	penalty         time.Duration
	forbiddenStreak int
	successStreak   int

	rng   *rand.Rand
	uaIdx int

	requests    int64
	rateLimited int64
	forbidden   int64
	reductions  int64
}

// NewAdaptiveController builds a controller, applying sane defaults for any
// unset field.
func NewAdaptiveController(cfg AdaptiveConfig) *AdaptiveController {
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = 40
	}
	if cfg.MinConcurrency <= 0 {
		cfg.MinConcurrency = 1
	}
	if cfg.MinConcurrency > cfg.MaxConcurrency {
		cfg.MinConcurrency = cfg.MaxConcurrency
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 250 * time.Millisecond
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 15 * time.Second
	}
	if cfg.MaxBackoff < cfg.BackoffBase {
		cfg.MaxBackoff = cfg.BackoffBase
	}
	if cfg.ForbiddenThreshold <= 0 {
		cfg.ForbiddenThreshold = 3
	}
	if cfg.Jitter < 0 {
		cfg.Jitter = 0
	}

	a := &AdaptiveController{
		cfg:   cfg,
		limit: cfg.MaxConcurrency,
		rng:   rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	a.cond = sync.NewCond(&a.mu)
	return a
}

// Acquire reserves a concurrency slot, blocking while the adaptive limit is
// reached. It then sleeps the current penalty plus random jitter.
func (a *AdaptiveController) Acquire() {
	a.mu.Lock()
	for a.inFlight >= a.limit {
		a.cond.Wait()
	}
	a.inFlight++

	delay := a.penalty
	if a.cfg.Jitter > 0 {
		delay += time.Duration(a.rng.Int63n(int64(a.cfg.Jitter)))
	}
	a.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}
}

// Release frees a concurrency slot.
func (a *AdaptiveController) Release() {
	a.mu.Lock()
	if a.inFlight > 0 {
		a.inFlight--
	}
	a.mu.Unlock()
	a.cond.Signal()
}

// Observe feeds a response status back into the controller. 429 and repeated
// 403 responses trigger exponential backoff and lower concurrency; healthy
// responses slowly restore capacity.
func (a *AdaptiveController) Observe(status int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.requests++
	switch {
	case status == 429:
		a.rateLimited++
		a.forbiddenStreak = 0
		a.successStreak = 0
		a.penalty = a.nextPenalty()
		a.reduceLocked()
	case status == 403:
		a.forbidden++
		a.successStreak = 0
		a.forbiddenStreak++
		if a.forbiddenStreak >= a.cfg.ForbiddenThreshold {
			a.forbiddenStreak = 0
			a.penalty = a.nextPenalty()
			a.reduceLocked()
		}
	case status >= 200 && status < 400:
		a.successStreak++
		a.forbiddenStreak = 0
		if a.successStreak >= recoverySuccesses {
			a.successStreak = 0
			a.recoverLocked()
		}
	}
}

// nextPenalty doubles the current delay up to MaxBackoff. Caller holds mu.
func (a *AdaptiveController) nextPenalty() time.Duration {
	if a.penalty <= 0 {
		return a.cfg.BackoffBase
	}
	p := a.penalty * 2
	if p > a.cfg.MaxBackoff {
		p = a.cfg.MaxBackoff
	}
	return p
}

// reduceLocked halves the concurrency limit. Caller holds mu.
func (a *AdaptiveController) reduceLocked() {
	newLimit := a.limit / 2
	if newLimit < a.cfg.MinConcurrency {
		newLimit = a.cfg.MinConcurrency
	}
	if newLimit < a.limit {
		a.limit = newLimit
		a.reductions++
	}
	a.cond.Broadcast()
}

// recoverLocked halves the penalty and restores one concurrency slot after a
// run of healthy responses. Caller holds mu.
func (a *AdaptiveController) recoverLocked() {
	if a.penalty > 0 {
		a.penalty /= 2
		if a.penalty < a.cfg.BackoffBase/4 {
			a.penalty = 0
		}
	}
	if a.limit < a.cfg.MaxConcurrency {
		a.limit++
		a.cond.Broadcast()
	}
}

// UserAgent returns the next rotated browser User-Agent, or "" when rotation is
// disabled.
func (a *AdaptiveController) UserAgent() string {
	if !a.cfg.RotateUserAgents {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	ua := BrowserUserAgents[a.uaIdx%len(BrowserUserAgents)]
	a.uaIdx++
	return ua
}

// Snapshot returns the current controller state.
func (a *AdaptiveController) Snapshot() AdaptiveState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return AdaptiveState{
		Concurrency: a.limit,
		InFlight:    a.inFlight,
		Penalty:     a.penalty,
		Requests:    a.requests,
		RateLimited: a.rateLimited,
		Forbidden:   a.forbidden,
		Reductions:  a.reductions,
	}
}

// Limit returns the current concurrency limit.
func (a *AdaptiveController) Limit() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.limit
}

// Penalty returns the current backoff delay.
func (a *AdaptiveController) Penalty() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.penalty
}
