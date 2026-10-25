package race

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RaceConfig sets up the parameters for a race condition attack.
type RaceConfig struct {
	URL        string
	Method     string
	Body       string
	Headers    map[string]string
	Threads    int           // Parallel requests (default: 20)
	Rounds     int           // Repetitions (default: 1)
	Timeout    time.Duration // Per-request timeout
	Insecure   bool
}

// RaceResult holds output from a single burst request.
type RaceResult struct {
	Index      int
	StatusCode int
	BodyHash   string
	BodyLen    int
	Duration   time.Duration
	Error      error
}

// RaceReport details the statistical outcome of the race burst.
type RaceReport struct {
	TotalRequests    int            `json:"total_requests"`
	UniqueStatuses   map[int]int    `json:"unique_statuses"`
	UniqueBodyHashes map[string]int `json:"unique_body_hashes"`
	AnomalyDetected  bool           `json:"anomaly_detected"`
	AnomalyReason    string         `json:"anomaly_reason"`
	Results          []RaceResult   `json:"results"`
}

// Run executes the nanosecond-synchronized race attack.
func Run(cfg RaceConfig) (*RaceReport, error) {
	if cfg.Threads <= 0 {
		cfg.Threads = 20
	}
	if cfg.Rounds <= 0 {
		cfg.Rounds = 1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Method == "" {
		cfg.Method = "POST"
	}

	transport := &http.Transport{
		MaxIdleConns:        cfg.Threads * 2,
		MaxIdleConnsPerHost: cfg.Threads * 2,
		MaxConnsPerHost:     cfg.Threads * 2,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.Insecure},
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}

	report := &RaceReport{
		UniqueStatuses:   make(map[int]int),
		UniqueBodyHashes: make(map[string]int),
		Results:          make([]RaceResult, 0, cfg.Threads*cfg.Rounds),
	}

	for r := 0; r < cfg.Rounds; r++ {
		// Pre-create HTTP requests to eliminate preparation overhead
		reqs := make([]*http.Request, cfg.Threads)
		for i := 0; i < cfg.Threads; i++ {
			var bodyReader io.Reader
			if cfg.Body != "" {
				bodyReader = strings.NewReader(cfg.Body)
			}
			req, err := http.NewRequest(cfg.Method, cfg.URL, bodyReader)
			if err != nil {
				return nil, err
			}
			for k, v := range cfg.Headers {
				req.Header.Set(k, v)
			}
			req.Header.Set("User-Agent", "NightfallLX-Race/2.0")
			reqs[i] = req
		}

		// Gate synchronization channel: all workers block until gate closes
		gate := make(chan struct{})
		resultsChan := make(chan RaceResult, cfg.Threads)
		var wg sync.WaitGroup

		for i := 0; i < cfg.Threads; i++ {
			wg.Add(1)
			go func(idx int, req *http.Request) {
				defer wg.Done()
				<-gate // Block until instant release

				start := time.Now()
				resp, err := httpClient.Do(req)
				elapsed := time.Since(start)

				if err != nil {
					resultsChan <- RaceResult{
						Index:    idx,
						Error:    err,
						Duration: elapsed,
					}
					return
				}
				defer resp.Body.Close()

				bodyBytes, _ := io.ReadAll(resp.Body)
				h := sha256.Sum256(bodyBytes)
				hashStr := hex.EncodeToString(h[:])

				resultsChan <- RaceResult{
					Index:      idx,
					StatusCode: resp.StatusCode,
					BodyHash:   hashStr[:8],
					BodyLen:    len(bodyBytes),
					Duration:   elapsed,
				}
			}(i, reqs[i])
		}

		// Instant release across all goroutines
		close(gate)
		wg.Wait()
		close(resultsChan)

		for res := range resultsChan {
			report.TotalRequests++
			report.Results = append(report.Results, res)
			if res.Error == nil {
				report.UniqueStatuses[res.StatusCode]++
				report.UniqueBodyHashes[res.BodyHash]++
			}
		}
	}

	// Analyze for race condition anomalies with false-positive filtering
	uniqueLengths := make(map[int]int)
	for _, res := range report.Results {
		if res.Error == nil {
			uniqueLengths[res.BodyLen]++
		}
	}

	if len(report.UniqueStatuses) > 1 {
		report.AnomalyDetected = true
		var statSummary []string
		for code, count := range report.UniqueStatuses {
			statSummary = append(statSummary, fmt.Sprintf("%d (%dx)", code, count))
		}
		report.AnomalyReason = fmt.Sprintf("Non-deterministic status codes detected: %s. Indicates limit bypass or concurrency collision.", strings.Join(statSummary, ", "))
	} else if len(report.UniqueBodyHashes) > 1 {
		// If every request has a unique hash but identical byte length, it's likely a dynamic timestamp/CSRF nonce
		isLikelyDynamicToken := len(report.UniqueBodyHashes) == report.TotalRequests && len(uniqueLengths) == 1
		if isLikelyDynamicToken {
			report.AnomalyDetected = false
			report.AnomalyReason = fmt.Sprintf("Response bodies varied (%d hashes) but lengths were strictly identical (%d bytes). Suspected dynamic timestamp/nonce; no race condition inferred.", len(report.UniqueBodyHashes), report.Results[0].BodyLen)
		} else {
			report.AnomalyDetected = true
			if len(uniqueLengths) > 1 {
				report.AnomalyReason = fmt.Sprintf("Race collision detected: %d distinct body variants with differing response sizes (%d length variations) across %d identical burst requests.", len(report.UniqueBodyHashes), len(uniqueLengths), report.TotalRequests)
			} else {
				report.AnomalyReason = fmt.Sprintf("%d discrete response variants observed among %d identical burst requests.", len(report.UniqueBodyHashes), report.TotalRequests)
			}
		}
	}

	return report, nil
}
