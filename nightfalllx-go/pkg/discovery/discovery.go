package discovery

import (
	"fmt"
	"math"
	"net/url"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/modules"
	"strings"
	"time"
)

type Config struct {
	BatchSize int
	Delay     time.Duration
}

type ParameterDiscovery struct {
	Config Config
}

func NewParameterDiscovery(batchSize int) *ParameterDiscovery {
	if batchSize <= 0 {
		batchSize = 50
	}
	return &ParameterDiscovery{
		Config: Config{
			BatchSize: batchSize,
		},
	}
}

// Discover tests a wordlist of parameter names against target and returns discovered hidden parameters.
func (pd *ParameterDiscovery) Discover(target *modules.Target, c *client.Client, words []string) ([]string, error) {
	if len(words) == 0 {
		return nil, nil
	}

	isPost := strings.ToUpper(target.Method) == "POST"

	// 1. Establish stable baseline
	var baseResp *client.Response
	var err error
	if isPost {
		baseResp, err = c.Request("POST", target.URL, "", nil)
	} else {
		baseResp, err = c.Request("GET", target.URL, "", nil)
	}
	if err != nil || baseResp == nil {
		return nil, fmt.Errorf("failed to fetch baseline for parameter discovery: %w", err)
	}

	// 2. Establish dummy baseline to check behavior when benign parameters are present
	dummyBatch := []string{"nflx_rand_dummy_a1", "nflx_rand_dummy_b2", "nflx_rand_dummy_c3"}
	dummyResp, _ := pd.sendBatch(target, c, isPost, dummyBatch)
	if dummyResp != nil {
		// Use dummy baseline if it is stable
		baseResp = dummyResp
	}

	var discovered []string
	discoveredMap := make(map[string]bool)

	// Process in batches
	for i := 0; i < len(words); i += pd.Config.BatchSize {
		end := i + pd.Config.BatchSize
		if end > len(words) {
			end = len(words)
		}
		chunk := words[i:end]

		resp, err := pd.sendBatch(target, c, isPost, chunk)
		if err != nil || resp == nil {
			continue
		}

		if isAnomalous(baseResp, resp) {
			// Anomaly detected in batch -> bisect to isolate exact parameter(s)
			hits := pd.bisect(target, c, isPost, baseResp, chunk)
			for _, hit := range hits {
				if !discoveredMap[hit] {
					discoveredMap[hit] = true
					discovered = append(discovered, hit)
				}
			}
		}
	}

	return discovered, nil
}

func (pd *ParameterDiscovery) bisect(target *modules.Target, c *client.Client, isPost bool, baseline *client.Response, batch []string) []string {
	if len(batch) == 0 {
		return nil
	}

	if len(batch) == 1 {
		// Verify single parameter individually
		singleResp, err := pd.sendBatch(target, c, isPost, batch)
		if err == nil && singleResp != nil && isAnomalous(baseline, singleResp) {
			return batch
		}
		return nil
	}

	mid := len(batch) / 2
	left := batch[:mid]
	right := batch[mid:]

	var hits []string

	leftResp, errLeft := pd.sendBatch(target, c, isPost, left)
	if errLeft == nil && leftResp != nil && isAnomalous(baseline, leftResp) {
		hits = append(hits, pd.bisect(target, c, isPost, baseline, left)...)
	}

	rightResp, errRight := pd.sendBatch(target, c, isPost, right)
	if errRight == nil && rightResp != nil && isAnomalous(baseline, rightResp) {
		hits = append(hits, pd.bisect(target, c, isPost, baseline, right)...)
	}

	return hits
}

func (pd *ParameterDiscovery) sendBatch(target *modules.Target, c *client.Client, isPost bool, params []string) (*client.Response, error) {
	vals := url.Values{}
	for _, p := range params {
		vals.Set(p, "nflx_probe_1")
	}

	if isPost {
		headers := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}
		return c.Request("POST", target.URL, vals.Encode(), headers)
	}

	u, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	for _, p := range params {
		q.Set(p, "nflx_probe_1")
	}
	u.RawQuery = q.Encode()
	return c.Request("GET", u.String(), "", nil)
}

func isAnomalous(baseline, current *client.Response) bool {
	if baseline.StatusCode != current.StatusCode {
		return true
	}
	if math.Abs(float64(baseline.Bytes-current.Bytes)) > 6 {
		return true
	}
	if math.Abs(float64(baseline.Words-current.Words)) > 2 {
		return true
	}
	if math.Abs(float64(baseline.Lines-current.Lines)) > 1 {
		return true
	}
	if modules.Similarity(baseline.Body, current.Body) < 0.92 {
		return true
	}
	return false
}
