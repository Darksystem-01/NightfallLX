package race

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func TestRaceGateSync(t *testing.T) {
	var count int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := atomic.AddInt32(&count, 1)
		if val == 1 {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "FIRST_WINNER")
		} else {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "ALREADY_PROCESSED")
		}
	}))
	defer server.Close()

	cfg := RaceConfig{
		URL:     server.URL,
		Method:  "POST",
		Threads: 10,
		Rounds:  1,
	}

	report, err := Run(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.TotalRequests != 10 {
		t.Errorf("expected 10 total requests, got %d", report.TotalRequests)
	}

	if !report.AnomalyDetected {
		t.Errorf("expected anomaly detected due to distinct status codes 200 and 400")
	}

	if report.UniqueStatuses[http.StatusOK] != 1 {
		t.Errorf("expected exactly 1 OK response, got %d", report.UniqueStatuses[http.StatusOK])
	}
}

func TestDeterministicResponses(t *testing.T) {
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "STANDARD_OUTPUT")
	}))
	defer server.Close()

	cfg := RaceConfig{
		URL:     server.URL,
		Method:  "GET",
		Threads: 8,
		Rounds:  1,
	}

	report, err := Run(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if report.AnomalyDetected {
		t.Errorf("expected no anomaly for identical responses")
	}
}
