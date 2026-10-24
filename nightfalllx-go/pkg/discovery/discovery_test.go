package discovery

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/modules"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestParameterDiscoveryExactThree(t *testing.T) {
	// Vulnerable fixture server listening for exactly 3 hidden parameters
	hiddenParams := map[string]bool{
		"debug":       true,
		"admin_token": true,
		"system_cmd":  true,
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var triggered []string
		for param := range hiddenParams {
			if q.Get(param) != "" {
				triggered = append(triggered, param)
			}
		}

		if len(triggered) > 0 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("SPECIAL DEBUG DATA TRIGGERED BY: %s (EXTRA CONTENT GENERATED HERE FOR ANOMALY)", strings.Join(triggered, ","))))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Standard public landing page without parameters."))
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &modules.Target{
		URL:    ts.URL,
		Method: "GET",
		Params: make(map[string]string),
	}

	// Wordlist with 100 parameter names including the 3 hidden ones
	var wordlist []string
	for i := 1; i <= 97; i++ {
		wordlist = append(wordlist, fmt.Sprintf("random_param_%d", i))
	}
	// Insert hidden params at different positions
	wordlist = append(wordlist[:15], append([]string{"debug"}, wordlist[15:]...)...)
	wordlist = append(wordlist[:50], append([]string{"admin_token"}, wordlist[50:]...)...)
	wordlist = append(wordlist, "system_cmd")

	pd := NewParameterDiscovery(25) // Batch size 25
	discovered, err := pd.Discover(target, c, wordlist)
	if err != nil {
		t.Fatalf("discovery failed: %v", err)
	}

	sort.Strings(discovered)
	expected := []string{"admin_token", "debug", "system_cmd"}

	if len(discovered) != 3 {
		t.Fatalf("expected exactly 3 discovered parameters, got %d: %v", len(discovered), discovered)
	}

	for i := 0; i < 3; i++ {
		if discovered[i] != expected[i] {
			t.Errorf("at index %d: expected %s, got %s", i, expected[i], discovered[i])
		}
	}
}
