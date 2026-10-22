package oast

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOASTCallbackFlow(t *testing.T) {
	// 1. Start OAST Server on random port
	oastSrv := NewServer("127.0.0.1:0", "", 3*time.Second)
	if err := oastSrv.Start(); err != nil {
		t.Fatalf("failed to start OAST server: %v", err)
	}
	defer oastSrv.Close()

	probeID := oastSrv.GenerateProbeID()
	callbackURL := oastSrv.CallbackURL(probeID)

	// 2. Mock vulnerable endpoint that triggers callback
	vulnSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target != "" {
			go func() {
				// Perform out-of-band request
				_, _ = http.Get(target)
			}()
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fetching background target"))
	}))
	defer vulnSrv.Close()

	// 3. Trigger vulnerable endpoint
	triggerURL := fmt.Sprintf("%s/?url=%s", vulnSrv.URL, callbackURL)
	resp, err := http.Get(triggerURL)
	if err != nil {
		t.Fatalf("failed to call vuln server: %v", err)
	}
	resp.Body.Close()

	// 4. Verify OAST hit
	hit, ok := oastSrv.WaitForHit(probeID, 3*time.Second)
	if !ok || hit == nil {
		t.Fatalf("expected OAST callback for probe %s, but timed out", probeID)
	}

	if hit.ID != probeID {
		t.Fatalf("expected hit ID %s, got %s", probeID, hit.ID)
	}

	// 5. Negative test: Probe that is never called should time out
	ghostProbe := oastSrv.GenerateProbeID()
	ghostHit, ghostOk := oastSrv.WaitForHit(ghostProbe, 100*time.Millisecond)
	if ghostOk || ghostHit != nil {
		t.Fatalf("expected timeout for ghost probe, but got a hit")
	}
}
