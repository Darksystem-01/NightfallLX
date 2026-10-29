package modules

import (
	"net/http"
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"strings"
	"testing"
	"time"
)

func TestIDORModule_MultiIDDiscovery(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ticket/4211":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><h1>Ticket #4211</h1><p>Customer Order Status: Pending</p></html>"))
		case "/ticket/4210":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><h1>Ticket #4210</h1><p>Refund on order #A-2231</p></html>"))
		case "/ticket/4200":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><h1>Ticket #4200</h1><p>Confidential Flag: IDOR{h0r1z0nt4l_4cc3ss_succ3ss}</p></html>"))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not found"))
		}
	}))
	defer ts.Close()

	c := client.NewClient("", 2*time.Second, true, "", nil)
	target := &Target{
		URL:    ts.URL + "/ticket/4211",
		Method: "GET",
		Params: map[string]string{"ticket": "4211"},
	}

	mod := NewIDORModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 IDOR findings (for 4210 and 4200), got %d", len(findings))
	}

	found4210 := false
	found4200 := false
	for _, f := range findings {
		if f.Payload == "4210" {
			found4210 = true
		}
		if f.Payload == "4200" && strings.Contains(f.Evidence, "IDOR{h0r1z0nt4l_4cc3ss_succ3ss}") {
			found4200 = true
			if f.Severity != SeverityCritical {
				t.Fatalf("expected 4200 flag finding to have SeverityCritical, got %s", f.Severity)
			}
		}
	}

	if !found4210 {
		t.Fatalf("expected finding for ticket #4210")
	}
	if !found4200 {
		t.Fatalf("expected finding with flag for ticket #4200")
	}
}
