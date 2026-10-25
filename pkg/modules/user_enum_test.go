package modules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"testing"
	"time"
)

func TestUserEnumModule(t *testing.T) {
	// Setup mock auth server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		username := r.FormValue("username")

		w.Header().Set("Content-Type", "application/json")
		if username == "admin" || username == "root" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"status":"error","message":"Password incorrect for user account"}`)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"error","message":"Username not found in database"}`)
	}))
	defer ts.Close()

	c := client.NewClient("", 5*time.Second, false, "", nil)
	target := &Target{
		URL:    ts.URL + "/login",
		Method: "POST",
		Data: map[string]string{
			"username": "FUZZ",
			"password": "dummyPassword123",
		},
	}

	mod := NewUserEnumModule()
	findings, err := mod.Run(target, c)
	if err != nil {
		t.Fatalf("UserEnumModule failed with error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("Expected user enumeration finding, got 0")
	}

	f := findings[0]
	if f.Payload != "admin" && f.Payload != "root" {
		t.Errorf("Expected payload 'admin' or 'root', got '%s'", f.Payload)
	}
	if f.Severity != SeverityMedium {
		t.Errorf("Expected MEDIUM severity, got %v", f.Severity)
	}
	t.Logf("✅ Successfully discovered username '%s' with evidence:\n%s", f.Payload, f.Evidence)
}
