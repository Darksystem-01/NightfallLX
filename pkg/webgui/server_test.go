package webgui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebGUIServing(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = rw.Write(indexHTML)
	})

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	body := w.Body.String()
	if !strings.Contains(body, "NightfallLX Command Center") {
		t.Errorf("Expected body to contain title, got: %s", body[:100])
	}
	if !strings.Contains(body, "Generated Terminal Command") {
		t.Errorf("Expected body to contain command box")
	}
}
