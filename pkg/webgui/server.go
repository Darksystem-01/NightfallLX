package webgui

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed static/index.html
var indexHTML []byte

type ScanRequest struct {
	Command string `json:"command"`
}

type ScanManager struct {
	mu         sync.Mutex
	cmd        *exec.Cmd
	isRunning  bool
	subscribers map[chan string]bool
}

var manager = &ScanManager{
	subscribers: make(map[chan string]bool),
}

func (sm *ScanManager) broadcast(msg string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for ch := range sm.subscribers {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (sm *ScanManager) subscribe() chan string {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	ch := make(chan string, 100)
	sm.subscribers[ch] = true
	return ch
}

func (sm *ScanManager) unsubscribe(ch chan string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.subscribers, ch)
	close(ch)
}

func (sm *ScanManager) startScan(rawCmd string) error {
	sm.mu.Lock()
	if sm.isRunning && sm.cmd != nil && sm.cmd.Process != nil {
		sm.mu.Unlock()
		return fmt.Errorf("scan is already running")
	}
	sm.mu.Unlock()

	parts := strings.Fields(rawCmd)
	if len(parts) == 0 {
		return fmt.Errorf("empty command")
	}

	bin := parts[0]
	args := parts[1:]

	if bin == "nightfalllx" {
		if path, err := exec.LookPath("nightfalllx"); err == nil {
			bin = path
		} else if _, err := os.Stat("/home/cyborg/.local/bin/nightfalllx"); err == nil {
			bin = "/home/cyborg/.local/bin/nightfalllx"
		} else if _, err := os.Stat("./nightfalllx"); err == nil {
			bin = "./nightfalllx"
		}
	}

	cmd := exec.Command(bin, args...)
	// Set session group to allow killing entire process tree
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	sm.mu.Lock()
	sm.cmd = cmd
	sm.isRunning = true
	sm.mu.Unlock()

	// Stream stdout
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			data, _ := json.Marshal(map[string]string{
				"type": "stdout",
				"line": line,
			})
			sm.broadcast(string(data))
		}
	}()

	// Stream stderr
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			data, _ := json.Marshal(map[string]string{
				"type": "stderr",
				"line": line,
			})
			sm.broadcast(string(data))
		}
	}()

	// Wait for process finish
	go func() {
		err := cmd.Wait()
		code := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				code = exitErr.ExitCode()
			} else {
				code = 1
			}
		}

		sm.mu.Lock()
		sm.isRunning = false
		sm.cmd = nil
		sm.mu.Unlock()

		doneData, _ := json.Marshal(map[string]interface{}{
			"type": "done",
			"code": code,
		})
		sm.broadcast(string(doneData))
	}()

	return nil
}

func (sm *ScanManager) stopScan() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.isRunning && sm.cmd != nil && sm.cmd.Process != nil {
		// Kill entire process group
		_ = syscall.Kill(-sm.cmd.Process.Pid, syscall.SIGKILL)
		sm.isRunning = false
		sm.cmd = nil
	}
}

// StartServer starts the persistent web server on specified host and port.
func StartServer(host string, port int) error {
	if host == "" {
		host = "127.0.0.1"
	}
	if port <= 0 {
		port = 8888
	}

	mux := http.NewServeMux()

	// Serve Frontend
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})

	// API Status
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "running",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"version":   "2.0.0",
		})
	})

	// API Launch Scan
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		if err := manager.startScan(req.Command); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "started",
		})
	})

	// API Stop Scan
	mux.HandleFunc("/api/scan/stop", func(w http.ResponseWriter, r *http.Request) {
		manager.stopScan()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "stopped",
		})
	})

	// API SSE Stream
	mux.HandleFunc("/api/scan/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		ch := manager.subscribe()
		defer manager.unsubscribe(ch)

		notify := r.Context().Done()
		for {
			select {
			case <-notify:
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				fmt.Fprintf(w, "data: %s\n\n", msg)
				flusher.Flush()
			}
		}
	})

	// Serve HTML Reports
	mux.HandleFunc("/reports/", func(w http.ResponseWriter, r *http.Request) {
		fileName := strings.TrimPrefix(r.URL.Path, "/reports/")
		cleanName := filepath.Base(fileName)
		// Check current directory, then /tmp
		candidates := []string{
			cleanName,
			filepath.Join("/tmp", cleanName),
			filepath.Join("/home/cyborg/NightfallLX", cleanName),
		}

		for _, p := range candidates {
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				http.ServeFile(w, r, p)
				return
			}
		}

		http.NotFound(w, r)
	})

	addr := fmt.Sprintf("%s:%d", host, port)
	fmt.Printf("\n\033[1;36m┌──────────────────────────────────────────────────────────────────────────────────┐\033[0m\n")
	fmt.Printf("\033[1;36m│\033[0m \033[1;37m⚡ NightfallLX Web Command Center & Generator Active\033[0m                               \033[1;36m│\033[0m\n")
	fmt.Printf("\033[1;36m│\033[0m URL:         \033[1;32mhttp://%s\033[0m\n", addr)
	fmt.Printf("\033[1;36m│\033[0m Access:      \033[1;33mOpen in browser -> http://127.0.0.1:%d\033[0m\n", port)
	fmt.Printf("\033[1;36m└──────────────────────────────────────────────────────────────────────────────────┘\033[0m\n\n")

	return http.ListenAndServe(addr, mux)
}
