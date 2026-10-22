package oast

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Hit records an incoming OAST interaction.
type Hit struct {
	ID         string              `json:"id"`
	Timestamp  time.Time           `json:"timestamp"`
	RemoteAddr string              `json:"remote_addr"`
	Method     string              `json:"method"`
	Path       string              `json:"path"`
	Headers    map[string][]string `json:"headers"`
	RawQuery   string              `json:"raw_query"`
}

// Server provides an in-process OAST HTTP interaction receiver.
type Server struct {
	ListenAddr  string
	PublicHost  string
	WaitTimeout time.Duration

	server   *http.Server
	listener net.Listener
	mu       sync.RWMutex
	hits     map[string][]*Hit
	waiters  map[string][]chan *Hit
}

// NewServer initializes a new OAST server.
func NewServer(listenAddr, publicHost string, waitTimeout time.Duration) *Server {
	if waitTimeout <= 0 {
		waitTimeout = 10 * time.Second
	}
	if publicHost == "" {
		publicHost = listenAddr
	}
	return &Server{
		ListenAddr:  listenAddr,
		PublicHost:  publicHost,
		WaitTimeout: waitTimeout,
		hits:        make(map[string][]*Hit),
		waiters:     make(map[string][]chan *Hit),
	}
}

// Start launches the OAST HTTP listener.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return err
	}
	s.listener = ln
	s.ListenAddr = ln.Addr().String()
	if s.PublicHost == "" || strings.HasSuffix(s.PublicHost, ":0") {
		s.PublicHost = s.ListenAddr
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleCallback)

	s.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	go func() {
		_ = s.server.Serve(ln)
	}()
	return nil
}

// Close gracefully stops the OAST listener.
func (s *Server) Close() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

// GenerateProbeID creates a unique 16-hex character probe identifier.
func (s *Server) GenerateProbeID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// CallbackURL returns the full HTTP callback URL for a given probe ID.
func (s *Server) CallbackURL(probeID string) string {
	host := s.PublicHost
	if host == "" {
		host = s.ListenAddr
	}
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "http://" + host
	}
	return fmt.Sprintf("%s/%s", strings.TrimRight(host, "/"), probeID)
}

// SubdomainURL returns an HTTP callback URL with the probe ID as a subdomain (for DNS/host callbacks).
func (s *Server) SubdomainURL(probeID string) string {
	host := s.PublicHost
	if host == "" {
		host = s.ListenAddr
	}
	scheme := "http://"
	cleanHost := host
	if strings.HasPrefix(host, "http://") {
		cleanHost = strings.TrimPrefix(host, "http://")
	} else if strings.HasPrefix(host, "https://") {
		scheme = "https://"
		cleanHost = strings.TrimPrefix(host, "https://")
	}
	return fmt.Sprintf("%s%s.%s/", scheme, probeID, cleanHost)
}

// WaitForHit waits up to timeout for a callback matching the probeID.
func (s *Server) WaitForHit(probeID string, timeout time.Duration) (*Hit, bool) {
	if timeout <= 0 {
		timeout = s.WaitTimeout
	}

	s.mu.Lock()
	// Check if already received
	if hits, ok := s.hits[probeID]; ok && len(hits) > 0 {
		h := hits[0]
		s.mu.Unlock()
		return h, true
	}

	ch := make(chan *Hit, 1)
	s.waiters[probeID] = append(s.waiters[probeID], ch)
	s.mu.Unlock()

	select {
	case hit := <-ch:
		return hit, true
	case <-time.After(timeout):
		return nil, false
	}
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Extract probe ID from Path (e.g. /a1b2c3d4e5f60718) or Host header
	path := strings.Trim(r.URL.Path, "/")
	var probeID string
	if len(path) >= 16 {
		probeID = path[:16]
	} else if path != "" {
		probeID = path
	}

	// Also check Host header (e.g. <probeID>.domain.com)
	if probeID == "" || len(probeID) < 8 {
		hostParts := strings.Split(r.Host, ".")
		if len(hostParts) > 1 && len(hostParts[0]) >= 12 {
			probeID = hostParts[0]
		}
	}

	headersCopy := make(map[string][]string)
	for k, v := range r.Header {
		headersCopy[k] = v
	}

	hit := &Hit{
		ID:         probeID,
		Timestamp:  time.Now().UTC(),
		RemoteAddr: r.RemoteAddr,
		Method:     r.Method,
		Path:       r.URL.Path,
		Headers:    headersCopy,
		RawQuery:   r.URL.RawQuery,
	}

	s.mu.Lock()
	if probeID != "" {
		s.hits[probeID] = append(s.hits[probeID], hit)
		if waiterList, exists := s.waiters[probeID]; exists {
			for _, ch := range waiterList {
				select {
				case ch <- hit:
				default:
				}
			}
			delete(s.waiters, probeID)
		}
	}
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("NFLX-OAST-ACK\n"))
}
