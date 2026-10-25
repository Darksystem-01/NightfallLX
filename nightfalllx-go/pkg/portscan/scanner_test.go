package portscan

import (
	"net"
	"strconv"
	"testing"
)

func TestScanLocalhost(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n"))
	}()

	s := NewScanner("127.0.0.1")
	results, err := s.ScanRange(port, port)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || !results[0].Open {
		t.Fatalf("expected port %d to be open", port)
	}
	if results[0].Banner == "" {
		t.Error("expected non-empty banner")
	}
}

func TestScanCustomPorts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	s := NewScanner("127.0.0.1")
	results, err := s.ScanPorts([]int{port, 65534})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Port != port {
		t.Fatalf("expected only open port %d in custom port list, got %+v", port, results)
	}
}

func TestClosedPort(t *testing.T) {
	s := NewScanner("127.0.0.1")
	results, err := s.ScanRange(65530, 65530)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("expected port to be closed, got %+v", results)
	}
}

func TestCVECacheDedup(t *testing.T) {
	cache := NewCVECache()
	cache.mu.Lock()
	cache.store["openssh 8.9"] = []CVEEntry{{ID: "CVE-2023-1234", CVSS: 7.5, Severity: "HIGH"}}
	cache.mu.Unlock()

	entries, err := cache.Lookup("openssh 8.9")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != "CVE-2023-1234" {
		t.Error("cache lookup failed")
	}
}
