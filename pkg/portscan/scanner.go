package portscan

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// CommonPorts contains top pentest ports for fast scanning.
var CommonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
	1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090, 9200, 27017, 6379,
	5432, 1433, 1521, 2181, 4848, 7001, 8161, 9042, 11211, 15672, 61616,
	2375, 2376, 4243, 8086, 9000, 9001, 5000, 5001, 8000, 8001, 8008, 8009,
	8181, 9080, 9443, 4000, 4001, 4040, 5601, 9300, 7474, 7687, 5984, 8983,
	2049, 6000, 6001, 6443, 10250, 10255, 2379, 2380, 4194, 8472, 10248,
	502, 1883, 8883, 47808, 20000, 44818, 1099, 2000, 2001, 3000, 3001,
	4200, 5173, 9999, 7000, 7777,
}

// ServiceNames maps port numbers to common service names.
var ServiceNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
	143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
	1723: "pptp", 3306: "mysql", 3389: "rdp", 5900: "vnc",
	5432: "postgres", 1433: "mssql", 1521: "oracle", 6379: "redis",
	27017: "mongodb", 9200: "elasticsearch", 9300: "elasticsearch-cluster",
	8080: "http-alt", 8443: "https-alt", 8888: "jupyter",
	2375: "docker", 2376: "docker-tls", 4243: "docker-alt",
	1883: "mqtt", 8883: "mqtt-tls", 5601: "kibana", 9042: "cassandra",
	11211: "memcached", 15672: "rabbitmq-mgmt", 61616: "activemq",
	2181: "zookeeper", 7001: "weblogic", 4848: "glassfish",
	10250: "kubelet", 6443: "k8s-api", 2379: "etcd",
	3000: "react/node", 4200: "angular", 5173: "vite",
}

// PortResult holds scan details for a port.
type PortResult struct {
	Port    int        `json:"port"`
	Open    bool       `json:"open"`
	Service string     `json:"service"`
	Banner  string     `json:"banner,omitempty"`
	Version string     `json:"version,omitempty"`
	CVEs    []CVEEntry `json:"cves,omitempty"`
}

// Scanner performs concurrent TCP scanning with banner grabbing.
type Scanner struct {
	Host        string
	Timeout     time.Duration
	Concurrency int
	GrabBanner  bool
	FetchCVEs   bool
}

// NewScanner creates a new Scanner instance.
func NewScanner(host string) *Scanner {
	return &Scanner{
		Host:        host,
		Timeout:     1500 * time.Millisecond,
		Concurrency: 200,
		GrabBanner:  true,
		FetchCVEs:   false,
	}
}

// ScanCommon scans CommonPorts.
func (s *Scanner) ScanCommon() ([]PortResult, error) {
	return s.ScanPorts(CommonPorts)
}

// ScanRange scans a range from start to end port inclusive.
func (s *Scanner) ScanRange(start, end int) ([]PortResult, error) {
	if start < 1 {
		start = 1
	}
	if end > 65535 {
		end = 65535
	}
	if start > end {
		return nil, fmt.Errorf("invalid range: start %d > end %d", start, end)
	}
	ports := make([]int, 0, end-start+1)
	for p := start; p <= end; p++ {
		ports = append(ports, p)
	}
	return s.ScanPorts(ports)
}

// ScanPorts scans a specific list of ports.
func (s *Scanner) ScanPorts(ports []int) ([]PortResult, error) {
	sem := make(chan struct{}, s.Concurrency)
	results := make([]PortResult, len(ports))
	var wg sync.WaitGroup

	for i, port := range ports {
		wg.Add(1)
		go func(idx, p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = s.probePort(p)
		}(i, port)
	}
	wg.Wait()

	var open []PortResult
	for _, r := range results {
		if r.Open {
			open = append(open, r)
		}
	}
	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })

	if s.FetchCVEs {
		cache := NewCVECache()
		for i := range open {
			if open[i].Service != "" {
				query := open[i].Service
				if open[i].Version != "" {
					query += " " + open[i].Version
				}
				open[i].CVEs, _ = cache.Lookup(query)
			}
		}
	}

	return open, nil
}

func (s *Scanner) probePort(port int) PortResult {
	addr := net.JoinHostPort(s.Host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, s.Timeout)
	if err != nil {
		return PortResult{Port: port, Open: false}
	}
	defer conn.Close()

	svc := ServiceNames[port]
	if svc == "" {
		svc = "unknown"
	}

	res := PortResult{
		Port:    port,
		Open:    true,
		Service: svc,
	}

	if s.GrabBanner {
		banner, version := grabBanner(conn, port, s.Timeout)
		res.Banner = banner
		res.Version = version
	}

	return res
}
