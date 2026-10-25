package portscan

import (
	"net"
	"regexp"
	"strings"
	"time"
)

var (
	reSSH   = regexp.MustCompile(`(?i)SSH-[\d.]+-(\S+)`)
	reHTTP  = regexp.MustCompile(`(?i)Server:\s*([^\r\n]+)`)
	reFTP   = regexp.MustCompile(`(?i)^220[- ]([^\r\n]+)`)
	reSMTP  = regexp.MustCompile(`(?i)^220[- ]([^\r\n]+)`)
)

func grabBanner(conn net.Conn, port int, timeout time.Duration) (banner, version string) {
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Send HTTP probe for web ports
	if port == 80 || port == 8080 || port == 8000 || port == 8008 ||
		port == 8888 || port == 9090 || port == 8001 || port == 3000 ||
		port == 4200 || port == 5173 {
		_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\nHost: " + conn.RemoteAddr().String() + "\r\n\r\n"))
	}

	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n == 0 {
		return "", ""
	}

	raw := string(buf[:n])
	banner = strings.TrimSpace(raw)
	if len(banner) > 200 {
		banner = banner[:200]
	}

	if m := reSSH.FindStringSubmatch(raw); len(m) > 1 {
		version = strings.TrimSpace(m[1])
	} else if m := reHTTP.FindStringSubmatch(raw); len(m) > 1 {
		version = strings.TrimSpace(m[1])
	} else if m := reFTP.FindStringSubmatch(raw); len(m) > 1 {
		version = strings.TrimSpace(m[1])
	} else if m := reSMTP.FindStringSubmatch(raw); len(m) > 1 {
		version = strings.TrimSpace(m[1])
	}

	return banner, version
}
