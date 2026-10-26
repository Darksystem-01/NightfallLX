package osint

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// ASNRecord holds autonomous system and BGP routing intelligence.
type ASNRecord struct {
	ASN      string
	CIDR     string
	Country  string
	Registry string
	OrgName  string
}

// LookupASN queries Team Cymru's passive DNS service to determine ASN, CIDR block, and Org.
func LookupASN(ipStr string, timeout time.Duration) (*ASNRecord, error) {
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	ipv4 := parsedIP.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("only IPv4 supported for Cymru ASN lookup: %s", ipStr)
	}

	if timeout <= 0 {
		timeout = 4 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var resolver net.Resolver

	// 1. Query origin.asn.cymru.com for ASN & CIDR: reverse octets 4.3.2.1.origin.asn.cymru.com
	reversedIP := fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", ipv4[3], ipv4[2], ipv4[1], ipv4[0])
	txts, err := resolver.LookupTXT(ctx, reversedIP)
	if err != nil || len(txts) == 0 {
		return nil, err
	}

	parts := strings.Split(txts[0], "|")
	if len(parts) < 3 {
		return nil, fmt.Errorf("unexpected Cymru response format: %s", txts[0])
	}

	asn := strings.TrimSpace(parts[0])
	cidr := strings.TrimSpace(parts[1])
	country := strings.TrimSpace(parts[2])
	registry := ""
	if len(parts) >= 4 {
		registry = strings.TrimSpace(parts[3])
	}

	record := &ASNRecord{
		ASN:      "AS" + asn,
		CIDR:     cidr,
		Country:  country,
		Registry: registry,
	}

	// 2. Query AS<asn>.asn.cymru.com for Organization Name
	asNameQuery := fmt.Sprintf("AS%s.asn.cymru.com", asn)
	if asTxts, err := resolver.LookupTXT(ctx, asNameQuery); err == nil && len(asTxts) > 0 {
		asParts := strings.Split(asTxts[0], "|")
		if len(asParts) >= 5 {
			record.OrgName = strings.TrimSpace(asParts[4])
		}
	}

	return record, nil
}

// buildAXFRQuery crafts a standard DNS AXFR query frame over TCP.
func buildAXFRQuery(domain string) []byte {
	var buf []byte

	// 12-byte DNS Header
	id := uint16(0x1337)
	flags := uint16(0x0000) // Standard query
	qdcount := uint16(1)
	ancount := uint16(0)
	nscount := uint16(0)
	arcount := uint16(0)

	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	binary.BigEndian.PutUint16(hdr[4:6], qdcount)
	binary.BigEndian.PutUint16(hdr[6:8], ancount)
	binary.BigEndian.PutUint16(hdr[8:10], nscount)
	binary.BigEndian.PutUint16(hdr[10:12], arcount)
	buf = append(buf, hdr...)

	// QNAME: length-prefixed labels
	labels := strings.Split(strings.Trim(domain, "."), ".")
	for _, label := range labels {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00) // Root label null terminator

	// QTYPE: AXFR (252 = 0x00FC), QCLASS: IN (1 = 0x0001)
	qtail := make([]byte, 4)
	binary.BigEndian.PutUint16(qtail[0:2], 252) // AXFR
	binary.BigEndian.PutUint16(qtail[2:4], 1)   // IN
	buf = append(buf, qtail...)

	// TCP DNS frame prefix: 2 bytes length
	frame := make([]byte, 2+len(buf))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(buf)))
	copy(frame[2:], buf)

	return frame
}

// TestAXFR attempts a DNS Zone Transfer on all provided nameservers for the target domain.
func TestAXFR(domain string, nameServers []string, timeout time.Duration) (bool, string, []string) {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}

	queryFrame := buildAXFRQuery(domain)

	for _, ns := range nameServers {
		nsHost := strings.TrimSuffix(ns, ".")
		targetAddr := net.JoinHostPort(nsHost, "53")

		conn, err := net.DialTimeout("tcp", targetAddr, timeout)
		if err != nil {
			continue
		}

		_ = conn.SetDeadline(time.Now().Add(timeout))

		// Send AXFR query
		if _, err := conn.Write(queryFrame); err != nil {
			conn.Close()
			continue
		}

		// Read 2-byte response length
		lenBuf := make([]byte, 2)
		if _, err := conn.Read(lenBuf); err != nil {
			conn.Close()
			continue
		}
		respLen := binary.BigEndian.Uint16(lenBuf)
		if respLen < 12 {
			conn.Close()
			continue
		}

		respBuf := make([]byte, respLen)
		n, err := conn.Read(respBuf)
		conn.Close()
		if err != nil || n < 12 {
			continue
		}

		// Parse DNS Header RCODE (flags in bytes 2-3)
		flags := binary.BigEndian.Uint16(respBuf[2:4])
		rcode := flags & 0x000F
		ancount := binary.BigEndian.Uint16(respBuf[6:8])

		// RCODE 0 = NoError, and ANCOUNT > 0 means the server accepted and returned zone data!
		if rcode == 0 && ancount > 0 {
			// Extract plain text string evidence from zone data
			records := []string{}
			rawStr := string(respBuf[12:])
			for _, part := range strings.Split(rawStr, "\x00") {
				cleaned := strings.Map(func(r rune) rune {
					if r >= 32 && r <= 126 {
						return r
					}
					return -1
				}, part)
				if len(cleaned) > 4 && strings.Contains(cleaned, domain) {
					records = append(records, cleaned)
				}
			}
			return true, nsHost, records
		}
	}

	return false, "", nil
}
