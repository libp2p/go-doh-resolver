package doh

import (
	"context"
	"net"
	"testing"
)

func TestLookupIPAddr(t *testing.T) {
	r := NewResolver("https://cloudflare-dns.com/dns-query")

	domain := "libp2p.io"
	ips, err := r.LookupIPAddr(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) == 0 {
		t.Fatal("got no IPs")
	}

	// check that we got both IPv4 and IPv6 addrs
	var got4, got6 bool
	for _, ip := range ips {
		if len(ip.IP.To4()) == 4 {
			got4 = true
		} else {
			got6 = true
		}
	}
	if !got4 {
		t.Fatal("got no IPv4 addresses")
	}
	if !got6 {
		t.Fatal("got no IPv6 addresses")
	}

	// check the cache
	ips2, ok := r.getCachedIPAddr(domain)
	if !ok {
		t.Fatal("expected cache to be populated")
	}
	if !sameIPs(ips, ips2) {
		t.Fatal("expected cache to contain the same addrs")
	}
}

func TestLookupTXT(t *testing.T) {
	r := NewResolver("https://cloudflare-dns.com/dns-query")

	domain := "_dnsaddr.bootstrap.libp2p.io"
	txt, err := r.LookupTXT(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if len(txt) == 0 {
		t.Fatal("got no TXT entries")
	}

	// check the cache
	txt2, ok := r.getCachedTXT(domain)
	if !ok {
		t.Fatal("expected cache to be populated")
	}
	if !sameTXT(txt, txt2) {
		t.Fatal("expected cache to contain the same txt entries")
	}

}

func sameIPs(a, b []net.IPAddr) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if !a[i].IP.Equal(b[i].IP) {
			return false
		}
	}

	return true
}

func sameTXT(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
