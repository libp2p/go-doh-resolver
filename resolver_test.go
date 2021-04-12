package doh

import (
	"context"
	"testing"
)

func TestLookupIPAddr(t *testing.T) {
	r := NewResolver("https://cloudflare-dns.com/dns-query")

	ips, err := r.LookupIPAddr(context.Background(), "libp2p.io")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) == 0 {
		t.Fatal("got no IPs")
	}
}

func TestLookupTXT(t *testing.T) {
	r := NewResolver("https://cloudflare-dns.com/dns-query")

	txt, err := r.LookupTXT(context.Background(), "_dnsaddr.bootstrap.libp2p.io")
	if err != nil {
		t.Fatal(err)
	}
	if len(txt) == 0 {
		t.Fatal("got no TXT entries")
	}
}
