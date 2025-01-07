package doh

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func mockDNSHeader(name string, rrType uint16) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: rrType, Class: dns.ClassINET, Ttl: 300}
}

func mockDNSAnswerA(name string, ip net.IP) *dns.Msg {
	return &dns.Msg{
		Answer: []dns.RR{
			&dns.A{
				Hdr: mockDNSHeader(name, dns.TypeA),
				A:   ip,
			},
		},
	}
}

func mockDNSAnswerAAAA(name string, ip net.IP) *dns.Msg {
	return &dns.Msg{
		Answer: []dns.RR{
			&dns.AAAA{
				Hdr:  mockDNSHeader(name, dns.TypeAAAA),
				AAAA: ip,
			},
		},
	}
}

func mockDNSAnswerTXT(name string, records []string) *dns.Msg {
	return &dns.Msg{
		Answer: []dns.RR{
			&dns.TXT{
				Hdr: mockDNSHeader(name, dns.TypeTXT),
				Txt: records,
			},
		},
	}
}

func mockDoHResolver(t *testing.T, msgs map[uint16]*dns.Msg) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal("sent request body to the mock DoH resolver cannot be read")
		}

		r := new(dns.Msg)
		r.Unpack(body)
		m := msgs[r.Question[0].Qtype]

		b, err := m.Pack()
		if err != nil {
			t.Fatal("expected mock dns answer to be packable")
		}
		res.Header().Add("Content-Type", dohMimeType)
		res.Write(b)
	}))
}

func TestLookupIPAddr(t *testing.T) {
	domain := "example.com"
	resolver := mockDoHResolver(t, map[uint16]*dns.Msg{
		dns.TypeA:    mockDNSAnswerA(dns.Fqdn(domain), net.IPv4(127, 0, 0, 1)),
		dns.TypeAAAA: mockDNSAnswerAAAA(dns.Fqdn(domain), net.IPv6loopback),
	})
	defer resolver.Close()

	r, err := NewResolver("https://cloudflare-dns.com/dns-query")
	if err != nil {
		t.Fatal("resolver cannot be initialised")
	}
	r.url = resolver.URL

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
	domain := "example.com"
	resolver := mockDoHResolver(t, map[uint16]*dns.Msg{
		dns.TypeTXT: mockDNSAnswerTXT(dns.Fqdn(domain), []string{"dnslink=/ipns/example.com"}),
	})
	defer resolver.Close()

	r, err := NewResolver(resolver.URL)
	if err != nil {
		t.Fatal("resolver cannot be initialised")
	}

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

func TestLookupCache(t *testing.T) {
	domain := "example.com"
	resolver := mockDoHResolver(t, map[uint16]*dns.Msg{
		dns.TypeTXT: mockDNSAnswerTXT(dns.Fqdn(domain), []string{"dnslink=/ipns/example.com"}),
	})
	defer resolver.Close()

	const cacheTTL = time.Second
	r, err := NewResolver(resolver.URL, WithMaxCacheTTL(cacheTTL))
	if err != nil {
		t.Fatal("resolver cannot be initialised")
	}

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

	// check cache is empty after its maxTTL
	time.Sleep(cacheTTL)
	txt2, ok = r.getCachedTXT(domain)
	if ok {
		t.Fatal("expected cache to be empty")
	}
	if txt2 != nil {
		t.Fatal("expected cache to not contain a txt entry")
	}
}

func TestCleartextRemoteEndpoint(t *testing.T) {
	// use remote endpoint over http and not https
	_, err := NewResolver("http://cloudflare-dns.com/dns-query")
	if err == nil {
		t.Fatal("using remote DoH endpoint over unencrypted http:// expected should produce error, but expected error was not returned")
	}
}

func TestCleartextLocalhostEndpoint(t *testing.T) {
	testCases := []struct{ hostname string }{
		{hostname: "localhost"},
		{hostname: "localhost:8080"},
		{hostname: "127.0.0.1"},
		{hostname: "127.0.0.1:8080"},
		{hostname: "[::1]"},
		{hostname: "[::1]:8080"},
	}
	for _, tc := range testCases {
		t.Run(tc.hostname, func(t *testing.T) {
			// use local endpoint over http and not https
			_, err := NewResolver("http://" + tc.hostname + "/dns-query")
			if err != nil {
				t.Fatalf("using %q DoH endpoint over unencrypted http:// expected to work, but unexpected error was returned instead", tc.hostname)
			}
		})
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
