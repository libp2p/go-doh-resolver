package doh

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

func TestLookupIPAddrSingleFamily(t *testing.T) {
	domain := "example.com"
	resolver := mockDoHResolver(t, map[uint16]*dns.Msg{
		dns.TypeA:    mockDNSAnswerA(dns.Fqdn(domain), net.IPv4(127, 0, 0, 1)),
		dns.TypeAAAA: new(dns.Msg), // IPv4-only domain: empty AAAA answer
	})
	defer resolver.Close()

	r, err := NewResolver(resolver.URL)
	if err != nil {
		t.Fatal("resolver cannot be initialised")
	}

	ips, err := r.LookupIPAddr(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips))
	}

	// the empty AAAA answer carries no RRset TTL and must not zero out the A
	// record's TTL (300s in the mock), so the result stays cacheable
	if _, ok := r.getCachedIPAddr(domain); !ok {
		t.Fatal("expected single-family result to be cached")
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

func TestLookupTXTWithTTL(t *testing.T) {
	domain := "example.com"
	resolver := mockDoHResolver(t, map[uint16]*dns.Msg{
		dns.TypeTXT: mockDNSAnswerTXT(dns.Fqdn(domain), []string{"dnslink=/ipns/example.com"}),
	})
	defer resolver.Close()

	r, err := NewResolver(resolver.URL)
	if err != nil {
		t.Fatal("resolver cannot be initialised")
	}

	// cold lookup returns the record TTL from the answer (300s in the mock)
	txt, ttl, err := r.LookupTXTWithTTL(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if len(txt) == 0 {
		t.Fatal("got no TXT entries")
	}
	if ttl != 300*time.Second {
		t.Fatalf("expected ttl 300s, got %s", ttl)
	}

	// warm lookup (cache hit) returns the remaining TTL, never more than the record TTL
	_, ttl2, err := r.LookupTXTWithTTL(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if ttl2 <= 0 || ttl2 > 300*time.Second {
		t.Fatalf("expected remaining ttl in (0s, 300s], got %s", ttl2)
	}
}

func TestLookupTXTWithTTLCappedByMaxCacheTTL(t *testing.T) {
	domain := "example.com"
	resolver := mockDoHResolver(t, map[uint16]*dns.Msg{
		dns.TypeTXT: mockDNSAnswerTXT(dns.Fqdn(domain), []string{"dnslink=/ipns/example.com"}),
	})
	defer resolver.Close()

	// record TTL (300s) is larger than the max cache TTL, so the returned TTL is capped
	r, err := NewResolver(resolver.URL, WithMaxCacheTTL(10*time.Second))
	if err != nil {
		t.Fatal("resolver cannot be initialised")
	}

	_, ttl, err := r.LookupTXTWithTTL(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if ttl != 10*time.Second {
		t.Fatalf("expected ttl capped to 10s, got %s", ttl)
	}
}

func TestLookupTXTWithTTLCacheDisabled(t *testing.T) {
	domain := "example.com"
	resolver := mockDoHResolver(t, map[uint16]*dns.Msg{
		dns.TypeTXT: mockDNSAnswerTXT(dns.Fqdn(domain), []string{"dnslink=/ipns/example.com"}),
	})
	defer resolver.Close()

	// a disabled cache means nothing may be cached, so the reported TTL is 0
	// no matter what the record says (300s in the mock)
	r, err := NewResolver(resolver.URL, WithCacheDisabled())
	if err != nil {
		t.Fatal("resolver cannot be initialised")
	}

	txt, ttl, err := r.LookupTXTWithTTL(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if len(txt) == 0 {
		t.Fatal("got no TXT entries")
	}
	if ttl != 0 {
		t.Fatalf("expected ttl 0 with cache disabled, got %s", ttl)
	}
	if _, _, ok := r.getCachedTXTWithTTL(domain); ok {
		t.Fatal("expected cache to stay empty")
	}

	// a nonsensical negative cap behaves like a disabled cache and is never
	// reported as a negative TTL
	rNeg, err := NewResolver(resolver.URL, WithMaxCacheTTL(-time.Second))
	if err != nil {
		t.Fatal("resolver cannot be initialised")
	}

	_, ttl, err = rNeg.LookupTXTWithTTL(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if ttl != 0 {
		t.Fatalf("expected ttl 0 with negative cap, got %s", ttl)
	}
	if _, _, ok := rNeg.getCachedTXTWithTTL(domain); ok {
		t.Fatal("expected cache to stay empty with negative cap")
	}
}

func mockDNSAnswerTXTWithTTLs(name string, ttls []uint32) *dns.Msg {
	m := new(dns.Msg)
	for _, ttl := range ttls {
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
			Txt: []string{"dnslink=/ipns/example.com"},
		})
	}
	return m
}

func TestLookupTXTWithTTLMixedTTLs(t *testing.T) {
	// per RFC 2181 an RRset with differing TTLs is treated as having the
	// lowest one, regardless of record order, and a genuine TTL 0 wins too
	for _, tc := range []struct {
		name     string
		ttls     []uint32
		expected time.Duration
	}{
		{"low first", []uint32{60, 300}, 60 * time.Second},
		{"low last", []uint32{300, 60}, 60 * time.Second},
		{"zero first", []uint32{0, 300}, 0},
		{"zero last", []uint32{300, 0}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			domain := "example.com"
			resolver := mockDoHResolver(t, map[uint16]*dns.Msg{
				dns.TypeTXT: mockDNSAnswerTXTWithTTLs(dns.Fqdn(domain), tc.ttls),
			})
			defer resolver.Close()

			r, err := NewResolver(resolver.URL)
			if err != nil {
				t.Fatal("resolver cannot be initialised")
			}

			_, ttl, err := r.LookupTXTWithTTL(context.Background(), domain)
			if err != nil {
				t.Fatal(err)
			}
			if ttl != tc.expected {
				t.Fatalf("expected ttl %s, got %s", tc.expected, ttl)
			}
		})
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

// countingRoundTripper counts the requests passing through it before delegating
// to the wrapped transport.
type countingRoundTripper struct {
	rt    http.RoundTripper
	count atomic.Int64
}

func (c *countingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	c.count.Add(1)
	return c.rt.RoundTrip(req)
}

func TestWithHTTPClient(t *testing.T) {
	domain := "example.com"
	resolver := mockDoHResolver(t, map[uint16]*dns.Msg{
		dns.TypeTXT: mockDNSAnswerTXT(dns.Fqdn(domain), []string{"dnslink=/ipns/example.com"}),
	})
	defer resolver.Close()

	rt := &countingRoundTripper{rt: http.DefaultTransport}
	r, err := NewResolver(resolver.URL, WithHTTPClient(&http.Client{Transport: rt}))
	if err != nil {
		t.Fatal("resolver cannot be initialised")
	}

	if _, err := r.LookupTXT(context.Background(), domain); err != nil {
		t.Fatal(err)
	}
	if rt.count.Load() == 0 {
		t.Fatal("expected the custom http client to be used")
	}
}

func TestWithHTTPClientNil(t *testing.T) {
	_, err := NewResolver("https://cloudflare-dns.com/dns-query", WithHTTPClient(nil))
	if err == nil {
		t.Fatal("expected an error when passing a nil http client")
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
