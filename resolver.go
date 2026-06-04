package doh

import (
	"context"
	"errors"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	madns "github.com/multiformats/go-multiaddr-dns"
)

type Resolver struct {
	url string

	// RR caches keyed by FQDN.
	ipCache  *cache[[]net.IPAddr]
	txtCache *cache[[]string]

	maxCacheTTL time.Duration
}

type Option func(*Resolver) error

// Specifies the maximum time entries are valid in the cache
// A maxCacheTTL of zero is equivalent to `WithCacheDisabled`
func WithMaxCacheTTL(maxCacheTTL time.Duration) Option {
	return func(tr *Resolver) error {
		tr.maxCacheTTL = maxCacheTTL
		return nil
	}
}

func WithCacheDisabled() Option {
	return func(tr *Resolver) error {
		tr.maxCacheTTL = 0
		return nil
	}
}

func NewResolver(url string, opts ...Option) (*Resolver, error) {
	if strings.HasPrefix(url, "http:") &&
		!strings.HasPrefix(url, "http://localhost") &&
		!strings.HasPrefix(url, "http://127.0.0.1") &&
		!strings.HasPrefix(url, "http://[::1]") {
		return nil, errors.New("insecure URL: non-local DoH resolvers must use HTTPS")
	}

	if !strings.HasPrefix(url, "http:") && !strings.HasPrefix(url, "https:") {
		url = "https://" + url
	}

	r := &Resolver{
		url:         url,
		ipCache:     newCache[[]net.IPAddr](),
		txtCache:    newCache[[]string](),
		maxCacheTTL: time.Duration(math.MaxUint32) * time.Second,
	}

	for _, o := range opts {
		if err := o(r); err != nil {
			return nil, err
		}
	}

	return r, nil
}

var _ madns.BasicResolver = (*Resolver)(nil)

func (r *Resolver) LookupIPAddr(ctx context.Context, domain string) (result []net.IPAddr, err error) {
	result, ok := r.getCachedIPAddr(domain)
	if ok {
		return result, nil
	}

	type response struct {
		ips []net.IPAddr
		ttl uint32
		err error
	}

	resch := make(chan response, 2)
	go func() {
		ip4, ttl, err := doRequestA(ctx, r.url, domain)
		resch <- response{ip4, ttl, err}
	}()

	go func() {
		ip6, ttl, err := doRequestAAAA(ctx, r.url, domain)
		resch <- response{ip6, ttl, err}
	}()

	var ttl uint32
	for range 2 {
		r := <-resch
		if r.err != nil {
			return nil, r.err
		}

		result = append(result, r.ips...)
		if ttl == 0 || r.ttl < ttl {
			ttl = r.ttl
		}
	}

	cacheTTL := minTTL(time.Duration(ttl)*time.Second, r.maxCacheTTL)
	r.cacheIPAddr(domain, result, cacheTTL)
	return result, nil
}

func (r *Resolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	result, ok := r.getCachedTXT(domain)
	if ok {
		return result, nil
	}

	result, ttl, err := doRequestTXT(ctx, r.url, domain)
	if err != nil {
		return nil, err
	}

	cacheTTL := minTTL(time.Duration(ttl)*time.Second, r.maxCacheTTL)
	r.cacheTXT(domain, result, cacheTTL)
	return result, nil
}

// cacheEntry is a cached value and the time it expires.
type cacheEntry[V any] struct {
	val    V
	expire time.Time
}

// cache is a TTL cache keyed by string, safe for concurrent use. A read that
// hits a fresh entry takes only the read lock, so concurrent reads run in
// parallel. Deleting an expired entry needs the write lock. Go cannot upgrade a
// read lock to a write lock in place, so get drops the read lock, takes the
// write lock, and re-checks the entry before it deletes.
type cache[V any] struct {
	mx      sync.RWMutex
	entries map[string]cacheEntry[V]
}

func newCache[V any]() *cache[V] {
	return &cache[V]{entries: make(map[string]cacheEntry[V])}
}

// get returns the value stored under key, or the zero value and ok=false when
// the key is absent or expired. It deletes an expired entry before returning.
func (c *cache[V]) get(key string) (V, bool) {
	c.mx.RLock()
	entry, ok := c.entries[key]
	c.mx.RUnlock()

	var zero V
	if !ok {
		return zero, false
	}
	if !time.Now().After(entry.expire) {
		return entry.val, true
	}

	// The entry is expired. Re-check it under the write lock before deleting: in
	// the gap between dropping the read lock and taking the write lock, a
	// concurrent set may have refreshed it, or another get may have deleted it.
	c.mx.Lock()
	defer c.mx.Unlock()

	entry, ok = c.entries[key]
	if !ok {
		return zero, false
	}
	if time.Now().After(entry.expire) {
		delete(c.entries, key)
		return zero, false
	}
	return entry.val, true
}

// set stores val under key for the given TTL. A zero TTL stores nothing, so a
// disabled cache stays empty.
func (c *cache[V]) set(key string, val V, ttl time.Duration) {
	if ttl == 0 {
		return
	}

	c.mx.Lock()
	defer c.mx.Unlock()
	c.entries[key] = cacheEntry[V]{val: val, expire: time.Now().Add(ttl)}
}

func (r *Resolver) getCachedIPAddr(domain string) ([]net.IPAddr, bool) {
	return r.ipCache.get(dns.Fqdn(domain))
}

func (r *Resolver) cacheIPAddr(domain string, ips []net.IPAddr, ttl time.Duration) {
	r.ipCache.set(dns.Fqdn(domain), ips, ttl)
}

func (r *Resolver) getCachedTXT(domain string) ([]string, bool) {
	return r.txtCache.get(dns.Fqdn(domain))
}

func (r *Resolver) cacheTXT(domain string, txt []string, ttl time.Duration) {
	r.txtCache.set(dns.Fqdn(domain), txt, ttl)
}

func minTTL(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
