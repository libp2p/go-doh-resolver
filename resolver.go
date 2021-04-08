package doh

import (
	"context"
	"net"
	"strings"

	madns "github.com/multiformats/go-multiaddr-dns"
)

type Resolver struct {
	url string
}

func NewResolver(url string) *Resolver {
	if !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	return &Resolver{url: url}
}

var _ madns.BasicResolver = (*Resolver)(nil)

func (r *Resolver) LookupIPAddr(ctx context.Context, domain string) ([]net.IPAddr, error) {
	ip4, err := doRequestA(ctx, r.url, domain)
	if err != nil {
		return nil, err
	}

	ip6, err := doRequestAAAA(ctx, r.url, domain)
	if err != nil {
		return nil, err
	}

	result := append(ip4, ip6...)
	return result, err
}

func (r *Resolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	return doRequestTXT(ctx, r.url, domain)
}
