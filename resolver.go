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

func (r *Resolver) LookupIPAddr(ctx context.Context, domain string) (result []net.IPAddr, err error) {
	type response struct {
		ips []net.IPAddr
		err error
	}

	resch := make(chan response, 2)
	go func() {
		ip4, err := doRequestA(ctx, r.url, domain)
		resch <- response{ip4, err}
	}()

	go func() {
		ip6, err := doRequestAAAA(ctx, r.url, domain)
		resch <- response{ip6, err}
	}()

	for i := 0; i < 2; i++ {
		r := <-resch
		if r.err != nil {
			return nil, r.err
		}

		result = append(result, r.ips...)
	}

	return result, nil
}

func (r *Resolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	return doRequestTXT(ctx, r.url, domain)
}
