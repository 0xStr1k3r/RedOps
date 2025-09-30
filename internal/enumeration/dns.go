package enumeration

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/redops/redops/internal/mitre"
	"github.com/redops/redops/internal/scope"
	"github.com/redops/redops/pkg/dnsx"
)

// DNSModule resolves A records for in-scope hostnames using the system
// resolver. It never queries out-of-scope names and never does zone transfers.
type DNSModule struct{}

func init() { Register(DNSModule{}) }

func (DNSModule) Name() string        { return "dns" }
func (DNSModule) Description() string { return "Forward DNS resolution of in-scope names (T1590)" }

func (DNSModule) Handles(svc ServiceRef) bool {
	n := strings.ToLower(svc.Name)
	return n == "dns" || n == "domain" || svc.Port == 53
}

// systemResolver wraps the Go system resolver for testability.
type systemResolver struct{}

func (systemResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// Resolve is exposed so service.go and tests share one path.
func (DNSModule) Resolve(ctx context.Context, sc *scope.Scope, hostname string) ([]string, error) {
	typ, norm, err := scope.Classify(hostname)
	if err != nil {
		return nil, err
	}
	if typ != scope.TypeDomain {
		return nil, fmt.Errorf("dns module needs a hostname, got %q", hostname)
	}
	if err := sc.Enforce(norm); err != nil {
		return nil, err
	}
	resolver := new(systemResolver)
	ips, err := resolver.LookupHost(ctx, norm)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", norm, err)
	}
	return ips, nil
}

func (DNSModule) Enumerate(ctx context.Context, sc *scope.Scope, svc ServiceRef, opts Options) (Result, error) {
	host := svc.Hostname
	if host == "" {
		host = svc.HostIP
	}
	ips, err := DNSModule{}.Resolve(ctx, sc, host)
	if err != nil {
		return Result{}, err
	}
	var obs []Observation
	for _, ip := range ips {
		obs = append(obs, Observation{Kind: "dns-record", Detail: host + " -> " + ip, TechniqueID: mitre.MapObservation("dns-record")})
	}
	_ = dnsx.Result{} // parser shared with recon dnsx in Phase 4 correlation
	_ = opts
	return Result{Module: "dns", Observations: obs, Summary: fmt.Sprintf("%s resolves to %d addr(s)", host, len(ips))}, nil
}
