package recon

import (
	"context"
	"fmt"
	"strings"

	"github.com/0xStr1k3r/RedOps/internal/scope"
	"github.com/0xStr1k3r/RedOps/pkg/dnsx"
)

// DnsxTool resolves DNS records for in-scope domains (T1590).
type DnsxTool struct{}

func init() { Register(DnsxTool{}) }

func (DnsxTool) Name() string        { return "dnsx" }
func (DnsxTool) Binary() string      { return "dnsx" }
func (DnsxTool) Description() string { return "DNS enumeration via dnsx JSON" }

func (DnsxTool) Supports(t scope.EntryType) bool { return t == scope.TypeDomain }

func (DnsxTool) Execute(ctx context.Context, sc *scope.Scope, target string, opts Options) ([]byte, error) {
	typ, norm, err := scope.Classify(target)
	if err != nil {
		return nil, err
	}
	if !(DnsxTool{}.Supports(typ)) {
		return nil, fmt.Errorf("dnsx needs a domain target, got %q", typ)
	}
	_ = opts
	// dnsx reads from -l file or stdin; use argv -d equivalent via echo-free path:
	// `dnsx -json -silent -a -cname -d <domain>` is not a real flag set for single
	// domains in all versions, so pass via stdin using /dev/stdin trick is avoided.
	// Instead use `-json -silent` with the domain as positional input through
	// a safe argv: dnsx accepts bare names on the command line in recent versions.
	args := []string{"-json", "-silent", "-a", "-cname", norm}
	// Enforce on the domain itself before spawning.
	if err := sc.Enforce(norm); err != nil {
		return nil, err
	}
	// runBinary re-enforces; pass norm as target for a clean audit trail.
	_ = strings.TrimSpace
	return runBinary(ctx, sc, "dnsx", norm, args, opts)
}

func (DnsxTool) Parse(output []byte) (Result, error) {
	res, err := dnsx.ParseJSONL(output)
	if err != nil {
		return Result{}, err
	}
	var r Result
	for _, d := range res {
		for _, ip := range d.A {
			r.Hosts = append(r.Hosts, Host{IP: ip, Hostname: d.Host})
		}
	}
	r.RawBytes = len(output)
	r.Summary = fmt.Sprintf("%d names", len(res))
	return r, nil
}
