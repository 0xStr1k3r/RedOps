package recon

import (
	"context"
	"fmt"

	"github.com/0xStr1k3r/RedOps/internal/scope"
)

// SubfinderTool enumerates subdomains passively (T1590). No active connections.
type SubfinderTool struct{}

func init() { Register(SubfinderTool{}) }

func (SubfinderTool) Name() string        { return "subfinder" }
func (SubfinderTool) Binary() string      { return "subfinder" }
func (SubfinderTool) Description() string { return "Passive subdomain enumeration" }

func (SubfinderTool) Supports(t scope.EntryType) bool { return t == scope.TypeDomain }

func (SubfinderTool) Execute(ctx context.Context, sc *scope.Scope, target string, opts Options) ([]byte, error) {
	typ, norm, err := scope.Classify(target)
	if err != nil {
		return nil, err
	}
	if !(SubfinderTool{}.Supports(typ)) {
		return nil, fmt.Errorf("subfinder needs a domain target, got %q", typ)
	}
	if err := sc.Enforce(norm); err != nil {
		return nil, err
	}
	_ = opts
	args := []string{"-d", norm, "-silent", "-json"}
	return runBinary(ctx, sc, "subfinder", norm, args, opts)
}

func (SubfinderTool) Parse(output []byte) (Result, error) {
	// subfinder -json emits {"host": "..."} per line; reuse dnsx shape loosely.
	var r Result
	for _, line := range splitLines(output) {
		host := extractJSONHost(line)
		if host == "" {
			continue
		}
		// Passive results are hostnames; IPs resolve in Phase 3 dnsx follow-up.
		r.Hosts = append(r.Hosts, Host{Hostname: host})
	}
	r.RawBytes = len(output)
	r.Summary = fmt.Sprintf("%d subdomains", len(r.Hosts))
	return r, nil
}
