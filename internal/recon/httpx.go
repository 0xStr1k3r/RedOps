package recon

import (
	"context"
	"fmt"
	"strings"

	"github.com/redops/redops/internal/scope"
	"github.com/redops/redops/pkg/httpx"
)

// HttpxTool probes web services: title, server, tech, status, TLS (T1046/T1594).
type HttpxTool struct{}

func init() { Register(HttpxTool{}) }

func (HttpxTool) Name() string        { return "httpx" }
func (HttpxTool) Binary() string      { return "httpx" }
func (HttpxTool) Description() string { return "HTTP enumeration via httpx JSON" }

func (HttpxTool) Supports(t scope.EntryType) bool {
	return t == scope.TypeIP || t == scope.TypeDomain
}

func normalizeHTTPInput(target string) (string, error) {
	typ, norm, err := scope.Classify(target)
	if err != nil {
		return "", err
	}
	if !(HttpxTool{}.Supports(typ)) {
		return "", fmt.Errorf("httpx does not support target type %q", typ)
	}
	if strings.HasPrefix(norm, "http://") || strings.HasPrefix(norm, "https://") {
		return norm, nil
	}
	return "http://" + norm, nil
}

func (HttpxTool) Execute(ctx context.Context, sc *scope.Scope, target string, opts Options) ([]byte, error) {
	input, err := normalizeHTTPInput(target)
	if err != nil {
		return nil, err
	}
	// httpx takes -u <url>; argv only, no shell. Target re-checked against scope
	// using the bare host (scheme stripped) for defense in depth.
	bare := strings.TrimPrefix(strings.TrimPrefix(input, "http://"), "https://")
	bare = strings.Split(bare, "/")[0]
	bare = strings.Split(bare, ":")[0]
	if err := sc.Enforce(bare); err != nil {
		return nil, err
	}
	_ = opts // ports/profile reserved for Phase 3 rate tuning
	args := []string{"-u", input, "-json", "-silent", "-title", "-tech-detect", "-status-code", "-web-server", "-tls-probe", "-timeout", "10", "-retries", "1"}
	return runBinary(ctx, sc, "httpx", bare, args, opts)
}

func (HttpxTool) Parse(output []byte) (Result, error) {
	res, err := httpx.ParseJSONL(output)
	if err != nil {
		return Result{}, err
	}
	var r Result
	seen := map[string]bool{}
	for _, h := range res {
		if h.Host != "" && !seen[h.Host] {
			seen[h.Host] = true
			r.Hosts = append(r.Hosts, Host{IP: h.Host})
		}
		name := fmt.Sprintf("http(%d)", h.StatusCode)
		if h.Title != "" {
			name = fmt.Sprintf("http(%d) %s", h.StatusCode, h.Title)
		}
		r.Services = append(r.Services, Service{
			HostIP: h.Host, Port: h.Port, Protocol: "tcp", State: "open",
			Name: name, Product: h.Server, Version: strings.Join(h.Tech, ","),
		})
	}
	r.RawBytes = len(output)
	r.Summary = fmt.Sprintf("%d urls, %d services", len(res), len(r.Services))
	return r, nil
}
