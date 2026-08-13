package recon

import (
	"context"
	"fmt"
	"strings"

	"github.com/0xStr1k3r/RedOps/internal/scope"
	pkgnmap "github.com/0xStr1k3r/RedOps/pkg/nmap"
)

// NmapTool runs authorized `nmap -oX -` scans. Never runs without scope.
type NmapTool struct{}

func init() { Register(NmapTool{}) }

func (NmapTool) Name() string        { return "nmap" }
func (NmapTool) Binary() string      { return "nmap" }
func (NmapTool) Description() string { return "Network service discovery (T1046) via nmap XML" }

func (NmapTool) Supports(t scope.EntryType) bool {
	return t == scope.TypeIP || t == scope.TypeCIDR
}

func (NmapTool) Execute(ctx context.Context, sc *scope.Scope, target string, opts Options) ([]byte, error) {
	if _, norm, err := scope.Classify(target); err != nil {
		return nil, err
	} else {
		target = norm
	}
	typ, _, _ := scope.Classify(target)
	if !(NmapTool{}.Supports(typ)) {
		return nil, fmt.Errorf("nmap does not support target type %q (use IP or CIDR)", typ)
	}
	args := []string{"-sV", "-oX", "-", "-T4"}
	switch opts.Profile {
	case "fast":
		args = append(args, "-F")
	case "full":
		args = append(args, "-p-", "--min-rate", "500")
	default: // top100-ish default: top 1000, throttled for labs
		args = append(args, "--top-ports", "1000")
	}
	if opts.Ports != "" {
		args = append(args, "-p", strings.ReplaceAll(opts.Ports, " ", ""))
	}
	args = append(args, target)
	return runBinary(ctx, sc, "nmap", target, args, opts)
}

func (NmapTool) Parse(output []byte) (Result, error) {
	hosts, err := pkgnmap.ParseXML(output)
	if err != nil {
		return Result{}, err
	}
	var r Result
	for _, h := range hosts {
		r.Hosts = append(r.Hosts, Host{IP: h.IP, Hostname: h.Hostname, OS: h.OS})
		for _, s := range h.Services {
			r.Services = append(r.Services, Service{
				HostIP: h.IP, Port: s.Port, Protocol: s.Protocol,
				State: s.State, Name: s.Name, Product: s.Product, Version: s.Version,
			})
		}
	}
	r.RawBytes = len(output)
	r.Summary = fmt.Sprintf("%d hosts, %d services", len(r.Hosts), len(r.Services))
	return r, nil
}
