// Package recon executes authorized reconnaissance through allowlisted tool
// adapters. Every execution re-enforces project scope before spawning any
// process, and every process is spawned with an argv list (never a shell).
package recon

import (
	"context"
	"fmt"
	"time"

	"github.com/redops/redops/internal/scope"
)

// Options controls one tool run. Only allowlisted fields reach the binary.
type Options struct {
	// Ports like "80,443" or "1-1000". Empty = tool default. Validated strictly.
	Ports string
	// Profile selects a canned flag set: "" (default), "fast", "full".
	Profile string
	// Timeout caps execution. Zero = 5 minutes.
	Timeout time.Duration
}

// Host and Service are adapter-neutral observations saved to the asset store.
type Host struct {
	IP       string
	Hostname string
	OS       string
}

type Service struct {
	HostIP   string
	Port     int
	Protocol string
	State    string
	Name     string
	Product  string
	Version  string
}

// Result is what an adapter returns after Parse.
type Result struct {
	Hosts    []Host
	Services []Service
	Summary  string
	RawBytes int
}

// Tool is the adapter interface from the RedOps design: Name, Binary,
// capability check, Execute (scope-gated), Parse.
type Tool interface {
	Name() string
	Binary() string
	Description() string
	Supports(entryType scope.EntryType) bool
	Execute(ctx context.Context, sc *scope.Scope, target string, opts Options) (raw []byte, err error)
	Parse(output []byte) (Result, error)
}

var registry = map[string]Tool{}

// Register adds an adapter. Called from adapter init() or service init.
func Register(t Tool) {
	registry[t.Name()] = t
}

// Get returns an adapter or an error listing what is available.
func Get(name string) (Tool, error) {
	if t, ok := registry[name]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("unknown tool %q (available: %v)", name, List())
}

// List returns registered tool names in registry order (sorted for stability).
func List() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	// small deterministic bubble sort to avoid importing sort for one call
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
