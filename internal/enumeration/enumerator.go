package enumeration

import (
	"context"
	"fmt"
	"time"

	"github.com/redops/redops/internal/scope"
)

// ServiceRef identifies one discovered service to enumerate.
type ServiceRef struct {
	HostIP   string
	Hostname string
	Port     int
	Protocol string // tcp|udp, default tcp
	Name     string // service name from recon, e.g. http, ssh
}

// Observation is one structured data point with its ATT&CK mapping.
type Observation struct {
	Kind        string `json:"kind"`        // e.g. http-title, ssh-banner
	Detail      string `json:"detail"`      // short human-readable value
	TechniqueID string `json:"technique_id"` // e.g. T1046
}

// Result is what a module returns.
type Result struct {
	Module       string        `json:"module"`
	Observations []Observation `json:"observations"`
	Summary      string        `json:"summary"`
}

// Options caps module behavior. Only safe read-only fetches; no credentials.
type Options struct {
	Timeout time.Duration
}

// Enumerator is the module interface: capability check + scope-gated run.
type Enumerator interface {
	Name() string
	Description() string
	Handles(svc ServiceRef) bool
	Enumerate(ctx context.Context, sc *scope.Scope, svc ServiceRef, opts Options) (Result, error)
}

var registry = map[string]Enumerator{}

// Register adds a module.
func Register(e Enumerator) { registry[e.Name()] = e }

// Get returns a module or an error listing what is available.
func Get(name string) (Enumerator, error) {
	if e, ok := registry[name]; ok {
		return e, nil
	}
	return nil, fmt.Errorf("unknown enumeration module %q (available: %v)", name, List())
}

// List returns registered module names, sorted.
func List() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// Match returns the first module claiming the service, or "".
func Match(svc ServiceRef) string {
	// Deterministic preference: specific modules before the generic fallback.
	for _, name := range []string{"http", "ssh-banner", "dns"} {
		if e, ok := registry[name]; ok && e.Handles(svc) {
			return name
		}
	}
	if e, ok := registry["tcp-banner"]; ok && e.Handles(svc) {
		return "tcp-banner"
	}
	return ""
}

func effectiveTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return 15 * time.Second
	}
	if d > 60*time.Second {
		return 60 * time.Second
	}
	return d
}
