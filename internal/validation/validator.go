package validation

import (
	"context"
	"fmt"
	"time"

	"github.com/0xStr1k3r/RedOps/internal/scope"
)

// Result is one validator run.
type Result struct {
	Validator string `json:"validator"`
	Confirmed bool   `json:"confirmed"`
	Detail    string `json:"detail"`
}

// Options caps validator behavior.
type Options struct {
	Timeout time.Duration
}

// Validator is the module interface: title matching + scope-gated,
// read-only confirmation.
type Validator interface {
	Name() string
	Description() string
	// Matches reports whether this validator applies to a finding title.
	Matches(title string) bool
	// Run re-observes the condition. Target is "host:port".
	Run(ctx context.Context, sc *scope.Scope, target string, opts Options) (Result, error)
}

var registry = map[string]Validator{}

// Register adds a validator.
func Register(v Validator) { registry[v.Name()] = v }

// Get returns a validator by name.
func Get(name string) (Validator, error) {
	if v, ok := registry[name]; ok {
		return v, nil
	}
	return nil, fmt.Errorf("unknown validator %q (available: %v)", name, List())
}

// List returns validator names, sorted.
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

// MatchAll returns every validator matching a finding title.
func MatchAll(title string) []Validator {
	var out []Validator
	for _, name := range List() {
		if v := registry[name]; v.Matches(title) {
			out = append(out, v)
		}
	}
	return out
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
