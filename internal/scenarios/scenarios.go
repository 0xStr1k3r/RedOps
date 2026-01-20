package scenarios

import (
	"fmt"
	"time"
)

// Step kinds reuse engine entry points.
const (
	KindRecon    = "recon"
	KindEnum     = "enum"
	KindRaise    = "raise"
	KindValidate = "validate"
	KindPaths    = "paths"
)

// Step is one playbook action.
type Step struct {
	Name      string        `json:"name"`
	Kind      string        `json:"kind"`
	Tool      string        `json:"tool,omitempty"`      // recon tool or enum module ("" = auto)
	Technique string        `json:"technique,omitempty"` // adversary-mapped steps only
	Detection string        `json:"detection"`           // defender observable hint
	Timeout   time.Duration `json:"-"`
}

// Scenario is a named playbook.
type Scenario struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Steps       []Step `json:"steps"`
}

// Catalog of built-in scenarios.
func Catalog() []Scenario {
	return []Scenario{webToAdmin(), internalNetwork()}
}

// Get returns a scenario by name.
func Get(name string) (Scenario, error) {
	for _, s := range Catalog() {
		if s.Name == name {
			return s, nil
		}
	}
	return Scenario{}, fmt.Errorf("unknown scenario %q", name)
}

func webToAdmin() Scenario {
	return Scenario{
		Name:        "web-to-admin",
		Description: "Web surface to admin surface: scan, enumerate web, raise/validate findings, generate paths.",
		Steps: []Step{
			{Name: "service-discovery", Kind: KindRecon, Tool: "nmap", Technique: "T1046",
				Detection: "Nmap version scan from the RedOps host; alert on SYN bursts + service probes",
				Timeout:   3 * time.Minute},
			{Name: "web-enumeration", Kind: KindEnum, Tool: "http", Technique: "T1594",
				Detection: "Sequential GET /, /robots.txt, /sitemap.xml from one client",
				Timeout:   30 * time.Second},
			{Name: "finding-triage", Kind: KindRaise,
				Detection: "Finding burst in RedOps timeline (platform action, no target traffic)"},
			{Name: "finding-validation", Kind: KindValidate,
				Detection: "Repeat GETs of the same paths (platform re-observation)"},
			{Name: "path-analysis", Kind: KindPaths,
				Detection: "No target traffic (offline graph computation)"},
		},
	}
}

func internalNetwork() Scenario {
	return Scenario{
		Name:        "internal-network",
		Description: "Internal sweep: host/service discovery, banner enumeration, findings, paths.",
		Steps: []Step{
			{Name: "host-discovery", Kind: KindRecon, Tool: "nmap", Technique: "T1046",
				Detection: "Port sweep + version probes across the lab range",
				Timeout:   3 * time.Minute},
			{Name: "banner-enumeration", Kind: KindEnum, Tool: "", Technique: "T1592",
				Detection: "Short TCP connections with banner reads, no auth attempts",
				Timeout:   30 * time.Second},
			{Name: "finding-triage", Kind: KindRaise,
				Detection: "Finding burst in RedOps timeline (platform action)"},
			{Name: "path-analysis", Kind: KindPaths,
				Detection: "No target traffic (offline graph computation)"},
		},
	}
}
