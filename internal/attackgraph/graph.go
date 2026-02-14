package attackgraph

// Node kinds. User/Role/Policy power cloud IAM analysis (Phase 12);
// Credential/Group arrive with AD phases.
const (
	KindProject   = "Project"
	KindTarget    = "Target"
	KindHost      = "Host"
	KindService   = "Service"
	KindFinding   = "Finding"
	KindTechnique = "Technique"
	KindUser      = "User"
	KindRole      = "Role"
	KindPolicy    = "Policy"
)

// Edge types with the reason convention from the design:
// every edge carries a human-readable reason.
const (
	EdgeHasTarget  = "HAS_TARGET"  // Project -> Target (scope entry assessed)
	EdgeMatches    = "MATCHES"     // Target -> Host (target observed as host)
	EdgeHasHost    = "HAS_HOST"    // Project -> Host (discovery source)
	EdgeRuns       = "RUNS"        // Host -> Service (port observed open)
	EdgeHasFinding = "HAS_FINDING" // Service|Host|Project -> Finding
	EdgeMapsTo     = "MAPS_TO"     // Finding -> Technique (rule catalog)
	EdgeCanAssume  = "CAN_ASSUME"  // Principal -> Role (trust policy)
	EdgeHasPolicy  = "HAS_POLICY"  // User|Role -> Policy (attachment)
)

// Node is one graph vertex. Props are strings to keep Cypher/DOT simple.
type Node struct {
	ID     string            `json:"id"`
	Kind   string            `json:"kind"`
	Labels []string          `json:"labels"`
	Props  map[string]string `json:"props"`
}

// Edge is one directed, reasoned relationship.
type Edge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

// Graph is the full assessment graph.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// Stats counts nodes per kind.
func (g *Graph) Stats() map[string]int {
	m := map[string]int{}
	for _, n := range g.Nodes {
		m[n.Kind]++
	}
	m["edges"] = len(g.Edges)
	return m
}

// Merge appends another graph's nodes/edges (e.g. cloud IAM over infra).
func Merge(base, extra *Graph) *Graph {
	if extra == nil {
		return base
	}
	out := &Graph{
		Nodes: append(append([]Node(nil), base.Nodes...), extra.Nodes...),
		Edges: append(append([]Edge(nil), base.Edges...), extra.Edges...),
	}
	return out
}
