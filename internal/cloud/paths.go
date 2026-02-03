package cloud

import (
	"fmt"
	"sort"
	"strings"

	"github.com/redops/redops/internal/attackgraph"
)

// Path is one privilege path to admin (or one over-broad trust warning).
type Path struct {
	Principal string   `json:"principal"` // starting user
	Chain     []string `json:"chain"`     // user → role → … → policy
	Risk      int      `json:"risk"`
	Objective string   `json:"objective"`
	Technique string   `json:"technique"`
}

// FindPaths computes admin-reaching assumption chains plus wildcard-trust
// warnings. Pure function over the validated import (no store, no network).
func FindPaths(imp *Import) []Path {
	// Trust adjacency: principal -> roles it can assume.
	assume := map[string][]string{}
	for _, r := range imp.Roles {
		for _, pr := range r.AssumeFrom {
			assume[pr] = append(assume[pr], r.Name)
		}
	}
	policiesOf := map[string][]string{}
	for _, u := range imp.Users {
		policiesOf["user:"+u.Name] = u.Policies
	}
	for _, r := range imp.Roles {
		policiesOf["role:"+r.Name] = r.Policies
	}

	var out []Path
	// 1. Wildcard trust warnings (anyone can assume).
	for _, r := range imp.Roles {
		for _, pr := range r.AssumeFrom {
			if pr == "*" {
				out = append(out, Path{
					Principal: "*",
					Chain:     []string{"role:" + r.Name},
					Risk:      75,
					Objective: fmt.Sprintf("role %s is assumable by anyone (*)", r.Name),
					Technique: "T1078",
				})
				break
			}
		}
	}
	// 2. Per-user BFS over assumption edges to an admin policy.
	for _, u := range imp.Users {
		start := "user:" + u.Name
		prev := map[string]string{start: ""}
		queue := []string{start}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			name := strings.TrimPrefix(strings.TrimPrefix(cur, "user:"), "role:")
			for _, role := range assume[name] {
				key := "role:" + role
				if _, seen := prev[key]; seen {
					continue
				}
				// Also match bare role-name principals.
				prev[key] = cur
				queue = append(queue, key)
			}
			// "*" trust already warned above; still traversable by named users.
			for _, role := range assume["*"] {
				key := "role:" + role
				if _, seen := prev[key]; seen {
					continue
				}
				prev[key] = cur
				queue = append(queue, key)
			}
		}
		// Any reachable principal with an admin policy = path.
		type hit struct {
			node   string
			policy string
		}
		var hits []hit
		for node := range prev {
			for _, pol := range policiesOf[node] {
				if AllowsAdmin(imp, []string{pol}) {
					hits = append(hits, hit{node, pol})
				}
			}
		}
		sort.Slice(hits, func(i, j int) bool { return hits[i].node < hits[j].node })
		for _, h := range hits {
			chain := reconstruct(prev, start, h.node)
			labels := make([]string, 0, len(chain)+1)
			labels = append(labels, chain...)
			labels = append(labels, "policy:"+h.policy)
			out = append(out, Path{
				Principal: u.Name,
				Chain:     labels,
				Risk:      90,
				Objective: fmt.Sprintf("%s reaches admin via %s", u.Name, h.policy),
				Technique: "T1078",
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Risk != out[j].Risk {
			return out[i].Risk > out[j].Risk
		}
		return out[i].Principal < out[j].Principal
	})
	return out
}

func reconstruct(prev map[string]string, start, target string) []string {
	var chain []string
	for cur := target; cur != ""; cur = prev[cur] {
		chain = append([]string{cur}, chain...)
		if cur == start {
			return chain
		}
	}
	return nil
}

// ToGraphFromDocument parses a stored import document into a graph.
func ToGraphFromDocument(doc string) (*attackgraph.Graph, error) {
	imp, err := ParseImport([]byte(doc))
	if err != nil {
		return nil, err
	}
	return ToGraph(imp), nil
}

// ToGraph converts the import to attack-graph nodes/edges for unified
// visualization (graph show/sync) and reporting.
func ToGraph(imp *Import) *attackgraph.Graph {
	g := &attackgraph.Graph{}
	added := map[string]bool{}
	add := func(id, kind string, props map[string]string) {
		if added[id] {
			return
		}
		added[id] = true
		labels := []string{kind}
		g.Nodes = append(g.Nodes, attackgraph.Node{ID: id, Kind: kind, Labels: labels, Props: props})
	}
	edge := func(from, to, typ, reason string) {
		g.Edges = append(g.Edges, attackgraph.Edge{From: from, To: to, Type: typ, Reason: reason})
	}
	for _, u := range imp.Users {
		id := "user:" + u.Name
		add(id, attackgraph.KindUser, map[string]string{"name": u.Name})
		for _, p := range u.Policies {
			add("policy:"+p, attackgraph.KindPolicy, map[string]string{"name": p, "admin": fmt.Sprint(AllowsAdmin(imp, []string{p}))})
			edge(id, "policy:"+p, attackgraph.EdgeHasPolicy, fmt.Sprintf("user %s has policy %s", u.Name, p))
		}
	}
	for _, r := range imp.Roles {
		id := "role:" + r.Name
		add(id, attackgraph.KindRole, map[string]string{"name": r.Name})
		for _, pr := range r.AssumeFrom {
			// Resolve principals to existing user/role nodes when possible so
			// chains render as user:X -CAN_ASSUME-> role:Y; "*" and unknown
			// externals get explicit principal: anchors (never dangling).
			from := "principal:" + pr
			if pr != "*" {
				for _, u := range imp.Users {
					if u.Name == pr {
						from = "user:" + pr
					}
				}
				for _, r2 := range imp.Roles {
					if r2.Name == pr {
						from = "role:" + pr
					}
				}
			}
			if !added[from] {
				add(from, attackgraph.KindUser, map[string]string{"name": pr})
			}
			edge(from, id, attackgraph.EdgeCanAssume, fmt.Sprintf("%s can assume role %s", pr, r.Name))
		}
		for _, p := range r.Policies {
			add("policy:"+p, attackgraph.KindPolicy, map[string]string{"name": p, "admin": fmt.Sprint(AllowsAdmin(imp, []string{p}))})
			edge(id, "policy:"+p, attackgraph.EdgeHasPolicy, fmt.Sprintf("role %s has policy %s", r.Name, p))
		}
	}
	return g
}
