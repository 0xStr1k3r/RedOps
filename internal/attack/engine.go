package attack

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/0xStr1k3r/RedOps/internal/attackgraph"
	"github.com/0xStr1k3r/RedOps/internal/project"
)

// Options bounds enumeration.
type Options struct {
	MaxPaths  int // default 50
	MaxLength int // default 8 hops
	MinRisk   int // filter applied by callers (API/CLI), not the engine
}

func (o Options) withDefaults() Options {
	if o.MaxPaths <= 0 {
		o.MaxPaths = 50
	}
	if o.MaxLength <= 0 {
		o.MaxLength = 8
	}
	return o
}

// FindPaths enumerates shortest entry→objective paths over the graph.
// Entries: Target + Host nodes. Objectives: Finding nodes (extended one hop
// to their Technique when present). One shortest path per entry→objective
// pair keeps output bounded and reviewable.
func FindPaths(g *attackgraph.Graph, st *project.Store, projectID string, opts Options) []Path {
	opts = opts.withDefaults()
	adj := map[string][]attackgraph.Edge{}
	for _, e := range g.Edges {
		adj[e.From] = append(adj[e.From], e)
	}
	nodes := map[string]attackgraph.Node{}
	for _, n := range g.Nodes {
		nodes[n.ID] = n
	}
	// Finding severity lookup for scoring/objectives.
	sevOf := map[string]string{}
	for _, n := range g.Nodes {
		if n.Kind == attackgraph.KindFinding {
			sevOf[n.ID] = strings.ToLower(n.Props["severity"])
		}
	}

	var entries []string
	for _, n := range g.Nodes {
		if n.Kind == attackgraph.KindTarget || n.Kind == attackgraph.KindHost {
			entries = append(entries, n.ID)
		}
	}
	sort.Strings(entries)

	var out []Path
	for _, entry := range entries {
		// BFS shortest paths from entry.
		prev := map[string]string{entry: ""}
		queue := []string{entry}
		for len(queue) > 0 && len(out) < opts.MaxPaths {
			cur := queue[0]
			queue = queue[1:]
			for _, e := range adj[cur] {
				if _, seen := prev[e.To]; seen {
					continue
				}
				// Depth guard: path via cur would be depth(cur)+1 hops.
				if depth(prev, cur)+1 > opts.MaxLength {
					continue
				}
				prev[e.To] = cur
				queue = append(queue, e.To)
			}
		}
		// Emit one path per reachable finding (+ technique extension).
		var findings []string
		for id := range prev {
			if id != entry {
				if n, ok := nodes[id]; ok && n.Kind == attackgraph.KindFinding {
					findings = append(findings, id)
				}
			}
		}
		sort.Strings(findings)
		for _, fid := range findings {
			chain := reconstruct(prev, entry, fid)
			if len(chain) == 0 {
				continue
			}
			out = append(out, buildPath(projectID, chain, nodes, sevOf, ""))
			if len(out) >= opts.MaxPaths {
				break
			}
			// Extend through MAPS_TO to the technique as its own path.
			for _, e := range adj[fid] {
				if tn, ok := nodes[e.To]; ok && tn.Kind == attackgraph.KindTechnique {
					ext := append(append([]string(nil), chain...), e.To)
					out = append(out, buildPath(projectID, ext, nodes, sevOf, nodes[fid].Props["title"]+" → "+tn.Props["technique_id"]))
					break
				}
			}
			if len(out) >= opts.MaxPaths {
				break
			}
		}
		if len(out) >= opts.MaxPaths {
			break
		}
	}
	// Sort by risk desc, then length asc.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Risk != out[j].Risk {
			return out[i].Risk > out[j].Risk
		}
		return out[i].Length < out[j].Length
	})
	if len(out) > opts.MaxPaths {
		out = out[:opts.MaxPaths]
	}
	return out
}

func depth(prev map[string]string, id string) int {
	d := 0
	for cur := id; prev[cur] != ""; cur = prev[cur] {
		d++
	}
	return d
}

func reconstruct(prev map[string]string, entry, target string) []string {
	var chain []string
	for cur := target; cur != ""; cur = prev[cur] {
		chain = append([]string{cur}, chain...)
		if cur == entry {
			return chain
		}
	}
	return nil
}

func buildPath(projectID string, chain []string, nodes map[string]attackgraph.Node, sevOf map[string]string, objective string) Path {
	pnodes := make([]PathNode, 0, len(chain))
	var techniques []string
	techSet := map[string]bool{}
	findingCount := 0
	terminalSev := "info"
	var privs []string
	for _, id := range chain {
		n := nodes[id]
		pnodes = append(pnodes, PathNode{Kind: n.Kind, ID: id, Label: nodeLabel(n)})
		switch n.Kind {
		case attackgraph.KindFinding:
			findingCount++
			if s := sevOf[id]; s != "" {
				terminalSev = s
			}
		case attackgraph.KindTechnique:
			if tid := n.Props["technique_id"]; tid != "" && !techSet[tid] {
				techSet[tid] = true
				techniques = append(techniques, tid)
			}
		case attackgraph.KindService:
			privs = append(privs, fmt.Sprintf("network-access %s:%s", n.Props["host"], n.Props["port"]))
		}
	}
	sort.Strings(techniques)
	confidence := ConfObserved
	if findingCount >= 2 {
		confidence = ConfPotential
	}
	// Chained findings also lift confidence: correlated observations.
	if len(techniques) >= 2 && confidence == ConfObserved {
		confidence = ConfPotential
	}
	if objective == "" {
		// Objective is the terminal finding title.
		for i := len(chain) - 1; i >= 0; i-- {
			if nodes[chain[i]].Kind == attackgraph.KindFinding {
				objective = nodes[chain[i]].Props["title"]
				break
			}
		}
	}
	return Path{
		ID:                 uuid.NewString(),
		ProjectID:          projectID,
		Nodes:              pnodes,
		Length:             len(chain) - 1,
		Risk:               Score(terminalSev, len(techniques), len(chain)-1),
		Confidence:         confidence,
		Techniques:         techniques,
		RequiredPrivileges: privs,
		Objective:          objective,
	}
}

func nodeLabel(n attackgraph.Node) string {
	switch n.Kind {
	case attackgraph.KindTarget:
		return "target " + n.Props["value"]
	case attackgraph.KindHost:
		return "host " + n.Props["ip"]
	case attackgraph.KindService:
		return "service " + n.Props["host"] + ":" + n.Props["port"]
	case attackgraph.KindFinding:
		return "finding [" + n.Props["severity"] + "] " + n.Props["title"]
	case attackgraph.KindTechnique:
		return "technique " + n.Props["technique_id"]
	case attackgraph.KindProject:
		return "project " + n.Props["name"]
	default:
		return n.ID
	}
}
