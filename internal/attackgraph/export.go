package attackgraph

import (
	"fmt"
	"sort"
	"strings"
)

// cypherEscape quotes a string for Cypher.
func cypherEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "\\'") + "'"
}

// ToCypher renders MERGE statements replayable in Neo4j Browser.
// Node/edge kinds come from internal constants (allowlisted below), so
// interpolation is safe: Sync validates kinds/types before pushing.
func ToCypher(g *Graph) string {
	var b strings.Builder
	nodes := append([]Node(nil), g.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	for _, n := range nodes {
		label := n.Kind
		props := []string{"id: " + cypherEscape(n.ID)}
		keys := make([]string, 0, len(n.Props))
		for k := range n.Props {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			props = append(props, k+": "+cypherEscape(n.Props[k]))
		}
		fmt.Fprintf(&b, "MERGE (n:%s {id: %s}) SET n += {%s};\n", label, cypherEscape(n.ID), strings.Join(props, ", "))
	}
	edges := append([]Edge(nil), g.Edges...)
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		return edges[i].To < edges[j].To
	})
	for _, e := range edges {
		fmt.Fprintf(&b, "MATCH (a {id: %s}), (b {id: %s}) MERGE (a)-[r:%s {reason: %s}]->(b);\n",
			cypherEscape(e.From), cypherEscape(e.To), e.Type, cypherEscape(e.Reason))
	}
	return b.String()
}

// ToDOT renders Graphviz DOT for quick local visualization.
func ToDOT(g *Graph) string {
	var b strings.Builder
	b.WriteString("digraph redops {\n  rankdir=LR;\n  node [shape=box, style=rounded];\n")
	nodes := append([]Node(nil), g.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	dotID := map[string]string{}
	for i, n := range nodes {
		id := fmt.Sprintf("n%d", i)
		dotID[n.ID] = id
		label := n.Kind
		switch n.Kind {
		case KindHost:
			label = "Host\\n" + n.Props["ip"]
		case KindService:
			label = "Service\\n" + n.Props["host"] + ":" + n.Props["port"]
		case KindFinding:
			label = "Finding\\n" + trunc(n.Props["title"], 28)
		case KindTechnique:
			label = n.Props["technique_id"]
		case KindTarget:
			label = "Target\\n" + n.Props["value"]
		case KindProject:
			label = "Project\\n" + n.Props["name"]
		}
		fmt.Fprintf(&b, "  %s [label=%q];\n", id, label)
	}
	for _, e := range g.Edges {
		fmt.Fprintf(&b, "  %s -> %s [label=%q];\n", dotID[e.From], dotID[e.To], e.Type)
	}
	b.WriteString("}\n")
	return b.String()
}
