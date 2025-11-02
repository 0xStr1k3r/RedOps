package attackgraph

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// allowlisted labels/relationship types: only graph-internal constants reach
// Cypher interpolation. Anything else is rejected before touching the driver.
var allowedKinds = map[string]bool{
	KindProject: true, KindTarget: true, KindHost: true,
	KindService: true, KindFinding: true, KindTechnique: true,
}

var allowedEdges = map[string]bool{
	EdgeHasTarget: true, EdgeMatches: true, EdgeHasHost: true,
	EdgeRuns: true, EdgeHasFinding: true, EdgeMapsTo: true,
}

// ConfigFromEnv reads Neo4j connection settings. Empty URI means unconfigured.
func ConfigFromEnv() (uri, user, pass string) {
	return os.Getenv("REDOPS_NEO4J_URI"), os.Getenv("REDOPS_NEO4J_USER"), os.Getenv("REDOPS_NEO4J_PASS")
}

// Sync pushes the graph to Neo4j with MERGE batches grouped by kind/type.
// Safe for re-runs: MERGE never duplicates nodes or relationships.
func Sync(ctx context.Context, uri, user, pass string, g *Graph) error {
	if uri == "" {
		return fmt.Errorf("neo4j not configured (set REDOPS_NEO4J_URI/USER/PASS)")
	}
	for _, n := range g.Nodes {
		if !allowedKinds[n.Kind] {
			return fmt.Errorf("refusing to sync unknown node kind %q", n.Kind)
		}
	}
	for _, e := range g.Edges {
		if !allowedEdges[e.Type] {
			return fmt.Errorf("refusing to sync unknown edge type %q", e.Type)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, pass, ""))
	if err != nil {
		return fmt.Errorf("neo4j driver: %w", err)
	}
	defer driver.Close(ctx)
	if err := driver.VerifyConnectivity(ctx); err != nil {
		return fmt.Errorf("neo4j unreachable at %s: %w", uri, err)
	}
	sess := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer sess.Close(ctx)

	// One UNWIND batch per node kind (labels cannot be parameterized).
	byKind := map[string][]map[string]any{}
	for _, n := range g.Nodes {
		props := map[string]any{"id": n.ID}
		for k, v := range n.Props {
			props[k] = v
		}
		byKind[n.Kind] = append(byKind[n.Kind], props)
	}
	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		q := fmt.Sprintf("UNWIND $nodes AS p MERGE (n:%s {id: p.id}) SET n += p", kind)
		if _, err := sess.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			_, err := tx.Run(ctx, q, map[string]any{"nodes": byKind[kind]})
			return nil, err
		}); err != nil {
			return fmt.Errorf("sync nodes %s: %w", kind, err)
		}
	}
	// One UNWIND batch per relationship type (types cannot be parameterized).
	byType := map[string][]map[string]any{}
	for _, e := range g.Edges {
		byType[e.Type] = append(byType[e.Type], map[string]any{"from": e.From, "to": e.To, "reason": e.Reason})
	}
	types := make([]string, 0, len(byType))
	for t := range byType {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, typ := range types {
		q := fmt.Sprintf("UNWIND $edges AS e MATCH (a {id: e.from}), (b {id: e.to}) MERGE (a)-[r:%s]->(b) SET r.reason = e.reason", typ)
		if _, err := sess.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			_, err := tx.Run(ctx, q, map[string]any{"edges": byType[typ]})
			return nil, err
		}); err != nil {
			return fmt.Errorf("sync edges %s: %w", typ, err)
		}
	}
	return nil
}
