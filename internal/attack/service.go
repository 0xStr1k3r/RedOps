package attack

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/redops/redops/internal/attackgraph"
	"github.com/redops/redops/internal/project"
)

// Generate rebuilds all attack paths for a project from the current graph
// and persists them (replace semantics). Returns the path count.
func Generate(ctx context.Context, st *project.Store, projectID, actor string, opts Options) (int, error) {
	_ = ctx
	g, err := attackgraph.Build(st, projectID)
	if err != nil {
		return 0, err
	}
	paths := FindPaths(g, st, projectID, opts)
	stored := make([]project.StoredPath, 0, len(paths))
	for _, p := range paths {
		raw, err := json.Marshal(p.Nodes)
		if err != nil {
			return 0, err
		}
		stored = append(stored, project.StoredPath{
			ID: p.ID, ProjectID: projectID, NodesJSON: string(raw),
			Length: p.Length, Risk: p.Risk, Confidence: p.Confidence,
			Techniques: strings.Join(p.Techniques, ","), Objective: p.Objective,
			Privileges: strings.Join(p.RequiredPrivileges, ";"),
		})
	}
	if err := st.ReplaceAttackPaths(projectID, stored); err != nil {
		return 0, err
	}
	_ = st.AppendAudit(projectID, actor, "attackpaths.generate", "", fmt.Sprintf("%d paths", len(stored)))
	return len(stored), nil
}
