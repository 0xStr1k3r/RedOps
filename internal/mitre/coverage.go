package mitre

import (
	"fmt"

	"github.com/0xStr1k3r/RedOps/internal/project"
)

// TechniqueHit is one observed technique with evidence counts.
type TechniqueHit struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Tactic   string   `json:"tactic"`
	Count    int      `json:"count"`
	Sources  []string `json:"sources"` // findings | enum | recon
	Findings int      `json:"findings"`
}

// TacticCoverage is one dashboard row.
type TacticCoverage struct {
	Tactic     string         `json:"tactic"`
	Total      int            `json:"total"`
	Seen       int            `json:"seen"`
	Techniques []TechniqueHit `json:"techniques"`
}

// Coverage is the full dashboard payload.
type Coverage struct {
	Tactics []TacticCoverage `json:"tactics"`
	Seen    int              `json:"seen"`
	Total   int              `json:"total"`
}

// reconModuleTechnique maps recon job tools to the technique they demonstrate.
var reconModuleTechnique = map[string]string{
	"nmap": "T1046", "httpx": "T1046", "dnsx": "T1590", "subfinder": "T1590",
}

// ProjectCoverage aggregates technique evidence for one project:
// findings (by technique_id) + enum observations (by technique_id) +
// recon jobs (by module default). Unknown IDs are kept under their raw ID
// with tactic "Unknown" so nothing is silently dropped.
func ProjectCoverage(st *project.Store, projectID string) (Coverage, error) {
	if _, err := st.GetProject(projectID); err != nil {
		return Coverage{}, err
	}
	type acc struct {
		count    int
		sources  map[string]bool
		findings int
	}
	hits := map[string]*acc{}
	add := func(id, source string, isFinding bool) {
		if id == "" {
			return
		}
		a, ok := hits[id]
		if !ok {
			a = &acc{sources: map[string]bool{}}
			hits[id] = a
		}
		a.count++
		a.sources[source] = true
		if isFinding {
			a.findings++
		}
	}
	findingRows, err := st.ListFindings(projectID, project.FindingFilter{})
	if err != nil {
		return Coverage{}, err
	}
	for _, f := range findingRows {
		add(f.TechniqueID, "findings", true)
	}
	enumResults, err := st.ListEnumResults(projectID)
	if err != nil {
		return Coverage{}, err
	}
	for _, r := range enumResults {
		for _, o := range r.Observations {
			add(o.TechniqueID, "enum", false)
		}
	}
	reconJobs, err := st.ListReconJobs(projectID)
	if err != nil {
		return Coverage{}, err
	}
	for _, j := range reconJobs {
		if j.Status != project.JobDone {
			continue
		}
		if tech, ok := reconModuleTechnique[j.Tool]; ok {
			add(tech, "recon", false)
		} else {
			add("T1595", "recon", false)
		}
	}

	var cov Coverage
	for _, tac := range Tactics {
		tc := TacticCoverage{Tactic: tac.Name}
		for _, t := range TechniquesByTactic(tac.Name) {
			tc.Total++
			cov.Total++
			if a, ok := hits[t.ID]; ok {
				tc.Seen++
				cov.Seen++
				var src []string
				for s := range a.sources {
					src = append(src, s)
				}
				// deterministic order
				for i := 0; i < len(src); i++ {
					for j := i + 1; j < len(src); j++ {
						if src[j] < src[i] {
							src[i], src[j] = src[j], src[i]
						}
					}
				}
				tc.Techniques = append(tc.Techniques, TechniqueHit{
					ID: t.ID, Name: t.Name, Tactic: t.Tactic,
					Count: a.count, Sources: src, Findings: a.findings,
				})
				delete(hits, t.ID)
			}
		}
		cov.Tactics = append(cov.Tactics, tc)
	}
	// Leftover IDs not in the embedded matrix (e.g. future imports).
	for id, a := range hits {
		name := id
		if t, ok := Lookup(id); ok {
			name = t.Name
		}
		var src []string
		for s := range a.sources {
			src = append(src, s)
		}
		cov.Tactics = append(cov.Tactics, TacticCoverage{
			Tactic: "Unknown", Total: 1, Seen: 1,
			Techniques: []TechniqueHit{{ID: id, Name: name, Count: a.count, Sources: src, Findings: a.findings}},
		})
		cov.Seen++
		cov.Total++
	}
	if cov.Tactics == nil {
		return Coverage{}, fmt.Errorf("empty matrix")
	}
	return cov, nil
}
