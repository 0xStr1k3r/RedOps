package mitre

import (
	"fmt"
	"strings"

	"github.com/redops/redops/internal/project"
)

// LayerTechnique is one Navigator cell.
type LayerTechnique struct {
	TechniqueID string `json:"techniqueID"`
	Score       int    `json:"score"`
	Color       string `json:"color,omitempty"`
	Comment     string `json:"comment,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// Layer is a minimal MITRE Navigator v4.5 layer: opens directly at
// mitre-attack.github.io/attack-navigator via "open existing layer".
type Layer struct {
	Name     string `json:"name"`
	Versions struct {
		Attack    string `json:"attack"`
		Navigator string `json:"navigator"`
		Layer     string `json:"layer"`
	} `json:"versions"`
	Domain      string           `json:"domain"`
	Description string           `json:"description"`
	Techniques  []LayerTechnique `json:"techniques"`
}

// scoreColor maps evidence count to a red intensity (Navigator-style heat).
func scoreColor(count, max int) string {
	if max <= 0 {
		max = 1
	}
	f := float64(count) / float64(max)
	r := 229
	g := int(230 - f*180)
	b := int(230 - f*190)
	if g < 40 {
		g = 40
	}
	if b < 40 {
		b = 40
	}
	return fmt.Sprintf("#%02x%02x%02x", r, g, b)
}

// ToLayer converts project coverage to a Navigator layer. Score = evidence
// count per technique; blind spots are simply absent (grey in Navigator).
func ToLayer(st *project.Store, projectID string) (*Layer, error) {
	p, err := st.GetProject(projectID)
	if err != nil {
		return nil, err
	}
	cov, err := ProjectCoverage(st, projectID)
	if err != nil {
		return nil, err
	}
	max := 1
	for _, tac := range cov.Tactics {
		for _, h := range tac.Techniques {
			if h.Count > max {
				max = h.Count
			}
		}
	}
	l := &Layer{Name: "RedOps " + p.Name, Domain: "enterprise-attack",
		Description: fmt.Sprintf("RedOps observed %d techniques. Scores = evidence counts.", cov.Seen)}
	l.Versions.Attack = "v16"
	l.Versions.Navigator = "4.5"
	l.Versions.Layer = "4.5"
	for _, tac := range cov.Tactics {
		for _, h := range tac.Techniques {
			l.Techniques = append(l.Techniques, LayerTechnique{
				TechniqueID: h.ID, Score: h.Count, Color: scoreColor(h.Count, max),
				Comment: fmt.Sprintf("%s · ×%d from %s · %d linked findings",
					h.Name, h.Count, strings.Join(h.Sources, ","), h.Findings),
				Enabled: true,
			})
		}
	}
	if l.Techniques == nil {
		l.Techniques = []LayerTechnique{}
	}
	return l, nil
}
