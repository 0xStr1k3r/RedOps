package report

import (
	"fmt"
	"sort"
	"time"

	"github.com/redops/redops/internal/mitre"
	"github.com/redops/redops/internal/project"
)

// Metrics headline the executive summary.
type Metrics struct {
	Hosts         int  `json:"hosts"`
	Services      int  `json:"services"`
	Findings      int  `json:"findings"`
	Validated     int  `json:"validated"`
	Critical      int  `json:"critical"`
	High          int  `json:"high"`
	Techniques    int  `json:"techniques_seen"`
	TechniquesTot int  `json:"techniques_total"`
	Paths         int  `json:"attack_paths"`
	Evidence      int  `json:"evidence_records"`
	EvidenceOK    bool `json:"evidence_chain_ok"`
}

// Report is the full aggregation consumed by all renderers.
type Report struct {
	Project   project.Project         `json:"project"`
	Scopes    []project.ScopeEntry    `json:"scopes"`
	Targets   []project.Target        `json:"targets"`
	Hosts     []project.Host          `json:"hosts"`
	Services  []project.Service       `json:"services"`
	Findings  []project.FindingRow    `json:"findings"`
	Coverage  mitre.Coverage          `json:"coverage"`
	Paths     []project.StoredPath    `json:"paths"`
	Timeline  []project.TimelineEvent `json:"timeline"`
	Metrics   Metrics                 `json:"metrics"`
	Generated time.Time               `json:"generated_at"`
}

// Generate aggregates everything known about a project. Findings sort by
// severity rank then target; paths arrive risk-ordered from the store.
func Generate(st *project.Store, projectID string) (*Report, error) {
	p, err := st.GetProject(projectID)
	if err != nil {
		return nil, err
	}
	r := &Report{Project: *p, Generated: time.Now().UTC()}
	if r.Scopes, err = st.ListScopes(projectID); err != nil {
		return nil, err
	}
	if r.Targets, err = st.ListTargets(projectID); err != nil {
		return nil, err
	}
	if r.Hosts, err = st.ListHosts(projectID); err != nil {
		return nil, err
	}
	if r.Services, err = st.ListServices(projectID); err != nil {
		return nil, err
	}
	if r.Findings, err = st.ListFindings(projectID, project.FindingFilter{}); err != nil {
		return nil, err
	}
	sort.Slice(r.Findings, func(i, j int) bool {
		if sevRank(r.Findings[i].Severity) != sevRank(r.Findings[j].Severity) {
			return sevRank(r.Findings[i].Severity) > sevRank(r.Findings[j].Severity)
		}
		return r.Findings[i].Target < r.Findings[j].Target
	})
	if r.Coverage, err = mitre.ProjectCoverage(st, projectID); err != nil {
		return nil, err
	}
	if r.Paths, err = st.ListAttackPaths(projectID, 0); err != nil {
		return nil, err
	}
	if len(r.Paths) > 10 {
		r.Paths = r.Paths[:10]
	}
	if r.Timeline, err = st.ListTimeline(projectID); err != nil {
		return nil, err
	}
	chain := st.VerifyEvidenceChain(projectID)
	evidence, err := st.ListEvidence(projectID)
	if err != nil {
		return nil, err
	}
	m := Metrics{
		Hosts: len(r.Hosts), Services: len(r.Services), Findings: len(r.Findings),
		Techniques: r.Coverage.Seen, TechniquesTot: r.Coverage.Total,
		Paths: len(r.Paths), Evidence: len(evidence), EvidenceOK: chain.OK,
	}
	for _, f := range r.Findings {
		switch f.Severity {
		case "critical":
			m.Critical++
		case "high":
			m.High++
		}
		if f.Confidence == "validated" || f.Confidence == "confirmed" {
			m.Validated++
		}
	}
	r.Metrics = m
	return r, nil
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func sevLabel(s string) string {
	if s == "" {
		return "info"
	}
	return s
}

func fmtTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

var _ = fmt.Sprint
