package insights

import (
	"fmt"
	"sort"

	"github.com/redops/redops/internal/mitre"
	"github.com/redops/redops/internal/project"
)

// Levels order critical first in every rendering.
const (
	LevelCritical = "critical"
	LevelWarn     = "warn"
	LevelInfo     = "info"
)

// Insight is one actionable observation. Link is a GUI hash route.
type Insight struct {
	Level  string `json:"level"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Link   string `json:"link"`
}

// Compute evaluates the rule catalog against current project data.
func Compute(st *project.Store, projectID string) ([]Insight, error) {
	if _, err := st.GetProject(projectID); err != nil {
		return nil, err
	}
	var out []Insight
	add := func(level, title, detail, link string) {
		out = append(out, Insight{Level: level, Title: title, Detail: detail, Link: link})
	}

	scopes, _ := st.ListScopes(projectID)
	targets, _ := st.ListTargets(projectID)
	hosts, _ := st.ListHosts(projectID)
	services, _ := st.ListServices(projectID)
	findings, _ := st.ListFindings(projectID, project.FindingFilter{})
	paths, _ := st.ListAttackPaths(projectID, 0)
	chain := st.VerifyEvidenceChain(projectID)
	cov, _ := mitre.ProjectCoverage(st, projectID)
	reconJobs, _ := st.ListReconJobs(projectID)

	if len(scopes) == 0 {
		add(LevelWarn, "No scope defined", "Targets cannot be added and no engine will run. Define authorized scope first.", "#/projects")
	}
	if len(scopes) > 0 && len(targets) == 0 {
		add(LevelInfo, "Scope set, no targets yet", "Add an in-scope target to start discovery.", "#/projects")
	}
	if len(targets) > 0 && len(hosts) == 0 {
		add(LevelInfo, "No hosts discovered", "Queue a recon scan in Operations (needs the worker running).", "#/ops")
	}
	if len(hosts) > 0 && len(services) == 0 {
		add(LevelInfo, "Hosts up, no services inventoried", "Run service discovery (nmap -sV) to fingerprint ports.", "#/ops")
	}

	var crit, high, open, unvalidatedHigh int
	for _, f := range findings {
		if f.Status == "resolved" || f.Status == "false_positive" {
			continue
		}
		open++
		switch f.Severity {
		case "critical":
			crit++
			if f.Confidence == "observed" || f.Confidence == "potential" {
				unvalidatedHigh++
			}
		case "high":
			high++
			if f.Confidence == "observed" || f.Confidence == "potential" {
				unvalidatedHigh++
			}
		}
	}
	if crit > 0 {
		add(LevelCritical, fmt.Sprintf("%d critical findings open", crit), "Triage immediately; confirm exposure with Validate, then remediate.", "#/findings")
	}
	if high > 0 {
		add(LevelWarn, fmt.Sprintf("%d high findings open", high), "Review and validate before the next window.", "#/findings")
	}
	if unvalidatedHigh > 0 {
		add(LevelWarn, fmt.Sprintf("%d crit/high findings unvalidated", unvalidatedHigh), "Read-only validators can confirm exposure without touching exploit code.", "#/findings")
	}
	if len(findings) > 0 && open == 0 {
		add(LevelInfo, "All findings resolved", "Triage queue is clear. Re-scan periodically to catch drift.", "#/findings")
	}

	unconfirmed := 0
	for _, p := range paths {
		if p.Risk >= 75 && (p.Confidence == "observed" || p.Confidence == "potential") {
			unconfirmed++
		}
	}
	if unconfirmed > 0 {
		add(LevelWarn, fmt.Sprintf("%d high-risk paths unconfirmed", unconfirmed), "Confirm the top chains after verifying each step — the engine never confirms for you.", "#/paths")
	}
	if len(findings) > 0 && len(paths) == 0 {
		add(LevelInfo, "Findings exist but no attack paths", "Generate paths to see how observations chain together.", "#/paths")
	}

	for _, j := range reconJobs {
		if j.Status == project.JobFailed {
			add(LevelWarn, "Recon job failed: "+j.Tool+" on "+j.Target, j.Error, "#/ops")
			break // one is enough to point at tooling/health
		}
	}
	if len(services) > 0 {
		// Blind-spot check: tactics with zero coverage despite activity.
		blind := []string{}
		for _, tac := range []string{"Credential Access", "Lateral Movement", "Persistence"} {
			seen := false
			for _, t := range cov.Tactics {
				if t.Tactic == tac && t.Seen > 0 {
					seen = true
				}
			}
			if !seen {
				blind = append(blind, tac)
			}
		}
		if len(blind) > 0 {
			add(LevelInfo, "ATT&CK blind spots: "+joinPlus(blind), "No observations map here yet — expected before validation, notable after.", "#/attack")
		}
	}

	if !chain.OK {
		add(LevelCritical, "Evidence chain BROKEN", "Verification failed — restore the DB from backup and investigate out-of-band.", "#/evidence")
	} else if chain.Checked == 0 && (len(findings) > 0 || len(hosts) > 0) {
		add(LevelInfo, "No evidence records yet", "Run any engine (recon/enum/validate) to start the tamper-evident ledger.", "#/ops")
	}

	rank := map[string]int{LevelCritical: 0, LevelWarn: 1, LevelInfo: 2}
	sort.Slice(out, func(i, j int) bool { return rank[out[i].Level] < rank[out[j].Level] })
	return out, nil
}

func joinPlus(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += " · "
		}
		out += s
	}
	return out
}
