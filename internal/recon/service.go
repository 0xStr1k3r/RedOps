package recon

import (
	"context"
	"fmt"
	"time"

	"github.com/0xStr1k3r/RedOps/internal/evidence"
	"github.com/0xStr1k3r/RedOps/internal/project"
)

// Enqueue validates tool support + scope, then persists a queued job.
func Enqueue(ctx context.Context, st *project.Store, projectID, toolName, target, actor string) (*project.ReconJob, error) {
	tool, err := Get(toolName)
	if err != nil {
		return nil, err
	}
	_ = ctx
	sc, err := st.LoadScope(projectID)
	if err != nil {
		return nil, fmt.Errorf("cannot run recon: project has no valid scope yet (%v)", err)
	}
	if err := sc.Enforce(target); err != nil {
		return nil, err
	}
	typ, _, err := classifyTarget(target)
	if err != nil {
		return nil, err
	}
	if !tool.Supports(typ) {
		return nil, fmt.Errorf("%s does not support %s targets (type %q)", toolName, target, typ)
	}
	return st.EnqueueReconJob(projectID, tool.Name(), target, actor)
}

// RunJob executes one claimed job to completion: scope re-check, tool run,
// parse, asset upsert, evidence + timeline. Terminal state always recorded.
func RunJob(ctx context.Context, st *project.Store, job *project.ReconJob, opts Options) error {
	tool, err := Get(job.Tool)
	if err != nil {
		return st.FinishReconJob(job.ID, project.JobFailed, "", err.Error())
	}
	sc, err := st.LoadScope(job.ProjectID)
	if err != nil {
		_ = st.FinishReconJob(job.ID, project.JobFailed, "", err.Error())
		return err
	}
	// Defense in depth: enforce again at execution time, even though enqueue checked.
	if err := sc.Enforce(job.Target); err != nil {
		_ = st.AppendAudit(job.ProjectID, job.CreatedBy, "recon.denied", job.Target, err.Error())
		_ = st.FinishReconJob(job.ID, project.JobFailed, "", err.Error())
		return err
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Minute
	}
	raw, err := tool.Execute(ctx, sc, job.Target, opts)
	if err != nil {
		// Missing binary and timeouts land here with actionable messages.
		_ = st.FinishReconJob(job.ID, project.JobFailed, "", err.Error())
		_ = st.AppendAudit(job.ProjectID, job.CreatedBy, "recon.failed", job.Target, tool.Name()+": "+err.Error())
		return err
	}
	res, err := tool.Parse(raw)
	if err != nil {
		_ = st.FinishReconJob(job.ID, project.JobFailed, "", "parse: "+err.Error())
		return err
	}
	for _, h := range res.Hosts {
		ip := h.IP
		if ip == "" {
			continue // hostname-only (subfinder) persists after DNS resolution in Phase 3
		}
		_ = st.UpsertHost(job.ProjectID, ip, h.Hostname, h.OS, tool.Name())
	}
	for _, s := range res.Services {
		if s.HostIP == "" || s.Port == 0 {
			continue
		}
		_ = st.UpsertService(job.ProjectID, s.HostIP, s.Port, s.Protocol, s.State, s.Name, s.Product, s.Version)
		_ = st.UpsertHost(job.ProjectID, s.HostIP, "", "", tool.Name())
	}
	ev := evidence.New(job.ProjectID, job.CreatedBy, job.Target, "recon."+tool.Name(), tool.Binary()+" <allowlisted args>", res.Summary, techniqueFor(tool.Name()))
	hash, _ := st.RecordEvidence(job.ProjectID, toEvidenceRow(ev))
	summary := fmt.Sprintf("%s | evidence %s", res.Summary, shortHash(hash))
	_ = st.FinishReconJob(job.ID, project.JobDone, summary, "")
	_ = st.AppendAudit(job.ProjectID, job.CreatedBy, "recon.done", job.Target, summary)
	return nil
}

func techniqueFor(tool string) string {
	switch tool {
	case "nmap", "httpx":
		return "T1046"
	case "dnsx", "subfinder":
		return "T1590"
	default:
		return "T1595"
	}
}

// toEvidenceRow converts without importing cycles (same module family).
func toEvidenceRow(ev *evidence.Evidence) project.EvidenceRow {
	return project.EvidenceRow{
		ID: ev.ID, ProjectID: ev.ProjectID, Timestamp: ev.Timestamp,
		Operator: ev.Operator, Target: ev.Target, Action: ev.Action,
		Command: ev.Command, OutputRef: ev.OutputRef, Technique: ev.Technique,
		FindingID: ev.FindingID,
	}
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
