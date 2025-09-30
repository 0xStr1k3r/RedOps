package enumeration

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redops/redops/internal/evidence"
	"github.com/redops/redops/internal/project"
)

// Enqueue validates the service, picks a module (explicit or auto-match),
// scope-checks the host, and persists a queued job.
func Enqueue(ctx context.Context, st *project.Store, projectID, host string, port int, module, actor string) (*project.EnumJob, error) {
	_ = ctx
	host = strings.TrimSpace(host)
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}
	sc, err := st.LoadScope(projectID)
	if err != nil {
		return nil, fmt.Errorf("cannot enumerate: project has no valid scope yet (%v)", err)
	}
	if err := sc.Enforce(host); err != nil {
		return nil, err
	}
	svc := ServiceRef{HostIP: host, Port: port}
	if module == "" {
		// Auto-match against the discovered inventory when possible.
		if svcs, err := st.ListServices(projectID); err == nil {
			for _, s := range svcs {
				if s.HostIP == host && s.Port == port {
					svc.Name = s.Name
					break
				}
			}
		}
		module = Match(svc)
		if module == "" {
			return nil, fmt.Errorf("no enumeration module handles %s:%d", host, port)
		}
	} else {
		if _, err := Get(module); err != nil {
			return nil, err
		}
	}
	return st.EnqueueEnumJob(projectID, host, port, module, actor)
}

// RunJob executes one claimed job: scope re-check, module run, result persist,
// evidence + audit. Terminal state always recorded.
func RunJob(ctx context.Context, st *project.Store, job *project.EnumJob, opts Options) error {
	mod, err := Get(job.Module)
	if err != nil {
		return st.FinishEnumJob(job.ID, project.JobFailed, "", err.Error())
	}
	sc, err := st.LoadScope(job.ProjectID)
	if err != nil {
		_ = st.FinishEnumJob(job.ID, project.JobFailed, "", err.Error())
		return err
	}
	if err := sc.Enforce(job.HostIP); err != nil {
		_ = st.AppendAudit(job.ProjectID, job.CreatedBy, "enum.denied", job.HostIP, err.Error())
		_ = st.FinishEnumJob(job.ID, project.JobFailed, "", err.Error())
		return err
	}
	svc := ServiceRef{HostIP: job.HostIP, Port: job.Port}
	if svcs, err := st.ListServices(job.ProjectID); err == nil {
		for _, s := range svcs {
			if s.HostIP == job.HostIP && s.Port == job.Port {
				svc.Name = s.Name
				svc.Hostname = ""
				break
			}
		}
	}
	if hosts, err := st.ListHosts(job.ProjectID); err == nil {
		for _, h := range hosts {
			if h.IP == job.HostIP && h.Hostname != "" {
				svc.Hostname = h.Hostname
				break
			}
		}
	}
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	res, err := mod.Enumerate(ctx, sc, svc, opts)
	if err != nil {
		_ = st.FinishEnumJob(job.ID, project.JobFailed, "", err.Error())
		_ = st.AppendAudit(job.ProjectID, job.CreatedBy, "enum.failed", fmt.Sprintf("%s:%d", job.HostIP, job.Port), mod.Name()+": "+err.Error())
		return err
	}
	if err := st.SaveEnumResult(job.ProjectID, job.ID, job.HostIP, job.Port, res.Module, res.Summary, toStored(res.Observations)); err != nil {
		_ = st.FinishEnumJob(job.ID, project.JobFailed, "", err.Error())
		return err
	}
	ev := evidence.New(job.ProjectID, job.CreatedBy, fmt.Sprintf("%s:%d", job.HostIP, job.Port), "enum."+res.Module, res.Module+" read-only fetch", res.Summary, techniqueOf(res))
	summary := fmt.Sprintf("%s | evidence %s", res.Summary, ev.Hash[:12])
	_ = st.FinishEnumJob(job.ID, project.JobDone, summary, "")
	_ = st.AppendAudit(job.ProjectID, job.CreatedBy, "enum.done", fmt.Sprintf("%s:%d", job.HostIP, job.Port), summary)
	return nil
}

func techniqueOf(res Result) string {
	if len(res.Observations) > 0 {
		return res.Observations[0].TechniqueID
	}
	return "T1595"
}

// toStored converts observations without importing project types back
// (project must not import enumeration).
func toStored(obs []Observation) []project.EnumObservation {
	out := make([]project.EnumObservation, 0, len(obs))
	for _, o := range obs {
		out = append(out, project.EnumObservation{Kind: o.Kind, Detail: o.Detail, TechniqueID: o.TechniqueID})
	}
	return out
}
