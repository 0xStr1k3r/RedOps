// Package worker polls the SQLite job queues (recon + enum) and executes
// scope-checked jobs. Used by both the standalone worker binary and the
// single-binary `redops worker` subcommand.
package worker

import (
	"context"
	"log"
	"time"

	"github.com/redops/redops/internal/enumeration"
	"github.com/redops/redops/internal/project"
	"github.com/redops/redops/internal/recon"
)

// RunOnce claims and executes at most one recon job and one enum job.
func RunOnce(st *project.Store) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	if job, err := st.ClaimNextJob(); err != nil {
		log.Printf("recon claim error: %v", err)
	} else if job != nil {
		log.Printf("running %s on %s (recon job %s)", job.Tool, job.Target, job.ID)
		if err := recon.RunJob(ctx, st, job, recon.Options{}); err != nil {
			log.Printf("recon job %s failed: %v", job.ID, err)
		} else {
			log.Printf("recon job %s done", job.ID)
		}
	}
	if ejob, err := st.ClaimNextEnumJob(); err != nil {
		log.Printf("enum claim error: %v", err)
	} else if ejob != nil {
		log.Printf("running %s on %s:%d (enum job %s)", ejob.Module, ejob.HostIP, ejob.Port, ejob.ID)
		if err := enumeration.RunJob(ctx, st, ejob, enumeration.Options{}); err != nil {
			log.Printf("enum job %s failed: %v", ejob.ID, err)
		} else {
			log.Printf("enum job %s done", ejob.ID)
		}
	}
}

// Loop polls forever until ctx is done.
func Loop(ctx context.Context, st *project.Store, interval time.Duration) {
	log.Printf("worker polling every %s (adapters: %v)", interval, recon.List())
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		RunOnce(st)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
