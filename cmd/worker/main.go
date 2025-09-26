// Command worker polls the SQLite job queue and runs scope-checked recon.
// Phase 2 uses SQLite as the queue (same DB as the API); Phase 6 migrates to Redis
// without changing the Tool interface. Poll interval and single-pass mode via env.
package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/redops/redops/internal/project"
	"github.com/redops/redops/internal/recon"
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	dbPath := envOr("REDOPS_DB", "redops.db")
	interval := 5 * time.Second
	if v := os.Getenv("REDOPS_WORKER_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			interval = d
		}
	}
	once := os.Getenv("REDOPS_WORKER_ONCE") != ""
	st, err := project.Open(dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer st.Close()
	log.Printf("redops-worker polling %s every %s (adapters: %v)", dbPath, interval, recon.List())
	if once {
		runOnce(st)
		return
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		runOnce(st)
		<-tick.C
	}
}

func runOnce(st *project.Store) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	job, err := st.ClaimNextJob()
	if err != nil {
		log.Printf("claim error: %v", err)
		return
	}
	if job == nil {
		return
	}
	log.Printf("running %s on %s (job %s)", job.Tool, job.Target, job.ID)
	if err := recon.RunJob(ctx, st, job, recon.Options{}); err != nil {
		log.Printf("job %s failed: %v", job.ID, err)
		return
	}
	log.Printf("job %s done", job.ID)
}
