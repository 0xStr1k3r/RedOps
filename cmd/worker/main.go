// Command worker polls the SQLite job queue and runs scope-checked recon.
// It shares the loop with the single-binary `redops worker` subcommand.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0xStr1k3r/RedOps/internal/project"
	"github.com/0xStr1k3r/RedOps/internal/worker"
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
	st, err := project.Open(dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer st.Close()
	if os.Getenv("REDOPS_WORKER_ONCE") != "" {
		worker.RunOnce(st)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	worker.Loop(ctx, st, interval)
}
