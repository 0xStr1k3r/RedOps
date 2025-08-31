// Command worker is a Phase-1 stub: it will consume the Redis job queue
// (recon/enumeration/validation jobs) in Phase 2+. It currently just logs
// that the queue is not yet configured, so deployments stay healthy.
package main

import (
	"log"
	"os"
	"time"
)

func main() {
	log.Println("redops-worker starting (Phase 1: no queue yet, idle loop)")
	tick := time.NewTicker(60 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			log.Println("redops-worker heartbeat: queue not configured (Phase 2)")
			if os.Getenv("REDOPS_WORKER_ONCE") != "" {
				return
			}
		}
	}
}
