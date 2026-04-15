// Command server runs the RedOps Phase-1 REST API.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/redops/redops/internal/api"
	"github.com/redops/redops/internal/project"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	dbPath := env("REDOPS_DB", "redops.db")
	addr := env("REDOPS_ADDR", ":8080")
	secret := os.Getenv("REDOPS_JWT_SECRET")
	if secret == "" || len(secret) < 32 {
		log.Fatal("REDOPS_JWT_SECRET must be set (>= 32 chars)")
	}
	st, err := project.Open(dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer st.Close()

	h := api.NewRouter(api.Config{Store: st, JWTSecret: secret, TokenTTL: 12 * time.Hour})
	log.Printf("redops-api listening on %s (db=%s)", addr, dbPath)
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
