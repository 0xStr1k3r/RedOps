// Package recon executes authorized reconnaissance through allowlisted tool
// adapters (nmap, httpx, dnsx, subfinder). See tool.go for the Tool interface,
// runner.go for the single safe-execution choke point, and service.go for
// queue orchestration. Every execution re-enforces project scope.
package recon
