# web/ — RedOps GUI (embedded, no build step)

Dark red-team SPA in `dist/` (vanilla HTML/CSS/JS, no Node required):
login + projects, overview metrics, findings, attack paths, ATT&CK matrix,
SVG attack graph, operations (recon/enum/scenarios/cloud), timeline,
evidence ledger, one-click Markdown/HTML/PDF reports.

Served by the API at `/` from an embedded copy (`make sync-web` copies
`web/dist/*` → `internal/api/webdist/`, which is git-ignored).
Edit files here, rebuild with `make build`, hard-refresh the browser.
