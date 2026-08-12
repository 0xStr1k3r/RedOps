# Sigma rules for validating detection coverage against RedOps runs.

These rules describe the **network observables** of authorized RedOps
engagements so blue teams can confirm their SIEM/IDS actually fires:

| File | Technique | What it matches |
|---|---|---|
| `syn_scan_burst.yml` | T1046 Network Service Discovery | many short SYN scans to one host (nmap -sV) |
| `redops_user_agent.yml` | T1594 Search Victim-Owned Websites | `RedOps-lab/1.0` User-Agent hitting /robots.txt or /sitemap.xml |

Usage: import into Sigma-compatible tooling (SigmaHQ, splunk Sigma app,
Elastic detection rules) and run a scenario against the lab sandbox — the
GUI is intentionally fingerprinted by these signatures.

Rules are **experimental** and tuned for lab use; widen filters before
production deployment.

Validating them is part of a RedOps engagement: run a scenario against the
`lab/` sandbox (read-only pipeline, same single binary) and confirm the
SIEM fires. The GUI/User-Agent in these rules is the visible fingerprint
RedOps intentionally leaves on HTTP enumeration.
