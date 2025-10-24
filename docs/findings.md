# Findings — Phase 4 module documentation

Normalized, deduplicated security findings raised deterministically from
recon/enumeration observations, plus operator-created manual findings.

## Schema

`id, project_id, title, description, severity, confidence, target, evidence,
source, cwe, cve, technique_id, remediation, status, created_at, updated_at`

- **Severity** (impact if true): info < low < medium < high < critical.
- **Confidence** (how sure): observed < potential < validated < confirmed.
  Auto-raised rules start at `observed` (`potential` for heuristic matches);
  operators promote to `validated`/`confirmed` after manual verification.
- **Status** (workflow): open → acknowledged → resolved | false_positive.

## Rule catalog (deterministic, no LLM)

| Observation | Finding | Sev | CWE | Technique |
|---|---|---|---|---|
| missing CSP header | Missing Content-Security-Policy | low | CWE-693 | T1046 |
| missing HSTS header | Missing Strict-Transport-Security | low | CWE-693 | T1046 |
| missing X-Frame-Options / X-Content-Type-Options / Referrer-Policy | Missing security header | info | CWE-693 | T1046 |
| robots.txt reachable | Exposed robots.txt | info | CWE-200 | T1594 |
| sitemap.xml reachable | Exposed sitemap.xml | info | CWE-200 | T1594 |
| title ~ admin/login/dashboard/console/... | Potentially sensitive interface exposed | low (`potential`) | CWE-200 | T1594 |
| Server banner with version token | Server version disclosure | info | CWE-200 | T1046 |
| TLS 1.0/1.1/SSL negotiated | Weak TLS version | high | CWE-327 | T1046 |
| SSH-1.x banner | Deprecated SSHv1 enabled | high | CWE-327 | T1046 |

Non-matching observations (plain banners, DNS records, 200 OK pages) stay
in `enum_results` but raise nothing — findings are signal, not logs.

## Dedupe

Key = SHA-256 hex (32) over `target|title|evidence`. Re-running `raise`
after new scans adds only genuinely new items (`ON CONFLICT DO NOTHING`).

## Run

```bash
redops --db redops.db findings raise acme        # from all enum results
redops --db redops.db findings list acme --severity low --status open
redops --db redops.db findings update acme <id-prefix> --status acknowledged --confidence validated

curl -X POST .../projects/$PID/findings/raise -H "Authorization: Bearer $TOKEN"  # {"raised": N}
curl ".../projects/$PID/findings?severity=high&status=open" -H "Authorization: Bearer $TOKEN"
```

Manual findings: `POST .../findings` with title/severity/confidence/target
(+ optional CWE/CVE/remediation/technique). Operator role required for all writes.

## Verified (Phase 4 acceptance)

- Live enum of test server → `raise` produced 8 findings (CSP+HSTS low,
  3× info headers, robots info, version-disclosure info, admin-title low/potential).
- Second `raise` → 0 new (idempotent).
- Rule unit tests: 15 kind/detail cases incl. negative cases (plain title,
  versionless banner, TLS 1.2, SSH-2.0 raise nothing).
- API flow: manual create → filter → patch → invalid patch 400 → viewer write 403.
