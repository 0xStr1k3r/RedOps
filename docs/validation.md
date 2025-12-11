# Validation — Phase 8 module documentation

Controlled, read-only re-observation of finding evidence. A validator confirms
the condition **still holds** and promotes the finding to `validated`.
Failed runs never demote (may be transient) — the operator decides via the
findings workflow.

## Design rules (public-repo safety)

- Read-only: HTTP GET, TLS handshake, banner read. No auth, no brute force,
  no payloads, no state changes on target.
- Scope-gated twice: finding host must be in project scope at run time
  (finding created earlier does not imply still-authorized).
- Exposure ≠ exploitability: validation promotes **findings** only.
  Attack paths still need operator `confirm` (Phase 7).
- Every run is an immutable `validation_runs` row + timeline + audit.

## Validators

| Name | Applies to (title match) | Check |
|---|---|---|
| `http-security-headers` | "missing … header" | re-GET page, header still absent → confirm |
| `http-robots` | "robots.txt" | re-GET /robots.txt, 200 + body → confirm |
| `http-sensitive-interface` | "sensitive interface" | re-GET, 200 + sensitive markers → confirm |
| `http-version-disclosure` | "version disclosure" | re-GET, Server still has version → confirm |
| `tls-version` | "weak tls" | handshake only, still TLS 1.0/1.1/SSL → confirm (port 80 findings imply 443) |
| `ssh-version` | "sshv1"/"ssh1" | banner read only, still SSH-1.x → confirm (port 80 findings imply 22) |

No validator matches (e.g. DNS observations, generic banners) → clear error,
finding untouched. Deliberately absent: credential checks, injection probes,
SMB session checks — lab-fixture-gated Phase 8+ work, not this repo.

## Run

```bash
redops --db redops.db validate validators
redops --db redops.db validate finding acme <id-prefix>

curl -X POST .../projects/$PID/findings/$FID/validate -H "Authorization: Bearer $TOKEN"
# {"results":[{"validator":"http-robots","confirmed":true,"detail":"..."}],"promoted":true}
curl .../projects/$PID/findings/$FID/validations -H "Authorization: Bearer $TOKEN"
```

API: `GET /validators`, `POST .../findings/{fid}/validate` (operator),
`GET .../findings/{fid}/validations`.

## Verified (Phase 8 acceptance)

- httptest target: headers/robots/interface confirm; versionless banner does NOT confirm.
- TLS 1.0 test server confirms; modern TLS server does not (skipped only if the
  runtime cannot negotiate 1.0 at all).
- SSH-2.0 banner does NOT confirm SSHv1.
- Out-of-scope target refused before connecting; unmatched finding errors clearly.
- Live: robots finding → `confirmed=true`, `promoted=true`, confidence `validated` in store.
- API: validate → promote → runs listed; viewer validate → 403.
