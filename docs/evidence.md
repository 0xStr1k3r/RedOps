# Evidence — Phase 9 module documentation

Every operation (recon, enum, validation) persists a hash-chained evidence
record. The chain is tamper-evident: any field edit or row deletion breaks
verification at that record.

## Record

`id, project_id, timestamp, operator, target, action, command, output_ref,
technique, finding_id, prev_hash, hash`

```text
hash = SHA256(project|target|action|command|output|timestamp|operator|finding|prev)
```

- `prev_hash` = previous record's hash in the same project (`""` for genesis).
- `RecordEvidence` stamps time before hashing (no zero-time mismatch),
  appends an `evidence.recorded` timeline event, and returns the sealed hash.
- Recon/enum job summaries keep the 12-char hash prefix pointing at the record.

## Chain verification

`VerifyEvidenceChain`: recompute each hash + check `prev_hash` linkage.
`{ok, checked, broken_at?}` — empty chain verifies (`ok, checked 0`).
Unit test tampers one row via SQL and asserts breakage at that exact ID.

## Run

```bash
redops --db redops.db evidence list lab
redops --db redops.db evidence verify lab     # "chain ok (N records)" or breakage error
```

API (auth): `GET .../evidence`, `GET .../evidence/{eid}`,
`GET .../evidence/verify → {ok, checked, broken_at?}`.

## Verified (Phase 9 acceptance)

- Live recon run → record persisted, `evidence list` shows it, `verify` ok.
- SQL tamper of one field → `chain broken at <id>` (exit non-zero CLI).
- API verify `{ok:true, checked:1}`; timeline ends with `evidence.recorded`.
- Chain tests: genesis links `""`, links `prev[i]==hash[i-1]`, tamper pinpoints record.
