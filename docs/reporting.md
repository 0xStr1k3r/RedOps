# Reporting — Phase 10 module documentation

Professional assessment reports rendered on demand from current project data.
No stored report copies: output is deterministic for the data at generation
time (re-generate after new activity).

## Formats

| Format | Renderer | Notes |
|---|---|---|
| Markdown | string builder | tables + sections, attaches well to tickets/wikis |
| HTML | `html/template` + inline CSS | severity badges, self-contained, all values escaped |
| PDF | `go-pdf/fpdf` (pure Go) | title block, metrics table, findings, coverage, paths, timeline |

Sections: executive metrics → scope/targets → assets → findings (severity
ranked) → ATT&CK coverage → attack paths (top 10 by risk) → timeline →
evidence integrity → authorized-use footer.

## Run

```bash
redops --db redops.db report generate acme --format pdf --out acme.pdf

curl -X POST .../projects/$PID/report?format=html -H "Authorization: Bearer $TOKEN"
```

API: `POST .../report?format=markdown|html|pdf` (any authenticated role —
reports are read-only artifacts). Correct content types + download filenames.

## Verified (Phase 10 acceptance)

- Seeded store: metrics correct, markdown has all 7 sections, HTML escapes
  hostile finding titles (`<b>` → `&lt;b&gt;`), PDF starts `%PDF` and >2 KB.
- Live chained DB: md 1835 B / html 4024 B / pdf 2663 B, all with real data.
- API: md/html/pdf 200 with correct content types, bad format 400,
  unknown project 404, viewer allowed (read-only).
