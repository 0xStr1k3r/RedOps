# Roadmap — RedOps phases

- [x] **Phase 1 Foundation**: auth, projects, scope enforcement, timeline, audit, parser schemas, CLI+API, CI
- [x] **Phase 2 Recon**: `Tool` interface + adapters (nmap, httpx, dnsx, subfinder) behind `Enforce()`; SQLite job queue + worker; hosts/services inventory
- [ ] **Phase 3 Enumeration**: http/ssh/smb/dns/ftp/ldap modules → structured results
- [ ] **Phase 4 Findings**: finding store, severity/confidence workflow, CWE/CVE enrichment
- [ ] **Phase 5 MITRE**: full enterprise matrix import, tactic dashboard
- [ ] **Phase 6 Neo4j**: asset/relationship graph sync from Postgres
- [ ] **Phase 7 Attack paths**: BFS with preconditions, states observed→potential→validated→confirmed, scoring
- [ ] **Phase 8 Validation**: lab-only safe checks (headers, SMB guest, default creds on lab fixtures)
- [ ] **Phase 9 Evidence**: command/output capture + screenshots + hash chain
- [ ] **Phase 10 Reporting**: Markdown/HTML/PDF with timeline + ATT&CK coverage
- [ ] **Phase 11 Adversary emulation**: scripted scenarios (web-to-admin, internal) with detection hooks
- [ ] **Phase 12 Cloud**: AWS IAM/EC2/S3 trust-graph paths

Rule: no phase adds tool execution without scope gate + audit + lab containment.
