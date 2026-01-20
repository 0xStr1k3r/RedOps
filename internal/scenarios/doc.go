// Package scenarios runs scripted adversary-emulation playbooks composed of
// existing RedOps engines (recon → enum → raise → validate → paths).
// Every step is scope-checked, read-only, and logged with its ATT&CK
// technique plus a defender detection hint, so the same run serves both
// red (emulation) and blue (detection validation) purposes.
//
// No exploits ship here: steps reuse Phase 2/3/4/8 read-only engines.
package scenarios
