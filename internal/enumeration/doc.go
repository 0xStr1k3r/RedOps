// Package enumeration runs service-specific data collection against
// already-discovered assets. Every run re-enforces project scope on the
// service host before opening any connection, uses short timeouts, and
// performs read-only fetches (no brute force, no exploits).
//
// Modules: http (full), ssh-banner, dns, tcp-banner (fallback).
// smb/ftp/ldap/snmp intrusive checks are deferred to lab-contained Phase 8.
package enumeration
