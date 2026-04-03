package scope

import "strings"

// blockedHosts are never fetched over HTTP(S) by enumeration or validation,
// even when in scope: cloud instance-metadata endpoints would turn a
// read-only check into credential disclosure into the findings database.
// Recon adapters (nmap banners) are unaffected: they never store page bodies.
var blockedHosts = map[string]bool{
	"169.254.169.254":           true, // AWS / GCP / Azure metadata
	"100.100.100.100":           true, // Alibaba Cloud metadata
	"metadata.google.internal":  true,
	"metadata.google.internal.": true,
	"instance-data":             true,
	"instance-data.":            true,
}

// IsBlockedHost reports whether a hostname/IP must never be HTTP-fetched.
func IsBlockedHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if blockedHosts[h] {
		return true
	}
	// Userinfo or port tricks are stripped by callers via splitTarget, but
	// reject embedded credentials defensively.
	if strings.Contains(h, "@") {
		return true
	}
	return false
}
