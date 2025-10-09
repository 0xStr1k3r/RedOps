// Package mitre ships a minimal embedded ATT&CK subset for Phase 1.
// Later phases load the full enterprise matrix from TAXII/CTI JSON.
package mitre

// Technique is a tactic/technique pair.
type Technique struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Tactic   string `json:"tactic"`
	Platform string `json:"platform,omitempty"`
	Summary  string `json:"summary,omitempty"`
}

// Subset covers the techniques RedOps Phase 1-3 actually emits.
var Techniques = []Technique{
	{"T1595", "Active Scanning", "Reconnaissance", "Pre", "Scanning authorized targets to discover hosts/services."},
	{"T1590", "Gather Victim Network Information", "Reconnaissance", "Pre", "DNS/IP collection within scope."},
	{"T1046", "Network Service Discovery", "Discovery", "All", "Nmap/httpx service enumeration."},
	{"T1018", "Remote System Discovery", "Discovery", "All", "Host discovery in lab network."},
	{"T1592", "Gather Victim Host Information", "Reconnaissance", "Pre", "OS/service fingerprinting."},
	{"T1003", "OS Credential Dumping", "Credential Access", "Windows/Linux", "LAB-ONLY simulated credential discovery."},
	{"T1552", "Unsecured Credentials", "Credential Access", "All", "Exposed creds in files/configs (lab)."},
	{"T1078", "Valid Accounts", "Persistence/Privilege Escalation", "All", "Use of lab-provided accounts."},
	{"T1021", "Remote Services", "Lateral Movement", "All", "SMB/RDP/SSH simulation in lab."},
	{"T1482", "Domain Trust Discovery", "Discovery", "Windows", "AD trust mapping (future)."},
	{"T1083", "File and Directory Discovery", "Discovery", "All", "Web path/robost enumeration."},
	{"T1135", "Network Share Discovery", "Discovery", "Windows", "SMB share enumeration (lab)."},
	{"T1594", "Search Victim-Owned Websites", "Reconnaissance", "Pre", "robots/sitemap analysis."},
}

var byID = func() map[string]Technique {
	m := map[string]Technique{}
	for _, t := range Techniques {
		m[t.ID] = t
	}
	return m
}()

// Lookup returns a technique by ID.
func Lookup(id string) (Technique, bool) { t, ok := byID[id]; return t, ok }

// MapObservation maps an engine observation to a technique ID.
// Deterministic rules only; LLM explanation is a later optional layer.
func MapObservation(observation string) string {
	switch observation {
	case "port-open", "service-banner", "http-tech", "http-title", "http-server", "http-status", "ssh-banner":
		return "T1046"
	case "host-up":
		return "T1018"
	case "dns-record":
		return "T1590"
	case "http-robots", "http-sitemap", "web-path":
		return "T1594"
	case "smb-share":
		return "T1135"
	case "exposed-credential":
		return "T1552"
	default:
		return "T1595"
	}
}
