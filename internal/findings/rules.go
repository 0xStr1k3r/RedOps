package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Observation is the rule-engine input: one structured data point from
// recon or enumeration, with the target it was observed on.
type Observation struct {
	Target      string // e.g. "10.10.10.10:80" or "10.10.10.10"
	Kind        string // e.g. http-missing-header, http-robots, ssh-banner
	Detail      string // free text from the module
	TechniqueID string
	Source      string // module name, e.g. http
}

// DedupeKey returns a stable identity for a finding's core content so
// re-raising the same observations never creates duplicates.
func DedupeKey(parts ...string) string {
	norm := strings.ToLower(strings.Join(strings.Fields(strings.Join(parts, "|")), " "))
	h := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(h[:])[:32]
}

// Raise converts observations into draft findings using the deterministic
// rule catalog below. Unknown kinds produce nothing (observations stay
// queryable in enum_results; only actionable items become findings).
func Raise(projectID string, obs []Observation) []Finding {
	var out []Finding
	for _, o := range obs {
		for _, f := range applyRules(projectID, o) {
			f.ID = uuid.NewString()
			f.ProjectID = projectID
			f.Timestamp = time.Now().UTC()
			f.Normalize()
			out = append(out, f)
		}
	}
	return out
}

func applyRules(projectID string, o Observation) []Finding {
	kind := strings.ToLower(o.Kind)
	detail := o.Detail
	target := o.Target
	mk := func(title, desc, severity, confidence, cwe, remediation, technique string) Finding {
		if technique == "" {
			technique = o.TechniqueID
		}
		return Finding{
			Title: title, Description: desc, Severity: severity, Confidence: confidence,
			Target: target, Source: o.Source, CWE: cwe, TechniqueID: technique,
			Remediation: remediation, Status: StatusOpen,
			Evidence: fmt.Sprintf("%s observed: %s", kind, trunc(detail, 200)),
		}
	}
	switch {
	case kind == "http-missing-header" && strings.Contains(strings.ToLower(detail), "strict-transport-security"):
		return []Finding{mk(
			"Missing HTTP Strict-Transport-Security header",
			"HSTS not set on "+target+". First-visit TLS stripping stays possible.",
			SeverityLow, ConfObserved, "CWE-693",
			"Set Strict-Transport-Security: max-age=31536000; includeSubDomains.",
			"T1046")}
	case kind == "http-missing-header" && strings.Contains(strings.ToLower(detail), "content-security-policy"):
		return []Finding{mk(
			"Missing Content-Security-Policy header",
			"No CSP on "+target+". XSS impact is harder to contain.",
			SeverityLow, ConfObserved, "CWE-693",
			"Deploy a restrictive Content-Security-Policy.",
			"T1046")}
	case kind == "http-missing-header" && (strings.Contains(strings.ToLower(detail), "x-frame-options") || strings.Contains(strings.ToLower(detail), "x-content-type-options") || strings.Contains(strings.ToLower(detail), "referrer-policy")):
		return []Finding{mk(
			"Missing security header: "+headerName(detail),
			detail+" on "+target+".",
			SeverityInfo, ConfObserved, "CWE-693",
			"Set the header to a restrictive value.",
			"T1046")}
	case kind == "http-robots":
		f := mk("Exposed robots.txt",
			"robots.txt is reachable on "+target+": "+trunc(detail, 160)+". Review listed paths for sensitive endpoints.",
			SeverityInfo, ConfObserved, "CWE-200",
			"Review robots.txt entries; do not rely on it for access control; remove stale paths.",
			"T1594")
		return []Finding{f}
	case kind == "http-sitemap":
		return []Finding{mk("Exposed sitemap.xml",
			"sitemap.xml reachable on "+target+". Enumerate listed routes for sensitive endpoints.",
			SeverityInfo, ConfObserved, "CWE-200",
			"Review sitemap entries; ensure no non-public routes leak.",
			"T1594")}
	case kind == "http-title" && looksSensitive(detail):
		return []Finding{mk("Potentially sensitive interface exposed",
			fmt.Sprintf("Title %q on %s suggests an admin/login surface. Verify authentication.", trunc(detail, 120), target),
			SeverityLow, ConfPotential, "CWE-200",
			"Confirm the interface requires authentication and is intended to be exposed.",
			"T1594")}
	case kind == "http-server" && hasVersion(detail):
		return []Finding{mk("Server version disclosure",
			"Banner "+trunc(detail, 120)+" on "+target+" aids targeted exploitation.",
			SeverityInfo, ConfObserved, "CWE-200",
			"Minimize Server header / version tokens where policy allows.",
			"T1046")}
	case kind == "http-tls" && isWeakTLS(detail):
		return []Finding{mk("Weak TLS version negotiated",
			detail+" on "+target+". TLS 1.0/1.1 are deprecated.",
			SeverityHigh, ConfObserved, "CWE-327",
			"Disable TLS 1.0/1.1; require TLS 1.2+ with strong ciphers.",
			"T1046")}
	case kind == "ssh-banner" && isSSHv1(detail):
		return []Finding{mk("Deprecated SSHv1 enabled",
			"Banner "+trunc(detail, 120)+" on "+target+" indicates SSH protocol 1, which is broken.",
			SeverityHigh, ConfObserved, "CWE-327",
			"Disable protocol 1; use OpenSSH with Protocol 2 only.",
			"T1046")}
	}
	return nil
}

func headerName(detail string) string {
	// detail looks like "missing X-Frame-Options"
	if i := strings.LastIndex(detail, "missing "); i >= 0 {
		return strings.TrimSpace(detail[i+len("missing "):])
	}
	return detail
}

func looksSensitive(title string) bool {
	t := strings.ToLower(title)
	for _, k := range []string{"admin", "login", "log in", "sign in", "dashboard", "console", "portal", "phpmyadmin", "jenkins", "grafana", "kibana", "router", "firewall", "vpn"} {
		if strings.Contains(t, k) {
			return true
		}
	}
	return false
}

func hasVersion(banner string) bool {
	// e.g. nginx/1.24, Apache/2.4.52, SimpleHTTP/0.6 Python/3.14
	for _, c := range banner {
		if c == '/' {
			return true
		}
	}
	return false
}

func isWeakTLS(detail string) bool {
	d := strings.ToLower(detail)
	return strings.Contains(d, "tls 1.0") || strings.Contains(d, "tls 1.1") || strings.Contains(d, "ssl")
}

func isSSHv1(banner string) bool {
	b := strings.TrimSpace(banner)
	return strings.HasPrefix(b, "SSH-1.")
}

func trunc(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n]
	}
	return s
}
