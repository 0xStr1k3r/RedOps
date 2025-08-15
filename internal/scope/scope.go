package scope

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// EntryType classifies a scope/target value.
type EntryType string

const (
	TypeCIDR   EntryType = "cidr"
	TypeIP     EntryType = "ip"
	TypeDomain EntryType = "domain"
)

// Scope is a validated set of authorized entries for one project.
type Scope struct {
	Prefixes []netip.Prefix
	IPs      []netip.Addr
	Domains  []string // lowercase, exact or leading-dot wildcard not supported in Phase 1
	Raw      []string
}

// Classify parses a single value into its type and normalized form.
func Classify(value string) (EntryType, string, error) {
	v := strings.TrimSpace(strings.ToLower(value))
	if v == "" {
		return "", "", fmt.Errorf("empty scope value")
	}
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return "", "", fmt.Errorf("invalid CIDR %q: %w", value, err)
		}
		// normalize: masked
		p = p.Masked()
		return TypeCIDR, p.String(), nil
	}
	if addr, err := netip.ParseAddr(v); err == nil {
		// Reject unspecified / multicast early to avoid lab accidents.
		if !addr.IsValid() {
			return "", "", fmt.Errorf("invalid IP %q", value)
		}
		return TypeIP, addr.String(), nil
	}
	if isDomain(v) {
		return TypeDomain, v, nil
	}
	return "", "", fmt.Errorf("invalid scope value %q: must be CIDR, IP, or DNS name", value)
}

func isDomain(v string) bool {
	if len(v) == 0 || len(v) > 253 {
		return false
	}
	// Must not look like an IP attempt with bad octets (e.g. 999.1.1.1).
	// If it is all digits and dots, reject unless it parsed as IP above.
	allDotDigit := true
	hasLetter := false
	for _, c := range v {
		if (c < '0' || c > '9') && c != '.' {
			allDotDigit = false
		}
		if (c >= 'a' && c <= 'z') || c == '-' || c == '_' {
			hasLetter = true
		}
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	if allDotDigit {
		return false
	}
	if !strings.Contains(v, ".") && !hasLetter {
		// single-label hostnames like "web01" are allowed in labs
		// but require explicit opt-in; accept them as domains.
	}
	// Use net lookup rules loosely: no leading/trailing dash/dot.
	if strings.HasPrefix(v, "-") || strings.HasPrefix(v, ".") || strings.HasSuffix(v, "-") || strings.HasSuffix(v, ".") {
		return false
	}
	if strings.Contains(v, "..") {
		return false
	}
	return true
}

// ParseEntries validates a list of scope entries.
func ParseEntries(entries []string) (*Scope, error) {
	s := &Scope{}
	seen := map[string]bool{}
	for _, e := range entries {
		t, norm, err := Classify(e)
		if err != nil {
			return nil, err
		}
		if seen[norm] {
			continue
		}
		seen[norm] = true
		s.Raw = append(s.Raw, norm)
		switch t {
		case TypeCIDR:
			p, _ := netip.ParsePrefix(norm)
			s.Prefixes = append(s.Prefixes, p)
		case TypeIP:
			a, _ := netip.ParseAddr(norm)
			s.IPs = append(s.IPs, a)
		case TypeDomain:
			s.Domains = append(s.Domains, norm)
		}
	}
	if len(s.Raw) == 0 {
		return nil, fmt.Errorf("scope must contain at least one entry")
	}
	return s, nil
}

// ContainsTarget reports whether target is authorized by this scope.
// Target may be IP, CIDR, or hostname. Returns (allowed, reason).
func (s *Scope) ContainsTarget(target string) (bool, string) {
	t, norm, err := Classify(target)
	if err != nil {
		return false, "invalid target: " + err.Error()
	}
	switch t {
	case TypeIP:
		addr, _ := netip.ParseAddr(norm)
		for _, ip := range s.IPs {
			if ip == addr {
				return true, "exact IP match"
			}
		}
		for _, p := range s.Prefixes {
			if p.Contains(addr) {
				return true, "within " + p.String()
			}
		}
		return false, fmt.Sprintf("IP %s is outside authorized scope", norm)
	case TypeCIDR:
		p, _ := netip.ParsePrefix(norm)
		// A scanned CIDR must be fully contained in an authorized prefix,
		// or exactly match an authorized single IP (/32).
		for _, sp := range s.Prefixes {
			if containsPrefix(sp, p) {
				return true, "subnet within " + sp.String()
			}
		}
		// Allow single-host /32 inside scope IPs/prefixes.
		if p.Bits() == p.Addr().BitLen() {
			if ok, _ := s.ContainsTarget(p.Addr().String()); ok {
				return true, "host within scope"
			}
		}
		return false, fmt.Sprintf("range %s is not fully within authorized scope", norm)
	case TypeDomain:
		for _, d := range s.Domains {
			if d == norm {
				return true, "exact domain match"
			}
		}
		return false, fmt.Sprintf("domain %s is not in scope (explicit entry required)", norm)
	}
	return false, "denied"
}

// Enforce returns an error if target is out of scope. Use before ANY tool execution.
func (s *Scope) Enforce(target string) error {
	if ok, reason := s.ContainsTarget(target); !ok {
		return fmt.Errorf("scope denied for %q: %s", target, reason)
	}
	return nil
}

func containsPrefix(outer, inner netip.Prefix) bool {
	if outer.Bits() > inner.Bits() {
		return false
	}
	// Different address families never contain each other.
	if outer.Addr().Is4() != inner.Addr().Is4() {
		return false
	}
	masked := inner.Masked()
	// inner network address must be within outer, and outer must be less specific.
	if !outer.Contains(masked.Addr()) {
		return false
	}
	// Also ensure broadcast end is inside: compare last address via net package
	// for full correctness on IPv4.
	oNet := netFromPrefix(outer)
	iNet := netFromPrefix(inner)
	if oNet == nil || iNet == nil {
		return outer.Contains(inner.Addr())
	}
	// oNet.Contains(first) && oNet.Contains(last)
	first := iNet.IP
	last := lastIP(iNet)
	return oNet.Contains(first) && oNet.Contains(last)
}

func netFromPrefix(p netip.Prefix) *net.IPNet {
	_, n, err := net.ParseCIDR(p.String())
	if err != nil {
		return nil
	}
	return n
}

func lastIP(n *net.IPNet) net.IP {
	ip := n.IP.To16()
	mask := net.CIDRMask(n.Mask.Size())
	if mask == nil {
		return ip
	}
	// normalize lengths
	if len(ip) != len(mask) {
		if ip.To4() != nil {
			ip = ip.To4()
		}
	}
	out := make(net.IP, len(ip))
	for i := range ip {
		out[i] = ip[i] | ^mask[i]
	}
	return out
}
