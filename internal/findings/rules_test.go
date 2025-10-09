package findings

import (
	"strings"
	"testing"
)

func TestRuleCatalog(t *testing.T) {
	cases := []struct {
		kind     string
		detail   string
		wantN    int
		severity string
		cwe      string
	}{
		{"http-missing-header", "missing Content-Security-Policy", 1, SeverityLow, "CWE-693"},
		{"http-missing-header", "missing Strict-Transport-Security", 1, SeverityLow, "CWE-693"},
		{"http-missing-header", "missing X-Frame-Options", 1, SeverityInfo, "CWE-693"},
		{"http-robots", "/robots.txt present (31 bytes): User-agent: *", 1, SeverityInfo, "CWE-200"},
		{"http-sitemap", "/sitemap.xml present", 1, SeverityInfo, "CWE-200"},
		{"http-title", "Admin Console", 1, SeverityLow, "CWE-200"},
		{"http-title", "Welcome to our blog", 0, "", ""},
		{"http-server", "nginx/1.24", 1, SeverityInfo, "CWE-200"},
		{"http-server", "nginx", 0, "", ""},
		{"http-tls", "TLS 1.0 ECDHE-RSA-AES256-SHA", 1, SeverityHigh, "CWE-327"},
		{"http-tls", "TLS 1.2 ECDHE-RSA-AES256-GCM", 0, "", ""},
		{"ssh-banner", "SSH-1.5-1.2.27", 1, SeverityHigh, "CWE-327"},
		{"ssh-banner", "SSH-2.0-OpenSSH_9.6", 0, "", ""},
		{"service-banner", "whatever", 0, "", ""},
	}
	for _, c := range cases {
		got := Raise("p1", []Observation{{Target: "10.0.0.1:80", Kind: c.kind, Detail: c.detail, Source: "http"}})
		if len(got) != c.wantN {
			t.Errorf("%s/%q: got %d findings, want %d", c.kind, c.detail, len(got), c.wantN)
			continue
		}
		if c.wantN > 0 {
			if got[0].Severity != c.severity || got[0].CWE != c.cwe {
				t.Errorf("%s: got %s/%s, want %s/%s", c.kind, got[0].Severity, got[0].CWE, c.severity, c.cwe)
			}
			if err := got[0].Validate(); err != nil {
				t.Errorf("%s: invalid finding: %v", c.kind, err)
			}
		}
	}
}

func TestDedupeStable(t *testing.T) {
	a := DedupeKey("10.0.0.1:80", "Missing CSP", "evidence-x")
	b := DedupeKey("10.0.0.1:80", "Missing CSP", "evidence-x")
	if a != b || len(a) != 32 {
		t.Fatal("dedupe key unstable")
	}
	if strings.Contains(a, " ") {
		t.Fatal("key must be hex")
	}
}
