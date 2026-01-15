package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/redops/redops/internal/project"
)

func seedReport(t *testing.T) (*project.Store, string) {
	t.Helper()
	st, err := project.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	p, _ := st.CreateProject("acme", "lab assessment")
	_, _ = st.AddScopeEntry(p.ID, "10.10.10.0/24")
	_, _ = st.AddTarget(p.ID, "10.10.10.10", "alice")
	_ = st.UpsertHost(p.ID, "10.10.10.10", "web01.lab", "Linux", "nmap")
	_ = st.UpsertService(p.ID, "10.10.10.10", 80, "tcp", "open", "http", "nginx", "1.24")
	_, _ = st.CreateFinding(p.ID, project.FindingRow{Title: "<b>XSS?</b> & \"quotes\"", Severity: "high", Target: "10.10.10.10:80", CWE: "CWE-79", TechniqueID: "T1594", Remediation: "Encode output."}, "k1")
	return st, p.ID
}

func TestGenerateAndMarkdown(t *testing.T) {
	st, pid := seedReport(t)
	r, err := Generate(st, pid)
	if err != nil {
		t.Fatal(err)
	}
	if r.Metrics.Hosts != 1 || r.Metrics.Findings != 1 || r.Metrics.High != 1 {
		t.Fatalf("metrics %+v", r.Metrics)
	}
	md := ToMarkdown(r)
	for _, want := range []string{"# RedOps Assessment Report — acme", "## Findings", "## MITRE ATT&CK coverage", "## Attack paths", "## Timeline", "## Evidence integrity", "CWE-79"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	if _, err := Generate(st, "nope"); err == nil {
		t.Fatal("unknown project must fail")
	}
}

func TestHTMLescapes(t *testing.T) {
	st, pid := seedReport(t)
	r, _ := Generate(st, pid)
	html := ToHTML(r)
	if html == "" {
		t.Fatal("empty html")
	}
	// Finding title contains markup: must be escaped, never interpreted.
	if strings.Contains(html, "<b>XSS?</b>") {
		t.Fatal("HTML must escape finding titles")
	}
	if !strings.Contains(html, "&lt;b&gt;XSS?&lt;/b&gt;") {
		t.Fatal("escaped title missing")
	}
	for _, want := range []string{"Executive summary", "Attack paths", "badge high"} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
	}
}

func TestPDF(t *testing.T) {
	st, pid := seedReport(t)
	r, _ := Generate(st, pid)
	pdf, err := ToPDF(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF")) {
		t.Fatal("not a PDF")
	}
	if len(pdf) < 2000 {
		t.Fatalf("suspiciously small PDF: %d bytes", len(pdf))
	}
}
