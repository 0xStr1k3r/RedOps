package report

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/go-pdf/fpdf"
)

// ToPDF renders a print-ready assessment report: title block, executive
// metrics, findings, ATT&CK coverage, attack paths, timeline, evidence.
func ToPDF(r *Report) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetAuthor("RedOps", false)
	pdf.SetTitle("RedOps Assessment Report — "+r.Project.Name, false)
	pdf.SetMargins(15, 15, 15)
	pdf.SetAutoPageBreak(true, 20)

	heading := func(level int, s string) {
		sizes := map[int]float64{1: 20, 2: 14, 3: 11}
		pdf.SetFont("Helvetica", "B", sizes[level])
		pdf.SetTextColor(17, 17, 17)
		pdf.MultiCell(0, 7, s, "", "L", false)
		pdf.Ln(1)
	}
	body := func(s string) {
		pdf.SetFont("Helvetica", "", 10)
		pdf.SetTextColor(30, 30, 30)
		pdf.MultiCell(0, 5, s, "", "L", false)
	}
	muted := func(s string) {
		pdf.SetFont("Helvetica", "I", 9)
		pdf.SetTextColor(100, 100, 100)
		pdf.MultiCell(0, 5, s, "", "L", false)
		pdf.SetTextColor(30, 30, 30)
	}

	pdf.AddPage()
	heading(1, "RedOps Assessment Report")
	heading(2, r.Project.Name)
	muted("Generated " + fmtTime(r.Generated) + " · Authorized assessment activity only")
	if r.Project.Description != "" {
		body(r.Project.Description)
	}
	pdf.Ln(2)

	heading(2, "Executive summary")
	m := r.Metrics
	metricRows := [][]string{
		{"Hosts discovered", fmt.Sprint(m.Hosts)},
		{"Services discovered", fmt.Sprint(m.Services)},
		{"Findings", fmt.Sprintf("%d (critical %d, high %d, validated %d)", m.Findings, m.Critical, m.High, m.Validated)},
		{"ATT&CK techniques", fmt.Sprintf("%d / %d", m.Techniques, m.TechniquesTot)},
		{"Attack paths", fmt.Sprint(m.Paths)},
		{"Evidence records", fmt.Sprintf("%d (chain %s)", m.Evidence, chainWord(m.EvidenceOK))},
	}
	table(pdf, []string{"Metric", "Value"}, metricRows)

	heading(2, "Scope & targets")
	for _, s := range r.Scopes {
		body("Scope: " + s.Value + " (" + s.Type + ")")
	}
	for _, t := range r.Targets {
		body("Target: " + t.Value)
	}
	if len(r.Scopes) == 0 && len(r.Targets) == 0 {
		body("No scope or targets recorded.")
	}

	heading(2, "Findings")
	if len(r.Findings) == 0 {
		body("No findings.")
	}
	for _, f := range r.Findings {
		heading(3, "["+strings.ToUpper(sevLabel(f.Severity))+"] "+f.Title)
		body(fmt.Sprintf("Target %s · Confidence %s · Status %s", f.Target, f.Confidence, f.Status))
		if f.CWE != "" || f.TechniqueID != "" {
			body(strings.TrimSpace(f.CWE + " " + f.TechniqueID))
		}
		if f.Remediation != "" {
			body("Remediation: " + f.Remediation)
		}
	}

	heading(2, "MITRE ATT&CK coverage")
	body(fmt.Sprintf("Observed %d of %d techniques.", m.Techniques, m.TechniquesTot))
	for _, tac := range r.Coverage.Tactics {
		if tac.Seen == 0 {
			continue
		}
		var ids []string
		for _, h := range tac.Techniques {
			ids = append(ids, h.ID)
		}
		body(fmt.Sprintf("%s (%d/%d): %s", tac.Tactic, tac.Seen, tac.Total, strings.Join(ids, ", ")))
	}

	heading(2, "Attack paths")
	if len(r.Paths) == 0 {
		body("No attack paths generated.")
	}
	for i, p := range r.Paths {
		body(fmt.Sprintf("Path %d — risk %d (%s): %s", i+1, p.Risk, p.Confidence, orDash(p.Objective)))
	}

	heading(2, "Timeline")
	if len(r.Timeline) == 0 {
		body("No events.")
	}
	for _, e := range r.Timeline {
		body(fmt.Sprintf("%s [%s] %s", e.Timestamp.UTC().Format("15:04:05"), e.Kind, e.Message))
	}

	heading(2, "Evidence integrity")
	body(fmt.Sprintf("Chain verification: %s over %d records.", chainWord(m.EvidenceOK), m.Evidence))

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// table renders a simple two-column table with a shaded header.
func table(pdf *fpdf.Fpdf, header []string, rows [][]string) {
	widths := []float64{70, 110}
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetFillColor(242, 242, 242)
	for i, h := range header {
		pdf.CellFormat(widths[i], 7, h, "1", 0, "L", true, 0, "")
	}
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", 10)
	for _, row := range rows {
		for i, c := range row {
			pdf.CellFormat(widths[i], 6, c, "1", 0, "L", false, 0, "")
		}
		pdf.Ln(-1)
	}
	pdf.Ln(2)
}
