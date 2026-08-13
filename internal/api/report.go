package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/0xStr1k3r/RedOps/internal/report"
)

func handleReport(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		format := strings.ToLower(r.URL.Query().Get("format"))
		if format == "" {
			format = "markdown"
		}
		rep, err := report.Generate(cfg.Store, chi.URLParam(r, "id"))
		if err != nil {
			writeErr(w, 404, "project not found")
			return
		}
		name := fmt.Sprintf("redops-%s-report", chi.URLParam(r, "id")[:8])
		switch format {
		case "markdown", "md":
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
			w.Header().Set("Content-Disposition", "attachment; filename="+name+".md")
			w.WriteHeader(200)
			_, _ = w.Write([]byte(report.ToMarkdown(rep)))
		case "html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(200)
			_, _ = w.Write([]byte(report.ToHTML(rep)))
		case "pdf":
			pdf, err := report.ToPDF(rep)
			if err != nil {
				writeErr(w, 500, "pdf render failed")
				return
			}
			w.Header().Set("Content-Type", "application/pdf")
			w.Header().Set("Content-Disposition", "attachment; filename="+name+".pdf")
			w.WriteHeader(200)
			_, _ = w.Write(pdf)
		default:
			writeErr(w, 400, "format must be markdown|html|pdf")
		}
	}
}
