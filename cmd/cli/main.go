// Command redops is the operator CLI. It works directly against the
// local SQLite file (same file the server uses), so no server is required:
//
//	redops --db redops.db project create acme --scope 10.10.10.0/24
//	redops --db redops.db target add <project-id-or-name> 10.10.10.10
//	redops --db redops.db recon run <project> --tool nmap --target 10.10.10.10
//	redops --db redops.db assets <project>
//	redops --db redops.db status <project-id-or-name>
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/redops/redops/internal/attack"
	"github.com/redops/redops/internal/attackgraph"
	"github.com/redops/redops/internal/enumeration"
	"github.com/redops/redops/internal/findings"
	"github.com/redops/redops/internal/mitre"
	"github.com/redops/redops/internal/project"
	"github.com/redops/redops/internal/recon"
	"github.com/redops/redops/internal/validation"
	"github.com/spf13/cobra"
)

var dbPath string

func store() (*project.Store, error) { return project.Open(dbPath) }

func truncObs(s string) string {
	if len(s) > 80 {
		return s[:80]
	}
	return s
}

// shortJoin renders source lists compactly for CLI tables.
func shortJoin(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

// resolvePathID accepts a full UUID or an unambiguous prefix.
func resolvePathID(s *project.Store, projectID, ref string) (string, error) {
	list, err := s.ListAttackPaths(projectID, 0)
	if err != nil {
		return "", err
	}
	var match string
	n := 0
	for _, p := range list {
		if p.ID == ref || (len(ref) >= 4 && len(p.ID) >= len(ref) && p.ID[:len(ref)] == ref) {
			match = p.ID
			n++
		}
	}
	if n == 0 {
		return "", fmt.Errorf("attack path not found")
	}
	if n > 1 {
		return "", fmt.Errorf("ambiguous path prefix %q (%d matches)", ref, n)
	}
	return match, nil
}

// resolveFindingID accepts a full UUID or an unambiguous prefix (list shows short IDs).
func resolveFindingID(s *project.Store, projectID, ref string) (string, error) {
	list, err := s.ListFindings(projectID, project.FindingFilter{})
	if err != nil {
		return "", err
	}
	var match string
	n := 0
	for _, f := range list {
		if f.ID == ref || (len(ref) >= 4 && len(f.ID) >= len(ref) && f.ID[:len(ref)] == ref) {
			match = f.ID
			n++
		}
	}
	if n == 0 {
		return "", fmt.Errorf("finding not found")
	}
	if n > 1 {
		return "", fmt.Errorf("ambiguous finding prefix %q (%d matches)", ref, n)
	}
	return match, nil
}

func findProject(s *project.Store, ref string) (*project.Project, error) {
	if p, err := s.GetProject(ref); err == nil {
		return p, nil
	}
	list, err := s.ListProjects()
	if err != nil {
		return nil, err
	}
	for _, p := range list {
		if p.Name == ref {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("project %q not found", ref)
}

func main() {
	root := &cobra.Command{Use: "redops", Short: "RedOps red-team platform CLI (Phase 1)"}
	root.PersistentFlags().StringVar(&dbPath, "db", "redops.db", "SQLite database file")

	projectCmd := &cobra.Command{Use: "project", Short: "Manage projects"}
	createCmd := &cobra.Command{
		Use:   "create NAME [--scope CIDR] [--description TEXT]",
		Args:  cobra.ExactArgs(1),
		Short: "Create a project with optional initial scope",
		RunE: func(cmd *cobra.Command, args []string) error {
			desc, _ := cmd.Flags().GetString("description")
			scopes, _ := cmd.Flags().GetStringArray("scope")
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := s.CreateProject(args[0], desc)
			if err != nil {
				return err
			}
			fmt.Printf("project %s (%s)\n", p.Name, p.ID)
			for _, sc := range scopes {
				e, err := s.AddScopeEntry(p.ID, sc)
				if err != nil {
					return fmt.Errorf("scope %q: %w", sc, err)
				}
				fmt.Printf("  scope: %s\n", e.Value)
			}
			return nil
		},
	}
	createCmd.Flags().String("description", "", "Project description")
	createCmd.Flags().StringArray("scope", nil, "Initial scope entry (repeatable)")
	projectCmd.AddCommand(createCmd)
	projectCmd.AddCommand(&cobra.Command{
		Use: "list", Short: "List projects",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			list, err := s.ListProjects()
			if err != nil {
				return err
			}
			for _, p := range list {
				fmt.Printf("%s\t%s\t%s\n", p.ID, p.Name, p.CreatedAt.Format("2006-01-02 15:04"))
			}
			return nil
		},
	})

	targetCmd := &cobra.Command{Use: "target", Short: "Manage targets (scope-enforced)"}
	targetCmd.AddCommand(&cobra.Command{
		Use: "add PROJECT VALUE", Args: cobra.ExactArgs(2), Short: "Add target (denied if out of scope)",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			t, err := s.AddTarget(p.ID, args[1], "cli")
			if err != nil {
				return err
			}
			fmt.Printf("target %s (%s)\n", t.Value, t.ID)
			return nil
		},
	})

	scopeCmd := &cobra.Command{Use: "scope", Short: "Manage scope"}
	scopeCmd.AddCommand(&cobra.Command{
		Use: "add PROJECT VALUE", Args: cobra.ExactArgs(2), Short: "Add scope entry",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			e, err := s.AddScopeEntry(p.ID, args[1])
			if err != nil {
				return err
			}
			fmt.Printf("scope %s\n", e.Value)
			return nil
		},
	})

	statusCmd := &cobra.Command{
		Use: "status PROJECT", Args: cobra.ExactArgs(1), Short: "Show project summary",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			sc, _ := s.ListScopes(p.ID)
			tg, _ := s.ListTargets(p.ID)
			tl, _ := s.ListTimeline(p.ID)
			hosts, _ := s.ListHosts(p.ID)
			svcs, _ := s.ListServices(p.ID)
			fmt.Printf("project: %s (%s)\nscopes: %d\ntargets: %d\nhosts: %d\nservices: %d\ntimeline events: %d\n", p.Name, p.ID, len(sc), len(tg), len(hosts), len(svcs), len(tl))
			for _, t := range tg {
				fmt.Printf("  - %s\n", t.Value)
			}
			return nil
		},
	}

	reconCmd := &cobra.Command{Use: "recon", Short: "Scope-checked reconnaissance jobs"}
	reconRun := &cobra.Command{
		Use: "run PROJECT --tool nmap --target 10.10.10.10", Args: cobra.ExactArgs(1),
		Short: "Enqueue a recon job and run it inline (use --async to only enqueue)",
		RunE: func(cmd *cobra.Command, args []string) error {
			toolName, _ := cmd.Flags().GetString("tool")
			target, _ := cmd.Flags().GetString("target")
			async, _ := cmd.Flags().GetBool("async")
			ports, _ := cmd.Flags().GetString("ports")
			profile, _ := cmd.Flags().GetString("profile")
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			job, err := recon.Enqueue(context.Background(), s, p.ID, toolName, target, "cli")
			if err != nil {
				return err
			}
			fmt.Printf("job %s queued (%s on %s)\n", job.ID, job.Tool, job.Target)
			if async {
				return nil
			}
			// Inline run for lab use (no worker daemon needed).
			if err := recon.RunJob(context.Background(), s, job, recon.Options{Ports: ports, Profile: profile}); err != nil {
				return fmt.Errorf("job %s failed: %w", job.ID, err)
			}
			fmt.Printf("job %s done\n", job.ID)
			return nil
		},
	}
	reconRun.Flags().String("tool", "nmap", "Tool: nmap|httpx|dnsx|subfinder")
	reconRun.Flags().String("target", "", "Target (must be in scope)")
	_ = reconRun.MarkFlagRequired("target")
	reconRun.Flags().Bool("async", false, "Only enqueue, do not run inline")
	reconRun.Flags().String("ports", "", "Ports allowlist, e.g. 80,443")
	reconRun.Flags().String("profile", "", "Profile: fast|full|top100")
	reconCmd.AddCommand(reconRun)
	reconCmd.AddCommand(&cobra.Command{
		Use: "list PROJECT", Args: cobra.ExactArgs(1), Short: "List recon jobs",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			jobs, err := s.ListReconJobs(p.ID)
			if err != nil {
				return err
			}
			for _, j := range jobs {
				fmt.Printf("%s\t%s\t%s\t%s\n", j.ID, j.Tool, j.Target, j.Status)
			}
			return nil
		},
	})
	assetsCmd := &cobra.Command{
		Use: "assets PROJECT", Args: cobra.ExactArgs(1), Short: "List discovered hosts and services",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			hosts, _ := s.ListHosts(p.ID)
			svcs, _ := s.ListServices(p.ID)
			fmt.Printf("hosts (%d):\n", len(hosts))
			for _, h := range hosts {
				fmt.Printf("  %s host=%s os=%s src=%s\n", h.IP, h.Hostname, h.OS, h.Source)
			}
			fmt.Printf("services (%d):\n", len(svcs))
			for _, sv := range svcs {
				fmt.Printf("  %s:%d/%s %s %s %s\n", sv.HostIP, sv.Port, sv.Protocol, sv.State, sv.Name, sv.Product)
			}
			return nil
		},
	}

	enumCmd := &cobra.Command{Use: "enum", Short: "Service enumeration (scope-checked, read-only)"}
	enumRun := &cobra.Command{
		Use: "run PROJECT --host 10.10.10.10 --port 80 [--module http]", Args: cobra.ExactArgs(1),
		Short: "Enumerate one service inline (auto-selects module when omitted)",
		RunE: func(cmd *cobra.Command, args []string) error {
			host, _ := cmd.Flags().GetString("host")
			port, _ := cmd.Flags().GetInt("port")
			module, _ := cmd.Flags().GetString("module")
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			job, err := enumeration.Enqueue(context.Background(), s, p.ID, host, port, module, "cli")
			if err != nil {
				return err
			}
			fmt.Printf("job %s queued (%s on %s:%d)\n", job.ID, job.Module, job.HostIP, job.Port)
			if err := enumeration.RunJob(context.Background(), s, job, enumeration.Options{}); err != nil {
				return fmt.Errorf("job %s failed: %w", job.ID, err)
			}
			fmt.Printf("job %s done\n", job.ID)
			return nil
		},
	}
	enumRun.Flags().String("host", "", "Service host (must be in scope)")
	enumRun.Flags().Int("port", 0, "Service port")
	enumRun.Flags().String("module", "", "Module: http|ssh-banner|dns|tcp-banner (default: auto)")
	_ = enumRun.MarkFlagRequired("host")
	_ = enumRun.MarkFlagRequired("port")
	enumCmd.AddCommand(enumRun)
	enumCmd.AddCommand(&cobra.Command{Use: "results PROJECT", Args: cobra.ExactArgs(1), Short: "Show enumeration results",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			results, err := s.ListEnumResults(p.ID)
			if err != nil {
				return err
			}
			for _, r := range results {
				fmt.Printf("== %s:%d [%s] %s\n", r.HostIP, r.Port, r.Module, r.Summary)
				for _, o := range r.Observations {
					fmt.Printf("   %-20s %s (%s)\n", o.Kind, truncObs(o.Detail), o.TechniqueID)
				}
			}
			return nil
		},
	})

	findingsCmd := &cobra.Command{Use: "findings", Short: "Finding management"}
	findingsList := &cobra.Command{
		Use: "list PROJECT [--severity low] [--status open]", Args: cobra.ExactArgs(1),
		Short: "List findings with optional filters",
		RunE: func(cmd *cobra.Command, args []string) error {
			sev, _ := cmd.Flags().GetString("severity")
			status, _ := cmd.Flags().GetString("status")
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			list, err := s.ListFindings(p.ID, project.FindingFilter{Severity: sev, Status: status})
			if err != nil {
				return err
			}
			for _, f := range list {
				fmt.Printf("%s [%s/%s/%s] %s (%s)\n", f.ID[:8], f.Severity, f.Confidence, f.Status, f.Title, f.Target)
			}
			return nil
		},
	}
	findingsList.Flags().String("severity", "", "Filter: info|low|medium|high|critical")
	findingsList.Flags().String("status", "", "Filter: open|acknowledged|resolved|false_positive")
	findingsCmd.AddCommand(findingsList)
	findingsCmd.AddCommand(&cobra.Command{
		Use: "raise PROJECT", Args: cobra.ExactArgs(1),
		Short: "Auto-raise findings from enumeration results (idempotent)",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			n, err := findings.RaiseFromEnumResults(s, p.ID, "cli")
			if err != nil {
				return err
			}
			fmt.Printf("raised %d new finding(s)\n", n)
			return nil
		},
	})
	findingsUpdate := &cobra.Command{
		Use: "update PROJECT ID [--status resolved] [--confidence validated] [--severity low]", Args: cobra.ExactArgs(2),
		Short: "Update finding workflow state",
		RunE: func(cmd *cobra.Command, args []string) error {
			status, _ := cmd.Flags().GetString("status")
			conf, _ := cmd.Flags().GetString("confidence")
			sev, _ := cmd.Flags().GetString("severity")
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			fullID, err := resolveFindingID(s, p.ID, args[1])
			if err != nil {
				return err
			}
			f, err := s.UpdateFinding(p.ID, fullID, status, conf, sev)
			if err != nil {
				return err
			}
			fmt.Printf("%s [%s/%s/%s] %s\n", f.ID[:8], f.Severity, f.Confidence, f.Status, f.Title)
			return nil
		},
	}
	findingsUpdate.Flags().String("status", "", "open|acknowledged|resolved|false_positive")
	findingsUpdate.Flags().String("confidence", "", "observed|potential|validated|confirmed")
	findingsUpdate.Flags().String("severity", "", "info|low|medium|high|critical")
	findingsCmd.AddCommand(findingsUpdate)

	mitreCmd := &cobra.Command{Use: "mitre", Short: "ATT&CK matrix and coverage"}
	mitreCmd.AddCommand(&cobra.Command{
		Use: "tactics", Short: "List the 14 enterprise tactics",
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, t := range mitre.Tactics {
				fmt.Printf("%s\t%s\n", t.ID, t.Name)
			}
			return nil
		},
	})
	mitreTechniques := &cobra.Command{
		Use: "techniques [--tactic Discovery]", Short: "List techniques, optionally filtered by tactic",
		RunE: func(cmd *cobra.Command, args []string) error {
			tactic, _ := cmd.Flags().GetString("tactic")
			list := mitre.Techniques
			if tactic != "" {
				list = mitre.TechniquesByTactic(tactic)
			}
			for _, t := range list {
				fmt.Printf("%s\t%s\t%s\n", t.ID, t.Tactic, t.Name)
			}
			return nil
		},
	}
	mitreTechniques.Flags().String("tactic", "", "Filter by tactic name")
	mitreCmd.AddCommand(mitreTechniques)
	mitreCmd.AddCommand(&cobra.Command{
		Use: "coverage PROJECT", Args: cobra.ExactArgs(1), Short: "Show ATT&CK coverage for a project",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			cov, err := mitre.ProjectCoverage(s, p.ID)
			if err != nil {
				return err
			}
			fmt.Printf("coverage: %d/%d techniques\n", cov.Seen, cov.Total)
			for _, tac := range cov.Tactics {
				if tac.Seen == 0 {
					continue
				}
				fmt.Printf("== %s (%d/%d)\n", tac.Tactic, tac.Seen, tac.Total)
				for _, h := range tac.Techniques {
					fmt.Printf("   %s %s x%d [%s]\n", h.ID, h.Name, h.Count, shortJoin(h.Sources))
				}
			}
			return nil
		},
	})

	graphCmd := &cobra.Command{Use: "graph", Short: "Attack graph (offline-first, optional Neo4j sync)"}
	graphShow := &cobra.Command{
		Use: "show PROJECT [--format json|cypher|dot]", Args: cobra.ExactArgs(1),
		Short: "Print the assessment graph",
		RunE: func(cmd *cobra.Command, args []string) error {
			format, _ := cmd.Flags().GetString("format")
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			g, err := attackgraph.Build(s, p.ID)
			if err != nil {
				return err
			}
			switch format {
			case "cypher":
				fmt.Println(attackgraph.ToCypher(g))
			case "dot":
				fmt.Println(attackgraph.ToDOT(g))
			default:
				fmt.Printf("nodes=%d edges=%d\n", len(g.Nodes), len(g.Edges))
				for kind, n := range g.Stats() {
					fmt.Printf("  %s: %d\n", kind, n)
				}
			}
			return nil
		},
	}
	graphShow.Flags().String("format", "summary", "json|cypher|dot (default: summary)")
	graphCmd.AddCommand(graphShow)
	graphCmd.AddCommand(&cobra.Command{
		Use: "sync PROJECT", Args: cobra.ExactArgs(1),
		Short: "Push the graph to Neo4j (needs REDOPS_NEO4J_URI/USER/PASS)",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			g, err := attackgraph.Build(s, p.ID)
			if err != nil {
				return err
			}
			uri, user, pass := attackgraph.ConfigFromEnv()
			if err := attackgraph.Sync(context.Background(), uri, user, pass, g); err != nil {
				return err
			}
			fmt.Printf("synced %d nodes, %d edges to %s\n", len(g.Nodes), len(g.Edges), uri)
			return nil
		},
	})

	pathsCmd := &cobra.Command{Use: "paths", Short: "Attack path analysis"}
	pathsCmd.AddCommand(&cobra.Command{
		Use: "generate PROJECT", Args: cobra.ExactArgs(1), Short: "Recompute attack paths from the current graph",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			n, err := attack.Generate(context.Background(), s, p.ID, "cli", attack.Options{})
			if err != nil {
				return err
			}
			fmt.Printf("generated %d attack path(s)\n", n)
			return nil
		},
	})
	pathsList := &cobra.Command{
		Use: "list PROJECT [--min-risk 50]", Args: cobra.ExactArgs(1), Short: "List attack paths by risk",
		RunE: func(cmd *cobra.Command, args []string) error {
			minRisk, _ := cmd.Flags().GetInt("min-risk")
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			list, err := s.ListAttackPaths(p.ID, minRisk)
			if err != nil {
				return err
			}
			for _, path := range list {
				fmt.Printf("%s risk=%d conf=%s len=%d tech=%s\n  %s\n", path.ID[:8], path.Risk, path.Confidence, path.Length, path.Techniques, path.Objective)
			}
			return nil
		},
	}
	pathsList.Flags().Int("min-risk", 0, "Minimum risk 0-100")
	pathsCmd.AddCommand(pathsList)
	pathsConfirm := &cobra.Command{
		Use: "confirm PROJECT ID --confidence validated", Args: cobra.ExactArgs(2), Short: "Promote path confidence after verification",
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, _ := cmd.Flags().GetString("confidence")
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			fullID, err := resolvePathID(s, p.ID, args[1])
			if err != nil {
				return err
			}
			updated, err := s.ConfirmAttackPath(p.ID, fullID, conf, "cli")
			if err != nil {
				return err
			}
			fmt.Printf("%s now %s\n", updated.ID[:8], updated.Confidence)
			return nil
		},
	}
	pathsConfirm.Flags().String("confidence", "", "validated|confirmed")
	pathsCmd.AddCommand(pathsConfirm)

	validateCmd := &cobra.Command{Use: "validate", Short: "Read-only finding validation (lab-safe)"}
	validateCmd.AddCommand(&cobra.Command{
		Use: "finding PROJECT ID", Args: cobra.ExactArgs(2), Short: "Re-observe finding evidence, promote to validated on confirm",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			fullID, err := resolveFindingID(s, p.ID, args[1])
			if err != nil {
				return err
			}
			results, promoted, err := validation.ValidateFinding(context.Background(), s, p.ID, fullID, "cli", validation.Options{})
			if err != nil {
				return err
			}
			for _, r := range results {
				fmt.Printf("%s confirmed=%v: %s\n", r.Validator, r.Confirmed, r.Detail)
			}
			fmt.Printf("promoted=%v\n", promoted)
			return nil
		},
	})
	validateCmd.AddCommand(&cobra.Command{
		Use: "validators", Short: "List available validators",
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, name := range validation.List() {
				v, _ := validation.Get(name)
				fmt.Printf("%s\t%s\n", v.Name(), v.Description())
			}
			return nil
		},
	})
	evidenceCmd := &cobra.Command{Use: "evidence", Short: "Tamper-evident operation ledger"}
	evidenceCmd.AddCommand(&cobra.Command{
		Use: "list PROJECT", Args: cobra.ExactArgs(1), Short: "List evidence records in chain order",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			list, err := s.ListEvidence(p.ID)
			if err != nil {
				return err
			}
			for _, e := range list {
				fmt.Printf("%s %s %s %s [%s]\n", e.ID[:8], e.Timestamp.Format("15:04:05"), e.Action, e.Target, truncObs(e.Hash))
			}
			return nil
		},
	})
	evidenceCmd.AddCommand(&cobra.Command{
		Use: "verify PROJECT", Args: cobra.ExactArgs(1), Short: "Verify the evidence hash chain",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store()
			if err != nil {
				return err
			}
			defer s.Close()
			p, err := findProject(s, args[0])
			if err != nil {
				return err
			}
			st := s.VerifyEvidenceChain(p.ID)
			if st.OK {
				fmt.Printf("chain ok (%d records)\n", st.Checked)
				return nil
			}
			return fmt.Errorf("chain broken at %s (%d records checked)", st.BrokenAt, st.Checked)
		},
	})

	root.AddCommand(projectCmd, targetCmd, scopeCmd, statusCmd, reconCmd, assetsCmd, enumCmd, findingsCmd, mitreCmd, graphCmd, pathsCmd, validateCmd, evidenceCmd)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
