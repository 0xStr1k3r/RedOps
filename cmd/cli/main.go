// Command redops is the operator CLI. Phase 1 works directly against the
// local SQLite file (same file the server uses), so no server is required:
//
//	redops --db redops.db project create acme --scope 10.10.10.0/24
//	redops --db redops.db target add <project-id-or-name> 10.10.10.10
//	redops --db redops.db status <project-id-or-name>
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/redops/redops/internal/project"
)

var dbPath string

func store() (*project.Store, error) { return project.Open(dbPath) }

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
			fmt.Printf("project: %s (%s)\nscopes: %d\ntargets: %d\ntimeline events: %d\n", p.Name, p.ID, len(sc), len(tg), len(tl))
			for _, t := range tg {
				fmt.Printf("  - %s\n", t.Value)
			}
			return nil
		},
	}

	root.AddCommand(projectCmd, targetCmd, scopeCmd, statusCmd)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
