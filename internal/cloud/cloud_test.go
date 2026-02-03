package cloud

import (
	"os"
	"strings"
	"testing"
)

func loadFixture(t *testing.T) *Import {
	t.Helper()
	data, err := os.ReadFile("../../lab/cloud-iam-example.json")
	if err != nil {
		t.Fatal(err)
	}
	imp, err := ParseImport(data)
	if err != nil {
		t.Fatal(err)
	}
	return imp
}

func TestFixturePaths(t *testing.T) {
	imp := loadFixture(t)
	paths := FindPaths(imp)
	// dev-alice → DeployRole → AdminRole → Administrator = 1 admin path;
	// PublicTestRole wildcard trust = 1 warning.
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %+v", paths)
	}
	if paths[0].Risk != 90 || !strings.Contains(paths[0].Objective, "dev-alice") {
		t.Fatalf("top path: %+v", paths[0])
	}
	want := []string{"user:dev-alice", "role:DeployRole", "role:AdminRole", "policy:Administrator"}
	if strings.Join(paths[0].Chain, ",") != strings.Join(want, ",") {
		t.Fatalf("chain: %v", paths[0].Chain)
	}
	if paths[1].Risk != 75 || !strings.Contains(paths[1].Objective, "PublicTestRole") {
		t.Fatalf("warning path: %+v", paths[1])
	}
}

func TestCleanPrincipalHasNoPath(t *testing.T) {
	imp := &Import{
		Users:    []User{{Name: "auditor", Policies: []string{"ReadOnly"}}},
		Policies: []Policy{{Name: "ReadOnly", Statements: []Statement{{Effect: "Allow", Actions: []string{"ec2:Describe*"}}}}},
	}
	if paths := FindPaths(imp); len(paths) != 0 {
		t.Fatalf("clean principal must have no paths: %+v", paths)
	}
}

func TestDenyOverridesAllow(t *testing.T) {
	imp := &Import{
		Users: []User{{Name: "u", Policies: []string{"GuardedAdmin"}}},
		Policies: []Policy{{Name: "GuardedAdmin", Statements: []Statement{
			{Effect: "Allow", Actions: []string{"*"}},
			{Effect: "Deny", Actions: []string{"iam:*"}},
		}}},
	}
	if AllowsAdmin(imp, []string{"GuardedAdmin"}) {
		t.Fatal("explicit Deny must override Allow")
	}
	if paths := FindPaths(imp); len(paths) != 0 {
		t.Fatalf("guarded admin must yield no path: %+v", paths)
	}
}

func TestValidation(t *testing.T) {
	for _, doc := range []string{
		`{"users":[{"name":"u","policies":["Missing"]}],"policies":[]}`,
		`{"policies":[{"name":"P","statements":[]}]}`,
		`{"policies":[{"name":"P","statements":[{"effect":"Maybe","actions":["*"]}]}]}`,
		`{"users":[{"name":"bad name!","policies":[]}]}`,
		`{not json`,
	} {
		if _, err := ParseImport([]byte(doc)); err == nil {
			t.Fatalf("must reject %q", doc)
		}
	}
}

func TestToGraph(t *testing.T) {
	imp := loadFixture(t)
	g := ToGraph(imp)
	stats := g.Stats()
	if stats["User"] < 3 || stats["Role"] != 3 || stats["Policy"] != 3 {
		t.Fatalf("stats %+v", stats)
	}
	types := map[string]bool{}
	for _, e := range g.Edges {
		if e.Reason == "" {
			t.Fatal("edge without reason")
		}
		types[e.Type] = true
	}
	if !types["CAN_ASSUME"] || !types["HAS_POLICY"] {
		t.Fatalf("edge types %+v", types)
	}
}
