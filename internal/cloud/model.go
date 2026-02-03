package cloud

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9+=,.@_*/-]+$`)

// Statement is one IAM policy statement (resources ignored for privilege math;
// scope them in review — see docs/cloud.md).
type Statement struct {
	Effect  string   `json:"effect"`
	Actions []string `json:"actions"`
}

// Policy is a named set of statements.
type Policy struct {
	Name       string      `json:"name"`
	Statements []Statement `json:"statements"`
}

// User has attached policies (and optional groups, informational only).
type User struct {
	Name     string   `json:"name"`
	Policies []string `json:"policies"`
	Groups   []string `json:"groups,omitempty"`
}

// Role has a trust policy (AssumeFrom principals) plus attached policies.
type Role struct {
	Name       string   `json:"name"`
	AssumeFrom []string `json:"assume_from"`
	Policies   []string `json:"policies"`
}

// Import is the accepted document shape.
type Import struct {
	Users    []User   `json:"users"`
	Roles    []Role   `json:"roles"`
	Policies []Policy `json:"policies"`
}

// ParseImport validates a JSON document. Unknown policy references,
// empty actions, and malformed names are rejected with clear errors.
func ParseImport(data []byte) (*Import, error) {
	var imp Import
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&imp); err != nil {
		return nil, fmt.Errorf("invalid IAM JSON: %w", err)
	}
	known := map[string]bool{}
	for _, p := range imp.Policies {
		if !nameRe.MatchString(p.Name) {
			return nil, fmt.Errorf("bad policy name %q", p.Name)
		}
		if known[p.Name] {
			return nil, fmt.Errorf("duplicate policy %q", p.Name)
		}
		known[p.Name] = true
		if len(p.Statements) == 0 {
			return nil, fmt.Errorf("policy %q has no statements", p.Name)
		}
		for _, s := range p.Statements {
			if len(s.Actions) == 0 {
				return nil, fmt.Errorf("policy %q has a statement with no actions", p.Name)
			}
			e := strings.ToLower(strings.TrimSpace(s.Effect))
			if e != "allow" && e != "deny" {
				return nil, fmt.Errorf("policy %q: effect must be Allow|Deny", p.Name)
			}
		}
	}
	checkRefs := func(owner string, refs []string) error {
		for _, r := range refs {
			if !known[r] {
				return fmt.Errorf("%s references unknown policy %q", owner, r)
			}
		}
		return nil
	}
	seen := map[string]bool{}
	for _, u := range imp.Users {
		if !nameRe.MatchString(u.Name) || seen["u:"+u.Name] {
			return nil, fmt.Errorf("bad or duplicate user %q", u.Name)
		}
		seen["u:"+u.Name] = true
		if err := checkRefs("user "+u.Name, u.Policies); err != nil {
			return nil, err
		}
	}
	for _, r := range imp.Roles {
		if !nameRe.MatchString(r.Name) || seen["r:"+r.Name] {
			return nil, fmt.Errorf("bad or duplicate role %q", r.Name)
		}
		seen["r:"+r.Name] = true
		if err := checkRefs("role "+r.Name, r.Policies); err != nil {
			return nil, err
		}
		for _, pr := range r.AssumeFrom {
			if pr != "*" && !nameRe.MatchString(pr) {
				return nil, fmt.Errorf("role %q: bad principal %q", r.Name, pr)
			}
		}
	}
	return &imp, nil
}

// actionMatches reports whether a granted action pattern covers a target
// action. Patterns: "*" or "svc:*" (prefix) or exact, case-insensitive.
func actionMatches(pattern, action string) bool {
	p, a := strings.ToLower(pattern), strings.ToLower(action)
	if p == "*" {
		return true
	}
	if strings.HasSuffix(p, ":*") && strings.HasPrefix(a, strings.TrimSuffix(p, "*")) {
		return true
	}
	return p == a
}

// AllowsAdmin reports whether the named policies grant admin-equivalent
// power (iam:* or * Allow, with explicit Deny overriding).
func AllowsAdmin(imp *Import, policyNames []string) bool {
	byName := map[string]Policy{}
	for _, p := range imp.Policies {
		byName[p.Name] = p
	}
	allowed, denied := false, false
	for _, name := range policyNames {
		for _, s := range byName[name].Statements {
			for _, a := range s.Actions {
				if actionMatches(a, "iam:*") || actionMatches(a, "*") {
					if strings.ToLower(s.Effect) == "deny" {
						denied = true
					} else {
						allowed = true
					}
				}
			}
		}
	}
	return allowed && !denied
}
