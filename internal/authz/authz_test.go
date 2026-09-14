package authz

import "testing"

func TestAuthorizerAllowsOnlyMatchingGroupActionAndScope(t *testing.T) {
	a := New([]Rule{{
		Groups:        []string{"platform"},
		Organizations: []string{"acme"},
		Projects:      []string{"api"},
		Stacks:        []string{"dev"},
		Actions:       []Action{Read, Write},
	}})

	for name, tc := range map[string]struct {
		groups  []string
		action  Action
		org     string
		project string
		stack   string
		want    bool
	}{
		"matching":        {[]string{"platform"}, Read, "acme", "api", "dev", true},
		"other group":     {[]string{"viewer"}, Read, "acme", "api", "dev", false},
		"other action":    {[]string{"platform"}, Secrets, "acme", "api", "dev", false},
		"other stack":     {[]string{"platform"}, Read, "acme", "api", "prod", false},
		"empty scope":     {[]string{"platform"}, Read, "acme", "api", "", false},
		"multiple groups": {[]string{"viewer", "platform"}, Write, "acme", "api", "dev", true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := a.Allows(tc.groups, tc.action, tc.org, tc.project, tc.stack); got != tc.want {
				t.Errorf("Allows() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAuthorizerSupportsExplicitWildcards(t *testing.T) {
	a := New([]Rule{{
		Groups:        []string{"admins"},
		Organizations: []string{"*"},
		Projects:      []string{"*"},
		Stacks:        []string{"*"},
		Actions:       []Action{"*"},
	}})
	if !a.Allows([]string{"admins"}, Secrets, "acme", "api", "prod") {
		t.Fatal("wildcard rule did not grant access")
	}
	if a.Allows([]string{"admins"}, Secrets, "acme", "api", "") {
		t.Fatal("wildcard rule granted an empty stack scope")
	}
}

func TestAuthorizerAllowsProjectForMatchingStackRule(t *testing.T) {
	a := New([]Rule{{
		Groups:        []string{"platform"},
		Organizations: []string{"acme"},
		Projects:      []string{"api"},
		Stacks:        []string{"dev"},
		Actions:       []Action{Read},
	}})
	if !a.AllowsProject([]string{"platform"}, Read, "acme", "api") {
		t.Fatal("matching project scope was denied")
	}
	if a.AllowsProject([]string{"platform"}, Read, "acme", "other") {
		t.Fatal("different project scope was allowed")
	}
}

func TestValidateRules(t *testing.T) {
	valid := Rule{
		Groups:        []string{"admins"},
		Organizations: []string{"*"},
		Projects:      []string{"*"},
		Stacks:        []string{"*"},
		Actions:       []Action{Read},
	}
	if err := ValidateRules([]Rule{valid}); err != nil {
		t.Fatalf("ValidateRules(valid): %v", err)
	}

	for name, rules := range map[string][]Rule{
		"missing rules":  nil,
		"wildcard group": {{Groups: []string{"*"}, Organizations: []string{"*"}, Projects: []string{"*"}, Stacks: []string{"*"}, Actions: []Action{Read}}},
		"missing action": {{Groups: []string{"admins"}, Organizations: []string{"*"}, Projects: []string{"*"}, Stacks: []string{"*"}}},
		"unknown action": {{Groups: []string{"admins"}, Organizations: []string{"*"}, Projects: []string{"*"}, Stacks: []string{"*"}, Actions: []Action{"admin"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateRules(rules); err == nil {
				t.Fatal("ValidateRules succeeded")
			}
		})
	}
}
