// Package authz evaluates the backend's group-based stack access rules.
package authz

import "fmt"

// Action describes an operation on a stack.
type Action string

const (
	Read    Action = "read"
	Write   Action = "write"
	Delete  Action = "delete"
	Secrets Action = "secrets"
)

// Rule grants members of Groups access to a scope. A scope component or action
// can be "*"; all other values are matched exactly.
type Rule struct {
	Groups        []string `yaml:"groups"`
	Organizations []string `yaml:"organizations"`
	Projects      []string `yaml:"projects"`
	Stacks        []string `yaml:"stacks"`
	Actions       []Action `yaml:"actions"`
}

// Authorizer evaluates rules with default-deny behavior.
type Authorizer struct {
	rules []Rule
}

// New constructs an authorizer from validated rules.
func New(rules []Rule) *Authorizer {
	return &Authorizer{rules: rules}
}

// Allows reports whether any caller group is granted the requested action and
// stack scope.
func (a *Authorizer) Allows(groups []string, action Action, org, project, stack string) bool {
	for _, rule := range a.rules {
		if intersects(groups, rule.Groups) &&
			matchesAction(rule.Actions, action) &&
			matchesScope(rule.Organizations, org) &&
			matchesScope(rule.Projects, project) &&
			matchesScope(rule.Stacks, stack) {
			return true
		}
	}
	return false
}

// AllowsProject reports whether a rule grants an action in the organization
// and project. It is used by endpoints whose response has no stack-specific
// data, such as the project HEAD check.
func (a *Authorizer) AllowsProject(groups []string, action Action, org, project string) bool {
	for _, rule := range a.rules {
		if intersects(groups, rule.Groups) &&
			matchesAction(rule.Actions, action) &&
			matchesScope(rule.Organizations, org) &&
			matchesScope(rule.Projects, project) {
			return true
		}
	}
	return false
}

// HasAnyGrant reports whether any caller group appears in a configured rule.
func (a *Authorizer) HasAnyGrant(groups []string) bool {
	for _, rule := range a.rules {
		if intersects(groups, rule.Groups) {
			return true
		}
	}
	return false
}

// ValidateRules rejects incomplete or unsafe rules before the service starts.
func ValidateRules(rules []Rule) error {
	if len(rules) == 0 {
		return fmt.Errorf("at least one authorization rule is required when noAuth is false")
	}
	for i, rule := range rules {
		if err := validateStrings(rule.Groups, "groups", i, false); err != nil {
			return err
		}
		for field, values := range map[string][]string{
			"organizations": rule.Organizations,
			"projects":      rule.Projects,
			"stacks":        rule.Stacks,
		} {
			if err := validateStrings(values, field, i, true); err != nil {
				return err
			}
		}
		if len(rule.Actions) == 0 {
			return fmt.Errorf("authorization[%d].actions is required", i)
		}
		for _, action := range rule.Actions {
			if action != "*" && action != Read && action != Write && action != Delete && action != Secrets {
				return fmt.Errorf("authorization[%d].actions contains unsupported action %q", i, action)
			}
		}
	}
	return nil
}

func validateStrings(values []string, field string, rule int, allowWildcard bool) error {
	if len(values) == 0 {
		return fmt.Errorf("authorization[%d].%s is required", rule, field)
	}
	for _, value := range values {
		if value == "" {
			return fmt.Errorf("authorization[%d].%s contains an empty value", rule, field)
		}
		if value == "*" && !allowWildcard {
			return fmt.Errorf("authorization[%d].%s must name an explicit group", rule, field)
		}
	}
	return nil
}

func intersects(a, b []string) bool {
	for _, left := range a {
		for _, right := range b {
			if left == right {
				return true
			}
		}
	}
	return false
}

func matchesAction(actions []Action, want Action) bool {
	for _, action := range actions {
		if action == "*" || action == want {
			return true
		}
	}
	return false
}

func matchesScope(values []string, want string) bool {
	if want == "" {
		return false
	}
	for _, value := range values {
		if value == "*" || value == want {
			return true
		}
	}
	return false
}
