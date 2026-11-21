package sshagent

import (
	"fmt"
	"sort"
	"strings"
)

// Purpose is the policy category for a sign request.
type Purpose string

const (
	// PurposeSSH is logging in to a host.
	PurposeSSH Purpose = "ssh"
	// PurposeGit is an SSHSIG signature in the "git" namespace.
	PurposeGit Purpose = "git"
	// PurposeSign is an SSHSIG signature in any other namespace.
	PurposeSign Purpose = "sign"
)

var purposes = []Purpose{PurposeSSH, PurposeGit, PurposeSign}

// PurposeOf maps a request to its policy purpose. ok is false for data the
// agent cannot classify; such requests are always denied.
func PurposeOf(r Request) (p Purpose, ok bool) {
	switch r.Kind {
	case KindUserAuth:
		return PurposeSSH, true
	case KindSSHSig:
		if r.Namespace == "git" {
			return PurposeGit, true
		}
		return PurposeSign, true
	}
	return "", false
}

// Action is what to do with a request.
type Action string

const (
	ActionDeny   Action = "deny"
	ActionPrompt Action = "prompt"
	// ActionPrompt5m prompts, then allows the same key and purpose for five
	// minutes without asking again.
	ActionPrompt5m Action = "prompt-5m"
	ActionAllow    Action = "allow"
)

// Policy maps purposes to actions. Purposes not present are denied.
type Policy map[Purpose]Action

// DefaultPolicy signs git commits silently and prompts for everything else.
func DefaultPolicy() Policy {
	return Policy{PurposeSSH: ActionPrompt, PurposeGit: ActionAllow, PurposeSign: ActionPrompt}
}

// Decide returns the action for a request.
//
// Forwarded requests come from a remote host using this agent, so they are
// never allowed silently: allow and prompt-5m become prompt.
func (p Policy) Decide(r Request) Action {
	purpose, ok := PurposeOf(r)
	if !ok {
		return ActionDeny
	}
	a, ok := p[purpose]
	if !ok {
		return ActionDeny
	}
	if r.Forwarded && (a == ActionAllow || a == ActionPrompt5m) {
		return ActionPrompt
	}
	return a
}

// ParsePolicy parses "git=allow,ssh=prompt". Unlisted purposes are denied.
func ParsePolicy(s string) (Policy, error) {
	p := Policy{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("policy %q: want purpose=action", part)
		}
		purpose, action := Purpose(strings.TrimSpace(k)), Action(strings.TrimSpace(v))
		if !validPurpose(purpose) {
			return nil, fmt.Errorf("policy %q: unknown purpose %q (want ssh, git or sign)", part, purpose)
		}
		if !validAction(action) {
			return nil, fmt.Errorf("policy %q: unknown action %q (want allow, prompt, prompt-5m or deny)", part, action)
		}
		if _, dup := p[purpose]; dup {
			return nil, fmt.Errorf("policy: %q listed twice", purpose)
		}
		p[purpose] = action
	}
	if len(p) == 0 {
		return nil, fmt.Errorf("policy %q: empty", s)
	}
	return p, nil
}

// String formats the policy in ParsePolicy syntax, sorted by purpose.
func (p Policy) String() string {
	parts := make([]string, 0, len(p))
	for k, v := range p {
		parts = append(parts, string(k)+"="+string(v))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func validPurpose(p Purpose) bool {
	for _, q := range purposes {
		if p == q {
			return true
		}
	}
	return false
}

func validAction(a Action) bool {
	switch a {
	case ActionDeny, ActionPrompt, ActionPrompt5m, ActionAllow:
		return true
	}
	return false
}
