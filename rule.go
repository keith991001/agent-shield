//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Severity classification used for alerting/sorting. Stable string values
// so rules.yaml and downstream tooling agree.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Action is what to do when a rule matches.
type Action string

const (
	ActionLog   Action = "log"   // emit to stream, no other effect
	ActionAlert Action = "alert" // emit + tag as alert
	ActionBlock Action = "block" // emit + kill the offending PID
)

// Rule is one entry in rules.yaml. Match clauses are AND-ed; within a
// list-valued field (e.g. PathPrefix), entries are OR-ed.
type Rule struct {
	Name       string   `yaml:"name"`
	EventTypes []string `yaml:"event_types"`
	Match      Match    `yaml:"match"`
	Action     Action   `yaml:"action"`
	Severity   Severity `yaml:"severity"`
}

// Match holds the per-rule conditions. Empty fields are not checked.
type Match struct {
	Comm          string   `yaml:"comm,omitempty"`
	PathPrefix    []string `yaml:"path_prefix,omitempty"`
	PathContains  []string `yaml:"path_contains,omitempty"`
	PathExact     []string `yaml:"path_exact,omitempty"`
	Family        string   `yaml:"family,omitempty"`
	DestPortIn    []uint16 `yaml:"dest_port_in,omitempty"`
	DestPortNotIn []uint16 `yaml:"dest_port_not_in,omitempty"`
	UIDMin        *uint32  `yaml:"uid_min,omitempty"` // ignore events from lower UIDs (e.g. system processes)
}

// RuleSet is the top-level YAML schema.
type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

// LoadRules reads and parses a YAML file into a RuleSet.
func LoadRules(path string) (*RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules file: %w", err)
	}
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	// Default action / severity if omitted.
	for i := range rs.Rules {
		if rs.Rules[i].Action == "" {
			rs.Rules[i].Action = ActionLog
		}
		if rs.Rules[i].Severity == "" {
			rs.Rules[i].Severity = SeverityInfo
		}
	}
	return &rs, nil
}

// Find returns the first rule that matches the event, or nil.
// First-match-wins semantics — order rules carefully (like iptables).
func (rs *RuleSet) Find(evt *Event) *Rule {
	for i := range rs.Rules {
		if matchEvent(&rs.Rules[i], evt) {
			return &rs.Rules[i]
		}
	}
	return nil
}

// dest port extracted from "ip:port" string in Event.Dest.
func parseDestPort(dest string) (uint16, bool) {
	idx := strings.LastIndex(dest, ":")
	if idx < 0 || idx == len(dest)-1 {
		return 0, false
	}
	var p uint16
	if _, err := fmt.Sscanf(dest[idx+1:], "%d", &p); err != nil {
		return 0, false
	}
	return p, true
}

func anyHasPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func anyContains(s string, subs []string) bool {
	for _, p := range subs {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func contains[T comparable](xs []T, v T) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func matchEvent(r *Rule, evt *Event) bool {
	// event_types: at least one must match (if specified).
	if len(r.EventTypes) > 0 && !contains(r.EventTypes, evt.Type) {
		return false
	}

	// UID floor.
	if r.Match.UIDMin != nil && evt.UID < *r.Match.UIDMin {
		return false
	}

	// comm: exact match.
	if r.Match.Comm != "" && evt.Comm != r.Match.Comm {
		return false
	}

	// Path conditions only apply to events that have a path.
	if len(r.Match.PathPrefix) > 0 && !anyHasPrefix(evt.Path, r.Match.PathPrefix) {
		return false
	}
	if len(r.Match.PathContains) > 0 && !anyContains(evt.Path, r.Match.PathContains) {
		return false
	}
	if len(r.Match.PathExact) > 0 && !contains(r.Match.PathExact, evt.Path) {
		return false
	}

	// Network conditions only apply to connect events.
	if r.Match.Family != "" && evt.Family != r.Match.Family {
		return false
	}
	if len(r.Match.DestPortIn) > 0 || len(r.Match.DestPortNotIn) > 0 {
		port, ok := parseDestPort(evt.Dest)
		if !ok {
			return false
		}
		if len(r.Match.DestPortIn) > 0 && !contains(r.Match.DestPortIn, port) {
			return false
		}
		if len(r.Match.DestPortNotIn) > 0 && contains(r.Match.DestPortNotIn, port) {
			return false
		}
	}

	return true
}
