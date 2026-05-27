//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseDestPort(t *testing.T) {
	cases := []struct {
		in    string
		port  uint16
		valid bool
	}{
		{"1.2.3.4:443", 443, true},
		{"127.0.0.1:8080", 8080, true},
		{"10.0.0.1:0", 0, true},
		{"", 0, false},
		{"no-colon", 0, false},
		{"1.2.3.4:", 0, false},
		{"1.2.3.4:abc", 0, false},
	}
	for _, c := range cases {
		got, ok := parseDestPort(c.in)
		if ok != c.valid {
			t.Errorf("parseDestPort(%q) valid=%v want %v", c.in, ok, c.valid)
		}
		if ok && got != c.port {
			t.Errorf("parseDestPort(%q) port=%d want %d", c.in, got, c.port)
		}
	}
}

func TestAnyHasPrefix(t *testing.T) {
	if !anyHasPrefix("/usr/bin/ls", []string{"/etc/", "/usr/"}) {
		t.Error("expected match")
	}
	if anyHasPrefix("/tmp/x", []string{"/etc/", "/usr/"}) {
		t.Error("expected no match")
	}
	if anyHasPrefix("/x", nil) {
		t.Error("nil should not match")
	}
}

func TestAnyContains(t *testing.T) {
	if !anyContains("/home/user/.env", []string{".env", "id_rsa"}) {
		t.Error("expected match")
	}
	if anyContains("/home/user/notes.txt", []string{".env", "id_rsa"}) {
		t.Error("expected no match")
	}
}

// TestMatchEvent_RuleMatching is the heart of the rule engine: given a
// well-defined event, does each rule type match correctly?
func TestMatchEvent_RuleMatching(t *testing.T) {
	tests := []struct {
		name  string
		rule  Rule
		evt   Event
		match bool
	}{
		{
			name: "event_type mismatch",
			rule: Rule{EventTypes: []string{"unlinkat"}},
			evt:  Event{Type: "exec"},
		},
		{
			name:  "event_type match (single)",
			rule:  Rule{EventTypes: []string{"unlinkat"}},
			evt:   Event{Type: "unlinkat"},
			match: true,
		},
		{
			name:  "event_type match (one of many)",
			rule:  Rule{EventTypes: []string{"exec", "openat", "unlinkat"}},
			evt:   Event{Type: "openat"},
			match: true,
		},
		{
			name:  "no event_types means accept any",
			rule:  Rule{},
			evt:   Event{Type: "openat"},
			match: true,
		},
		{
			name:  "comm match",
			rule:  Rule{Match: Match{Comm: "rm"}},
			evt:   Event{Comm: "rm"},
			match: true,
		},
		{
			name: "comm mismatch",
			rule: Rule{Match: Match{Comm: "rm"}},
			evt:  Event{Comm: "bash"},
		},
		{
			name:  "path_prefix match",
			rule:  Rule{Match: Match{PathPrefix: []string{"/usr/", "/etc/"}}},
			evt:   Event{Path: "/usr/bin/python3"},
			match: true,
		},
		{
			name: "path_prefix no match",
			rule: Rule{Match: Match{PathPrefix: []string{"/usr/", "/etc/"}}},
			evt:  Event{Path: "/home/user/file"},
		},
		{
			name:  "path_contains match",
			rule:  Rule{Match: Match{PathContains: []string{".env", "id_rsa"}}},
			evt:   Event{Path: "/home/user/.env"},
			match: true,
		},
		{
			name:  "path_exact match",
			rule:  Rule{Match: Match{PathExact: []string{"/etc/shadow"}}},
			evt:   Event{Path: "/etc/shadow"},
			match: true,
		},
		{
			name: "path_exact no match (substring not enough)",
			rule: Rule{Match: Match{PathExact: []string{"/etc/shadow"}}},
			evt:  Event{Path: "/etc/shadowy-thing"},
		},
		{
			name:  "family match",
			rule:  Rule{Match: Match{Family: "AF_INET"}},
			evt:   Event{Family: "AF_INET"},
			match: true,
		},
		{
			name: "family mismatch",
			rule: Rule{Match: Match{Family: "AF_INET"}},
			evt:  Event{Family: "AF_UNIX"},
		},
		{
			name:  "dest_port_in match",
			rule:  Rule{Match: Match{DestPortIn: []uint16{80, 443}}},
			evt:   Event{Dest: "1.2.3.4:443"},
			match: true,
		},
		{
			name: "dest_port_in no match",
			rule: Rule{Match: Match{DestPortIn: []uint16{80, 443}}},
			evt:  Event{Dest: "1.2.3.4:22"},
		},
		{
			name: "dest_port_not_in excludes known good ports",
			rule: Rule{Match: Match{DestPortNotIn: []uint16{80, 443}}},
			evt:  Event{Dest: "1.2.3.4:443"},
		},
		{
			name:  "dest_port_not_in includes weird ports",
			rule:  Rule{Match: Match{DestPortNotIn: []uint16{80, 443}}},
			evt:   Event{Dest: "1.2.3.4:6667"},
			match: true,
		},
		{
			name: "uid_min filters out low-UID",
			rule: Rule{Match: Match{UIDMin: u32ptr(1000)}},
			evt:  Event{UID: 0},
		},
		{
			name:  "uid_min admits non-system UID",
			rule:  Rule{Match: Match{UIDMin: u32ptr(1000)}},
			evt:   Event{UID: 1001},
			match: true,
		},
		{
			name: "multi-field AND semantics: comm wrong fails the whole rule",
			rule: Rule{
				EventTypes: []string{"exec"},
				Match: Match{
					Comm:       "rm",
					PathPrefix: []string{"/usr/"},
				},
			},
			evt: Event{Type: "exec", Comm: "ls", Path: "/usr/bin/ls"},
		},
		{
			name: "multi-field AND semantics: all match",
			rule: Rule{
				EventTypes: []string{"exec"},
				Match: Match{
					Comm:       "rm",
					PathPrefix: []string{"/usr/"},
				},
			},
			evt:   Event{Type: "exec", Comm: "rm", Path: "/usr/bin/rm"},
			match: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchEvent(&tc.rule, &tc.evt)
			if got != tc.match {
				t.Errorf("match = %v, want %v", got, tc.match)
			}
		})
	}
}

// TestFirstMatchWins verifies that Find() returns the first matching rule
// (iptables-style), not the most-specific.
func TestFirstMatchWins(t *testing.T) {
	rs := &RuleSet{
		Rules: []Rule{
			{
				Name:       "broad",
				EventTypes: []string{"unlinkat"},
				Action:     ActionLog,
			},
			{
				Name:       "specific",
				EventTypes: []string{"unlinkat"},
				Match:      Match{PathPrefix: []string{"/usr/"}},
				Action:     ActionBlock,
			},
		},
	}
	evt := Event{Type: "unlinkat", Path: "/usr/bin/python3"}
	matched := rs.Find(&evt)
	if matched == nil {
		t.Fatal("expected a match")
	}
	if matched.Name != "broad" {
		t.Errorf("expected first-match-wins to pick %q, got %q", "broad", matched.Name)
	}
}

func TestLoadRules_DefaultsApplied(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(p, []byte(`
rules:
  - name: missing_action
    event_types: [exec]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, err := LoadRules(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := rs.Rules[0].Action; got != ActionLog {
		t.Errorf("default action = %v, want %v", got, ActionLog)
	}
	if got := rs.Rules[0].Severity; got != SeverityInfo {
		t.Errorf("default severity = %v, want %v", got, SeverityInfo)
	}
}

func TestLoadRules_FileNotFound(t *testing.T) {
	if _, err := LoadRules("/nonexistent/rules.yaml"); err == nil {
		t.Error("expected error for missing file")
	}
}

func u32ptr(v uint32) *uint32 { return &v }
