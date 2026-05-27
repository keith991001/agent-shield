//go:build linux

package main

import (
	"strings"
	"testing"
)

func TestNtohs(t *testing.T) {
	cases := map[uint16]uint16{
		0x0000: 0x0000,
		0x0050: 0x5000, // network 0x0050 (=80) byte-swapped is 0x5000 — but ntohs returns host order
		0x1F90: 0x901F, // 8080 → swapped
	}
	for in, want := range cases {
		got := ntohs(in)
		if got != want {
			t.Errorf("ntohs(%#04x) = %#04x, want %#04x", in, got, want)
		}
	}
}

func TestFamilyName(t *testing.T) {
	if got := familyName(2); got != "AF_INET" {
		t.Errorf("familyName(2) = %q", got)
	}
	if got := familyName(1); got != "AF_UNIX" {
		t.Errorf("familyName(1) = %q", got)
	}
	if got := familyName(999); !strings.HasPrefix(got, "AF(") {
		t.Errorf("unknown family should be AF(N), got %q", got)
	}
}

func TestProtoName(t *testing.T) {
	if got := protoName(0); got != "default" {
		t.Errorf("proto 0 should be default, got %q", got)
	}
	if got := protoName(6); got != "TCP" {
		t.Errorf("proto 6 should be TCP, got %q", got)
	}
	if got := protoName(17); got != "UDP" {
		t.Errorf("proto 17 should be UDP, got %q", got)
	}
}

func TestSockTypeName(t *testing.T) {
	if got := sockTypeName(1); got != "SOCK_STREAM" {
		t.Errorf("type 1 should be SOCK_STREAM, got %q", got)
	}
	// SOCK_STREAM | SOCK_CLOEXEC = 1 | 0x80000 — should still be SOCK_STREAM
	if got := sockTypeName(1 | 0x80000); got != "SOCK_STREAM" {
		t.Errorf("SOCK_STREAM with flags should still be SOCK_STREAM, got %q", got)
	}
}

func TestShouldScore(t *testing.T) {
	cases := []struct {
		name  string
		evt   Event
		score bool
	}{
		{"no rule", Event{}, false},
		{"matched but info", Event{Rule: "x", Severity: SeverityInfo}, false},
		{"matched but low", Event{Rule: "x", Severity: SeverityLow}, false},
		{"matched medium", Event{Rule: "x", Severity: SeverityMedium}, true},
		{"matched high", Event{Rule: "x", Severity: SeverityHigh}, true},
		{"matched critical", Event{Rule: "x", Severity: SeverityCritical}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldScore(&c.evt); got != c.score {
				t.Errorf("shouldScore = %v, want %v", got, c.score)
			}
		})
	}
}

func TestBuildUserPrompt(t *testing.T) {
	evt := &Event{
		PID: 1234, UID: 0, Comm: "rm", Type: "unlinkat",
		Path: "/usr/bin/python3",
		Rule: "protected_unlink", Action: ActionBlock, Severity: SeverityCritical,
	}
	got := buildUserPrompt(evt)
	must := []string{
		`process "rm"`,
		`pid=1234`,
		`uid=0`,
		`unlinkat`,
		`path="/usr/bin/python3"`,
		`matched rule "protected_unlink"`,
		`action=block`,
	}
	for _, m := range must {
		if !strings.Contains(got, m) {
			t.Errorf("prompt missing %q\nfull prompt:\n%s", m, got)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("abcdef", 10); got != "abcdef" {
		t.Errorf("short string unchanged, got %q", got)
	}
	if got := truncate("abcdef", 3); got != "abc…" {
		t.Errorf("long string truncated with ellipsis, got %q", got)
	}
}
