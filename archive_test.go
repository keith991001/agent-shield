//go:build linux

package main

import (
	"testing"
)

func TestArchive_RecordAndProfile(t *testing.T) {
	a, err := OpenAlertArchive(":memory:")
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer a.Close()

	// Empty archive → no profile.
	p, err := a.ProfileForPID(1234)
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Errorf("expected nil profile for empty archive, got %+v", p)
	}

	// Record three events for PID 1234, two for PID 5678.
	events := []Event{
		{ID: 1, Time: "t1", PID: 1234, UID: 0, Comm: "rm", Type: "unlinkat", Path: "/usr/bin/a",
			Rule: "protected_unlink", Action: ActionBlock, Severity: SeverityCritical,
			Risk: 90, RiskCategory: "destructive"},
		{ID: 2, Time: "t2", PID: 1234, UID: 0, Comm: "rm", Type: "unlinkat", Path: "/usr/bin/b",
			Rule: "protected_unlink", Action: ActionBlock, Severity: SeverityCritical,
			Risk: 95, RiskCategory: "destructive"},
		{ID: 3, Time: "t3", PID: 1234, UID: 0, Comm: "cat", Type: "openat", Path: "/etc/shadow",
			Rule: "sensitive_path_read", Action: ActionAlert, Severity: SeverityHigh,
			Risk: 80, RiskCategory: "exfiltration"},
		{ID: 4, Time: "t4", PID: 5678, UID: 1000, Comm: "ls", Type: "exec",
			Rule: "some_rule", Action: ActionLog, Severity: SeverityInfo,
			Risk: 5, RiskCategory: "benign"},
		// Unmatched event (Rule = "") should be silently skipped.
		{ID: 5, Time: "t5", PID: 9999, UID: 0, Comm: "noise", Type: "openat"},
	}
	for _, e := range events {
		if err := a.Record(&e); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	p, err = a.ProfileForPID(1234)
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("expected non-nil profile for PID 1234")
	}
	if p.TotalAlerts != 3 {
		t.Errorf("TotalAlerts = %d, want 3", p.TotalAlerts)
	}
	if p.TotalBlocks != 2 {
		t.Errorf("TotalBlocks = %d, want 2", p.TotalBlocks)
	}
	if p.MaxRisk != 95 {
		t.Errorf("MaxRisk = %d, want 95", p.MaxRisk)
	}
	// avg = (90+95+80)/3 ≈ 88.33
	if p.AvgRisk < 88 || p.AvgRisk > 89 {
		t.Errorf("AvgRisk = %.2f, want ~88.33", p.AvgRisk)
	}
	if len(p.Categories) != 2 {
		t.Errorf("Categories = %v, want 2 distinct", p.Categories)
	}

	// Unrelated PID (the one we logged with no rule) should not appear.
	p, err = a.ProfileForPID(9999)
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Errorf("PID 9999 should have no profile (rule was empty), got %+v", p)
	}
}

func TestArchive_Nil(t *testing.T) {
	var a *AlertArchive
	// Nil-safe: all methods should no-op or return cleanly.
	if err := a.Record(&Event{Rule: "x"}); err != nil {
		t.Errorf("nil archive Record returned %v, want nil", err)
	}
	p, err := a.ProfileForPID(1)
	if err != nil || p != nil {
		t.Errorf("nil archive ProfileForPID returned (%v, %v), want (nil, nil)", p, err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("nil archive Close returned %v, want nil", err)
	}
}

func TestArchive_FormatNilProfile(t *testing.T) {
	var p *PIDProfile
	if s := p.Format(); s == "" {
		t.Error("nil profile Format should return a non-empty string")
	}
}
