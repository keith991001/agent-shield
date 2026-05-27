//go:build linux

package main

import "testing"

func TestEventHistory_AddAndLen(t *testing.T) {
	h := NewEventHistory(3)
	h.Add(Event{ID: 1, PID: 100, Comm: "a"})
	h.Add(Event{ID: 2, PID: 100, Comm: "b"})
	if got := h.Len(); got != 2 {
		t.Errorf("Len = %d, want 2", got)
	}
}

func TestEventHistory_CapacityEviction(t *testing.T) {
	h := NewEventHistory(3)
	for i := 1; i <= 5; i++ {
		h.Add(Event{ID: uint64(i), PID: 100})
	}
	if got := h.Len(); got != 3 {
		t.Errorf("Len = %d, want 3 (capacity)", got)
	}
	// Only the newest 3 (IDs 3,4,5) should remain — verify via recent().
	events := h.RecentForPID(100, 10)
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}
	// Newest first.
	if events[0].ID != 5 || events[2].ID != 3 {
		t.Errorf("unexpected order: ids=%v", []uint64{events[0].ID, events[1].ID, events[2].ID})
	}
}

func TestEventHistory_RecentForPID_FiltersAndLimits(t *testing.T) {
	h := NewEventHistory(100)
	for i := 1; i <= 10; i++ {
		h.Add(Event{ID: uint64(i), PID: 100})
		h.Add(Event{ID: uint64(i + 100), PID: 200})
	}
	// PID 200 has 10 events; ask for newest 3
	events := h.RecentForPID(200, 3)
	if len(events) != 3 {
		t.Fatalf("got %d, want 3", len(events))
	}
	for _, e := range events {
		if e.PID != 200 {
			t.Errorf("contaminated PID: %d", e.PID)
		}
	}
	// Newest first
	if events[0].ID != 110 {
		t.Errorf("expected newest id=110, got %d", events[0].ID)
	}
}

func TestEventHistory_CountByPattern(t *testing.T) {
	h := NewEventHistory(100)
	h.Add(Event{Comm: "rm", Type: "unlinkat"})
	h.Add(Event{Comm: "rm", Type: "unlinkat"})
	h.Add(Event{Comm: "rm", Type: "openat"})
	h.Add(Event{Comm: "cat", Type: "openat"})

	if got := h.CountByPattern("rm", "unlinkat"); got != 2 {
		t.Errorf("rm+unlinkat = %d, want 2", got)
	}
	if got := h.CountByPattern("rm", ""); got != 3 {
		t.Errorf("rm any = %d, want 3", got)
	}
	if got := h.CountByPattern("", "openat"); got != 2 {
		t.Errorf("any openat = %d, want 2", got)
	}
	if got := h.CountByPattern("", ""); got != 4 {
		t.Errorf("wildcard = %d, want 4", got)
	}
}

func TestExtractVerdict_PlainJSON(t *testing.T) {
	blocks := []contentBlock{
		{Type: "text", Text: `{"risk":85,"category":"destructive","reason":"system bin deletion"}`},
	}
	v, err := extractVerdict(blocks)
	if err != nil {
		t.Fatal(err)
	}
	if v.Risk != 85 || v.Category != "destructive" {
		t.Errorf("got %+v", v)
	}
}

func TestExtractVerdict_WithMarkdownFences(t *testing.T) {
	blocks := []contentBlock{
		{Type: "text", Text: "```json\n{\"risk\":50,\"category\":\"benign\",\"reason\":\"ok\"}\n```"},
	}
	v, err := extractVerdict(blocks)
	if err != nil {
		t.Fatal(err)
	}
	if v.Risk != 50 {
		t.Errorf("risk = %d, want 50", v.Risk)
	}
}

func TestExtractVerdict_WithPreamble(t *testing.T) {
	blocks := []contentBlock{
		{Type: "text", Text: `Here is my verdict:
{"risk":42,"category":"benign","reason":"after investigation, no risk"}`},
	}
	v, err := extractVerdict(blocks)
	if err != nil {
		t.Fatal(err)
	}
	if v.Risk != 42 {
		t.Errorf("risk = %d, want 42", v.Risk)
	}
}

func TestExtractVerdict_ClampsRange(t *testing.T) {
	for _, raw := range []int{-10, 150, 999} {
		blocks := []contentBlock{
			{Type: "text", Text: `{"risk":` + itoa(raw) + `,"category":"x","reason":"y"}`},
		}
		v, err := extractVerdict(blocks)
		if err != nil {
			t.Fatal(err)
		}
		if v.Risk < 0 || v.Risk > 100 {
			t.Errorf("risk %d not clamped (input %d)", v.Risk, raw)
		}
	}
}

// small local helper to avoid importing strconv just for the test
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}
