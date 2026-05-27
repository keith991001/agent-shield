//go:build linux

package main

import "sync"

// EventHistory is an in-memory ring buffer of the most recent events the
// daemon has observed. It exists so the LLM investigator agent can call
// the `recent_events_for_pid` tool to gather context across syscalls.
//
// Concurrency: writes from the single event loop goroutine, reads from
// LLM worker goroutines. Guarded by an RWMutex.
type EventHistory struct {
	mu     sync.RWMutex
	cap    int
	events []Event // append-only with cap; oldest at index 0
}

func NewEventHistory(capacity int) *EventHistory {
	if capacity <= 0 {
		capacity = 10_000
	}
	return &EventHistory{
		cap:    capacity,
		events: make([]Event, 0, capacity),
	}
}

// Add records an event. Truncates the head when over capacity.
func (h *EventHistory) Add(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, e)
	if len(h.events) > h.cap {
		// Drop the oldest entries. Re-slice rather than copy so we
		// don't realloc; the backing array is reused.
		over := len(h.events) - h.cap
		h.events = h.events[over:]
	}
}

// RecentForPID returns up to n most recent events for a given PID,
// newest first.
func (h *EventHistory) RecentForPID(pid uint32, n int) []Event {
	h.mu.RLock()
	defer h.mu.RUnlock()

	out := make([]Event, 0, n)
	for i := len(h.events) - 1; i >= 0 && len(out) < n; i-- {
		if h.events[i].PID == pid {
			out = append(out, h.events[i])
		}
	}
	return out
}

// CountByPattern returns how many events match a (comm, type) pair.
// Empty string in either field is a wildcard. Used by the
// `count_similar_events` tool.
func (h *EventHistory) CountByPattern(comm, eventType string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	n := 0
	for i := range h.events {
		if comm != "" && h.events[i].Comm != comm {
			continue
		}
		if eventType != "" && h.events[i].Type != eventType {
			continue
		}
		n++
	}
	return n
}

// Len returns the current number of events held.
func (h *EventHistory) Len() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.events)
}
