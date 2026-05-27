#!/usr/bin/env bash
# agent-shield demo runner.
#
# Sets up a sandbox directory, runs the daemon in the background,
# triggers each demo scenario, and verifies the daemon reacted as expected.
#
# Run from the repo root: sudo ./scripts/demo.sh

set -uo pipefail

DEMO_DIR=/tmp/agent-shield-demo
EVENTS_LOG=/tmp/agent-shield-events.json
DAEMON=./agent-shield
RULES=./rules.yaml

if [[ $EUID -ne 0 ]]; then
    echo "run as root: sudo $0" >&2
    exit 1
fi

if [[ ! -x "$DAEMON" ]]; then
    echo "$DAEMON not built. Run: make build" >&2
    exit 1
fi

cleanup() {
    kill "${DAEMON_PID:-0}" 2>/dev/null || true
    wait "${DAEMON_PID:-0}" 2>/dev/null || true
    rm -rf "$DEMO_DIR"
}
trap cleanup EXIT

setup_demo_dir() {
    rm -rf "$DEMO_DIR"
    mkdir -p "$DEMO_DIR"
    for ch in a b c d e f g h i j; do
        echo "test file $ch" > "$DEMO_DIR/$ch.txt"
    done
    echo "  → seeded $DEMO_DIR with 10 files"
}

start_daemon() {
    : > "$EVENTS_LOG"
    "$DAEMON" -rules "$RULES" > "$EVENTS_LOG" 2>/tmp/agent-shield-daemon.log &
    DAEMON_PID=$!
    # Give the daemon time to attach probes.
    sleep 1
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "FAILED: daemon did not start. Stderr:" >&2
        cat /tmp/agent-shield-daemon.log >&2
        exit 1
    fi
    echo "  → daemon started (PID $DAEMON_PID)"
}

count_events_of() {
    local rule_name="$1"
    grep -c "\"rule\":\"$rule_name\"" "$EVENTS_LOG" || true
}

# ════════════════════════════════════════════════════════════════════════
echo
echo "▶ Demo 1: destructive unlink on protected directory should be BLOCKED"
echo "════════════════════════════════════════════════════════════════════════"
setup_demo_dir
start_daemon

echo "  → attempting rm -rf $DEMO_DIR/* (should get killed)"
rm -rf "$DEMO_DIR"/* 2>/tmp/rm_stderr.txt &
RM_PID=$!
wait $RM_PID
RM_EXIT=$?

sleep 0.5

REMAINING=$(ls "$DEMO_DIR" 2>/dev/null | wc -l)
BLOCKED=$(grep -c '"blocked":true' "$EVENTS_LOG" || true)

echo
echo "  result:"
echo "    rm exit code:        $RM_EXIT          (non-zero ⇒ killed)"
echo "    files remaining:     $REMAINING / 10"
echo "    blocked events:      $BLOCKED"
echo "    matched events:"
grep '"rule":"protected_unlink"' "$EVENTS_LOG" | head -3 | sed 's/^/      /'
echo

if (( BLOCKED >= 1 )) && (( REMAINING >= 1 )); then
    echo "  ✓ Demo 1 PASSED — daemon killed rm before all files were removed"
else
    echo "  ✗ Demo 1 FAILED — expected at least 1 blocked event and 1 remaining file"
fi

cleanup
trap - EXIT
echo
echo "all demos complete. event log: $EVENTS_LOG"
