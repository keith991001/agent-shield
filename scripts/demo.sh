#!/usr/bin/env bash
# agent-shield demo runner.
#
# Sets up sandboxes, runs the daemon in the background, triggers each
# demo scenario in sequence, and verifies the daemon reacted as expected.
#
# Run from the repo root: sudo ./scripts/demo.sh

set -uo pipefail

DEMO_DIR=/tmp/agent-shield-demo
EXFIL_DIR=/tmp/agent-shield-demo-exfil
EVENTS_LOG=/tmp/agent-shield-events.json
DAEMON_LOG=/tmp/agent-shield-daemon.log
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

DAEMON_PID=""
cleanup() {
    if [[ -n "$DAEMON_PID" ]]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf "$DEMO_DIR" "$EXFIL_DIR"
}
trap cleanup EXIT

start_daemon() {
    : > "$EVENTS_LOG"
    "$DAEMON" -rules "$RULES" -ws-listen "" > "$EVENTS_LOG" 2>"$DAEMON_LOG" &
    DAEMON_PID=$!
    sleep 1.0
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "FAILED: daemon did not start. Stderr:" >&2
        cat "$DAEMON_LOG" >&2
        exit 1
    fi
}

stop_daemon() {
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
    DAEMON_PID=""
}

count_rule_hits() {
    local name="$1"
    # `grep -c` prints "0" AND exits 1 when there are no matches. Without
    # the trailing `|| true` set -uo pipefail would propagate that exit.
    local n
    n=$(grep -c "\"rule\":\"$name\"" "$EVENTS_LOG" 2>/dev/null || true)
    echo "${n:-0}"
}

count_action() {
    local action="$1"
    local n
    n=$(grep -c "\"action\":\"$action\"" "$EVENTS_LOG" 2>/dev/null || true)
    echo "${n:-0}"
}

count_blocked() {
    local n
    n=$(grep -c '"blocked":true' "$EVENTS_LOG" 2>/dev/null || true)
    echo "${n:-0}"
}

PASS_COUNT=0
FAIL_COUNT=0
pass() { echo "  ✓ $1"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { echo "  ✗ $1"; FAIL_COUNT=$((FAIL_COUNT+1)); }

# ════════════════════════════════════════════════════════════════════════
echo
echo "▶ Demo 1: destructive unlink on protected directory should be BLOCKED"
echo "════════════════════════════════════════════════════════════════════════"
rm -rf "$DEMO_DIR" && mkdir -p "$DEMO_DIR"
for ch in a b c d e f g h i j; do
    echo "test $ch" > "$DEMO_DIR/$ch.txt"
done
echo "  → seeded $DEMO_DIR with 10 files"

start_daemon
echo "  → daemon up (pid $DAEMON_PID)"

echo "  → attempting rm -rf $DEMO_DIR/* (should get killed)"
rm -rf "$DEMO_DIR"/* 2>/dev/null
RM_EXIT=$?
sleep 0.3

REMAINING=$(ls "$DEMO_DIR" 2>/dev/null | wc -l)
BLOCKED=$(count_blocked)

echo "  result: rm_exit=$RM_EXIT  remaining=$REMAINING/10  blocked_events=$BLOCKED"
[[ "$BLOCKED" -ge 1 ]] && pass "block fired" || fail "expected at least 1 blocked event"
[[ "$REMAINING" -ge 1 ]] && pass "files preserved" || fail "expected at least 1 file remaining"

stop_daemon

# ════════════════════════════════════════════════════════════════════════
echo
echo "▶ Demo 2: reading a sensitive file should fire an ALERT"
echo "════════════════════════════════════════════════════════════════════════"
mkdir -p "$EXFIL_DIR"
# Synthesize a "sensitive" file the rule will pick up. /etc/shadow itself
# is rule-matched but reading it on every run is noisy in the daemon's
# own startup, so use a path that matches path_contains: .env
echo "API_KEY=fake-secret-12345" > "$EXFIL_DIR/.env"
echo "  → seeded $EXFIL_DIR/.env"

start_daemon
echo "  → daemon up"
sleep 0.3

echo "  → reading $EXFIL_DIR/.env (sensitive)"
cat "$EXFIL_DIR/.env" >/dev/null
sleep 0.3

ALERTS=$(count_rule_hits sensitive_keyword_read)
echo "  result: alerts_for_.env=$ALERTS"
[[ "$ALERTS" -ge 1 ]] && pass "alert fired" || fail "expected sensitive_keyword_read alert"

stop_daemon

# ════════════════════════════════════════════════════════════════════════
echo
echo "▶ Demo 3: normal operations should NOT trigger any alert or block"
echo "════════════════════════════════════════════════════════════════════════"
mkdir -p /tmp/normal-work && echo hello > /tmp/normal-work/data.txt

start_daemon
echo "  → daemon up"
sleep 0.3

echo "  → ls / cat / sleep — normal work"
ls /tmp/normal-work >/dev/null
cat /tmp/normal-work/data.txt >/dev/null
sleep 0.3

ALERT_TOTAL=$(count_action alert)
BLOCK_TOTAL=$(count_action block)
echo "  result: alerts=$ALERT_TOTAL  blocks=$BLOCK_TOTAL"
# Some alerts may show up from background system noise; we only assert
# zero blocks since that's the hard requirement.
[[ "$BLOCK_TOTAL" -eq 0 ]] && pass "no blocks for normal work" || fail "unexpected blocks for normal work"

stop_daemon
rm -rf /tmp/normal-work

# ════════════════════════════════════════════════════════════════════════
echo
echo "════════════════════════════════════════════════════════════════════════"
echo "  SUMMARY: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "  Event log: $EVENTS_LOG"
echo "  Daemon log: $DAEMON_LOG"
echo "════════════════════════════════════════════════════════════════════════"

exit "$FAIL_COUNT"
