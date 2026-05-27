# Eval framework

A small offline test harness that grades the LLM investigator agent
against a corpus of hand-labelled syscall scenarios. Useful for:

- Catching prompt regressions after a system-prompt edit
- Comparing models (Haiku 4.5 vs Sonnet 4.6 vs Opus 4.7)
- Tuning rule severity thresholds
- Producing a confidence number for the README

The eval mode is built into the daemon binary itself — no extra binary,
no Python deps. eBPF is skipped, so the eval can run on any Linux host
with network access (and on macOS too, via colima).

## Run

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
sudo -E ./agent-shield -eval evals/scenarios.yaml
```

The `-eval` mode short-circuits the daemon: it skips eBPF setup,
skips the dashboard, and exits with the eval results. Exit code 0 if
all scenarios passed.

Specify the model:

```bash
sudo -E ./agent-shield -eval evals/scenarios.yaml -llm-model claude-sonnet-4-6
```

## Output

```
Running 14 scenarios (model=claude-haiku-4-5)

  [ 1/14] destructive_rm_system_binary    ✓ PASS  risk=92  cat=destructive    2.1s
  [ 2/14] destructive_rm_etc_passwd       ✓ PASS  risk=95  cat=destructive    1.8s
  [ 3/14] benign_rm_tmp_file              ✓ PASS  risk=5   cat=benign         1.2s
  [ 4/14] exfil_read_etc_shadow           ✓ PASS  risk=88  cat=exfiltration   2.4s
  …

═══════════════════════════════════════════════════════
  SUMMARY
═══════════════════════════════════════════════════════
  Scenarios:       14
  Passed:          13  (92.9%)
  Failed:          1

  By expected category:
    destructive    : 3/3   (100%)
    exfiltration   : 3/3   (100%)
    recon          : 1/2   (50%)
    egress         : 2/2   (100%)
    benign         : 4/4   (100%)

  Average latency: 1.9s

  Failures:
    recon_exec_tcpdump  →  category "egress" ≠ expected "recon"
```

## Scenario format

Each scenario is a YAML object:

```yaml
- id: destructive_rm_system_binary           # stable identifier
  description: rm of /usr/bin/python3        # human note
  history:                                   # optional: seed event history
    - {type: exec, pid: 9001, uid: 0, comm: bash, path: /usr/bin/rm}
  event:                                     # the syscall under test
    type: unlinkat
    pid: 9001
    uid: 0
    comm: rm
    path: /usr/bin/python3
    rule: protected_unlink
    action: block
    severity: critical
  expected:                                  # passing range
    risk_min: 75
    risk_max: 100
    category: destructive
```

`event` must populate the same fields the daemon would emit (see
`Event` in `main.go`). `expected.category` may be omitted — only the
`risk_min/max` range is then checked.

## Cost

Each scenario triggers 1-4 Anthropic API calls (the agent loop may
fan out into tool use). With Haiku 4.5 at ~$0.0005/call, a 14-scenario
sweep costs roughly $0.02-$0.03.

## What this evaluates

This is **end-to-end** prompt/agent quality:

- Whether the model picks reasonable categories
- Whether risk numbers are calibrated (a `rm /usr/bin/python` should
  score ≥ 75; a `ls /tmp` should score ≤ 20)
- Whether the agent uses tools well (the `path_metadata` tool should
  flip system-critical=true on `/usr/bin/python3`)
- How prompt changes affect overall accuracy

It does **not** evaluate:

- eBPF correctness (covered by `scripts/demo.sh`)
- Rule engine correctness (covered by `rule_test.go`)
- Latency under load (would need a separate benchmark harness)

## Extending

Add a new scenario by appending to `scenarios.yaml`. A balanced corpus
has roughly equal representation across each `category`, plus enough
"benign" cases to surface false positives.

If a scenario fails reliably, that's a signal to either:

1. Refine the system prompt in `llm.go` to give better guidance, or
2. Widen the expected range if the model's verdict is plausible but
   outside the bounds.
