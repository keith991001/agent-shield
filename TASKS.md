# TASKS.md — common operational recipes

Concrete step-by-step playbooks for things you'll likely ask the
assistant to do. Each recipe has: **goal**, **files touched**,
**steps**, **verification**.

Add to this file when you do something new that's worth a recipe.

---

## R1. Add a new syscall probe

**Goal.** Have agent-shield observe a syscall it currently ignores
(e.g. `chmod`, `mmap`, `ptrace`).

**Files touched.**
- `bpf/probe.c` — define the SEC + handler, extend the event_type enum
- `main.go` — extend the EventType constants, the decode() switch, and
  the tracepoint attach list
- `rules.yaml` (optional) — add a rule that uses the new event type
- `evals/scenarios.yaml` (optional) — add coverage

**Steps.**

1. In `bpf/probe.c`:
   - Add a new constant to the `enum event_type` (sequential value)
   - Add a `SEC("tracepoint/syscalls/sys_enter_<name>")` function that
     fills `event` and submits to the ring buffer. Copy `handle_openat`
     as a template (it's the canonical path-based probe)
2. In `main.go`:
   - Mirror the new event_type constant
   - Add a `link.Tracepoint("syscalls", "sys_enter_<name>", objs.Handle<Name>, nil)`
     call below the existing five — remember the `defer tp.Close()`
   - Extend the `decode()` switch to set `evt.Type = "<name>"` and
     populate the relevant field
3. Regenerate eBPF bindings:
   ```bash
   go generate ./...
   git add bpf_*.go bpf_*.o
   ```
4. `make build && make test`
5. Smoke test with a 2-second timeout: `sudo timeout 2 ./agent-shield > /tmp/out.json` then trigger the syscall.
6. Add coverage in `evals/scenarios.yaml` so the new event type has at
   least one scenario.

**Verification.** `jq -r .type /tmp/out.json | sort -u` includes the new
event type after triggering it in another terminal.

---

## R2. Add a new investigator tool

**Goal.** Give Claude a new tool to call during investigation.

**Files touched.** `llm.go` only (in most cases).

**Steps.**

1. Implement the tool function:
   ```go
   func toolDoX(args ...) string {
       // do the work, return human-readable string
       // (error → "error: ..." prefix; callers can detect)
   }
   ```
2. Add a case to `dispatchTool()`:
   ```go
   case "do_x":
       var args struct{ Foo string `json:"foo"` }
       if err := json.Unmarshal(input, &args); err != nil {
           return fmt.Sprintf("error: bad input: %v", err)
       }
       return toolDoX(args.Foo)
   ```
3. Add an entry to the `allTools` slice with the Anthropic JSON schema.
4. Add the tool to the **"Tools available"** section of `systemPrompt`.
5. Optionally update `DESIGN.md` §6.3.1 (tools table).
6. Add a unit test for the tool function if it has non-trivial logic.

**Verification.**
```bash
sudo -E ./agent-shield -eval evals/scenarios.yaml | grep tools=
```
`avg_tools` should rise slightly if the model finds the new tool useful.

---

## R3. Tune the system prompt

**Goal.** Improve verdict accuracy or reduce cost by editing the prompt.

**Steps.**

1. **Don't edit `systemPrompt` directly first.** Instead, add a new
   variant to `evals/prompts.yaml`:
   ```yaml
   - id: my_change_v1
     description: "Stronger emphasis on benign explanations"
     system_prompt: |
       <your new prompt>
   ```
2. Run A/B comparison:
   ```bash
   sudo -E ./agent-shield -eval evals/scenarios.yaml \
                          -eval-prompts evals/prompts.yaml
   ```
3. Read the comparison table. The new variant wins iff:
   - Pass rate ≥ baseline, AND
   - Cost per pass ≤ 1.2× baseline (small accuracy gain isn't worth a
     large cost increase)
4. **If it wins**: replace `systemPrompt` const in `llm.go` with the
   new text, drop the variant from `prompts.yaml`, commit.
5. **If it loses**: keep the variant in `prompts.yaml` (as a regression
   test for future prompts), don't promote it.

**Anti-pattern.** Editing `systemPrompt` directly without A/B comparison
is what this harness exists to prevent.

---

## R4. Add an eval scenario

**Goal.** Cover a class of events the current 14 scenarios miss
(common need: new syscall type, new attack pattern).

**Files touched.** `evals/scenarios.yaml` only.

**Steps.**

1. Find a similar existing scenario to copy as a template.
2. Set realistic `risk_min`/`risk_max` — start with a wide range
   (say `40..90`) and tighten once you see the model's actual output.
3. Pick `category` honestly:
   - `destructive` — irreversible damage to system state
   - `exfiltration` — reading secrets that would be leaked
   - `recon` — scanning, probing, fingerprinting
   - `egress` — outbound traffic of note (not exfil yet)
   - `benign` — should not have been flagged at all
4. Optionally seed `history` with prior events for context (rare).
5. Run eval and tighten the range based on observed risk values.

**Verification.** Add the scenario, run `-eval`, ensure your new
scenario passes. If it doesn't, decide: prompt issue, or unrealistic
expectation?

---

## R5. Run the full demo for a screencast

**Goal.** Produce a clean demo run for documentation / screencast.

**Steps.**

1. Reset state:
   ```bash
   rm -rf /tmp/agent-shield-demo /tmp/agent-shield-demo-exfil
   mkdir -p /tmp/agent-shield-demo /tmp/agent-shield-demo-exfil
   for i in {1..10}; do touch /tmp/agent-shield-demo/file$i.txt; done
   echo "API_KEY=fake-leaked" > /tmp/agent-shield-demo-exfil/.env
   clear
   ```
2. In **Terminal 1** (daemon):
   ```bash
   sudo -E ./agent-shield -llm -archive /tmp/demo-alerts.db
   ```
3. In **Terminal 2** (browser): `open http://localhost:8090`
4. In **Terminal 3** (trigger), wait ~3 seconds then run:
   ```bash
   rm -rf /tmp/agent-shield-demo/*
   cat /tmp/agent-shield-demo-exfil/.env
   ```
5. Dashboard shows one BLOCKED row (red), one ALERT row (orange).
   1-2 seconds later, LLM risk pills fade in beneath each.
6. `Ctrl-C` on daemon, run `./scripts/demo.sh` for the 4/4 PASS summary
   in the same terminal.

**Verification.** Daemon stderr logs `5 probes attached`, `dashboard at
http://localhost:8090`, and at least 1 `client connected` line.

---

## R6. Persist alerts and inspect cross-session memory

**Goal.** Show that the SQLite archive accumulates across daemon restarts.

**Steps.**

1. Run the daemon with archive, trigger several alerts:
   ```bash
   sudo -E ./agent-shield -archive /tmp/demo.db &
   for i in 1 2 3; do
     rm -rf /tmp/agent-shield-demo/*  # blocked, but rebuild after each
     mkdir -p /tmp/agent-shield-demo
     touch /tmp/agent-shield-demo/file.txt
   done
   sudo pkill -f agent-shield
   ```
2. Inspect the archive:
   ```bash
   sqlite3 /tmp/demo.db 'SELECT pid, COUNT(*), SUM(action="block") FROM alerts GROUP BY pid'
   ```
3. Restart daemon with same `-archive /tmp/demo.db` — the agent's
   `get_pid_history` tool now returns historical data.

**Verification.** SQL row counts are non-zero. With `-llm` enabled, the
investigator agent will call `get_pid_history` and reference past
incidents in its `risk_reason`.

---

## R7. Bisect a prompt regression

**Goal.** A prompt change worsened eval results. Find the offending edit.

**Steps.**

1. `git log --oneline llm.go` to see commits touching the prompt.
2. Identify last-good and first-bad commits.
3. Use `git bisect`:
   ```bash
   git bisect start
   git bisect bad HEAD
   git bisect good <last-good-sha>
   ```
4. At each step: `make build && sudo -E ./agent-shield -eval evals/scenarios.yaml`.
   Read pass rate from the summary; mark `git bisect good` or `bad`.
5. Bisect converges. Read the offending commit's diff in `llm.go`.

**Verification.** Bisect prints the first bad commit. Review the prompt
diff to understand the regression source.

---

## R8. Investigate why a specific scenario fails

**Goal.** One scenario in `evals/scenarios.yaml` keeps failing — find why.

**Steps.**

1. Note the failure in the eval summary, e.g.
   `recon_exec_tcpdump → category "egress" ≠ expected "recon"`.
2. The agent's full reasoning isn't currently logged at scenario level
   in eval mode. Two ways to inspect:
   - **Quick:** run the scenario through a one-off ad-hoc script
     that constructs the Event in Go and calls `runAgentLoop` with a
     debug print of each turn.
   - **Better:** add a `-eval-verbose` flag (not yet implemented) that
     logs each assistant content block. (TODO recipe — add when needed.)
3. Look at the agent's tool calls and reasoning. Common findings:
   - The expected category is wrong (tcpdump *is* often used for egress
     interception). Widen the scenario or revise.
   - The prompt doesn't disambiguate categories well. Add an example
     to `systemPrompt`.
   - The model lacks a tool to make a confident classification.
4. Choose: widen the scenario, update the prompt (via R3), or add a
   new tool (R2).

---

## R9. Push to GitHub

**Goal.** Land a change on `main`.

**Steps.**

1. `make check && make test` — ensure local green
2. `git add` only the files you intend to commit (no `git add -A` without
   `git status --short` review first)
3. Write a commit following the convention. The body should explain *why*
   for non-trivial changes
4. `git push origin main`
5. `gh run watch $(gh run list --limit 1 --json databaseId -q '.[0].databaseId')`
   to confirm CI green

**Anti-pattern.** Pushing then walking away without confirming CI.
