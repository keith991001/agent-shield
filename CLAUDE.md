# CLAUDE.md — agent-shield contributor brief

This file is **automatically loaded as project context** by Claude Code
when it operates inside this repository. It is the fastest path to
productivity for a fresh AI assistant (or a fresh human contributor).
Keep it short, action-oriented, and current.

For deeper context, follow the trail:

| If you need… | Read |
|---|---|
| 30-second pitch | [`README.md`](README.md) |
| Architecture decisions ("why") | [`DESIGN.md`](DESIGN.md) §5 |
| Component internals ("how") | [`DESIGN.md`](DESIGN.md) §6 |
| Narrative / blog-style writeup | [`BLOG.md`](BLOG.md) |
| Common task recipes | [`TASKS.md`](TASKS.md) |

---

## What this project is

A single Go daemon + Python companion that demonstrates a complete
"AI agent runtime governance" loop:

```
sysadmin-agent (Python, Anthropic SDK)
     ↓ syscall
agent-shield daemon (Go, eBPF + rules + WebSocket dashboard)
     ↓ matched events (severity ≥ medium)
LLM Investigator Agent (Claude Haiku via Anthropic Messages API)
     ↓ uses 4 tools (proc / in-mem history / fs / SQLite archive)
     ↓ Plan-Execute-Synthesize + reflection
risk verdict re-broadcast to dashboard
```

Plus an **A/B eval harness** to grade the investigator across 14
labelled scenarios.

The project demonstrates four reusable patterns:

1. eBPF observation → userspace rule engine → action loop
2. Multi-turn LLM agent with parallel tool use
3. Persistent memory (SQLite) feeding agent tools across sessions
4. Offline eval framework with prompt A/B comparison

---

## Current state (snapshot)

- MVP complete (Weeks 1-6 of the original roadmap)
- Plus 4.1-4.5 senior-track upgrades (plan-execute, reflection, SQLite
  memory, A/B eval, cost telemetry)
- 20+ commits with linear, semantic history
- GitHub Actions CI green
- ~2400 lines of Go + eBPF C + Python + HTML
- Single ~17 MB binary (pure-Go SQLite, no cgo)

The "front" of work next is in [`DESIGN.md`](DESIGN.md) §9.2 / §9.3.
**Do not start v2 work unless explicitly asked.**

---

## Repository map

```
main.go              daemon entrypoint, event loop, eval-mode dispatch
rule.go              YAML rule engine (first-match-wins, like iptables)
dashboard.go         embedded HTTP server + WebSocket hub
llm.go               LLM investigator agent (Plan-Execute-Synthesize +
                     reflection + 4 tools + token tracking)
history.go           in-memory ring buffer of recent events (short-term)
archive.go           SQLite persistent alert archive (long-term)
eval.go              scenario loader + grading runner
eval_ab.go           A/B prompt eval harness

bpf/probe.c          eBPF program — 5 syscall tracepoints, ring buffer
headers/             vendored libbpf headers (do not edit)
static/index.html    embedded dashboard UI (vanilla JS, no build step)

rules.yaml           default ruleset
evals/scenarios.yaml 14 hand-labelled grading scenarios
evals/prompts.yaml   3 prompt variants for A/B comparison
scripts/demo.sh      end-to-end CLI demo (3 scenarios, exit-code asserted)

examples/sysadmin-agent/  Python AI agent demo (the "monitored side")

*_test.go            unit tests — rule engine, history, archive,
                     helpers, verdict extraction
```

---

## Daily commands

```bash
make build          # compile eBPF + daemon
make test           # go test -race ./... (skips eBPF runtime)
make check          # gofmt + go vet (same as CI)
make run            # build + sudo run

sudo ./agent-shield                              # daemon, dashboard at :8090
sudo ./scripts/demo.sh                           # 3-scenario verifiable demo
sudo -E ./agent-shield -llm                      # daemon + LLM investigator
sudo -E ./agent-shield -archive /tmp/alerts.db   # + persistent memory
sudo -E ./agent-shield -eval evals/scenarios.yaml                          # grading
sudo -E ./agent-shield -eval evals/scenarios.yaml -eval-prompts evals/prompts.yaml   # A/B
```

`-E` preserves `ANTHROPIC_API_KEY` through `sudo`.

---

## Hard requirements before merging changes

Run this **one-liner** before every `git push` — it's not optional:

```bash
[ -z "$(gofmt -l .)" ] && go vet ./... && go test -race ./... && go build ./...
```

(or use the `make check && make test && make build` shortcut — but
`make` isn't always installed inside the colima VM, so the raw
command above is the portable fallback.)

CI runs the same four steps. If any of them fails locally, CI will too.

**The most-bitten rule**: gofmt is strict about godoc list/sub-bullet
indentation. If you write a multi-line Go comment with indented
sub-items, run `gofmt -w <file>` before committing — gofmt has
opinions about exact whitespace that are hard to predict by eye.

If you change `bpf/probe.c`, also run `go generate ./...` and commit
the regenerated `bpf_*_bpfel.{go,o}` files alongside the C change.

---

## Conventions

- Commit messages: `type(scope): summary\n\nbody`. See `git log --oneline`
  for the full corpus. Types in use: `feat` / `fix` / `docs` / `refactor`.
- Go files start with `//go:build linux` — this project is Linux-only by
  necessity (eBPF).
- Tests are table-driven where it makes sense (`rule_test.go` is canonical).
- Errors flow up; the event loop logs and continues. No panics in
  steady-state code.
- One feature per commit; never bundle unrelated changes.
- Do not commit: build artifacts, *.db files, /tmp/* outputs, recordings.

---

## Things to NOT do

- Don't push to `main` without CI green
- Don't commit `agent-shield` binary or `*.o` files except the
  regenerated `bpf_*_bpfel.o` (which are linked into the binary)
- Don't commit secrets — `ANTHROPIC_API_KEY` belongs in env, not files
- Don't reformat unrelated code while making changes
- Don't bump dependencies unless required for a feature
- Don't use `git push --force` on shared branches
- Don't skip pre-commit hooks (`--no-verify`) to bypass formatting

---

## Where to ask "why"

The single most useful entry point for *why* something is the way it is
is `DESIGN.md` §5 (key design decisions). Every non-obvious tradeoff is
written down there with rationale, organized as §5.1-§5.12. If you're
about to change something and can't find rationale, **add a §5.N entry
in the same commit**.

`BLOG.md` has the same content in narrative form — useful when you want
to *feel* the design rather than scan it.

---

## When unsure

Default behaviour: **ask the human** before doing anything that touches
the public GitHub repo, modifies committed history, or spends
non-trivial money on API calls.

Spend budgets for reference (Haiku 4.5 list prices):
- Full eval sweep: ≈ $0.03
- Full A/B eval (3 variants × 14 scenarios): ≈ $0.09
- 1 hour live daemon with `-llm`: ≈ $0.05-$0.20 depending on traffic
