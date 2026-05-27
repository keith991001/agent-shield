# agent-shield

> **AI Agent runtime governance** — observe LLM agent behavior at the syscall layer,
> block dangerous actions in real time, and let an LLM explain what happened.

[![Status](https://img.shields.io/badge/status-alpha-orange)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://go.dev/)
[![eBPF](https://img.shields.io/badge/Linux-eBPF-orange?logo=linux)](https://ebpf.io/)

## Why

LLM agents (Claude Code, Cursor Agent, Devin, …) execute arbitrary shell commands,
write files, and make network requests. A misjudgment or a prompt injection can
turn into `rm -rf`, key exfiltration, or attacks on internal services.

Existing isolation tools focus on **before** (permission allowlists) or **after**
(audit logs). `agent-shield` fills the **during** gap: real-time observability
plus real-time intervention.

```
before (permission)  ──── during (agent-shield) ──── after (audit log)
                              ▲
                              │
                  "what is the agent doing right now —
                   and do I want to let it?"
```

## Architecture

```
┌─ AI Agent process ─┐
│ rm -rf /usr/bin    │ ─► ⚠ blocked → kill + log
│ curl evil.xyz      │ ─► ⚠ alert
│ ls /tmp            │ ─► ✅ allowed
└────────────────────┘
            ↓ syscall
       [eBPF probes]
            ↓ ringbuf
       [Rule Engine]
            ↓
   [Action: log / alert / block]
            ↓
  [Web Dashboard + LLM risk scoring]
```

See [DESIGN.md](DESIGN.md) for full architecture, technology choices, and rationale.

## Status

**Week 2 / 6 — rules + blocking** ✅

- [x] Project skeleton
- [x] eBPF probe for `execve` with structured events via ringbuf
- [x] Userspace Go daemon, JSON event stream on stdout
- [x] 4 more syscalls (`openat` / `unlinkat` / `connect` / `socket`)
- [x] YAML rule engine + kill-based blocking
- [x] Demo 1: `rm -rf /tmp/agent-shield-demo/` → blocked (rm gets SIGKILL'd)
- [ ] Web dashboard (Next.js + WebSocket)
- [ ] Claude API risk scoring
- [ ] More demos + screencast

## Quick start

Requires **Linux ≥ 5.8** (CO-RE + ringbuf), `clang`, `llvm`, `libbpf-dev`,
`linux-headers`, and Go ≥ 1.24. macOS users can run inside a colima VM.

```bash
# clone
git clone https://github.com/keith991001/agent-shield.git
cd agent-shield

# build
make build

# run with default rules.yaml (needs root for eBPF)
sudo ./agent-shield

# or run a self-contained demo (recommended)
sudo ./scripts/demo.sh
```

The default ruleset blocks `rm` inside protected directories
(`/usr/`, `/etc/`, `/bin/`, `/tmp/agent-shield-demo/`). With the daemon
running, in another terminal:

```bash
mkdir -p /tmp/agent-shield-demo && touch /tmp/agent-shield-demo/{a,b,c}.txt
rm -rf /tmp/agent-shield-demo/*    # gets SIGKILL'd after the first unlink
```

You'll see structured events on stdout:

```json
{"time":"...","type":"exec","pid":67209,"uid":1000,"comm":"bash","path":"/usr/bin/curl"}
{"time":"...","type":"connect","pid":67210,"uid":1000,"comm":"curl","family":"AF_INET","dest":"1.1.1.1:443"}
{"time":"...","type":"unlinkat","pid":67211,"uid":0,"comm":"rm","path":"/tmp/agent-shield-demo/a.txt","rule":"protected_unlink","action":"block","severity":"critical","blocked":true}
```

The last event is an `unlinkat` that matched the `protected_unlink` rule
and was blocked — `rm` was killed before it could delete more files.

## Project layout

```
agent-shield/
├── DESIGN.md          # full design doc — read this first
├── README.md          # you are here
├── LICENSE            # MIT
├── Makefile           # build / run / clean / generate
├── go.mod / go.sum    # Go module
├── main.go            # userspace daemon entry
├── rule.go            # YAML rule engine
├── rules.yaml         # default ruleset (edit to customize)
├── scripts/
│   └── demo.sh        # end-to-end demo runner
├── bpf/
│   └── probe.c        # eBPF program (compiled with clang to BPF bytecode)
└── headers/           # vendored libbpf headers (from cilium/ebpf examples)
```

## Development

```bash
make generate   # compile bpf/probe.c → bpf_bpfel.o + Go bindings
make build      # compile the Go daemon
make run        # build + run with sudo
make clean      # remove build artifacts
```

The `make generate` step uses [`bpf2go`](https://github.com/cilium/ebpf/tree/main/cmd/bpf2go)
to compile the C program with `clang` and emit Go bindings.

## Prior art / inspiration

- [Falco](https://falco.org/) — eBPF runtime security for containers
- [Tetragon](https://github.com/cilium/tetragon) — modern eBPF security observability
- [Tracee](https://github.com/aquasecurity/tracee) — runtime threat detection
- This project is the AI-agent-specialized cousin: smaller scope, but the
  "explain with LLM" angle is unique

## License

MIT — see [LICENSE](LICENSE).

## Author

Built as a personal project while at Pepabo 16th-gen new grad training.
Learning notes and design rationale in [DESIGN.md](DESIGN.md).
