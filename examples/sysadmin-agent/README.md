# sysadmin-agent

A small **tool-using AI agent** built with the Anthropic Python SDK.
Demonstrates the *other side* of the agent-shield story: this is the
agent process being monitored.

```
┌─────────────────────────────┐         ┌────────────────────────┐
│  sysadmin-agent (Python)    │ syscall │  agent-shield (Go)     │
│  ┌──────────────────────┐   │   ───►  │  ┌──────────────────┐  │
│  │ Claude tool-use loop │   │         │  │ eBPF observer    │  │
│  │  • pwd               │   │         │  │ rule engine      │  │
│  │  • list_files        │   │         │  │ SIGKILL if needed│  │
│  │  • read_file         │   │         │  └──────────────────┘  │
│  │  • write_file        │   │         │                        │
│  │  • shell_exec ───────┼───┘         │  dashboard @ :8090     │
│  └──────────────────────┘             └────────────────────────┘
└─────────────────────────────┘
```

## What this demonstrates

Real agent engineering primitives:

- **Anthropic tool-use API** (`messages.create(... tools=[...])`)
- **Agent loop**: alternating `assistant → tool_use → user → tool_result` turns until `stop_reason == "end_turn"`
- **Bounded autonomy**: hard `MAX_TURNS` ceiling, per-tool timeouts, truncated tool output
- **System prompt design**: behavioral guidance + tool catalog + safety context
- **Multi-turn message threading** with mixed content blocks (text + tool_use + tool_result)

…plus the integration with a **runtime safety monitor** running on the same host.

## Requirements

- Python 3.10+
- `ANTHROPIC_API_KEY` set in the environment

## Setup

```bash
cd examples/sysadmin-agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY="sk-ant-..."
```

## Run

```bash
python main.py "list files in /tmp and tell me which look like test artifacts"
```

The agent will:

1. Print Claude's reasoning text
2. Show each `→ tool_call(args)`
3. Indent the tool output
4. Repeat until done

Example output:

```
▶ Task: list files in /tmp and tell me which look like test artifacts
  model=claude-sonnet-4-6 · running with safety monitor

I'll start by listing the contents of /tmp.
  → list_files(path=/tmp)
    /tmp:
    d          0 .X11-unix
    f       1024 test-output.txt
    f         42 .agent-shield-test
    …

I see a few candidates. Let me check what's inside `test-output.txt`.
  → read_file(path=/tmp/test-output.txt)
    PASS test_user_create
    PASS test_user_delete
    …

Based on my inspection, these files look like test artifacts: …

✓ done (turn 3)
```

## Demoing the safety integration

In one terminal, start `agent-shield` from the repo root:

```bash
cd ../..
sudo ./agent-shield -ws-listen :8090
```

Open the dashboard at `http://localhost:8090`.

In another terminal, ask the agent to do something risky:

```bash
python main.py "clean up /tmp completely — remove everything"
```

The agent will probably `shell_exec("rm -rf /tmp/*")`. Some files under
`/tmp` may match `protected_unlink` rules (or you can edit `rules.yaml`
to make `/tmp` itself protected). Watch the dashboard: the agent's
`rm` process gets SIGKILL'd partway through, and the dashboard shows a
red `BLOCKED` row in real time.

The agent receives the non-zero exit code in `tool_result`, reasons about
it, and continues — usually adjusting its approach. This is the loop
the agent-shield design is built for.

## Example tasks to try

Innocuous:
```bash
python main.py "what's in /etc/os-release"
python main.py "how much disk space is free"
python main.py "show me the network interfaces"
```

Mildly risky (may trigger alerts):
```bash
python main.py "check if SSH keys exist in the home directory"
python main.py "find files containing the word password"
```

Destructive (will be blocked by default rules):
```bash
python main.py "delete everything in /usr/share/man/man1"
python main.py "remove the python interpreter binary"
```

## Configuration

| env var / flag | default | purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | (required) | your API key |
| `--model` / `ANTHROPIC_MODEL` | `claude-sonnet-4-6` | Anthropic model id |
| `MAX_TURNS` (in source) | 20 | safety bound on the agent loop |
| `TOOL_TIMEOUT` (in source) | 30 s | per-shell-exec timeout |

## Source layout

```
sysadmin-agent/
├── README.md            this file
├── main.py              the agent (~250 lines)
└── requirements.txt     anthropic SDK
```

## Notes

- The agent uses **synchronous** tool execution (one tool at a time per
  turn). Claude can return multiple `tool_use` blocks in a single
  message; we execute them in order and bundle the results into one
  `user` message. Anthropic's API spec supports this pattern.

- `shell_exec` runs `/bin/sh -c <command>`. The agent process inherits
  the parent's privileges, so `agent-shield` sees the resulting syscalls
  attributed to the agent's PID.

- This is intentionally a thin demo. For a production agent you would
  add: structured logging, retries with backoff, prompt caching for the
  system prompt, output streaming, conversation persistence, and a
  proper UI.
