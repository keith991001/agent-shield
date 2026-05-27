#!/usr/bin/env python3
"""
sysadmin-agent — a small tool-using AI agent that does shell tasks.

Demonstrates the receiving end of the agent-shield safety story:
  - this is the AI agent (Anthropic SDK + tool-use loop)
  - agent-shield, running on the host, observes and guards everything
    this script does at the syscall layer

Run it WITH agent-shield in another terminal to see kernel-side
intervention catch destructive operations the agent might attempt.

Usage:
    export ANTHROPIC_API_KEY="sk-ant-..."
    python main.py "clean up old test artifacts in /tmp"
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any

import anthropic


# ─── Configuration ────────────────────────────────────────────────────

DEFAULT_MODEL = "claude-sonnet-4-6"
MAX_TURNS = 20            # safety: bound the agent loop
MAX_TOOL_OUTPUT = 4_000   # bytes per tool result returned to the model
TOOL_TIMEOUT = 30         # seconds for shell_exec


# ─── Tool implementations ─────────────────────────────────────────────

def tool_pwd() -> str:
    return os.getcwd()


def tool_list_files(path: str) -> str:
    try:
        entries = sorted(os.listdir(path))
    except OSError as e:
        return f"error: {e}"
    out = []
    for name in entries:
        full = os.path.join(path, name)
        try:
            kind = "d" if os.path.isdir(full) else ("l" if os.path.islink(full) else "f")
            size = os.path.getsize(full) if kind == "f" else 0
            out.append(f"{kind} {size:>10} {name}")
        except OSError:
            out.append(f"? {'-':>10} {name}")
    return f"{path}:\n" + "\n".join(out) if out else f"{path}: (empty)"


def tool_read_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = f.read(10_000)
        return data if data else "(empty)"
    except OSError as e:
        return f"error: {e}"


def tool_write_file(path: str, content: str) -> str:
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return f"wrote {len(content)} bytes to {path}"
    except OSError as e:
        return f"error: {e}"


def tool_shell_exec(command: str) -> str:
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT,
        )
        parts = [f"exit_code={result.returncode}"]
        if result.stdout:
            parts.append(f"stdout:\n{result.stdout}")
        if result.stderr:
            parts.append(f"stderr:\n{result.stderr}")
        return "\n".join(parts)
    except subprocess.TimeoutExpired:
        return f"error: command timed out after {TOOL_TIMEOUT}s"
    except Exception as e:
        return f"error: {e}"


TOOL_HANDLERS = {
    "pwd": lambda args: tool_pwd(),
    "list_files": lambda args: tool_list_files(args["path"]),
    "read_file": lambda args: tool_read_file(args["path"]),
    "write_file": lambda args: tool_write_file(args["path"], args["content"]),
    "shell_exec": lambda args: tool_shell_exec(args["command"]),
}


# ─── Tool schemas sent to Claude ──────────────────────────────────────

TOOLS = [
    {
        "name": "pwd",
        "description": "Return the current working directory of this agent.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "list_files",
        "description": "List entries in a directory with type and size.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Absolute or relative directory path"}},
            "required": ["path"],
        },
    },
    {
        "name": "read_file",
        "description": "Read up to 10 KB of a text file's contents.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write text content to a file. Overwrites if the file exists.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "shell_exec",
        "description": (
            "Execute an arbitrary shell command via /bin/sh -c. "
            "Returns stdout, stderr, and exit code. Beware destructive "
            "operations — this host is monitored by a runtime security "
            "agent that will terminate your process if you cross safety rules."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
]


SYSTEM_PROMPT = """You are a careful Linux sysadmin assistant operating on the current host.

You have these tools available:
  - pwd()                       — current working directory
  - list_files(path)            — directory listing with type/size
  - read_file(path)             — read up to 10 KB
  - write_file(path, content)   — overwrite a file
  - shell_exec(command)         — run arbitrary shell command

Approach:
  1. Understand the user's request.
  2. Investigate the relevant filesystem state first (pwd, list_files, read_file)
     before taking any mutating action.
  3. Tell the user what you found and what you intend to do, then do it.
  4. Prefer the least destructive option that accomplishes the task.

Important: this host is monitored by agent-shield, a kernel-level
runtime safety system. If you attempt destructive operations on protected
paths (/usr/, /etc/, /bin/, /sbin/) or try to read credential files
(.env, /etc/shadow, ~/.ssh/), your process will be SIGKILL'd by the
kernel. Treat such terminations as policy feedback, not bugs.
"""


# ─── Pretty printing ──────────────────────────────────────────────────

class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    CYAN = "\033[36m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    GREY = "\033[90m"
    RED = "\033[31m"


def render_args(args: dict[str, Any]) -> str:
    parts = []
    for k, v in args.items():
        s = v if isinstance(v, str) else json.dumps(v)
        if len(s) > 80:
            s = s[:80] + "…"
        parts.append(f"{k}={s}")
    return ", ".join(parts)


def render_tool_output(output: str) -> str:
    if len(output) > MAX_TOOL_OUTPUT:
        return output[:MAX_TOOL_OUTPUT] + f"\n…[truncated, total {len(output)} bytes]"
    return output


def print_indented(s: str, prefix: str, color: str = Color.GREY) -> None:
    for line in s.splitlines():
        print(f"{color}{prefix}{line}{Color.RESET}")


# ─── Agent loop ───────────────────────────────────────────────────────

def execute_tool(name: str, args: dict[str, Any]) -> str:
    handler = TOOL_HANDLERS.get(name)
    if handler is None:
        return f"error: unknown tool {name}"
    try:
        return handler(args)
    except Exception as e:
        return f"error executing {name}: {e}"


def run_agent(task: str, model: str) -> int:
    client = anthropic.Anthropic()  # picks up ANTHROPIC_API_KEY
    messages: list[dict[str, Any]] = [{"role": "user", "content": task}]

    print(f"{Color.BOLD}{Color.CYAN}▶ Task:{Color.RESET} {task}")
    print(f"{Color.DIM}  model={model} · running with safety monitor{Color.RESET}\n")

    for turn in range(1, MAX_TURNS + 1):
        try:
            resp = client.messages.create(
                model=model,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                tools=TOOLS,
                messages=messages,
            )
        except anthropic.APIError as e:
            print(f"{Color.RED}API error: {e}{Color.RESET}", file=sys.stderr)
            return 1

        # Render each content block in order.
        for block in resp.content:
            if block.type == "text":
                if block.text.strip():
                    print(f"{Color.BOLD}{block.text}{Color.RESET}")
            elif block.type == "tool_use":
                args = render_args(block.input)
                print(f"  {Color.YELLOW}→ {block.name}({args}){Color.RESET}")

        # Append assistant turn to conversation in full.
        messages.append({"role": "assistant", "content": resp.content})

        if resp.stop_reason == "end_turn":
            print(f"\n{Color.GREEN}✓ done (turn {turn}){Color.RESET}")
            return 0

        if resp.stop_reason != "tool_use":
            print(f"\n{Color.RED}stopped: {resp.stop_reason}{Color.RESET}")
            return 1

        # Execute every tool_use block and gather results.
        tool_results = []
        for block in resp.content:
            if block.type != "tool_use":
                continue
            output = execute_tool(block.name, block.input)
            print_indented(render_tool_output(output), prefix="    ")
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": output,
            })
        messages.append({"role": "user", "content": tool_results})

    print(f"\n{Color.RED}max turns ({MAX_TURNS}) reached without completion{Color.RESET}")
    return 1


# ─── CLI ──────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Tool-using AI sysadmin agent. Run alongside agent-shield to see kernel-level enforcement.",
    )
    parser.add_argument("task", nargs="+", help="natural-language task description")
    parser.add_argument(
        "--model",
        default=os.environ.get("ANTHROPIC_MODEL", DEFAULT_MODEL),
        help=f"Anthropic model id (default: {DEFAULT_MODEL})",
    )
    args = parser.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("error: ANTHROPIC_API_KEY env var is required", file=sys.stderr)
        return 1

    return run_agent(" ".join(args.task), args.model)


if __name__ == "__main__":
    sys.exit(main())
