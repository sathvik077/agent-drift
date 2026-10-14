#!/usr/bin/env python3
"""A deliberately slow upstream MCP server, for the timeout-budget regression.

It advertises the same tool names and schemas as the bundled fixture, but `repo.write_file`
sleeps past any reasonable gateway timeout *before* reporting, while still performing and
counting the write. That reproduces the real hazard: the tool runs, the gateway gives up
waiting, and the question is what the gateway then records and refunds.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

import anyio
from mcp.server.mcpserver import MCPServer

SLEEP_SECONDS = float(os.environ.get("AD_SLOW_UPSTREAM_SLEEP", "4.0"))
_lock = threading.Lock()


def state_dir() -> Path:
    """Where counters and the sandbox live."""
    return Path(os.environ.get("AD_FIXTURE_STATE", "/tmp/ad-slow")).resolve()


def workspace() -> Path:
    """Path-resolution root."""
    return state_dir() / "workspace"


def counters_path() -> Path:
    """The execution-counter oracle."""
    return state_dir() / "counters.json"


def _bump(tool: str) -> int:
    """Increment the tool's execution counter before anything else can fail."""
    with _lock:
        try:
            counters = json.loads(counters_path().read_text())
        except (OSError, ValueError):
            counters = {}
        counters[tool] = int(counters.get(tool, 0)) + 1
        counters_path().parent.mkdir(parents=True, exist_ok=True)
        tmp = counters_path().with_suffix(".json.tmp")
        tmp.write_text(json.dumps(counters, sort_keys=True))
        os.replace(tmp, counters_path())
        return counters[tool]


server: MCPServer = MCPServer(name="sandbox", version="0.1.0")


@server.tool(name="repo.read_file", description="Read a file from the sandbox repo.")
def repo_read_file(path: str) -> str:
    """Read quickly."""
    _bump("repo.read_file")
    return f"contents-of:{path}"


@server.tool(name="repo.list_files", description="List files in the sandbox repo.")
def repo_list_files(path: str = "sandbox-repo") -> str:
    """List quickly."""
    _bump("repo.list_files")
    return path


@server.tool(name="repo.write_file", description="Write a file in the sandbox repo, slowly.")
def repo_write_file(path: str, content: str) -> str:
    """Perform the write, then sleep past the gateway's timeout before replying."""
    count = _bump("repo.write_file")
    target = workspace() / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    print(f"[slow-upstream] WROTE {path!r} (execution #{count}), now sleeping", file=sys.stderr, flush=True)
    time.sleep(SLEEP_SECONDS)
    return json.dumps({"written": path})


@server.tool(name="repo.delete_file", description="Delete a file from the sandbox repo.")
def repo_delete_file(path: str) -> str:
    """Delete quickly."""
    _bump("repo.delete_file")
    return json.dumps({"deleted": path})


@server.tool(name="network.http_post", description="Simulated POST; no network I/O.")
def network_http_post(url: str, body: str = "") -> str:
    """Simulate quickly."""
    _bump("network.http_post")
    return json.dumps({"simulated_post": url})


if __name__ == "__main__":
    state_dir().mkdir(parents=True, exist_ok=True)
    (workspace() / "sandbox-repo" / "docs").mkdir(parents=True, exist_ok=True)
    anyio.run(server.run_stdio_async)
