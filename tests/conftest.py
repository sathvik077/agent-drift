"""Shared pytest fixtures.

Design rules this file enforces for every test:

* **Isolation.** Each test gets its own temporary database and its own temporary fixture
  state directory. Nothing is shared, so no test can pass because a previous one left
  state behind, and no test can fail for the same reason.
* **No network.** A socket guard fails any test that attempts an outbound connection.
  That is how the claim "the fixture performs no network I/O" is kept true rather than
  merely intended.
* **External oracles.** The ``counters`` and ``sink`` helpers read the *upstream's own*
  files. A test never asks the gateway whether it forwarded a call.
"""

from __future__ import annotations

import json
import os
import socket
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "packages"))
sys.path.insert(0, str(REPO_ROOT))

FIXTURE_SERVER = REPO_ROOT / "examples" / "upstream_mcp" / "server.py"


@pytest.fixture(autouse=True)
def _no_outbound_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any test that opens an outbound socket to a non-loopback address.

    Loopback is permitted because the API integration tests talk to a local server.
    Everything else raises, which is what makes "no real exfiltration from test tools"
    (AD-22) an enforced property instead of a promise.
    """
    real_connect = socket.socket.connect

    def guarded(self: socket.socket, address: Any) -> Any:
        host = address[0] if isinstance(address, tuple) and address else ""
        if isinstance(host, str) and (
            host in ("127.0.0.1", "::1", "localhost", "", "0.0.0.0") or host.startswith("127.")
        ):
            return real_connect(self, address)
        raise AssertionError(
            f"outbound network connection to {address!r} attempted during a test; "
            "Agent Drift's test suite and fixtures must perform no external network I/O"
        )

    monkeypatch.setattr(socket.socket, "connect", guarded)


@pytest.fixture
def fixture_state(tmp_path: Path) -> Path:
    """An isolated upstream fixture state directory with a seeded sandbox."""
    state = tmp_path / "fixture"
    state.mkdir(parents=True, exist_ok=True)
    os.environ["AD_FIXTURE_STATE"] = str(state)

    sys.path.insert(0, str(FIXTURE_SERVER.parent))
    import importlib

    module = importlib.import_module("server")
    importlib.reload(module)
    module.state_dir().mkdir(parents=True, exist_ok=True)
    module.seed_sandbox(force=True)
    return state


@pytest.fixture
def workspace(fixture_state: Path) -> Path:
    """The path-resolution root inside the isolated fixture state."""
    return fixture_state / "workspace"


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    """An isolated SQLite database path."""
    path = tmp_path / "agent_drift.db"
    os.environ["AD_DB_PATH"] = str(path)
    return path


@pytest.fixture
def store(db_path: Path) -> Iterator[Any]:
    """An open, isolated store."""
    from agent_drift.store import Store

    instance = Store(db_path)
    try:
        yield instance
    finally:
        instance.close()


@pytest.fixture
def engine(store: Any, workspace: Path) -> Any:
    """A policy engine bound to the isolated store and workspace."""
    from agent_drift.policy import PolicyEngine

    return PolicyEngine(store, sandbox_root=workspace, approval_ttl_s=60)


def read_counters(state: Path) -> dict[str, int]:
    """Upstream execution counters, read from the file the upstream itself writes."""
    try:
        data = json.loads((state / "counters.json").read_text())
    except (OSError, ValueError):
        return {}
    return {str(key): int(value) for key, value in data.items()}


def read_sink(state: Path) -> int:
    """Number of simulated egress events recorded by the upstream."""
    try:
        return sum(1 for line in (state / "egress_sink.jsonl").read_text().splitlines() if line.strip())
    except OSError:
        return 0


def sha256_of(path: Path) -> str | None:
    """SHA-256 of a file, or ``None`` when it does not exist."""
    import hashlib

    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None
