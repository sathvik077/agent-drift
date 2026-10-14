"""Start a real uvicorn server for tests that need genuine HTTP and SSE behaviour.

Used by the SSE latency test and by the Playwright end-to-end suite. A real server is
necessary because an in-process test client cannot reproduce streaming behaviour, and
because the browser tests need something to connect to.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def free_port() -> int:
    """Find an unused localhost port."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@dataclass
class LiveServer:
    """A running control plane."""

    base_url: str
    port: int
    token: str
    db_path: Path
    process: subprocess.Popen[bytes]

    def get(self, path: str, **kwargs: object) -> httpx.Response:
        """GET against the live server."""
        return httpx.get(f"{self.base_url}{path}", timeout=15.0, **kwargs)  # type: ignore[arg-type]

    def post(self, path: str, json: object = None) -> httpx.Response:
        """Authenticated POST against the live server."""
        return httpx.post(
            f"{self.base_url}{path}",
            json=json,
            headers={"authorization": f"Bearer {self.token}"},
            timeout=15.0,
        )


@contextmanager
def live_server(
    db_path: Path,
    *,
    token: str = "test-admin-token",
    fixture_state: Path | None = None,
    serve_dashboard: bool = False,
) -> Iterator[LiveServer]:
    """Run the control plane as a subprocess and yield a handle to it."""
    port = free_port()
    env = {
        **os.environ,
        "AD_DB_PATH": str(db_path),
        "AD_ADMIN_TOKEN": token,
        "AD_API_PORT": str(port),
        "PYTHONPATH": f"{REPO_ROOT / 'packages'}:{REPO_ROOT}",
    }
    env.pop("AD_DISABLE_AUTH", None)
    if fixture_state is not None:
        env["AD_FIXTURE_STATE"] = str(fixture_state)
        env["AD_SANDBOX_ROOT"] = str(fixture_state / "workspace")

    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "agent_drift.cli",
            "api",
            "--port",
            str(port),
            "--db",
            str(db_path),
            "--log-level",
            "warning",
        ],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )

    base_url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 30
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stderr = (process.stderr.read() if process.stderr else b"").decode(errors="replace")
            raise RuntimeError(f"api exited with {process.returncode}: {stderr[-2000:]}")
        try:
            response = httpx.get(f"{base_url}/healthz", timeout=2.0)
            if response.status_code == 200:
                break
        except Exception as exc:
            last_error = exc
        time.sleep(0.15)
    else:
        process.kill()
        raise RuntimeError(f"api did not become healthy at {base_url}: {last_error}")

    server = LiveServer(base_url=base_url, port=port, token=token, db_path=db_path, process=process)
    try:
        yield server
    finally:
        try:
            os.killpg(os.getpgid(process.pid), 15)
        except (ProcessLookupError, PermissionError):
            process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
