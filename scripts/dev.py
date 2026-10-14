#!/usr/bin/env python3
"""Run the control plane and the dashboard watcher together, with clean teardown.

The blueprint asks for ``make dev`` to start both with clean teardown via a script. The
teardown matters more than it sounds: the previous shape of this problem is an orphaned
uvicorn holding port 8001 after Ctrl-C, which then makes the next run look broken.

Both children are started in their own process group and are signalled as a group on
exit, so an uvicorn reloader's grandchildren go with them.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def load_dotenv(path: Path) -> dict[str, str]:
    """Read simple KEY=VALUE lines from a .env file."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def main() -> int:
    """Start both services and wait."""
    env = {**os.environ, **load_dotenv(REPO_ROOT / ".env")}
    api_port = env.get("AD_API_PORT", "8001")
    web_port = env.get("AD_WEB_PORT", "5173")
    env.setdefault("PYTHONPATH", f"{REPO_ROOT / 'packages'}:{REPO_ROOT}")
    env["NODE_PATH"] = ":".join(
        [str(REPO_ROOT / "apps" / "dashboard" / "node_modules"), "/opt/npm-tools/node_modules"]
    )

    python = str(REPO_ROOT / ".venv" / "bin" / "python")
    if not Path(python).is_file():
        python = sys.executable

    children: list[subprocess.Popen[bytes]] = []

    def spawn(name: str, argv: list[str], cwd: Path) -> None:
        print(f"[dev] starting {name}: {' '.join(argv)}", flush=True)
        children.append(subprocess.Popen(argv, cwd=str(cwd), env=env, start_new_session=True))

    spawn(
        "api",
        [
            python,
            "-m",
            "agent_drift.cli",
            "api",
            "--port",
            api_port,
            "--db",
            env.get("AD_DB_PATH", str(REPO_ROOT / "var" / "agent_drift.db")),
        ],
        REPO_ROOT,
    )
    spawn("dashboard watcher", ["node", "build.mjs", "--watch"], REPO_ROOT / "apps" / "dashboard")

    print(f"[dev] API        http://127.0.0.1:{api_port}  (docs at /docs)", flush=True)
    print(f"[dev] dashboard  http://127.0.0.1:{api_port}/  (served by the API)", flush=True)
    print(
        f"[dev] dev bundle rebuilt on change; dedicated web port {web_port} is unused in this mode",
        flush=True,
    )
    print("[dev] press Ctrl-C to stop both", flush=True)

    def shutdown(signum: int = 0, _frame: object = None) -> None:
        print(f"\n[dev] shutting down (signal {signum})", flush=True)
        for child in children:
            if child.poll() is None:
                try:
                    os.killpg(os.getpgid(child.pid), signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    child.terminate()
        deadline = time.monotonic() + 6
        for child in children:
            remaining = max(0.1, deadline - time.monotonic())
            try:
                child.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(child.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    child.kill()
        print("[dev] stopped", flush=True)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        while True:
            time.sleep(0.4)
            for child in children:
                if child.poll() is not None:
                    print(
                        f"[dev] a child exited with {child.returncode}; stopping the rest",
                        file=sys.stderr,
                        flush=True,
                    )
                    shutdown()
                    return child.returncode or 1
    except KeyboardInterrupt:
        shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
