#!/usr/bin/env python3
"""Capture dashboard screenshots from a genuinely running system.

The point of this script is that there is **no path by which it can produce a screenshot of
data the system did not produce**. It:

1. resets local state and runs every bundled scenario through a real gateway against a real
   upstream server, so the decisions in the database were produced by actual tool calls;
2. starts a real control plane serving the real built dashboard;
3. drives a real headless browser and captures the pages.

If any step fails, it exits non-zero and writes nothing, rather than falling back to a
placeholder. `make screenshots` runs this; the same captures are also produced by the
Playwright suite (`tests/e2e/test_dashboard.py`), which additionally asserts the pages show
what they claim to.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "packages"))
sys.path.insert(0, str(REPO_ROOT / "tests"))

#: Page captures: (output name, tab id or None, selector to wait for, extra action)
CAPTURES: list[tuple[str, str | None, str]] = [
    ("dashboard-overview.png", None, ".panel.trusted"),
    ("blocked-action.png", "#tab-timeline", ".timeline"),
    ("replay-lab.png", "#tab-replay", "#replay-observed-panel"),
    ("approval-inbox.png", "#tab-approvals", "#panel-approvals"),
    ("scenarios.png", "#tab-scenarios", "#panel-scenarios"),
]


def build_dashboard() -> None:
    """Produce the production bundle."""
    print("==> building the dashboard bundle")
    subprocess.run(
        ["node", "build.mjs"],
        cwd=str(REPO_ROOT / "apps" / "dashboard"),
        check=True,
        env={**os.environ, "NODE_PATH": "/opt/npm-tools/node_modules"},
    )


def run_scenarios(db_path: Path, fixture_state: Path) -> None:
    """Produce real decisions by running the scenarios through a real gateway."""
    print("==> running scenarios through a real gateway to produce real data")
    result = subprocess.run(
        [sys.executable, "scripts/run_scenarios.py", "--db", str(db_path), "--fresh"],
        cwd=str(REPO_ROOT),
        env={
            **os.environ,
            "AD_FIXTURE_STATE": str(fixture_state),
            "PYTHONPATH": f"{REPO_ROOT / 'packages'}:{REPO_ROOT}",
            "AD_LOG_LEVEL": "WARNING",
        },
        capture_output=True,
        text=True,
        timeout=900,
    )
    if result.returncode != 0:
        print(result.stdout[-4000:], file=sys.stderr)
        print(result.stderr[-4000:], file=sys.stderr)
        raise SystemExit(
            "the scenario run failed, so there is no real data to screenshot. Nothing was written."
        )
    print(result.stdout.strip().splitlines()[-1] if result.stdout.strip() else "")


def main() -> int:
    """Capture every screenshot."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(REPO_ROOT / "var" / "screenshots"))
    parser.add_argument(
        "--publish",
        action="store_true",
        help="also copy the captures into docs/assets for the README",
    )
    args = parser.parse_args()

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise SystemExit(
            "playwright is not installed. Install it with:\n"
            "  uv pip install --python .venv/bin/python playwright==1.56.0\n"
            "  .venv/bin/playwright install chromium"
        ) from None

    from integration.live_server import live_server  # type: ignore[import-not-found]

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    workdir = Path(tempfile.mkdtemp(prefix="agent-drift-shots-"))
    db_path = workdir / "screenshots.db"
    fixture_state = workdir / "fixture"
    fixture_state.mkdir(parents=True, exist_ok=True)

    try:
        build_dashboard()
        run_scenarios(db_path, fixture_state)

        print("==> starting the control plane")
        with live_server(db_path, fixture_state=fixture_state, serve_dashboard=True) as server:
            print(f"    serving {server.base_url}")
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(args=["--no-sandbox"])
                try:
                    context = browser.new_context(
                        viewport={"width": 1440, "height": 960}, device_scale_factor=2
                    )
                    page = context.new_page()
                    page.add_init_script(
                        "try { sessionStorage.setItem('agent-drift.admin-token', "
                        f"{server.token!r}); }} catch (e) {{}}"
                    )
                    page.goto(server.base_url, wait_until="domcontentloaded")
                    page.wait_for_selector(".topbar", timeout=30_000)

                    for name, tab, selector in CAPTURES:
                        if tab:
                            page.click(tab)
                        page.wait_for_selector(selector, timeout=30_000)
                        if name == "blocked-action.png":
                            denied = page.locator(".tl-row").filter(has=page.locator(".pill.deny")).first
                            if denied.count():
                                denied.click()
                                page.wait_for_selector(".tl-detail", timeout=10_000)
                        page.wait_for_timeout(900)
                        target = out_dir / name
                        page.screenshot(path=str(target), full_page=True)
                        size = target.stat().st_size
                        if size < 20_000:
                            raise SystemExit(f"{name} is only {size} bytes; the page looks empty")
                        print(f"    captured {name} ({size // 1024} kB)")
                        if args.publish:
                            assets = REPO_ROOT / "docs" / "assets"
                            assets.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(target, assets / name)

                    # A mobile capture, so the responsive claim has an artifact too.
                    mobile = context.new_page()
                    mobile.set_viewport_size({"width": 390, "height": 844})
                    mobile.add_init_script(
                        "try { sessionStorage.setItem('agent-drift.admin-token', "
                        f"{server.token!r}); }} catch (e) {{}}"
                    )
                    mobile.goto(server.base_url, wait_until="domcontentloaded")
                    mobile.wait_for_selector(".topbar", timeout=30_000)
                    mobile.wait_for_timeout(900)
                    mobile_target = out_dir / "dashboard-mobile.png"
                    mobile.screenshot(path=str(mobile_target), full_page=True)
                    print(f"    captured dashboard-mobile.png ({mobile_target.stat().st_size // 1024} kB)")
                    if args.publish:
                        shutil.copy2(mobile_target, REPO_ROOT / "docs" / "assets" / "dashboard-mobile.png")
                finally:
                    browser.close()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print(f"\nscreenshots written to {out_dir}")
    if args.publish:
        print(f"published to {REPO_ROOT / 'docs' / 'assets'}")
    else:
        print("re-run with --publish to copy them into docs/assets for the README")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
