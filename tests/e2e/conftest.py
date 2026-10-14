"""Playwright fixtures for the browser end-to-end suite.

Decision D-005: these are Python Playwright tests rather than ``@playwright/test`` specs,
because the npm registry is blocked in the build environment while the Python SDK and a
Chromium build are both present. What matters for AD-13, AD-14, AD-17 and AD-18 is a real
headless browser driving the real built dashboard against the real backend, which is what
this does.

Every test runs against a freshly seeded database whose contents were produced by actually
running the bundled scenarios through a real gateway. No screenshot or assertion in this
suite is based on data the dashboard invented.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DIST = REPO_ROOT / "apps" / "dashboard" / "dist"

sys.path.insert(0, str(REPO_ROOT / "tests"))
from integration.live_server import LiveServer, live_server  # noqa: E402


def _have_playwright() -> bool:
    """Is Playwright importable with a usable browser?"""
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        return False
    return True


pytestmark = pytest.mark.e2e


@pytest.fixture(scope="session")
def dashboard_built() -> Path:
    """Ensure the production dashboard bundle exists."""
    if not (DIST / "app.js").is_file():
        subprocess.run(
            ["node", "build.mjs"],
            cwd=str(REPO_ROOT / "apps" / "dashboard"),
            check=True,
            env={**os.environ, "NODE_PATH": "/opt/npm-tools/node_modules"},
        )
    assert (DIST / "app.js").is_file(), "dashboard bundle was not produced"
    assert (DIST / "index.html").is_file()
    return DIST


@pytest.fixture(scope="session")
def seeded_state(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """Run every bundled scenario through a real gateway to produce real data.

    This is the step that makes the screenshots honest: the decisions the browser
    renders were produced by actual tool calls traversing an actual gateway to an actual
    upstream server, not by a seeding script writing rows it made up.
    """
    base = tmp_path_factory.mktemp("e2e-state")
    db_path = base / "agent_drift.db"
    fixture_state = base / "fixture"
    fixture_state.mkdir(parents=True, exist_ok=True)

    env = {
        **os.environ,
        "AD_FIXTURE_STATE": str(fixture_state),
        "PYTHONPATH": f"{REPO_ROOT / 'packages'}:{REPO_ROOT}",
        "AD_LOG_LEVEL": "WARNING",
    }
    result = subprocess.run(
        [sys.executable, "scripts/run_scenarios.py", "--db", str(db_path), "--fresh"],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert result.returncode == 0, (
        "the scenario runner failed, so there is no real data to show in the browser:\n"
        f"{result.stdout[-4000:]}\n{result.stderr[-4000:]}"
    )
    return db_path, fixture_state


@pytest.fixture(scope="session")
def server(seeded_state: tuple[Path, Path], dashboard_built: Path) -> Iterator[LiveServer]:
    """A live control plane serving the built dashboard over real data."""
    db_path, fixture_state = seeded_state
    with live_server(db_path, fixture_state=fixture_state, serve_dashboard=True) as handle:
        yield handle


@pytest.fixture(scope="session")
def browser_context():
    """A headless Chromium context."""
    if not _have_playwright():
        pytest.skip("playwright is not installed")
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch(args=["--no-sandbox"])
        except Exception as exc:  # pragma: no cover - missing browser binary
            pytest.skip(f"chromium could not be launched: {exc}")
        context = browser.new_context(viewport={"width": 1440, "height": 960})
        try:
            yield context
        finally:
            context.close()
            browser.close()


@pytest.fixture
def page(browser_context, server: LiveServer):
    """A page with the admin token pre-seeded, pointed at the dashboard."""
    page = browser_context.new_page()
    console_errors: list[str] = []
    page.on(
        "console", lambda message: console_errors.append(message.text) if message.type == "error" else None
    )
    page.add_init_script(
        f"try {{ sessionStorage.setItem('agent-drift.admin-token', {server.token!r}); }} catch (e) {{}}"
    )
    page.goto(server.base_url, wait_until="domcontentloaded")
    page.wait_for_selector(".topbar", timeout=20_000)
    # Wait for the initial data load to finish, not just for the shell to paint. The app
    # renders a loading card first and the tab list only once the control plane has
    # answered, so a test that queried the tabs immediately raced the fetch. Settling here
    # means every test starts from the same state instead of each adding its own wait.
    page.wait_for_selector('[role="tablist"]', timeout=30_000)
    page.console_errors = console_errors  # type: ignore[attr-defined]
    try:
        yield page
    finally:
        page.close()


@pytest.fixture
def screenshot_dir() -> Path:
    """Where screenshots captured during the suite are written."""
    target = REPO_ROOT / "var" / "screenshots"
    target.mkdir(parents=True, exist_ok=True)
    return target


def copy_asset(source: Path, name: str) -> Path:
    """Copy a captured screenshot into docs/assets under a published name."""
    assets = REPO_ROOT / "docs" / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    destination = assets / name
    shutil.copy2(source, destination)
    return destination
