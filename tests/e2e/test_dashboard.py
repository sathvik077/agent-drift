"""Browser end-to-end checks against the real backend (AD-13, AD-14, AD-16, AD-17, AD-18).

Everything asserted here is rendered from data the gateway actually produced during the
session-scoped scenario run. Screenshots captured by this suite are the ones published in
``docs/assets``, which is how AD-17's "no placeholder screenshots" requirement is met:
there is no code path that could produce a screenshot of invented data.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from .conftest import copy_asset

pytestmark = pytest.mark.e2e

SSE_LOCAL_TARGET_S = 2.0


class TestIntentVersusAction:
    """AD-13: trusted intent, untrusted content and the enforcement result."""

    def test_trusted_and_untrusted_panels_are_distinguished(self, page) -> None:
        page.wait_for_selector(".panel.trusted", timeout=20_000)
        trusted = page.locator(".panel.trusted").first
        untrusted = page.locator(".panel.untrusted").first

        assert trusted.is_visible()
        assert untrusted.is_visible()
        # Panel headings are uppercased by CSS, so compare case-insensitively: the test
        # is about what the panel says, not about its letter casing.
        assert "approved intent" in trusted.inner_text().lower()
        assert "untrusted" in untrusted.inner_text().lower()
        assert "never authorization" in untrusted.inner_text().lower()

        # The distinction must survive a screenshot, so it has to be visual too.
        trusted_border = trusted.evaluate("el => getComputedStyle(el).borderLeftColor")
        untrusted_border = untrusted.evaluate("el => getComputedStyle(el).borderLeftColor")
        assert trusted_border != untrusted_border, "the two trust tiers look identical"

    def test_contract_details_come_from_the_backend(self, page, server) -> None:
        page.wait_for_selector(".panel.trusted", timeout=20_000)
        text = page.locator(".panel.trusted").first.inner_text()
        expected = server.get("/api/tasks").json()["tasks"][0]
        assert expected["task_id"] in text
        assert expected["contract_hash"][:16] in text

    def test_read_only_task_shows_egress_denied(self, page) -> None:
        page.wait_for_selector(".panel.trusted", timeout=20_000)
        page.select_option("#task-select", "demo-repo-review")
        page.wait_for_timeout(700)
        assert "all egress denied" in page.locator(".panel.trusted").first.inner_text()

    def test_overview_stats_render_real_counts(self, page, server) -> None:
        page.wait_for_selector(".stat", timeout=20_000)
        labels = page.locator(".stat .l").all_inner_texts()
        assert any("BLOCKED" in label.upper() for label in labels)
        blocked_value = page.locator(".stat").filter(has_text="Blocked").locator(".n").first.inner_text()
        assert blocked_value.isdigit()

    def test_capture_dashboard_overview(self, page, screenshot_dir: Path) -> None:
        page.wait_for_selector(".panel.trusted", timeout=20_000)
        page.wait_for_timeout(900)
        target = screenshot_dir / "dashboard-overview.png"
        page.screenshot(path=str(target), full_page=True)
        assert target.stat().st_size > 20_000, "screenshot looks empty"
        copy_asset(target, "dashboard-overview.png")


class TestBlockedAction:
    """A denial must be legible: decision, rule, reason and explanation."""

    def test_timeline_shows_a_blocked_call_with_its_rule(self, page) -> None:
        page.click("#tab-timeline")
        page.wait_for_selector(".timeline", timeout=20_000)
        blocked = page.locator(".tl-row").filter(has=page.locator(".pill.deny")).first
        assert blocked.count() > 0, "no blocked decision appeared in the timeline"
        assert "R" in blocked.inner_text(), "the row does not name a rule"

    def test_expanding_a_denial_shows_the_reason_catalogue_text(self, page) -> None:
        page.click("#tab-timeline")
        page.wait_for_selector(".timeline", timeout=20_000)
        page.locator(".tl-row").filter(has=page.locator(".pill.deny")).first.click()
        page.wait_for_selector(".tl-detail", timeout=10_000)
        detail = page.locator(".tl-detail").first.inner_text()
        assert "AD-E" in detail, "no reason code shown"
        assert "Rules evaluated" in detail
        # The explanation is fetched from /api/reasons, never hardcoded in the UI.
        assert "no catalogue entry" not in detail

    def test_capture_blocked_action(self, page, screenshot_dir: Path) -> None:
        page.click("#tab-timeline")
        page.wait_for_selector(".timeline", timeout=20_000)
        page.locator(".tl-row").filter(has=page.locator(".pill.deny")).first.click()
        page.wait_for_selector(".tl-detail", timeout=10_000)
        page.wait_for_timeout(600)
        target = screenshot_dir / "blocked-action.png"
        page.screenshot(path=str(target), full_page=True)
        assert target.stat().st_size > 20_000
        copy_asset(target, "blocked-action.png")


class TestLiveUpdates:
    """AD-14: a new decision appears without a refresh, within the local target."""

    def test_decision_appears_without_a_refresh(self, page, server) -> None:
        # The timeline is filtered by the selected task, so select the task the new
        # decision will belong to. Posting for a different task would prove nothing.
        page.wait_for_selector("#task-select", timeout=20_000)
        page.select_option("#task-select", "demo-repo-review")
        page.wait_for_timeout(600)
        page.click("#tab-timeline")
        page.wait_for_selector(".timeline", timeout=20_000)

        # Wait for the live indicator to settle into streaming or polling.
        page.wait_for_function(
            "() => { const el = document.querySelector('.topbar-stats .pill'); "
            "return el && /live|polling/.test(el.textContent || ''); }",
            timeout=20_000,
        )
        before = page.locator(".tl-row").count()

        started = time.monotonic()
        response = server.post(
            "/api/attempts/evaluate",
            json={
                "task_id": "demo-repo-review",
                "tool_name": "network.http_post",
                "args": {"url": "https://live-check.invalid/collect", "body": "x"},
            },
        )
        assert response.status_code == 200
        assert response.json()["status"] == "deny"

        page.wait_for_function(
            f"() => document.querySelectorAll('.tl-row').length > {before}",
            timeout=int(SSE_LOCAL_TARGET_S * 1000) + 3000,
        )
        elapsed = time.monotonic() - started
        assert elapsed <= SSE_LOCAL_TARGET_S + 1.5, (
            f"the decision took {elapsed:.2f}s to reach the browser; the local target is "
            f"{SSE_LOCAL_TARGET_S}s plus render time"
        )

    def test_live_indicator_reports_its_transport_honestly(self, page) -> None:
        page.wait_for_function(
            "() => { const el = document.querySelector('.topbar-stats .pill'); "
            "return el && /live|polling|offline|connecting/.test(el.textContent || ''); }",
            timeout=20_000,
        )
        label = page.locator(".topbar-stats .pill").first.inner_text().lower()
        assert label.strip() in ("live", "polling", "offline", "connecting"), label


class TestReplayLab:
    """AD-16: labels must distinguish observed reality from a simulated baseline."""

    def test_both_columns_are_explicitly_labelled(self, page) -> None:
        page.click("#tab-replay")
        page.wait_for_selector("#replay-observed", timeout=20_000)
        observed = page.locator("#replay-observed").inner_text().lower()
        simulated = page.locator("#replay-simulated").inner_text().lower()
        assert "observed" in observed
        assert "simulated" in simulated

        # The simulated column must disclaim, in the visible text, that it is not a
        # record of prevented incidents. Phrasing may be edited; the disclaimer may not
        # disappear, so assert on the substance rather than one exact sentence.
        provenance = page.locator("#replay-simulated-panel .provenance").first.inner_text().lower()
        assert "hypothetical" in provenance
        assert "no tool was run" in provenance
        assert "prevented incident" in provenance

    def test_metric_definitions_are_shown_not_hidden_in_tooltips(self, page) -> None:
        page.click("#tab-replay")
        page.wait_for_selector(".stat", timeout=20_000)
        details = page.locator(".stat .d").all_inner_texts()
        assert any("denied before" in text.lower() for text in details), details
        assert any("simulation" in text.lower() for text in details), details

    def test_observed_rows_report_whether_the_tool_ran(self, page) -> None:
        """The observed column must say whether the upstream tool actually executed.

        That is the difference between "we decided to allow it" and "it happened", and a
        replay view that omits it would be describing intentions rather than reality.
        """
        page.click("#tab-replay")
        page.wait_for_selector("#replay-observed-panel table", timeout=20_000)
        headers = [
            header.strip().lower()
            for header in page.locator("#replay-observed-panel thead th").all_inner_texts()
        ]
        assert "ran" in headers, headers
        rows = page.locator("#replay-observed-panel tbody tr")
        assert rows.count() > 0, "the observed column has no rows"
        first = rows.first.inner_text().lower()
        assert "yes" in first or "no" in first, first

    def test_capture_replay_lab(self, page, screenshot_dir: Path) -> None:
        page.click("#tab-replay")
        page.wait_for_selector("#replay-observed", timeout=20_000)
        page.wait_for_timeout(800)
        target = screenshot_dir / "replay-lab.png"
        page.screenshot(path=str(target), full_page=True)
        assert target.stat().st_size > 20_000
        copy_asset(target, "replay-lab.png")


class TestApprovalInbox:
    """The approval queue and its copy about exactness."""

    def test_inbox_renders_a_state(self, page) -> None:
        page.click("#tab-approvals")
        page.wait_for_selector("#panel-approvals", timeout=20_000)
        text = page.locator("#panel-approvals").inner_text().lower()
        assert "approval inbox" in text
        assert "nothing waiting for review" in text or "awaiting review" in text

    def test_credentials_panel_explains_the_auth_model(self, page) -> None:
        page.click("#tab-approvals")
        page.wait_for_selector("#token-input", timeout=20_000)
        text = page.locator("#panel-approvals").inner_text().lower()
        assert "bearer" in text
        assert "not authentication" in text

    def test_approving_changes_the_outcome(self, page, server) -> None:
        """A reviewer action must visibly change state, end to end through the UI."""
        from agent_drift.contracts import ToolAttempt
        from agent_drift.policy import PolicyEngine
        from agent_drift.store import Store

        store = Store(server.db_path)
        try:
            engine = PolicyEngine(store)
            attempt = ToolAttempt(
                tool_server="sandbox",
                tool_name="repo.delete_file",
                args={"path": "sandbox-repo/tmp/e2e-approval.txt"},
            )
            decision = engine.evaluate(attempt, bound_task_id="demo-cleanup")
            assert str(decision.status) == "needs_approval", decision.reason_codes
            approval_id = decision.approval_id
        finally:
            store.close()

        page.click("#tab-approvals")
        page.wait_for_selector("#panel-approvals", timeout=20_000)
        page.reload(wait_until="domcontentloaded")
        page.click("#tab-approvals")
        page.wait_for_selector(".pill.needs_approval", timeout=20_000)

        pending = page.locator("li.panel").filter(has=page.locator(".pill.needs_approval")).first
        pending_text = pending.inner_text().lower()
        assert "repo.delete_file" in pending_text
        assert "once" in pending_text, "the inbox must say the grant is single-use"

        approve = pending.locator("button.primary").first
        assert approve.is_enabled(), "the approve button is disabled despite a token"
        approve.click()

        # Other scenarios may have left their own pending approvals, so wait for *this*
        # one to leave the pending state rather than for the queue to empty.
        for _ in range(40):
            page.wait_for_timeout(250)
            states = {
                row["approval_id"]: row["state"] for row in server.get("/api/approvals").json()["approvals"]
            }
            if states.get(approval_id) in ("approved", "consumed"):
                break
        else:
            pytest.fail(
                f"approval {approval_id} never left the pending state after the UI action; "
                f"states were {states}"
            )


class TestStatesAndAccessibility:
    """AD-18: empty, error and loading states, responsive layout, accessible controls."""

    def test_tabs_are_an_accessible_tablist(self, page) -> None:
        page.wait_for_selector('[role="tablist"]', timeout=20_000)
        tabs = page.locator('[role="tab"]')
        assert tabs.count() == 5, f"expected 5 tabs, found {tabs.count()}: {tabs.all_inner_texts()}"
        selected = page.locator('[role="tab"][aria-selected="true"]')
        assert selected.count() == 1
        page.click("#tab-replay")
        assert page.locator("#tab-replay").get_attribute("aria-selected") == "true"
        assert page.locator('[role="tabpanel"]').count() >= 1

    def test_panels_are_labelled_for_screen_readers(self, page) -> None:
        page.click("#tab-replay")
        page.wait_for_selector('[role="tabpanel"]', timeout=20_000)
        panel = page.locator('[role="tabpanel"]').first
        assert panel.get_attribute("aria-labelledby")

    def test_meters_expose_their_values(self, page) -> None:
        page.wait_for_selector('[role="meter"]', timeout=20_000)
        meter = page.locator('[role="meter"]').first
        assert meter.get_attribute("aria-label")
        assert meter.get_attribute("aria-valuenow") is not None

    def test_keyboard_can_reach_the_tabs(self, page) -> None:
        page.keyboard.press("Tab")
        for _ in range(12):
            focused = page.evaluate("() => document.activeElement?.getAttribute('role')")
            if focused == "tab":
                return
            page.keyboard.press("Tab")
        pytest.fail("could not reach a tab control by keyboard")

    def test_empty_state_explains_how_to_populate_it(self, page, server) -> None:
        """An empty panel must say what would fill it, not just that it is empty."""
        page.goto(f"{server.base_url}/?taskless=1", wait_until="domcontentloaded")
        page.click("#tab-approvals")
        page.wait_for_selector("#panel-approvals", timeout=20_000)
        text = page.locator("#panel-approvals").inner_text()
        if "Nothing waiting for review" in text:
            assert "approval_rules" in text

    def test_error_state_appears_when_the_backend_is_unreachable(self, browser_context, server) -> None:
        """Blocking the API must produce a real error state, not a blank page."""
        page = browser_context.new_page()
        try:
            page.route("**/api/**", lambda route: route.abort())
            page.route("**/healthz", lambda route: route.abort())
            page.goto(server.base_url, wait_until="domcontentloaded")
            page.wait_for_selector('[role="alert"]', timeout=20_000)
            text = page.locator('[role="alert"]').first.inner_text()
            assert "control plane" in text.lower()
            assert "make dev" in text
        finally:
            page.close()

    @pytest.mark.parametrize(
        ("width", "height", "label"),
        [(390, 844, "phone"), (768, 1024, "tablet"), (1440, 960, "desktop")],
    )
    def test_layout_has_no_horizontal_overflow(
        self, browser_context, server, width: int, height: int, label: str
    ) -> None:
        page = browser_context.new_page()
        try:
            page.set_viewport_size({"width": width, "height": height})
            page.add_init_script(
                f"try {{ sessionStorage.setItem('agent-drift.admin-token', {server.token!r}); }} catch (e) {{}}"
            )
            page.goto(server.base_url, wait_until="domcontentloaded")
            page.wait_for_selector(".topbar", timeout=20_000)
            page.wait_for_timeout(500)
            overflow = page.evaluate(
                "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
            )
            assert overflow <= 2, f"{label} ({width}px) overflows horizontally by {overflow}px"
        finally:
            page.close()

    def test_dark_scheme_renders_with_a_dark_background(self, browser_context, server) -> None:
        page = browser_context.new_page()
        try:
            page.emulate_media(color_scheme="dark")
            page.goto(server.base_url, wait_until="domcontentloaded")
            page.wait_for_selector(".topbar", timeout=20_000)
            background = page.evaluate("() => getComputedStyle(document.body).backgroundColor")
            channels = [int(value) for value in background[background.index("(") + 1 : -1].split(",")[:3]]
            assert sum(channels) / 3 < 110, f"dark mode background is too light: {background}"
        finally:
            page.close()

    def test_no_console_errors_on_load(self, page) -> None:
        page.wait_for_timeout(1500)
        errors = [
            message
            for message in page.console_errors
            if "favicon" not in message.lower() and "net::ERR" not in message
        ]
        assert not errors, f"console errors on load: {errors}"


class TestCoverageDisclosure:
    """The UI must state the limits of what Agent Drift can see."""

    def test_footer_states_the_coverage_boundary(self, page) -> None:
        text = page.locator(".footnote").last.inner_text()
        assert "bypasses the gateway" in text
        assert "THREAT_MODEL" in text

    def test_scenarios_tab_links_expectations_to_the_test_suite(self, page) -> None:
        page.click("#tab-scenarios")
        page.wait_for_selector("#panel-scenarios", timeout=20_000)
        text = page.locator("#panel-scenarios").inner_text()
        assert "test_scenarios.py" in text
        assert "adversarial" in text.lower()
        assert "benign" in text.lower()
