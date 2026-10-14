#!/usr/bin/env python3
"""`make verify` — the release gate.

Runs every check in sequence, records each exit code, and prints a table. The exit code of
this script is the release verdict: **non-zero if any mandatory gate fails**.

Two rules this script exists to enforce:

1. **A gate that cannot run is not a gate that passed.** A blocked check is reported as
   `BLOCKED` with the reason and the exact retry command, and it does not count as success.
2. **Evidence is recorded, not summarized.** Each gate's command and observed output tail
   are written to `var/verify-report.json`, which `docs/VERIFICATION.md` cites.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
VENV_PY = REPO_ROOT / ".venv" / "bin" / "python"
PY = str(VENV_PY) if VENV_PY.is_file() else sys.executable


@dataclass
class GateResult:
    """One gate's outcome."""

    gate: str
    description: str
    command: str
    mandatory: bool
    status: str  # PASS | FAIL | BLOCKED | SKIPPED
    exit_code: int | None
    duration_s: float
    output_tail: str = ""
    note: str = ""
    counts: dict[str, Any] = field(default_factory=dict)


def _env() -> dict[str, str]:
    """Environment for every subprocess."""
    return {
        **os.environ,
        "PYTHONPATH": f"{REPO_ROOT / 'packages'}:{REPO_ROOT}",
        "NODE_PATH": ":".join(
            [str(REPO_ROOT / "apps" / "dashboard" / "node_modules"), "/opt/npm-tools/node_modules"]
        ),
        "AD_FIXTURE_STATE": os.environ.get("AD_FIXTURE_STATE", str(REPO_ROOT / "var" / "fixture")),
        "PLAYWRIGHT_BROWSERS_PATH": os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers"),
    }


def run_gate(
    gate: str,
    description: str,
    argv: list[str],
    *,
    cwd: Path = REPO_ROOT,
    mandatory: bool = True,
    timeout: int = 900,
) -> GateResult:
    """Run one gate and capture its result."""
    started = time.monotonic()
    printable = " ".join(argv)
    print(f"\n=== {gate}: {description}")
    print(f"    $ {printable}")
    try:
        completed = subprocess.run(
            argv, cwd=str(cwd), env=_env(), capture_output=True, text=True, timeout=timeout
        )
        output = (completed.stdout or "") + (completed.stderr or "")
        status = "PASS" if completed.returncode == 0 else "FAIL"
        code = completed.returncode
    except FileNotFoundError as exc:
        output, status, code = str(exc), "BLOCKED", None
    except subprocess.TimeoutExpired:
        output, status, code = f"timed out after {timeout}s", "FAIL", None

    duration = time.monotonic() - started
    tail = "\n".join(line for line in output.strip().splitlines()[-18:])
    print(f"    -> {status} (exit {code}) in {duration:.1f}s")
    if status != "PASS":
        for line in tail.splitlines()[-10:]:
            print(f"       {line}")
    return GateResult(
        gate=gate,
        description=description,
        command=printable,
        mandatory=mandatory,
        status=status,
        exit_code=code,
        duration_s=round(duration, 2),
        output_tail=tail,
    )


def blocked(gate: str, description: str, command: str, reason: str, retry: str) -> GateResult:
    """Record a gate that cannot run here, with its retry command."""
    print(f"\n=== {gate}: {description}")
    print(f"    -> BLOCKED: {reason}")
    print(f"       retry with: {retry}")
    return GateResult(
        gate=gate,
        description=description,
        command=command,
        mandatory=True,
        status="BLOCKED",
        exit_code=None,
        duration_s=0.0,
        note=f"{reason} Retry: {retry}",
    )


def _pytest_counts(tail: str) -> dict[str, int]:
    """Extract pass/fail/skip counts from a pytest summary line."""
    import re

    counts: dict[str, int] = {}
    for line in reversed(tail.splitlines()):
        if " passed" in line or " failed" in line or " error" in line:
            for number, label in re.findall(r"(\d+)\s+(passed|failed|skipped|error[s]?|xfailed)", line):
                counts[label.rstrip("s")] = int(number)
            if counts:
                break
    return counts


def check_registry(host: str) -> bool:
    """Is a package registry reachable? Used to classify a blocked gate honestly."""
    import urllib.error
    import urllib.request

    try:
        urllib.request.urlopen(f"https://{host}", timeout=6)
        return True
    except (TimeoutError, urllib.error.URLError, OSError):
        return False


def main() -> int:
    """Run every gate and write the report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-e2e", action="store_true", help="skip the browser suite")
    parser.add_argument("--report", default=str(REPO_ROOT / "var" / "verify-report.json"))
    args = parser.parse_args()

    print("=" * 78)
    print("Agent Drift — make verify")
    print("=" * 78)
    print(f"python   {platform.python_version()}  ({PY})")
    print(f"platform {platform.platform()}")
    print(f"repo     {REPO_ROOT}")

    results: list[GateResult] = []

    # ---- static analysis ---------------------------------------------------------
    targets = ["packages", "apps", "tests", "evals", "scripts", "examples"]
    results.append(run_gate("lint", "Ruff lint", [PY, "-m", "ruff", "check", *targets]))
    results.append(run_gate("format", "Ruff format check", [PY, "-m", "ruff", "format", "--check", *targets]))
    results.append(run_gate("typecheck-py", "mypy", [PY, "-m", "mypy", "--config-file", "pyproject.toml"]))

    dashboard = REPO_ROOT / "apps" / "dashboard"
    tsc = dashboard / "node_modules" / "typescript" / "bin" / "tsc"
    if tsc.is_file():
        results.append(
            run_gate(
                "typecheck-web",
                "TypeScript typecheck",
                ["node", str(tsc), "--noEmit", "-p", "tsconfig.json"],
                cwd=dashboard,
            )
        )
    else:
        results.append(
            blocked(
                "typecheck-web",
                "TypeScript typecheck",
                "tsc --noEmit",
                "TypeScript is not installed in apps/dashboard/node_modules.",
                "python scripts/offline_bootstrap.py --node  (or npm ci) then make typecheck-web",
            )
        )

    # ---- build -------------------------------------------------------------------
    results.append(
        run_gate(
            "build-dashboard",
            "Production dashboard bundle",
            ["node", "build.mjs"],
            cwd=dashboard,
        )
    )

    bundle = dashboard / "dist" / "app.js"
    bundle_ok = bundle.is_file() and bundle.stat().st_size > 50_000
    results.append(
        GateResult(
            gate="bundle-size",
            description="Dashboard bundle exists and is plausibly sized",
            command="stat apps/dashboard/dist/app.js",
            mandatory=True,
            status="PASS" if bundle_ok else "FAIL",
            exit_code=0 if bundle_ok else 1,
            duration_s=0.0,
            output_tail=f"{bundle} = {bundle.stat().st_size if bundle.is_file() else 0} bytes",
            counts={"bytes": bundle.stat().st_size if bundle.is_file() else 0},
        )
    )
    print(f"\n=== bundle-size: {results[-1].output_tail} -> {results[-1].status}")

    # ---- tests -------------------------------------------------------------------
    for gate, path, label in (
        ("test-unit", "tests/unit", "Unit tests"),
        ("test-security", "tests/security", "Security regression tests"),
        ("test-integration", "tests/integration", "Integration tests (real MCP processes)"),
    ):
        result = run_gate(gate, label, [PY, "-m", "pytest", path, "-q", "--no-header"])
        result.counts = _pytest_counts(result.output_tail)
        results.append(result)

    if args.skip_e2e:
        results.append(
            GateResult(
                gate="test-e2e",
                description="Playwright end-to-end suite",
                command="pytest tests/e2e -q",
                mandatory=True,
                status="SKIPPED",
                exit_code=None,
                duration_s=0.0,
                note="skipped by --skip-e2e; a skipped gate is not a passed gate",
            )
        )
    else:
        result = run_gate(
            "test-e2e",
            "Playwright end-to-end (real browser)",
            [PY, "-m", "pytest", "tests/e2e", "-q", "--no-header"],
            timeout=1200,
        )
        result.counts = _pytest_counts(result.output_tail)
        results.append(result)

    # ---- real MCP smoke ----------------------------------------------------------
    results.append(
        run_gate(
            "smoke",
            "Real client -> gateway -> upstream, with counters",
            [PY, "-m", "agent_drift.cli", "smoke", "--db", str(REPO_ROOT / "var" / "verify-smoke.db")],
        )
    )

    # ---- benchmark ---------------------------------------------------------------
    eval_result = run_gate(
        "eval",
        "Offline benchmark (exits non-zero if a target is missed)",
        [PY, "evals/run_eval.py", "--out", "evals"],
    )
    results.append(eval_result)

    # ---- dataset gate ------------------------------------------------------------
    dataset_status, dataset_note, dataset_counts = "FAIL", "", {}
    try:
        report = json.loads((REPO_ROOT / "evals" / "RESULTS.json").read_text())
        data = report["dataset"]
        problems: list[str] = []
        if data["total_cases"] < 120:
            problems.append(f"{data['total_cases']} cases, gate is 120")
        if data["held_out_cases"] < 20:
            problems.append(f"{data['held_out_cases']} held-out cases, gate is 20")
        minority = min(data["benign"], data["adversarial"]) / data["total_cases"]
        if minority < 0.3:
            problems.append(f"class balance {minority:.0%}, gate is 30%")
        if not report["all_targets_met"]:
            problems.append("a pre-registered target was missed")
        dataset_status = "PASS" if not problems else "FAIL"
        dataset_note = "; ".join(problems) or (
            f"{data['total_cases']} cases, {data['held_out_cases']} held out, all targets met"
        )
        dataset_counts = {
            "total_cases": data["total_cases"],
            "benign": data["benign"],
            "adversarial": data["adversarial"],
            "held_out": data["held_out_cases"],
        }
    except (OSError, ValueError, KeyError) as exc:
        dataset_note = f"could not read evals/RESULTS.json: {exc}"
    results.append(
        GateResult(
            gate="dataset",
            description="Benchmark size, balance and targets",
            command="evals/RESULTS.json",
            mandatory=True,
            status=dataset_status,
            exit_code=0 if dataset_status == "PASS" else 1,
            duration_s=0.0,
            output_tail=dataset_note,
            counts=dataset_counts,
        )
    )
    print(f"\n=== dataset: {dataset_note} -> {dataset_status}")

    # ---- README assets -----------------------------------------------------------
    required_assets = [
        "dashboard-overview.png",
        "blocked-action.png",
        "replay-lab.png",
        "architecture.svg",
    ]
    missing = [
        name
        for name in required_assets
        if not (REPO_ROOT / "docs" / "assets" / name).is_file()
        or (REPO_ROOT / "docs" / "assets" / name).stat().st_size < 2000
    ]
    # Evidence documents the project cites must actually exist and have content.
    # A ledger that references a missing file is the defect this check prevents.
    required_docs = [
        "docs/VERIFICATION.md",
        "docs/ACCEPTANCE_STATUS.md",
        "docs/SECURITY_REVIEW.md",
        "docs/THREAT_MODEL.md",
        "docs/RESEARCH.md",
        "docs/DECISIONS.md",
        "evals/RESULTS.md",
        "evals/RESULTS.json",
    ]
    missing += [
        name
        for name in required_docs
        if not (REPO_ROOT / name).is_file() or (REPO_ROOT / name).stat().st_size < 1000
    ]
    results.append(
        GateResult(
            gate="assets",
            description="README assets and cited evidence documents exist and are non-trivial",
            command="ls docs/assets && ls docs/VERIFICATION.md docs/ACCEPTANCE_STATUS.md",
            mandatory=True,
            status="PASS" if not missing else "FAIL",
            exit_code=0 if not missing else 1,
            duration_s=0.0,
            output_tail="all present" if not missing else f"missing or empty: {', '.join(missing)}",
        )
    )
    print(f"\n=== assets: {results[-1].output_tail} -> {results[-1].status}")

    # ---- git hygiene -------------------------------------------------------------
    hygiene_problems: list[str] = []
    if shutil.which("git") and (REPO_ROOT / ".git").is_dir():
        probe = REPO_ROOT / "private" / "verify-probe.pdf"
        probe.parent.mkdir(parents=True, exist_ok=True)
        probe.write_text("probe")
        ignored = (
            subprocess.run(
                ["git", "check-ignore", "-q", str(probe)], cwd=str(REPO_ROOT), capture_output=True
            ).returncode
            == 0
        )
        probe.unlink(missing_ok=True)
        if not ignored:
            hygiene_problems.append("private/ is not gitignored")
        tracked = subprocess.run(
            ["git", "ls-files", "private/"], cwd=str(REPO_ROOT), capture_output=True, text=True
        ).stdout.strip()
        if tracked:
            hygiene_problems.append(f"tracked files under private/: {tracked}")
        all_tracked = subprocess.run(
            ["git", "ls-files"], cwd=str(REPO_ROOT), capture_output=True, text=True
        ).stdout.splitlines()
        leaked = [p for p in all_tracked if p.endswith((".env", ".db", ".sqlite", ".sqlite3"))]
        if leaked:
            hygiene_problems.append(f"tracked secrets or state: {', '.join(leaked)}")
        status = "PASS" if not hygiene_problems else "FAIL"
        note = "; ".join(hygiene_problems) or "private/ ignored, no .env or database tracked"
    else:
        status, note = "BLOCKED", "not a git repository, so ignore rules cannot be checked"
    results.append(
        GateResult(
            gate="hygiene",
            description="private/ ignored; no secrets or local state tracked",
            command="git check-ignore private/... && git ls-files private/",
            mandatory=True,
            status=status,
            exit_code=0 if status == "PASS" else 1,
            duration_s=0.0,
            output_tail=note,
        )
    )
    print(f"\n=== hygiene: {note} -> {status}")

    # ---- docker ------------------------------------------------------------------
    if check_registry("registry-1.docker.io"):
        results.append(
            run_gate(
                "docker",
                "Build the API and dashboard images",
                ["make", "docker-build"],
                timeout=1800,
            )
        )
    else:
        results.append(
            blocked(
                "docker",
                "Build the API and dashboard images",
                "make docker-build",
                "The container registry is unreachable from this environment, so base images "
                "cannot be pulled and the images cannot be built here.",
                "make docker-build  (on a machine with registry access; also runs in CI)",
            )
        )

    # ---- report ------------------------------------------------------------------
    mandatory_failures = [r for r in results if r.mandatory and r.status in ("FAIL", "SKIPPED")]
    blocked_gates = [r for r in results if r.status == "BLOCKED"]
    ready = not mandatory_failures and not blocked_gates

    print("\n" + "=" * 78)
    print(f"{'GATE':<18}{'STATUS':<10}{'EXIT':<7}{'TIME':<9}DETAIL")
    print("-" * 78)
    for result in results:
        detail = (
            result.note or result.output_tail.splitlines()[-1] if (result.note or result.output_tail) else ""
        )
        counts = " ".join(f"{k}={v}" for k, v in result.counts.items())
        print(
            f"{result.gate:<18}{result.status:<10}"
            f"{result.exit_code if result.exit_code is not None else '-'!s:<7}"
            f"{result.duration_s:<9.1f}{(counts or detail)[:34]}"
        )
    print("=" * 78)

    total = {"passed": 0, "failed": 0}
    for result in results:
        for key, value in result.counts.items():
            if key == "passed":
                total["passed"] += value
            elif key in ("failed", "error"):
                total["failed"] += value
    if total["passed"]:
        print(f"test totals: {total['passed']} passed, {total['failed']} failed")

    if mandatory_failures:
        print(f"\nNOT READY — {len(mandatory_failures)} mandatory gate(s) failed:")
        for result in mandatory_failures:
            print(f"  - {result.gate}: {result.description}")
    if blocked_gates:
        print(f"\nNOT READY — {len(blocked_gates)} gate(s) could not run here:")
        for result in blocked_gates:
            print(f"  - {result.gate}: {result.note}")
    if ready:
        print("\nREADY — every mandatory gate passed in this environment.")

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(
            {
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "python": platform.python_version(),
                "platform": platform.platform(),
                "ready": ready,
                "mandatory_failures": [r.gate for r in mandatory_failures],
                "blocked": [r.gate for r in blocked_gates],
                "test_totals": total,
                "gates": [asdict(result) for result in results],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"\nevidence written to {report_path}")

    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
