# Contributing

Thanks for looking. The most valuable contribution to this project is a finding that
contradicts one of its claims.

## Before you open a pull request

```bash
make setup
make verify        # the release gate; include its output in the PR
```

`make verify` runs lint, typecheck, every test suite, the real stdio smoke check, the
benchmark and the hygiene gates. It exits non-zero if a mandatory gate fails **or is
blocked**, because a gate that could not run is not a gate that passed.

## What a change needs

| Change | Also needs |
|---|---|
| New or changed security behaviour | A regression test in `tests/security/` that fails without the change |
| New or changed policy behaviour | Cases in `evals/cases.py` — **including the benign cases that would catch a false block** |
| New enforcement stage or reason code | An entry in `packages/agent_drift/reasons.py` with an explanation, and a rule mapping |
| New API route | An entry in `apps/api/openapi.py`; `tests/unit/test_openapi.py` fails otherwise |
| New dashboard behaviour | A Playwright assertion in `tests/e2e/` |
| A design tradeoff | A dated entry in `docs/DECISIONS.md` saying what was given up |

The benign-case requirement is not bureaucracy. A policy change that blocks more is trivial;
the hard part is not blocking things users legitimately do, and the benchmark only catches
that if someone writes the case.

## Things that will be rejected

- A number in a document that no command reproduces.
- A screenshot that was not captured from a running system.
- A test that asserts the component under test agrees with itself. Assertions about whether a
  tool ran must read the fixture's own `counters.json`, not the gateway's report.
- A new `# noqa` or `# type: ignore` without a comment saying why.
- Marking an acceptance gate as passed without the command and the observed output.
- Any claim of a formal guarantee. See `docs/RESEARCH.md` §4.

## Research contributions

`docs/RESEARCH.md` §3 lists five falsifiable hypotheses and exactly what would refute each
one. H1, H2 and H5 require running AgentDojo or Agent Security Bench, which has **not** been
done. If you run one of them, the result belongs in that file whichever way it comes out.

The novelty statement in §4 is explicitly provisional: a survey of existing MCP proxies and
gateways on the package registries could not be performed in the environment where this was
built (§5, item 11). If you do that survey, say so there.

## Code style

Ruff for lint and formatting, mypy for types, `tsc --noEmit` for the dashboard. Configuration
lives in `pyproject.toml` and `apps/dashboard/tsconfig.json`; `make fmt` applies what is
mechanical.

Comments should explain *why*, especially where a choice looks odd — most of the non-obvious
code in this repository is non-obvious because of a specific attack, and the comment should
name it.

## Reporting a vulnerability

Open an issue describing the bypass and how to reproduce it. This is a local development tool
with no production deployment, so there is no embargo process; a public reproduction is the
most useful form.
