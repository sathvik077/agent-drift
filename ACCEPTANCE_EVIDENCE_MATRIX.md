
# ACCEPTANCE_EVIDENCE_MATRIX.md

This is a **definition of evidence**, not a claim that implementation or tests have passed. Once the project is built, copy this into `docs/ACCEPTANCE_STATUS.md` and add `Status`, `Evidence path`, `Command`, `Observed result`, `Date` to each row. PASS requires direct observed evidence, not a screenshot of a mockup. Release status is **NOT READY** unless every mandatory gate has passing evidence and the complete `make verify` passes.

## Evidence naming conventions

- `pytest` unit/integration/security tests: `tests/unit/test_*.py`, `tests/integration/test_*.py`, `tests/security/test_*.py`
- Release fixture runner: `tests/integration/test_release_vectors.py` (or named equivalent) loads all seed cases and asserts real outputs.
- Playwright: `tests/e2e/*.spec.ts` with snapshots made from actual UI/backend, not mocked metrics.
- Evaluation: `evals/RESULTS.json` and `evals/RESULTS.md` created by `make eval` with case ids and errors.
- Verification: `docs/VERIFICATION.md` + `docs/ACCEPTANCE_STATUS.md` (locally observed facts) + CI logs.
- If an integration only works with an external credential, it is **optional**, not evidence for required offline release.

## Mandatory gate mapping

| Gate | Proof required | Suggested evidence source |
|---|---|---|
| AD-01 | Fresh setup and local startup | make setup; make dev; curl /healthz |
| AD-02 | Real tools/list via stdio | MCP SDK roundtrip integration test |
| AD-03 | Allowed real upstream execution | fixture invocation count and relayed content |
| AD-04 | Deny before upstream execution | fixture upstream counter remains zero |
| AD-05 | Read-only/resource restriction | sandbox file hash and path-scope tests |
| AD-06 | Expired/untrusted contract fails closed | missing/expired fixture cases |
| AD-07 | Trusted task isolation | forged task ID and parallel-run tests |
| AD-08 | Human approvals are exact single-use | pending/approve/decline/TTL/revision tests |
| AD-09 | No replayed side effects | retry / replay immutable DB tests |
| AD-10 | MCP manifest drift | tool list fingerprint mutation test |
| AD-11 | Real typed API routes | OpenAPI schema test and HTTP smoke |
| AD-12 | Python SDK + host config | SDK quickstart and Inspector instructions |
| AD-13 | Intent/action juxtaposition | Playwright real event view |
| AD-14 | Live SSE under 2s target | timestamped local Playwright SSE check |
| AD-15 | Six resettable demos | scripts and fixture outputs |
| AD-16 | Replay explicit simulated baseline | comparison output with labels |
| AD-17 | README assets from running app | file existence + screenshot provenance |
| AD-18 | Accessible states/layout | browser checks and manual notes |
| AD-19 | All make commands pass | make verify log + make -n checks |
| AD-20 | 100+ cases and real metrics | schema-validated evals/RESULTS.json |
| AD-21 | Security edge regressions | pytest security suite incl. traversal, Unicode, race |
| AD-22 | Secrets/API/sandbox protections | auth/token/redaction and no egress tests |
| AD-23 | CI and images | workflow job + image build log |
| AD-24 | Five verified primary sources | docs/RESEARCH.md reference audit |
| AD-25 | Git ignored private PDF | git check-ignore private/... + clean status |
| AD-26 | Honest evidence ledger | docs/VERIFICATION.md direct command outputs |

## Release review: required independent red-team questions

1. Can untrusted user/model content forge an authority field or cross a trust boundary?
2. Does any policy, auth or DB exception result in permissive behavior?
3. Can an unauthorized side effect or poisoned context exposure occur while dashboard says BLOCKED?
4. Is any required test skipped by default, or does an evaluation chart use fabricated data?
5. Can a clean user follow the README without secret keys and reproduce screenshots or causal demo?
6. Are limitations, bypass cases and exact coverage clearly documented?

**Disposition:** Mark NOT READY if any critical flaw remains; do not conceal failures to meet a release date.
