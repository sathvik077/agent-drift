# SECURITY_REVIEW.md — independent adversarial review and fix pass

**Date:** 2026-10-14. **Reviewer:** an independent agent that did not write the code, given
the repository, the claims, and instructions to break it. **Scope:** the six red-team
questions in `ACCEPTANCE_EVIDENCE_MATRIX.md`. **Method:** executable exploits against the
real `PolicyEngine`, the real `Store` and the real gateway over stdio, with the upstream
fixture's own execution counters and file hashes as the oracle.

The review's verdict was **three HIGH and one MEDIUM-HIGH finding, all confirmed by running
code**. Every finding is recorded below with its fix and the regression test that now closes
it. Findings are reproduced faithfully, including the ones that were embarrassing.

---

## Summary

| ID | Severity | Finding | Status |
|---|---|---|---|
| RT-01 | **High** | A timed-out call was refunded its budget and recorded as not executed, so a slow tool could exceed `max_writes` indefinitely | **Fixed**, regression-tested |
| RT-02 | **High** | `/api/audit/verify` reported `verified: true` over an unsigned log; the control plane never gave its store the signing key | **Fixed**, regression-tested |
| RT-03 | **High** | Unicode normalization let one approval grant authorize two distinct files, and the effect landed on a file the request did not name | **Fixed**, regression-tested |
| RT-04 | Med-high | A local process with no admin token installed a permissive contract by writing SQLite and recomputing the unkeyed hash | **Fixed** under a signing key; residual risk documented |
| RT-05 | Medium | Budget and approval stages ran in the reverse of the documented order; a denied call consumed a single-use human approval | **Fixed**, regression-tested |
| RT-06 | Medium | The benchmark's per-family table read a leaked loop variable instead of each family's own matrix | **Fixed**, plus a reconciliation assertion |
| RT-07 | Medium | `--tool-specs` did not exist, so the documented "guard your own server" path denied every call | **Fixed**, with an example file |
| RT-08 | Medium | Cited evidence documents and five test files did not exist | **Fixed** |
| RT-09 | Low | Advisory heuristics never escalated, contrary to three documents | **Implemented** as opt-in, regression-tested |
| RT-10 | Low | The held-out benchmark slice had no benign cases, so held-out precision was unmeasurable | **Fixed**: 13 benign held-out cases added |
| RT-11 | Low | `AD-E023` was unreachable | **Fixed**: the stored `source` is now checked before validation |
| RT-12 | Low | Identity-key spoof detection was ASCII-only, losing audit signal on lookalikes | **Fixed** with NFKC plus a homoglyph fold |
| RT-13 | Info | Stale test count; unvalidated query parameters returned 500 | **Fixed** |

---

## The high findings, in detail

### RT-01 — a timed-out write was refunded and recorded as not having happened

**What the reviewer did.** Built a third-party-shaped upstream whose `repo.write_file`
performs the write, increments its own counter, then sleeps past the gateway's timeout. With
`max_writes: 2`, five attempts produced:

```
FINAL budget: {'calls_used': 2, 'writes_used': 2}
FINAL upstream counters: {'repo.write_file': 3}
FILES ACTUALLY WRITTEN: ['a.md', 'b.md', 'slow.md']
>>> files written = 3  vs contract max_writes = 2
```

Every timed-out write was recorded `upstream_executed = 0` and refunded, so the budget was
effectively unbounded against any tool slower than the timeout. The upstream's own counter
file — the oracle this project uses to prove its central claim — said the writes happened.

**Why it mattered more than the budget.** The receipt asserted something the gateway did not
know. "Deny before execution, and here is the evidence" is the project's headline; a decision
row claiming a write did not happen when it did undermines the evidence path itself.

**Fix.** `gateway._request_may_have_been_delivered` classifies the failure. A timeout or
cancellation means the request was delivered and the outcome is **unknown**: the budget
reservation is retained and `upstream_executed` is recorded as `unknown` (a third state, not
a coerced `no`). Only a provably pre-delivery failure — the upstream process was never
there, the connection was refused — refunds. The classifier errs toward "delivered", because
guessing wrong in that direction costs one unit of budget while guessing wrong in the other
direction loses the invariant. `--upstream-timeout` is now a flag; it previously was not
configurable at all.

`store.counts()["denied_but_executed"]` now counts `unknown` alongside `yes`, so a denial of
uncertain outcome cannot look clean.

**Tested by.** `tests/integration/test_timeout_budget.py` drives the same slow upstream and
asserts the upstream's counters never exceed `max_writes`; plus
`tests/security/test_review_findings.py::TestRT01TimeoutDoesNotRefundBudget`.

---

### RT-02 — the audit endpoint claimed verification it had not performed

**What the reviewer did.** Set `AD_AUDIT_HMAC_KEY`, registered a task and evaluated an
attempt through the control plane, then read the events:

```
seq=1 CONTRACT_REGISTERED  hmac=None
seq=2 ATTEMPT              hmac=None
seq=3 DECISION_DENY        hmac=None
GET /api/audit/verify -> {"configured": true, "verified": true, "events": 3}
```

`create_app` built its `Store` without the key, so every control-plane event was unsigned.
`verify_chain()` short-circuited to `(True, None)` when there was no key, and the endpoint
derived `configured` from the *environment* and `verified` from the *keyless store*. Worse,
in the documented `make dev` layout the gateway and the API share a database, so the CLI
raised a **false tamper alarm** on a clean log while the endpoint said verified.

**Fix.** `create_app` uses `open_default_store()`, which reads the key. `verify_chain()`
returns three states — `None` (nothing to verify), `True`, `False` — so "no key" is
unrepresentable as "verified" by a caller treating the result as a boolean. The endpoint
reports `status: not_configured | verified | broken`, derives `configured` from **the store**
rather than the environment, and says so explicitly when the environment has a key the
process did not load.

**Tested by.** `tests/security/test_review_findings.py::TestRT02AuditChainIsThreeState`,
including a test that asserts control-plane events are actually signed.

---

### RT-03 — one approval authorized two different files

**What the reviewer did.** Created two genuinely distinct files differing only in unicode
composition — `café.txt` as `caf\xc3\xa9.txt` (NFC) and as `cafe\xcc\x81.txt` (NFD) — and ran
the real approval flow through the real gateway:

```
reviewer sees: {"args_preview": {"path": ".../café.txt"}}
digest(NFC) = 92e8112dc2ab61c0
digest(NFD) = 92e8112dc2ab61c0   <-- identical
request for the OTHER file -> allow ['AD-A002', 'AD-OK03']
[upstream] repo.delete_file path='sandbox-repo/tmp/café.txt' (execution #2)
```

The request named one file; the other was deleted. Within a single approval record, the
preview shown to the human and the target recorded by the policy named **different files**.

The cause was a defensible decision applied too broadly: canonicalization NFC-normalizes
strings so that key order and unicode composition cannot produce two digests for one logical
value. For a filesystem path, two compositions are two files, so folding them was wrong.

**Fix, in two parts.** A path argument that is not already NFC is now **refused**
(`AD-E064`), so what the policy checked, what the reviewer saw and what the tool receives are
the same bytes. And an approval grant binds a second, **raw** digest computed with no
normalization at all; both must match. Either fix alone would be insufficient: the first
keeps the policy and the tool in agreement, the second keeps a grant from spanning two
arguments that merely canonicalize alike.

Legitimate non-ASCII filenames in NFC form still work, which is asserted explicitly.

**Tested by.** `tests/security/test_review_findings.py::TestRT03UnicodeApprovalAliasing`.

---

### RT-04 — a contract installed by writing the database

**What the reviewer did.** Wrote a fully permissive contract directly into SQLite — no admin
token, no HTTP request — and recomputed the `contract_hash`, whose algorithm ships in this
repository:

```
forged contract written directly to sqlite
  repo.write_file   -> allow ['AD-OK01']
  network.http_post -> allow ['AD-OK01']   (url=https://exfil.invalid/collect)
verify_chain() AFTER forgery: True
```

`docs/THREAT_MODEL.md` listed this adversary (A5) as **"Addressed: Yes"**, which was true of
the HTTP surface only.

**Fix.** When `AD_AUDIT_HMAC_KEY` is set, each contract carries an HMAC over its semantic
fields, verified on every read; a contract written without the key is refused with `AD-E025`
and the call is denied. The stored `source` is checked against the trusted values before
pydantic validation, which also makes the previously unreachable `AD-E023` reachable (RT-11).

**What was not fixed, and is now documented.** With **no** key configured, filesystem write
access to the database remains equivalent to holding the admin token. The A5 row and a new
`docs/THREAT_MODEL.md` §5.11 say so plainly instead of claiming the adversary is addressed.

**Tested by.** `tests/security/test_review_findings.py::TestRT04ContractIntegrity`.

---

## The six required red-team questions

**1. Can untrusted user or model content forge an authority field or cross a trust boundary?**
Not through model-supplied arguments. Identity-shaped keys are refused before the contract is
even loaded and nothing in the engine reads their values; `extra="forbid"` blocks smuggled
fields on every model; type confusion in a path argument lands on a denial; symlink escapes
resolve and are denied. Two real crossings were found and fixed: **RT-03** (approval
exactness defeated by unicode aliasing) and **RT-04** (contract forgery by database write).

**2. Does any policy, auth or database exception result in permissive behaviour?**
No. Twenty-four exotic inputs — 4000-deep nesting, NaN and infinities, lone surrogates, raw
bytes, a 200 kB path, non-dict arguments, NUL bytes — all denied. Store faults all denied: a
dropped `budgets` table, a closed store, garbage contract JSON, a corrupted database file.
The `except BaseException` fail-closed wrapper is real and effective, and there is no bypass
flag. The one failure was an over-permissive **assurance**, not an over-permissive decision:
RT-02's false "verified".

**3. Can an unauthorized side effect occur while the system records BLOCKED?**
No path was found where a `deny` row coexists with a forward: the decision is committed before
the client is touched, `_forward_once` has one call site, and `denied_but_executed` stayed 0
throughout. But **RT-01** is the same failure in a different place — the upstream executed, the
file changed, and the record said it had not. That is fixed. **RT-05** additionally let a
denied call consume a human approval, which is now prevented by running budgets before
approvals as documented.

**4. Is any required test skipped by default, or does any chart use fabricated data?**
No meaningfully skipped test: three `pytest.skip` calls exist, all environment-conditional and
honestly worded, and `scripts/verify.py` records a skipped gate as `SKIPPED` with the note
"a skipped gate is not a passed gate". The benchmark genuinely runs the real engine with the
same schemas the gateway uses, and the reviewer reproduced every committed confusion matrix
exactly. One fabricated column was found: **RT-06**, the per-family table reading a leaked
loop variable. Fixed, with an assertion that the family numbers reconcile with the overall
matrix.

**5. Can a clean user follow the README and reproduce the demo?**
Yes for the demo — the reviewer ran `make smoke`, the scenarios, `make eval`, the SDK
quickstart and the README's verbatim snippet, and all matched their documented output. No for
two things, both fixed: the cited evidence documents did not exist (**RT-08**), and the
"guard your own server" path was inert (**RT-07**).

**6. Are limitations, bypass cases and coverage honestly documented?**
"Unusually honest in aggregate, with five specific overstatements." The five were: A5 marked
addressed; `/api/audit/verify` described as never claiming verification; advisory escalation
described as implemented; §5.1's claim that fixture re-validation closes the TOCTOU gap
(RT-03 was a counterexample — re-validation *redirected* the tool); and AD-09's "documented"
at-most-once behaviour, which was undocumented. All five are corrected, and two previously
undocumented gaps — the timeout refund and the unconfigurable timeout — are now documented
and fixed.

---

## Defenses that held

Worth recording, because it says which parts did not need changing:

- Argument-level authority forgery — every spelling denied before the contract was consulted.
- Type confusion in resource arguments — `list`, `dict`, `bool`, `int`, `None`, `bytes`, 200 kB
  strings, NaN all denied.
- Path traversal and symlinks — `../`, percent- and double-percent-encoding, backslashes,
  Windows drives, UNC, NUL, control bytes, fullwidth and ideographic separators, zero-width and
  bidi controls; in-sandbox symlinks to out-of-scope directories and symlinks to `/etc`.
- Destination allowlisting — `inet_aton` spellings, bracketed IPv6, zone ids, IPv4-mapped and
  6to4, userinfo, trailing dots, non-default ports, non-HTTP schemes, IDNA homographs.
- Manifest rug pull — the fingerprint covers name, title, description, both schemas and
  annotations; re-pinning is always a deliberate reviewer action.
- Approval single-use under concurrency — 8 threads racing one grant produced exactly 1 allow.
- Budget reservation race — no over-reservation observed.
- Store failure as a pass — every induced fault produced a denial.
- Double-forward — a single call site; a `needs_approval` that later denies never forwards.
- Deny-before-execute — confirmed independently against the upstream's own counters and file
  hashes.
- Fabricated evaluation numbers — none; the published matrices reproduce from the seed.

---

## Residual risk accepted for v1

1. **No signing key configured** → filesystem write to the database equals admin authority
   (§5.11). Mitigated by `make setup` generating a key by default.
2. **A third-party tool that ignores its arguments** cannot be constrained by an
   argument-level check (§5.1). Needs OS-level sandboxing underneath.
3. **Cross-script homoglyphs** in argument *names* beyond the small fold table are recorded as
   undeclared arguments rather than spoof attempts. No authority is gained; the loss is audit
   fidelity.
4. **Sequence and aggregate harm** remains undetected (§5.3), as hypothesis H2 anticipates.
5. **A host that bypasses the gateway** gets no protection and no warning (§5.2).

## Re-running this review

The reviewer's scratch exploits were written outside the repository and are not committed. The
behaviours they probed are now covered by `tests/security/test_review_findings.py` and
`tests/integration/test_timeout_budget.py`, which run under `make test` and `make verify`. A
future reviewer should not trust those tests to be exhaustive — they encode the attacks
somebody already thought of, which is exactly the limitation this document exists to name.
