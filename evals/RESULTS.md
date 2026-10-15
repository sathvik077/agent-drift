# Agent Drift evaluation results

**Generated** 2026-10-15T03:19:10Z · Agent Drift 0.1.0 · MCP SDK 2.2.0 (protocol 2026-07-28)

**Environment** Python 3.13.16 on Linux-6.18.44-fc-v114-x86_64-with-glibc2.39 · fully offline · no language model used

Regenerate with `make eval`. The run is deterministic from the seed (`20261014`); only the latency figures vary between runs.

## Dataset

- **206 labeled cases** (96 benign, 110 adversarial)
- Ground truth: 95 `should_allow`, 111 `should_block`
- 16 randomized rephrasings of existing intents
- 48 cases in 5 held-out families: `argument_smuggling`, `private_address_egress`, `schema_violation`, `unicode_confusable`, `unknown_tool`

A case's label comes from the text of the approved contract it is evaluated against, not from any model's opinion and not from what Agent Drift decides. A call that must pause for human review counts as **blocked**, because it is not authorized to execute unattended.

### Cases per family

| Family | Cases | Held out |
|---|---:|:---:|
| `argument_smuggling` | 9 | yes |
| `benign_alarming_text` | 14 |  |
| `budget_exhaustion` | 4 |  |
| `destination_variant` | 10 |  |
| `exfiltration_attempt` | 19 |  |
| `expired_contract` | 3 |  |
| `legitimate_approved_egress` | 11 |  |
| `legitimate_list` | 10 |  |
| `legitimate_read` | 30 |  |
| `legitimate_scoped_write` | 17 |  |
| `missing_contract` | 4 |  |
| `path_traversal` | 10 |  |
| `private_address_egress` | 13 | yes |
| `readonly_delete_attempt` | 3 |  |
| `readonly_write_attempt` | 5 |  |
| `schema_violation` | 8 | yes |
| `scope_escape` | 11 |  |
| `task_spoof` | 7 |  |
| `unicode_confusable` | 11 | yes |
| `unknown_tool` | 7 | yes |

## Arms

- **`unguarded_passthrough`** — No gateway. Every proposed tool call is forwarded. Establishes the benign completion ceiling and the zero-protection floor.
- **`keyword_classifier`** — Blocks a call when the tool name or any argument string matches a list of dangerous keywords. No notion of a task, a scope, a budget or an approval.
- **`contract_policy`** — Agent Drift's deterministic policy engine evaluating each call against the approved intent contract for its task, with the same enforcement order and the same upstream input schemas the gateway applies.

## All cases

| Arm | Cases | TP | FP | TN | FN | Recall | Precision | FPR | Benign completion | Accuracy | p50 ms | p95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `unguarded_passthrough` | 206 | 0 | 0 | 95 | 111 | 0.0% | n/a | 0.0% | 100.0% | 46.1% | 0.00 | 0.00 |
| `keyword_classifier` | 206 | 108 | 53 | 42 | 3 | 97.3% | 67.1% | 55.8% | 44.2% | 72.8% | 0.03 | 0.06 |
| `contract_policy` | 206 | 111 | 0 | 95 | 0 | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | 0.37 | 0.82 |

## Development families only

| Arm | Cases | TP | FP | TN | FN | Recall | Precision | FPR | Benign completion | Accuracy | p50 ms | p95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `unguarded_passthrough` | 158 | 0 | 0 | 82 | 76 | 0.0% | n/a | 0.0% | 100.0% | 51.9% | 0.00 | 0.00 |
| `keyword_classifier` | 158 | 74 | 41 | 41 | 2 | 97.4% | 64.3% | 50.0% | 50.0% | 72.8% | 0.03 | 0.06 |
| `contract_policy` | 158 | 76 | 0 | 82 | 0 | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | 0.61 | 0.82 |

## Held-out families only

| Arm | Cases | TP | FP | TN | FN | Recall | Precision | FPR | Benign completion | Accuracy | p50 ms | p95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `unguarded_passthrough` | 48 | 0 | 0 | 13 | 35 | 0.0% | n/a | 0.0% | 100.0% | 27.1% | 0.00 | 0.00 |
| `keyword_classifier` | 48 | 34 | 12 | 1 | 1 | 97.1% | 73.9% | 92.3% | 7.7% | 72.9% | 0.03 | 0.05 |
| `contract_policy` | 48 | 35 | 0 | 13 | 0 | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | 0.20 | 0.78 |

## Targets

Targets are from `CLAUDE.md` section 8 and were fixed before the run. They are compared against the measurement below; a missed target is reported, not adjusted.

| Check | Measured | | Target | Result | Detail |
|---|---:|:---:|---:|:---:|---|
| All deterministic prohibited actions blocked | 100.00 | `>=` | 100.0 | PASS | 76/76 seeded prohibited cases blocked |
| Precision | 100.00 | `>=` | 95.0 | PASS | TP=111 FP=0 |
| Recall | 100.00 | `>=` | 95.0 | PASS | TP=111 FN=0 |
| Benign false blocks | 0.00 | `<=` | 5.0 | PASS | FP=0 of 95 benign cases |
| p95 decision latency (ms) | 0.82 | `<=` | 100.0 | PASS | policy evaluation only, excluding the upstream call |

**Overall: all targets met.**

### Bypasses

None. No `should_block` case was allowed by the contract policy.

### False blocks

None. Every `should_allow` case was permitted by the contract policy.

### Where the keyword baseline differs

The keyword classifier produced **53 false blocks** and **3 bypasses**, against 0 and 0 for the contract policy. The `benign_alarming_text` family is where the difference is clearest: documents that merely mention deletion or exfiltration are blocked by a text filter and correctly permitted by a contract, because the authorization question is what the call *does*.

### Per-family breakdown (contract policy)

| Family | Cases | Correct | Bypasses | False blocks |
|---|---:|---:|---:|---:|
| `argument_smuggling` | 9 | 9 | 0 | 0 |
| `benign_alarming_text` | 14 | 14 | 0 | 0 |
| `budget_exhaustion` | 4 | 4 | 0 | 0 |
| `destination_variant` | 10 | 10 | 0 | 0 |
| `exfiltration_attempt` | 19 | 19 | 0 | 0 |
| `expired_contract` | 3 | 3 | 0 | 0 |
| `legitimate_approved_egress` | 11 | 11 | 0 | 0 |
| `legitimate_list` | 10 | 10 | 0 | 0 |
| `legitimate_read` | 30 | 30 | 0 | 0 |
| `legitimate_scoped_write` | 17 | 17 | 0 | 0 |
| `missing_contract` | 4 | 4 | 0 | 0 |
| `path_traversal` | 10 | 10 | 0 | 0 |
| `private_address_egress` | 13 | 13 | 0 | 0 |
| `readonly_delete_attempt` | 3 | 3 | 0 | 0 |
| `readonly_write_attempt` | 5 | 5 | 0 | 0 |
| `schema_violation` | 8 | 8 | 0 | 0 |
| `scope_escape` | 11 | 11 | 0 | 0 |
| `task_spoof` | 7 | 7 | 0 | 0 |
| `unicode_confusable` | 11 | 11 | 0 | 0 |
| `unknown_tool` | 7 | 7 | 0 | 0 |

## Limitations

1. **A perfect or near-perfect score here does not mean the system is robust.** Cases are constructed by the authors of the policy, so the labels encode the same understanding of the contracts that the rules encode. What a high score demonstrates is internal consistency -- the rules do what their authors believe the contracts say -- plus the absence of the specific failure modes enumerated here. It is not evidence about attacks nobody thought to write down. Five families are held out to make overfitting visible, but a held-out family is still an author-chosen family.
2. Two defects in this project were found by running this suite rather than by reasoning: undeclared arguments such as `force: true` were being forwarded, and `docs/../docs/x` was being rejected as traversal when it is a legitimate spelling of `docs/x`. Both are fixed (see docs/DECISIONS.md D-013). That the suite found them is the argument for it; that it took a run to find them is the argument against trusting a score alone.
3. Decisions are deterministic, so repeated runs give identical outcomes. The only variance is in the latency measurement.
4. This suite measures argument-level authorization. It does not measure end-to-end agent task success, and it says nothing about harm that is only visible across a sequence of individually in-contract calls.
5. The keyword baseline is one reasonable implementation, not the best possible text classifier. It bounds what naive filtering achieves, not what filtering could achieve.
6. The unguarded arm has no latency cost by construction; its latency figures measure the harness, not a real system.

## What this is not

This is a measurement of **argument-level authorization against a declared contract**, on a set the authors constructed. It is not AgentDojo, it is not Agent Security Bench, and it does not measure end-to-end agent task success under attack. Those comparisons are described as future work in `docs/RESEARCH.md`, with the falsifiable hypotheses that would test them.

_Raw per-case outcomes: `RESULTS.json` → `per_case` (618 rows). Case definitions: `cases.json`._
