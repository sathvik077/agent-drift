# RESEARCH.md — prior art, protocol constraints, and honest novelty

**Compiled 2026-10-14.** Every source below was fetched and read during this build. Where a
claim could not be confirmed from a primary source it appears in §5 ("Could not verify")
rather than being asserted. No "first ever" claim is made or supported.

---

## 1. Comparison matrix

| Source | Citation | What it actually provides | Verified | Gap this project tests |
|---|---|---|---|---|
| **AgentDojo** | Debenedetti, E., Zhang, J., Balunović, M., Beurer-Kellner, L., Fischer, M., Tramèr, F. "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents." *NeurIPS 2024, Datasets & Benchmarks Track*. DOI 10.52202/079017-2636. [link](https://proceedings.nips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html) | An extensible **benchmark/environment**, not a defense: 97 realistic tool-use tasks, 629 security test cases, plus a library of attacks and defenses. Reports that current LLMs fail many tasks even unattacked. | Yes — proceedings page fetched; title, 6 authors, track, year, DOI present | It is the measurement harness, not a control. It has no notion of a *user-approved task contract*, and it evaluates model/agent-level defenses rather than a protocol-level interposer. Agent Drift would have to be wrapped as an AgentDojo defense to be comparable, which is future work (H1). |
| **MELON** | Zhu, K., Yang, X., Wang, J., Guo, W., Wang, W. Y. "MELON: Provable Defense Against Indirect Prompt Injection Attacks in AI Agents." *ICML 2025*, PMLR v267, pp. 80310–80329. [link](https://proceedings.mlr.press/v267/zhu25z.html) | A **training-free, inference-time detector**: re-executes the agent's trajectory with the user prompt masked; similar actions in the masked run imply the action was driven by injected content. Evaluated on AgentDojo. | Yes — PMLR page fetched; title, 5 authors, volume, page range confirmed | The closest conceptual neighbour: it operationalizes "is this action attributable to the user's task?". But it infers intent from model behaviour, is probabilistic, and costs an extra masked re-execution per step. It derives intent from the *prompt* rather than from an explicit immutable artifact, and produces a flag rather than an auditable allow/deny record at the protocol boundary. |
| **CaMeL** | Debenedetti, E., Shumailov, I., Fan, T., Hayes, J., Carlini, N., Fabian, D., Kern, C., Shi, C., Terzis, A., Tramèr, F. "Defeating Prompt Injections by Design." arXiv:2503.18813 (v1 2025-03-24; v2 2025-06-24). [link](https://arxiv.org/abs/2503.18813) | A **system-layer design**: extracts control and data flow from the trusted query so untrusted data cannot influence program flow; attaches capabilities to data; **enforces security policies at the point tools are called**. Reports 77% of AgentDojo tasks solved with provable security vs 84% undefended. | Yes — arXiv abstract page fetched; title, 10 authors, version dates, 77%/84% figures present | The strongest prior art for "enforce at action time", and it must be cited as such. The difference is architectural commitment: CaMeL needs a planner that emits a program whose control flow can be extracted. A tools-only proxy is architecture-agnostic but consequently has **no control-flow graph** — only tool name, arguments and a contract. The 84%→77% utility cost is the number any gateway must beat (H5). |
| **Agent Security Bench** | Zhang, H., Huang, J., Mei, K., Yao, Y., Wang, Z., Zhan, C., Wang, H., Zhang, Y. "Agent Security Bench (ASB): Formalizing and Benchmarking Attacks and Defenses in LLM-based Agents." *ICLR 2025*. [link](https://proceedings.iclr.cc/paper_files/paper/2025/hash/5750f91d8fb9d5c02bd8ad2c3b44456b-Abstract-Conference.html) | A broad **benchmark + formalization**: 10 scenarios, 10 agents, 400+ tools, 27 attack/defense methods, 7 metrics; 10 prompt-injection attacks, memory poisoning, a Plan-of-Thought backdoor, 4 mixed attacks, 11 defenses, 13 backbones. Highest average ASR reported 84.30%. Finds current defenses of limited effectiveness. | Yes — ICLR proceedings page fetched; title, 8 authors, venue, 84.30% figure present | Widens the threat surface to memory poisoning and backdoored plans, neither of which a stateless argument-level check addresses. Use it to avoid overclaiming: a tool-call gateway does nothing about a poisoned plan *except* insofar as the contract is protected from the agent — which this project demonstrates (`tests/security/test_task_identity.py`) rather than asserts. |
| **Microsoft SFI guidance** | Microsoft. "Defend against indirect prompt injection attacks." Microsoft Learn, Zero Trust / Secure Future Initiative. Author Rayne Wiselman; March 2026. [link](https://learn.microsoft.com/en-us/security/zero-trust/sfi/defend-indirect-prompt-injection) | A **vendor defense-in-depth taxonomy** with nine layers: prompt shields; spotlighting; plan drift detection; critic agents; tool chain analysis; guardrails in skills; information flow control; least privilege / short-lived privileges; human-in-the-loop for risky actions. States that injection will sometimes succeed and that probabilistic and deterministic defenses must be combined; **no single solution is sufficient**. | Yes — page fetched; layer list, author, dates, framing present | The best available industry framing to position against, not a product. It names "plan drift detection" and "tool chain analysis" as desirable layers to be built; it specifies no contract format, no argument-level policy language and no audit artifact. Cite it for the claim that deterministic action-time controls are considered necessary. |
| **Microsoft MCP injection guidance** | Microsoft Developer Blogs. "Protecting against indirect injection attacks in MCP." Published 28 April 2025. [link](https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp/) | An advisory post. Defines **tool poisoning** (malicious instructions hidden in tool metadata) and warns about **rug pulls** — a tool changing after the user approved it. Recommends AI Prompt Shields, supply-chain verification and security fundamentals. | Yes — page fetched; date, bylines and mitigation categories present. **Verified negative:** the post contains no code or SDK specifics and does **not** recommend a gateway, tool-call interception, or user confirmation. | This is the clearest documented gap, and the strongest motivation for the manifest fingerprint: authoritative MCP-specific vendor guidance **names** the post-approval-mutation problem and proposes only text classification and supply-chain scanning in response. Binding approval to a hash of the approved tool definitions is a direct, deterministic answer (H3). |
| **MCP 2026-07-28 specification** | Model Context Protocol, revision 2026-07-28. [release post](https://blog.modelcontextprotocol.io/posts/2026-07-28/) · [changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog) · [tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | See §2. | Yes — all three fetched, plus the same revision's [Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http), [pagination](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/pagination), [authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) and [security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) pages | See §2 and §4. |

### Compared, not endorsed

These are adjacent products. None of these organizations has adopted, reviewed or endorsed
this project, and nothing here should be read as implying otherwise.

| System | What it does | Verified limitation relevant here |
|---|---|---|
| [Google Cloud **Model Armor**](https://docs.cloud.google.com/model-armor/overview) | Screens prompts and responses: responsible-AI categories, prompt-injection/jailbreak detection, DLP, malicious-URL detection, document and image screening. Enforcement is "inspect only" or "inspect and block", where **the calling service or Policy Enforcement Point is responsible for actually stopping processing**. | Each prompt or response is inspected as a **single turn with no conversation history**; encoded content (Base64, hex, URL-encoding) is not decoded; inputs under three words return `NO_MATCH_FOUND`. The overview page does **not** mention tool calls, function calling, agent actions or task-level intent. Complementary to an argument-aware allow/deny, not a substitute. |
| [Azure AI **Prompt Shields**](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection) | Two classifiers: user-prompt shields (jailbreak risk) and document shields (indirect attacks). In Foundry, document shields scan the user input and **tool response** intervention points. Spotlighting (preview) tags documents as lower-trust. | **Classification, not authorization.** The standalone API reports a detection result and the application decides. The concepts page documents scanning the *tool response* — data coming back — and does **not** document denying a tool call's outbound arguments. Stated limits: "helps prevent", false positives expected, attacks may go undetected. |
| [LangGraph / LangSmith](https://docs.langchain.com/langsmith/add-human-in-the-loop.md) | Tool-call review and approval is attributed to **LangGraph's** human-in-the-loop features via `interrupt(...)`, resumed with `Command(resume=...)`. Static `interrupt_before`/`interrupt_after` exist but the docs say they are "not recommended for human-in-the-loop workflows". | Denial lives **inside the graph**: it protects only agents written in that framework, requires the author to place interrupts correctly, and is bypassed by any tool call not routed through an interrupting node. LangSmith's documented role is tracing and evaluation; approval and denial are documented as LangGraph runtime features. |
| [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/) | Define telemetry **signal naming** — spans, metrics, events — including an MCP page. | Both the GenAI and MCP pages now serve only a relocation notice ("moved to the OpenTelemetry GenAI semantic conventions repository"), so current span and attribute names are unverified (§5). The structural point stands: conventions name telemetry; nothing on the fetched pages describes blocking, enforcement or a decision point. Independently verified from the MCP changelog: `traceparent`/`tracestate`/`baggage` propagation in `_meta` is specified (SEP-414), which is the sanctioned way to correlate a receipt with a host's trace. |

---

## 2. MCP 2026-07-28: what the revision means for a tools-only proxy

Each point below is traceable to the release post (B), the changelog (C) or the tools page
(T); items marked † were corroborated on the same revision's transport, pagination,
authorization or security-best-practices pages.

**Statelessness — the largest architectural consequence**

- **Protocol-level sessions are gone.** The `Mcp-Session-Id` header is removed from
  Streamable HTTP and the `initialize` / `notifications/initialized` handshake is removed;
  the revision is explicitly stateless (C, SEP-2567/SEP-2575). A proxy therefore holds
  **no connection-scoped identity**. This is the spec-level justification for a design
  decision this project had already made for threat-model reasons: *transport identity is
  not task identity*. Agent Drift binds a task when the gateway process is launched.
- **Every request is self-contained.** Protocol version and client capabilities travel in
  `params._meta` under `io.modelcontextprotocol/protocolVersion` and
  `io.modelcontextprotocol/clientCapabilities`; servers identify themselves in each
  result's `_meta` (C, T).
- **`server/discover` added**; servers MUST implement it to advertise supported versions,
  capabilities and identity (C).

**Result shapes**

- **All results carry a required `resultType`** (`"complete"`, or `"input_required"` for
  MRTR). Clients MUST treat results from earlier-revision servers that omit it as
  `"complete"` (C).
- **Two error channels persist and must not be conflated.** Protocol errors are JSON-RPC
  errors; tool execution errors are `isError: true` inside a successful result. Clients
  SHOULD feed tool execution errors to the model for self-correction and MAY feed protocol
  errors (T). **This directly determined decision D-006**: a policy denial is returned as a
  tool-execution error, because the agent should see it and adapt.

**Human confirmation is in the protocol**

- **Multi Round-Trip Requests (MRTR)** replace server-initiated requests. A server returns
  an `InputRequiredResult` carrying `inputRequests`; the client retries the original
  request with `inputResponses` plus an opaque `requestState`, and the JSON-RPC `id`
  **MUST differ** between the initial request and the retry (C, T).
- Agent Drift v1 uses a bounded in-process wait instead (D-007), because MRTR requires host
  cooperation. MRTR is the more spec-idiomatic mechanism and is the documented upgrade path.

**Discovery, caching, names**

- Servers SHOULD return tools in **deterministic order** to enable caching (C, T).
- List results now carry **`ttlMs` and `cacheScope`** (`"public"` / `"private"`), where
  `private` controls whether **shared intermediaries** may cache (C, SEP-2549). A gateway is
  a shared intermediary, which is why D-010 honours it.
- **Pagination cursors are opaque**; clients MUST NOT parse or modify them, and an empty
  string is a valid cursor that MUST NOT be read as end-of-results (†). A proxy that
  *filtered* the tool list would have to synthesize its own cursors; Agent Drift forwards
  the set unmodified, so pass-through is correct (D-009).
- **Tool name constraints are `SHOULD`-level**: 1–128 characters, case-sensitive,
  `A–Z a–z 0–9 _ - .` (T). Dotted names such as `repo.read_file` are conformant.
- **The spec anticipates aggregating proxies**: proxies that aggregate tools from multiple
  servers SHOULD implement a disambiguation strategy such as prefixing, and `serverInfo.name`
  **SHOULD NOT** be relied on for disambiguation (T). v1 proxies one server (D-009).

**Transport-level interposition (not used in v1, but it shapes the roadmap)**

- Streamable HTTP POSTs now REQUIRE `Mcp-Method` and `Mcp-Name` headers so intermediaries can
  route and inspect without parsing the body (C, SEP-2243; B). The transport page adds the
  enforcement rule: header values MUST match the body, and servers MUST reject mismatches
  with `400` / `-32020` (†).
- A new `x-mcp-header` schema property mirrors an argument into `Mcp-Param-{name}` for
  intermediaries, with constraints (primitive types, statically reachable, no sensitive
  parameters) (T).
- † **The most important protocol-correctness rule for a project like this**: a
  policy-enforcing intermediary SHOULD verify that `MCP-Protocol-Version` indicates a version
  requiring header–body validation, and SHOULD reject the request rather than trusting
  unvalidated header values. Agent Drift v1 is stdio-only and parses the body directly, so it
  is not exposed to this — and that is a reason the HTTP transport is *not* claimed as
  supported rather than quietly assumed to work.
- **SSE resumability is removed**: a broken stream loses the in-flight request and clients
  MUST re-issue it with a **new request ID** (C). An approval keyed on request id would
  therefore be incorrect by construction, which is why the grant key is
  `(task, revision, tool, canonical args digest, nonce)` and excludes it.

---

## 3. Falsifiable hypotheses

Each is phrased so a specific experimental outcome refutes it. None is claimed as
established; H4 is partially tested in this repository and the rest are stated as the work
that would be needed.

**H1 — Contract-scoped argument policy beats prompt-level filtering at equal utility.**
On AgentDojo's 629 security test cases, a gateway enforcing a user-approved task contract
achieves a lower targeted attack success rate than a text-classifier guardrail applied to
tool-call arguments and results, **while** keeping benign task utility within a
pre-registered margin (propose 3 percentage points) of the undefended agent.
*Refuted if* ASR is equal to or higher than the classifier baseline, **or** benign utility
drops by more than the margin. Pre-register margin, agent, model and attack set first, and
report utility-without-attack separately — AgentDojo's own finding is that models fail many
tasks unattacked, a confound that would otherwise read as a defense cost.
*Status in this repository:* **not run.** The local benchmark (`evals/`) shows the direction
on a constructed set — the keyword baseline produces 41 false blocks to the contract
policy's 0 — but that is not AgentDojo and must not be reported as if it were.

**H2 — Most injection-induced harm is argument-visible at the protocol boundary.**
For some pre-registered fraction *p* (propose *p* ≥ 0.6) of AgentDojo + ASB injection cases
that succeed against an undefended agent, the harmful action is detectable from the
`tools/call` name and arguments alone, checked against the approved contract — with no model
introspection, no re-execution and no control-flow graph.
*Refuted if* the measured fraction falls below *p*: that is, if harm is predominantly
carried in arguments that are individually contract-conformant and only harmful in
aggregate or in sequence.
**This is the hypothesis most likely to fail and the one worth running first.** ASB's
memory-poisoning and Plan-of-Thought-backdoor cases are deliberately adversarial to it, and
a failure here bounds the entire product claim. Report per-benchmark, not pooled.

**H3 — Contract immutability, not description filtering, is what defeats rug pulls.**
On a corpus of tools whose `description`, `inputSchema` or `annotations` change *after* user
approval, binding the contract to a hash of the approved tool definitions blocks ≥ 95% of
cases, substantially more than a text classifier over descriptions.
*Refuted if* hash-binding's block rate is below 95%, or is not meaningfully above the
classifier's. *Refuted as practical* if hash-binding's false-positive rate on benign version
churn (legitimate upgrades, `listChanged`, `ttlMs` expiry) is high enough to make the gateway
unusable — which must be measured against real servers over time, not synthetically.
*Status in this repository:* the mechanism works against a real mutating server
(`examples/scenarios/06-attack-f-manifest-rug-pull.json`, with
`AD_FIXTURE_MUTATE_MANIFEST=1`), but **the benign-churn false-positive rate is unmeasured**,
and that is the half that decides whether it is usable.

**H4 — Receipts are sufficient for independent adjudication.**
Given only a replayable receipt — the contract, the tool definitions as approved, the call
name and arguments, the decision and the rule that fired — and no access to the live system,
a third party reproduces the allow/deny decision deterministically in ≥ 99% of recorded
cases.
*Refuted if* replay diverges above 1%, for example because decisions depend on unrecorded
state or on a request id that did not survive a stream break.
*Status in this repository:* **partially supported.** Decisions are deterministic given the
contract and arguments, the grant key deliberately excludes the request id, and
`/api/export/{task_id}` emits the receipt bundle. A genuine third-party replay harness that
consumes only the export has not been built, so the 99% figure is untested.

**H5 — Protocol-boundary enforcement costs less utility than program-level enforcement.**
A tools-only gateway, imposing no planner or control-flow constraints, lands closer to the
undefended baseline than CaMeL's reported 77%-of-84% on the same benchmark and a comparable
backbone, accepting weaker guarantees.
*Refuted if* measured utility is at or below CaMeL's figure — which would mean paying a
program-level price without buying a program-level guarantee.
*Caveat:* 77% and 84% are figures reported in the CaMeL abstract for their configuration.
They are not a normalized baseline, and any comparison must re-run the undefended baseline
locally rather than differencing published numbers.

---

## 4. Honest novelty statement

**No "first ever" claim is made.** All four components have clear prior art. The defensible
claim is about *integration, placement and artifact*, and even that is provisional (§5,
item 11).

### Clearly prior art — cite, do not reinvent

- **Enforcing policy at the moment a tool is called** is CaMeL's central mechanism
  (arXiv:2503.18813). Any "we enforce at action time" framing must cite it.
- **Deciding whether an action is attributable to the user's task rather than to injected
  content** is MELON's core insight (ICML 2025), via masked re-execution.
- **Human-in-the-loop confirmation of tool invocations** is a `SHOULD` in the MCP
  specification itself, and MRTR is the protocol's own mechanism. LangGraph's `interrupt`
  is a shipped, widely used implementation. This is not a new idea at any level.
- **Logging tool usage for audit** is an explicit client `SHOULD` in the MCP tools page's
  security considerations, and trace correlation is already specified via
  `traceparent`/`tracestate`/`baggage` in `_meta` (SEP-414).
- **Defense-in-depth layering, plan-drift detection and tool-chain analysis** are already
  named as recommended practice by Microsoft's SFI guidance.
- **Argument and content screening at a policy enforcement point** is what Model Armor and
  Prompt Shields already do, including Model Armor's explicit PEP model.
- **Benchmarks and metrics** are AgentDojo's and ASB's contribution. This project should
  consume them, not re-derive them.

### What is plausibly new, and why

1. **An immutable, user-approved task contract as a durable artifact that outlives the
   agent's context.** Prior work infers intent at runtime: CaMeL extracts control flow from
   the trusted query; MELON masks the prompt to test attribution. Neither produces an
   artifact that the user approved, that is fixed at approval time, and that survives into
   later turns. This matters specifically because Microsoft's own MCP guidance **names** rug
   pulls and answers them only with supply-chain scanning and text classification. Binding
   approval to a hash of the approved tool definitions is a deterministic answer to a threat
   that first-party vendor guidance names and does not answer. *This is the strongest claim,
   and H3 is its test — including the usability half that is still unmeasured.*
2. **Enforcement at the MCP protocol boundary rather than inside the agent program.** CaMeL
   buys stronger guarantees by constraining the agent's architecture. LangGraph's `interrupt`
   protects only LangGraph agents, and only where the author remembered to place it. A
   tools-only proxy is framework- and model-agnostic and cannot be forgotten by the agent
   author — at the explicit cost of having no control-flow graph. That trade (weaker
   guarantee, zero architectural commitment, universal coverage over what traverses it) does
   not appear to be occupied by any verified source. The 2026-07-28 revision makes it
   unusually tractable: stateless, per-request credentials, declared `cacheScope` for shared
   intermediaries, and MRTR as a sanctioned confirmation channel.
3. **A replayable receipt as the unit of accountability.** The spec asks clients to log tool
   usage; OTel gives correlation identifiers. Neither defines a decision record from which a
   third party can deterministically reproduce an allow/deny and check it against what the
   user actually approved. H4 is its test.
4. **Discharging the client-side `SHOULD`s on the client's behalf.** The MCP tools page asks
   *clients* to show tool inputs to the user, prompt for confirmation on sensitive
   operations, validate results, enforce timeouts and log for audit. Most hosts implement a
   subset. A gateway that discharges these for any host against any server is a
   **conformance-and-completeness contribution** rather than a new security primitive —
   which is both more accurate and more defensible than framing it as a new defense.

### Explicitly disclaimed

- **No formal guarantee.** CaMeL claims provable security for a constrained architecture; a
  tools-only proxy sees name, arguments and contract. Any "provable" or "guaranteed"
  language would be unsupported.
- **Memory poisoning and backdoored plans (ASB) are not addressed**, except insofar as the
  contract itself is protected from agent modification — which is demonstrated
  (`tests/security/test_task_identity.py`) rather than assumed.
- **Content classification is not replaced.** Model Armor and Prompt Shields catch things an
  argument policy cannot, and vice versa. The honest claim is complementarity, matching the
  SFI guidance's own "no single solution is sufficient".
- **Sequence- and aggregate-level harm is a known open weakness**: many individually
  in-contract calls that are jointly harmful. H2 is designed to expose it.
- **The local benchmark is not a published benchmark.** 192 author-constructed cases measure
  internal consistency, not robustness. See `evals/RESULTS.md`.

---

## 5. Could not verify

1. **Full verbatim abstracts** for AgentDojo, MELON, CaMeL and ASB. Titles, authors, venues,
   years, DOIs, page ranges and the specific figures (77%/84%, 84.30%, 97 tasks, 629 cases,
   400+ tools) were read directly off the pages; the descriptions above are accurate
   paraphrases, not transcriptions.
2. **Stated limitations sections** of all four papers. None of the landing pages carries one.
   In particular, **MELON's claimed provability is asserted by its title and not
   characterized on the PMLR page** — do not describe its formal guarantee without reading
   the PDF. The same applies to CaMeL's notion of "provable security".
3. **Microsoft MCP blog authorship.** The page shows bylines for two people without clearly
   attributing the post to one; cited as a Microsoft Developer Blogs post.
4. **Microsoft SFI page date.** The page is internally inconsistent (front matter 2026-03-19,
   footer 2026-03-24); cited as "March 2026".
5. **Taint tracking in the SFI doc** — explicitly **not present**. The nearest named concept
   is Information Flow Control, citing arXiv:2505.23643. Neither that paper nor
   arXiv:2403.14720 (spotlighting) was fetched.
6. **MCP security-best-practices canonical URL.** The `/specification/.../basic/` path
   returned a client error; content was read at the `/docs/.../tutorials/security/` path that
   the authorization page itself links to.
7. **OpenTelemetry GenAI/MCP conventions — current span names, attributes and stability
   level.** Both pages now serve only a relocation notice. Resolve against the new repository
   before citing any span name.
8. **LangSmith's full product surface.** Verified only that the "Add human-in-the-loop" page
   attributes approval to LangGraph and never to LangSmith. One page is not an exhaustive
   negative, so the claim is phrased as what is documented.
9. **Prompt Shields' behaviour on tool calls.** Verified negative on the concepts page only;
   the guardrail documentation was not fetched. The claim is that the concepts page does not
   document tool-call denial, not that it is impossible.
10. **Model Armor's MCP integration.** A navigation link titled "Integrate with Google and
    Google Cloud MCP servers" exists; its content was not read.
11. **A package-ecosystem survey of existing MCP proxies and gateways.** `pypi.org`,
    `registry.npmjs.org` and the container registry are all blocked by egress policy in this
    build environment (see `docs/VERIFICATION.md`). **This is the most material omission in
    this document**: the competitive landscape for MCP gateways lives largely in those
    registries and on GitHub. The novelty statement in §4 is **provisional** until that survey
    is done from an unrestricted environment — search for MCP proxies, MCP gateways,
    policy-enforcing MCP middleware and `mcp-scan`-style tooling before making any public
    novelty claim.
12. **The SEP documents themselves** (SEP-2575, 2567, 2243, 2549, 2106, 414 and others). SEP
    numbers and their effects are quoted as the MCP changelog, blog and spec pages attribute
    them; the individual SEP texts were not read.

---

## 6. Resume line

The template in `CLAUDE.md` §11 may be filled **only** from measured output. As of the run
recorded in `evals/RESULTS.md` and `docs/VERIFICATION.md`:

> Built an MCP-based runtime intent-integrity gateway (MCP protocol 2026-07-28) enforcing
> task-scoped tool policies, blocking unauthorized side effects before execution and
> visualizing replayable agent traces; evaluated on **192** labeled tool-call scenarios with
> **100%** recall, **100%** precision, **0** false blocks and **1.2 ms** p95 local decision
> overhead against unguarded and keyword-classifier baselines.

Anyone using that line should be ready to add the qualifier that belongs with it: the 192
cases are author-constructed and measure internal consistency rather than robustness, and
the AgentDojo and ASB comparisons (H1, H2, H5) have **not** been run.
