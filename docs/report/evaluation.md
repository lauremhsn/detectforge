# Report draft: How we evaluated the agent

Draft text for the final report. It answers "how did you evaluate your agent?" along the
dimensions of the course's evaluation chapter (levels, metric families, methods, benchmarks
versus the real world). Numbers are from the test split, run once after the prompts were frozen:
- 9 hardening runs;
- 54 writing runs, plus 1 lost to a model outage.

Sources:
- `scripts/agent_metrics.py`, which computes the agent metrics offline from the saved runs, with no model calls;
- its output, `data/eval/results/agent_metrics_{test,dev,dev_budget25}.json`;
- `docs/report/results.md`.

Items marked **[pending]** are planned and not done yet.

---

## Principle: score the rule and the agent separately

The rule is scored deterministically: the harness replays it against attack variations and legitimate look-alikes, and the gate applies 16 checks. That answers "is the output good?".

But a good final rule doesn't show that the agent worked well. It could get there by luck, by loops, or by seeing data it shouldn't. So the agent's *process* is scored too, from what every run records:
- each model and tool call;
- the full transcript (only what the agent saw);
- its gate results;
- its provenance.

## Evaluation levels

| Level | Question | How DetectForge answers it |
|---|---|---|
| **Component** | Do the building blocks work? | 366 automated tests: the Sigma matcher, validator, mutation engine, harness, gate checks, tools, review and security. CI runs them on every PR, plus an eval gate that fails if Arm 1's results change. |
| **Step** | Was each action right? | Every tool call is checked against its schema and recorded (ok / error). Success rate, refused arguments, redundant calls. |
| **Trajectory** | Was the path good? | From each transcript: measured before changing anything? Recovered from a gate refusal? Stopped once accepted? Looped? |
| **End-to-end** | Did it achieve the user's goal? | Evasion resistance on **unseen** variation types, false alarms on unseen legitimate commands, then human approval. |

## What we measure (slide 14's metric families)

### Task success and output quality

| Metric | Hardened | Written |
|---|---|---|
| Completion: submitted a rule | 9/9 | 50/54 (93%) |
| Success: passed all quality checks | 9/9 | 45/54 (83%) |
| Goal: unseen evasion resistance, before → after | 50% → 72% | 0% → 78% |
| Approved by the reviewer | 7/9 | 27/54 (50%) |
| Constraint satisfaction (metadata, fields, filters kept) | enforced by the gate: a run can't pass without it | same |
| Groundedness: rationale claims ("catches all", "no false alarms") contradicted by the agent's own last tuning score | 0 of 6 rationales with claims | 0 of 32 |

**Groundedness is checked deterministically.** The rationale's claims are compared with the scorecard the tool returned, with no judge model.

**Faithfulness to sources** is the gate's `keeps_original_metadata`: a hardened rule keeps its SigmaHQ id, author, date and references.

### Tool use and planning

| Metric | Hardened | Written |
|---|---|---|
| Tool calls that succeeded | 72/72 | 593/593 |
| Tool arguments rejected by the schemas | 0 | 0 |
| Calls to a tool that doesn't exist | 0 | 0 |
| Redundant scoring calls (same rule text scored twice) | 0% | 2% |
| Calls per run | tuning 3.2, validate 2.0, submit 1.7, search 0.9, schema 0.2 | validate 3.7, tuning 2.7, search 2.2, submit 1.4, schema 1.0 |
| Measured before changing (first call is a measurement) | 9/9 | 54/54 |
| Runs where the gate refused a submission | 6/9 | 28/54 |
| Recovered: refused, then fixed and passed | 6/6 | 23/28 (82%) |

**Across all 1,434 saved tool calls, the only refusals are 5 "tuning budget exhausted" messages.**

**What the gate refused most** (test, per submission): case-sensitive regexes (30), copied look-alike characters (10), false alarms on tuning look-alikes (7), bypassable exclusions (2). Each check exists because of a real failure (`docs/failure-matrix.md`, D1–D29).

**Planning in our design** is a fixed outer workflow (find → validate → harden → re-validate → approve), with the agent choosing the inner steps. Writing runs search for references and inspect the schema more (2.2 and 1.0 per run) than hardening runs do (0.9 and 0.2). That adaptation is expected: with no community rule, the agent needs more context.

### Memory

**Not applicable by design.** Each run starts fresh: no memory across runs, techniques or users. This is deliberate:
- one run can't leak what it learned on another technique's held-out data;
- repeated runs are independent, so their spread means something.

The only state passed on is the human-approved rule itself.

### Reliability

| Metric | Hardened | Written |
|---|---|---|
| Repeated setups (same prompt, model, budgets, code, rule, events) | 3 | 18 |
| pass@3: passed in at least one of 3 runs | 3/3 | 17/18 (94%) |
| Passed in all 3 runs | 3/3 | 13/18 (72%) |
| Spread of unseen resistance across repeats (mean st. dev.) | 16 points | 8 points |
| Runs answered by the fallback model | 0 | 0 |
| Runs lost to a model outage | 0 | 1/55 (detected, labelled, redone) |
| Runs stopped by the model-call budget | 0 | 7/54 |

How each failure kind is handled:
- **An outage never counts as a result.** The run is labelled from its last failed call and redone by the batch.
- **A run stopped by the budget** ends as "needs human review" with its best attempt and the reasons. It is never silent.

### Efficiency

| Metric | Hardened | Written |
|---|---|---|
| Model calls per run | 8.0 | 11.0 |
| Tokens per run | 67k | 69k |
| Time per run (free tier, mostly queueing) | 5.4 min | 2.0 min |
| Model calls per approved rule | 10.3 | 22.0 |
| Cost | $0 (free models; the limit is 1,000 requests a day) | $0 |

**Budget ablation, dev only (written rules):** 25 calls instead of 15 raises the pass rate from 10/18 to 17/18 at the same total cost, but the unseen score doesn't rise (71% vs 77%). See `results.md`.

### Safety

| Metric (slide 19) | Result | How it's ensured and checked |
|---|---|---|
| Unauthorized actions | 0: the agent can't deploy, approve, or write files | 5 tools, none of which deploys. Test: a whole run needs no network and writes no files |
| Excessive permissions | none | No tool takes a path, URL or split. Test: exactly five tools, none taking a split path or URL |
| Failure to request human approval | 0 of 63 runs | Every rule leaves the agent as `proposed`. Only a reviewer key can approve it (strict key parsing, lockout after repeated wrong keys) |
| **Held-out leakage** (the agent sees evaluation data) | **0 of 63 runs** | Each transcript is scanned for any held-out event id or command line, matched exactly |
| Prompt-injection susceptibility | blocked in tests | Tests on an injected community rule and injected text in an event; untrusted text escaped in the UI. **[pending: a behavioural injection set run through the agent, as a demo scenario]** |
| Sensitive data leakage | none found | Test: the API key never reaches saved runs, errors or printed objects; no secret tracked by git or copied into the Docker image |

## How we evaluate (methods)

- **Deterministic, the main method:**
  - the harness (rule against events);
  - the 16-check gate;
  - the agent metrics above.

  They're reproducible, cost nothing, and can't be talked into a pass.
- **Human:** every rule is approved or rejected against a written rubric, the policy at the top of each decisions file:
  - **Hardened:** approve if the rule passed the checks and adds no false alarm.
  - **Written:** approve if the rule also catches at least 80% of unseen variations, or is tightly scoped when there's nothing to measure.
  - **Both:** reject a rule that fires on everyday legitimate commands checked by hand.

  Human review caught what the deterministic checks couldn't: three over-broad `reg` rules, and one rule that would stay silent on logs without `OriginalFileName`. **[pending: inter-rater agreement, with both team members reviewing the same 20 runs blind, reported as Cohen's kappa]**
- **LLM-as-judge: deliberately not used.** Everything we need to judge can be checked deterministically. A judge model would add cost, its own biases, and memorization risk: it may know the SigmaHQ rules.

## Benchmarks versus the real world

A fixed benchmark can be overfitted, and the professor's point stands: a few benchmarks don't show the agent will hold up in production. Each layer below tests a different way the evaluation could fool us.

| Risk | Layer | Status |
|---|---|---|
| The agent memorizes the variations it tunes on | Held-out **variation types** (omission, insertion, recoding); the agent never sees them | done |
| Prompts tuned until the numbers look good | Held-out **techniques**: dev for iterating, test run once after the freeze | done |
| "0 false alarms" only because the look-alike set is small | Stress-check look-alikes, re-scored on the saved rules (three rules already failed it by hand) | **[pending]** |
| The model recalls SigmaHQ rules instead of reasoning | Memorization probe: report memorized vs clean techniques separately | **[pending]** |
| A mutation no longer works as an attack | VM check: run a sample in Windows with Sysmon | **[pending]** |
| A result depends on one lucky run | 3 runs per setup, reported with spread and pass@k | done |
| Results come from a different setup than claimed | Provenance per run: prompt, model, budgets, code and data fingerprints | done |

## From offline evaluation to monitoring

- **Tracing:** every model and tool call carries latency, tokens, retries, fallback and errors. The Lab tab shows calls today against the provider's daily limit, failures by kind, and prompt versions side by side.
- **Feedback into development (evaluation-driven):**
  1. every failure found in runs or review becomes a row in the failure matrix (29 so far);
  2. the row gets a regression test;
  3. where needed, it becomes a gate check or a new prompt version.

  Prompts v1 to v7 were each a response to measured failures on dev, never on test.
- **In production, a team would add** (future work): reviewer rejection rate per technique as a drift signal, alert rate per deployed rule (shadow deployment to a SIEM, a stretch goal), and the same evaluation as a CI gate before a prompt or model change ships.
