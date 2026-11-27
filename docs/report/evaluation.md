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
| Estimated on a paid model (illustrative tiers: small $0.25/$1.25, large $3/$15 per million tokens in/out) | $0.04 / $0.47 per approved rule | $0.05 / $0.55 per approved rule |

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

  Human review caught what the deterministic checks couldn't: three over-broad `reg` rules, and one rule that would stay silent on logs without `OriginalFileName`.
- **Human labels, checked for agreement:** the one judgment that feeds a headline number is the class of each legitimate look-alike.
  - **A, near-miss:** a precise rule should stay silent on it, so it counts toward false alarms.
  - **B, inherently ambiguous:** the command line alone can't tell it from the attack. Reported apart.

  Rule scores need no agreement check: the harness computes them. The labels do. `scripts/label_agreement.py` gives a blind sheet with the written A/B rubric:
  - **Main set (58 items):** an independent labeller against the dataset author's labels.
  - **Pilot (7 new look-alikes):** both team members label blind.

  With 2 labellers, a few dozen items and far more A than B, kappa is unstable and can be near 0 even at high agreement. A labeller marking everything A scores 90% raw agreement and kappa 0.00. So raw agreement is reported next to Cohen's kappa, and every disagreement is discussed as a gap in the rubric.

  **First result: a model rater against the dataset author.** A fresh model, given only the sheet and the rubric (no file access, no tools), labelled all 58 items: **53/58 (91%) raw agreement, Cohen's kappa 0.66** (substantial). All 5 disagreements go the same way: the model says B where the author says A, each for a command that does the *same action* as the attack on a *friendlier target* (an intranet URL, a UNC share, a signed company binary, `cmd < file`). That is a real ambiguity in the rubric: whether a different target makes a near-miss (A) or only context can tell (B). It is reported as model-vs-author, not as human agreement. **[pending: the human labels]**
- **LLM-as-judge: deliberately not used.** Everything we need to judge can be checked deterministically. A judge model would add cost, its own biases, and memorization risk: it may know the SigmaHQ rules.

## Benchmarks versus the real world

A fixed benchmark can be overfitted, and the professor's point stands: a few benchmarks don't show the agent will hold up in production. Each layer below tests a different way the evaluation could fool us.

| Risk | Layer | Status |
|---|---|---|
| The agent memorizes the variations it tunes on | Held-out **variation types** (omission, insertion, recoding); the agent never sees them | done |
| Prompts tuned until the numbers look good | Held-out **techniques**: dev for iterating, test run once after the freeze | done |
| "0 false alarms" only because the look-alike set is small | Stress check: 29 everyday look-alikes outside the dataset, re-scored on every saved rule (below) | done |
| The numbers hold only in our own matcher, not in a real SIEM | SIEM parity: every rule's exported query run in a real Elasticsearch on the same events (below) | done |
| The model recalls SigmaHQ rules instead of reasoning | Memorization probe: report memorized vs clean techniques separately | **[pending]** |
| A mutation no longer works as an attack | VM check: run a sample in Windows with Sysmon | **[pending]** |
| A result depends on one lucky run | 3 runs per setup, reported with spread and pass@k | done |
| Results come from a different setup than claimed | Provenance per run: prompt, model, budgets, code and data fingerprints | done |

### Stress check: look-alikes the dataset doesn't have

`scripts/stress_check.py` replays every saved rule, in all three arms, against 29 legitimate commands outside the dataset (`data/eval/extra_lookalikes.yml`), with no model calls:
- the 7 found while reviewing the test split: reg query / add / delete on `HKLM\SYSTEM` and `HKLM\SECURITY`, deleting a Run-key value, `wmic service … delete`, a system-state backup;
- 22 more everyday admin commands drawn from SigmaHQ's own false-positive notes (querying or disabling tasks, service configuration, listing shadow copies, reading event logs, checking backups), only clear near-misses (class A).

They're kept out of the main event files, whose hash is part of every run's setup key, and reported apart from the frozen results.

| Rules | Test split | Dev split (frozen budget, 15 calls) |
|---|---|---|
| Community (Arm 1) firing on at least one | **0 / 18** | **0 / 9** |
| Hardened (Arm 2) | 2 / 9 | 1 / 4 |
| Written with variations (Arm 3) | 1 / 36 | 5 / 18 |
| Written zero-shot (Arm 3) | 0 / 18 | 1 / 8 |
| **Approved rules firing** | **0** | **0** |

**What it shows:**
- **The agent's rules are broader than the community rules, and the dataset's look-alikes didn't reveal it.** Making a rule catch more evasions tends to make it catch more legitimate commands too.
- **On the test split, human review rejected every rule that fires on a look-alike.** On dev, the firing rules are rejected or not yet reviewed.
- **The gate alone isn't enough here, which is the case for a human approval step.**

The 22 extra commands barely change the picture: only one of them (`bcdedit /timeout`) trips a single dev rule. The over-breadth is concentrated in a few verbs (`reg query/add/delete`, `wmic … delete`), not spread across the agent's rules. The model rater labels all 7 pilot items A, so they count as false alarms; `--labels` applies human labels once they exist.

### SIEM parity: the same rules in a real Elasticsearch

`scripts/elastic_parity.py` loads the 300 events into Elasticsearch 8.15 with an ECS mapping like Elastic's own, runs each rule's exported query, and compares event by event with DetectForge's matcher. It also runs nightly in CI against an Elasticsearch container.

| Rules | Lucene export: identical | EQL export: identical |
|---|---|---|
| 27 community rules | 16 | **27** |
| 40 approved agent rules | 10 | 14 (21 refused by Elastic) |

- **EQL export matches our matcher exactly on all 27 community rules.** The scores measured here hold in a real SIEM, and the UI now exports EQL by default.
- **Lucene export is case-sensitive on command lines** (pySigma's output against ECS's `wildcard` field): the rule says `hklm`, the attack `HKLM`, and Elastic misses it (251 event matches lost).
- **Agent rules that use regular expressions don't port cleanly.** 26 of the 40 approved agent rules use regexes; Elastic's EQL rejects 21 (`\/` escapes, `(?i)`, `\b`). The gate's `deployable` check only tests that a rule converts, which is too weak: it should check the dialect Elastic accepts (future work, a core change).

## The evaluation set: what it covers and what it doesn't (slide 31)

| Dimension | Covered | Not covered |
|---|---|---|
| Techniques | 19 ATT&CK techniques, 27 SigmaHQ rules, across 6 tactics: credential access (T1003.001, T1003.002, T1555.003), defense evasion (T1027, T1036.003, T1218.005/.007/.010/.011, T1685, T1685.001), execution (T1047, T1059.001, T1059.003), persistence (T1053.005, T1543.003, T1547.001), command and control (T1105), impact (T1490) | Lateral movement, discovery, exfiltration; techniques with no process-creation signal |
| Normal cases | 66 base attack command lines from Atomic Red Team | Captured logs from real intrusions |
| Adversarial cases | 176 mutations from the 5 Uetz transforms: substitution 67 and reordering 10 for tuning; insertion 54, omission 44, recoding 1 held out | Binary renaming, other parents, longer chains; recoding has 1 mutation (L4) |
| Legitimate look-alikes | 58 hard negatives for 19 techniques: 52 class A (34 held out, 18 for tuning), 6 class B reported apart, plus 7 stress-check look-alikes | Real benign telemetry at volume (a SIEM's normal day); the false-alarm *rate* in production |
| Splits | By variation type (tuning vs held-out) and by technique (9 dev rules to iterate on, 18 test rules run once) | A second, independent test set |
| Edge cases | Rules with no tuning variation (zero-shot writes), no held-out variation (n/a, not averaged), no community rule (the write fallback), model outages, budget exhaustion | Very long command lines, non-ASCII paths in real logs |
| Request intake | Vague, injected and API-failure scenarios in the demo and the tests | A user study with analysts |
| Log source | Sysmon Event ID 1 (Image, CommandLine, ParentImage, OriginalFileName) | Windows 4688 (no OriginalFileName), Linux, EDR-specific fields |

The "not covered" column is the honest scope: results hold for Windows process-creation rules facing these five transform types, not for detection engineering in general.

## From offline evaluation to monitoring

- **Tracing:** every model and tool call carries latency, tokens, retries, fallback and errors. The Lab tab shows calls today against the provider's daily limit, failures by kind, and prompt versions side by side.
- **Feedback into development (evaluation-driven):**
  1. every failure found in runs or review becomes a row in the failure matrix (29 so far);
  2. the row gets a regression test;
  3. where needed, it becomes a gate check or a new prompt version.

  Prompts v1 to v7 were each a response to measured failures on dev, never on test.
### What we would monitor in production (slides 44–46)

Offline evaluation says a rule was good on our data the day it was approved. In production three things drift:
- **The attacks:** new evasions appear.
- **The environment:** new legitimate software that looks like an attack.
- **The agent:** a provider updates the model behind the same name.

| Signal | Where it comes from | Act when | Action |
|---|---|---|---|
| Alerts per deployed rule per day | the SIEM (shadow deployment first) | a rule's volume jumps, or it fires on a process a reviewer marks benign | add the command as a look-alike, re-run the agent with it in tuning, review the new version |
| Reviewer rejection rate, per technique and prompt version | review decisions (already recorded) | rejections rise for a technique, or after a model change | inspect the traces; a recurring cause becomes a failure-matrix row and a gate check |
| Gate pass rate, model calls and tokens per run | saved runs (Lab tab) | pass rate drops, or calls per run rise, with no prompt change: the provider's model changed | re-run the dev split, compare with the frozen baseline before trusting new runs |
| Held-out evasion resistance of deployed rules | the harness, re-run when the mutation set grows | a deployed rule falls below the gate's 80% on new mutation types | queue it for hardening (it is the "before" of a new run) |
| Model errors, fallbacks, outages | model-call records | failures above a few percent of calls, or near the daily limit (already a warning in the Lab) | pause batches; switch to the fallback model, labelled in provenance |
| Prompt-injection attempts | tool calls the dispatcher refused; text the UI escaped | any attempt to call a non-existent tool or reach held-out data | inspect the source rule or report; add it to the injection tests |

**Experimenting safely (slide 46):** a new prompt or model never replaces the frozen one directly.
1. It runs in **shadow** first: same requests, results saved under its own prompt version (provenance keeps them apart), nothing deployed.
2. It's compared on the dev split and on live reviewer decisions.
3. It's promoted only if it isn't worse on held-out resistance, false alarms and rejection rate.

**Human feedback (slides 47–48):** every reviewer rejection already carries a reason. In production those reasons are the main signal: they find what the dataset didn't anticipate, as the three over-broad reg rules did here. They feed back as new look-alikes, new gate checks and new prompt versions.

What exists today: the tracing, the Lab tab and its quota warning, recorded decisions with reasons, and provenance per run. The SIEM side (alert volume, shadow deployment) is future work.
