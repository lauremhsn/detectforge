# Report draft: Results

Draft text for the final report. Every number comes from the test split, run once after the
hardening prompt (harden-v7) and the writing prompt (write-v2) were frozen; nothing was changed
in response to these results. Items marked **[pending]** wait for runs not done yet. Sources: `data/eval/results/arm1_community.json`, the saved runs (`detectforge export`),
`docs/limitations.md`.

---

## Setup in one paragraph

18 test rules (14 techniques) from SigmaHQ, replayed against attack command lines and their
mutations (the five Uetz transforms) plus legitimate look-alike commands. Mutations are split by
type: the agent tunes on **substitution and reordering** and is scored on the types it never saw,
**omission, insertion and recoding** ("unseen variations" below). Each configuration ran 3 times
on one free model (Nemotron Ultra via OpenRouter, Gemma as the fallback). A rule whose attacks
have no unseen mutation type has no unseen score: it is reported as n/a, never as 0% or 100%, and
left out of means.

## Arm 1: community rules as published

| | Value |
|---|---|
| Test rules with unseen variations | 15 of 18 |
| Unseen variations caught, mean per rule | **82%** |
| All variations caught, mean (dev + test, 27 rules) | 82% |
| By type (27 rules) | omission 100%, reordering 100%, substitution 77%, insertion 73%, recoding 0% |
| Rules evaded by at least one type (27 rules) | 10 |

Community rules are strong against omission and reordering, and weak against insertion,
substitution and recoding, which is the pattern Uetz et al. report.

## Arm 2: the same rules after agent hardening (the headline)

The agent hardens a rule only when it misses some tuning variation. **3 of the 18 test rules**
qualified; the other 15 already catch every tuning variation or have none to learn from.

| Rule | Runs | Unseen, before → after (per run) | Mean after | New false alarms |
|---|---|---|---|---|
| Dumping of Sensitive Hives Via Reg.EXE (T1003.002) | 3 | 0→100, 0→100, 0→0 | 67% (spread 47) | 0 |
| Suspicious Execution of PowerShell with Base64 (T1059.001) | 3 | 50→50 (×3) | 50% (spread 0) | 0 |
| Process Creation Attempt via Wmic.EXE (T1047) | 3 | 100→100 (×3) | 100% (spread 0) | 0 |
| **Mean over the 3 rules** | 9 | **50% → 72%** | | **0 of 9 runs** |

- All 9 runs passed the quality checks, and none added a false alarm on unseen legitimate commands.
- By type: insertion went from 0% to 57%. Omission was already 100% and stayed there.
- **Honest reading:**
  - One rule gained everything in 2 of 3 runs and nothing in the third, which shows the run-to-run spread of a free model.
  - One rule gained on the tuning types but not on the unseen ones: the agent fixed what it saw.
  - One rule was already fully robust on unseen types.
- The 72% rests on 3 rules. Present it as evidence that hardening can work, not as a general rate.
- **The gain came with over-breadth that the data didn't show.** The two T1003.002 runs that reached 100% did it by matching any `reg` verb on `HKLM\SAM|SYSTEM|SECURITY`.
  - Checked by hand on four everyday administrator commands (`reg query HKLM\SYSTEM\…`, `reg query HKLM\SECURITY\Policy`, `reg add HKLM\SYSTEM\…\Lsa …`, `reg delete HKLM\SYSTEM\…\Services\…`), both fire on all four. The community rule fires on none, and neither does the third run, which gained nothing on unseen variations.
  - The data has no such look-alike, so neither the gate nor the "0 new false alarms" figure could see it. The same happens with one written rule (Arm 3).
  - This is the trade-off Uetz et al. describe: a rule made harder to evade tends to fire on more. It's why a human approves every change.

### A gap that tuning variations don't show

Three test rules were skipped because they catch every tuning variation, or have none to learn from. On the unseen types they still miss a lot:

| Rule | Tuning | Unseen |
|---|---|---|
| Suspicious Download Via Certutil.EXE | 100% | 50% |
| PowerShell Download Pattern | 100% | 67% |
| File Download Via Bitsadmin | n/a | 62% |

A team that tested only with the variations it already knows would call these rules covered. This supports the project's premise (a rule existing is not coverage) and is a limitation of selecting rules by tuning score (L18).

## Arm 3: rules written by the agent, the technique's community rules hidden

54 runs (18 rules × 3), one more redone after a model outage. Reported as two subsets (L4b),
because 6 test rules have no tuning variation, so their rule is written from the base attacks alone.

| Subset | Runs | Passed the checks | Runs scored on unseen | Unseen caught, mean | Runs with new false alarms (unseen legit) | Model calls / run | Time / run |
|---|---|---|---|---|---|---|---|
| With tuning variations | 36 | 28 (78%) | 33 | **72%** | 0 | 12.0 | 2.4 min |
| Zero-shot | 18 | 17 (94%) | 12 | **95%** | **4** | 9.0 | 1.3 min |
| All written | 54 | 45 (83%) | 45 | **0% → 78%** | 4 | 11.0 | 2.0 min |

- **Zero-shot is not better at writing.** Its unseen variations are mostly omission (45 of 60), the easiest type. On insertion the two subsets are close: 67% zero-shot, 61% with variations.
- **Zero-shot rules raise false alarms the gate couldn't catch.** All three zero-shot rundll32 rules fire on the same legitimate command, which they never saw, and one zero-shot sc.exe rule fires on another. With no tuning look-alikes, the gate has nothing to test them on. With variations: 0 of 36 runs raise one.
- **The weakest technique is log tampering (T1685.001, auditpol and wevtutil).** 4 of its 6 written rules passed the checks yet catch 0% of unseen variations.
- **Recoding:** 3 unseen recoded attacks, none caught by any arm. Too few to report as their own bar (L4).

### Why written rules fail (54 runs; a run can have several causes)

| Cause | Runs |
|---|---|
| Catch less than 80% of unseen variations | 16 |
| Ran out of model calls (15 per run) | 7 |
| False alarms on tuning look-alikes (blocked by the gate) | 4 |
| Fire on unseen legitimate commands | 4 |
| Case-sensitive regexes on case-insensitive Windows fields (blocked) | 3 |
| Copied look-alike Unicode dashes from the attacks (blocked) | 2 |
| Miss some of the unmutated attacks (blocked) | 2 |
| An exclusion an attacker can add for free (blocked) | 1 |

The main failure is **generalizing to unseen evasion types** (16), not gate-level mistakes. Every
mistake the gate can see (case, copied characters, bypassable exclusions, false alarms on tuning
look-alikes) was blocked before reaching a reviewer. The dev ablation below tests the budget limit (7): more
calls turn those runs into passes but don't raise the unseen score.

## Arm 2 vs Arm 3

| | Hardened | Written |
|---|---|---|
| Starting point on unseen variations | 50% (the community rule) | 0% (no rule) |
| After | 72% | 78% |
| Passed the checks | 9 / 9 | 45 / 54 |
| Approved by the reviewer | 7 / 9 | 27 / 54 |
| New false alarms on unseen legitimate commands | 0 / 9 runs | 4 / 54 runs |
| Model calls / run | 8.0 | 11.0 |
| Time / run | 5.4 min | 2.0 min |

The two "after" numbers are not on the same rules, so don't compare them as a ranking. The
fair comparison is the one each arm was built for:
- **Hardening:** raises an existing rule without adding measured false alarms, though a reviewer still rejected 2 of 9 for over-breadth.
- **Writing:** covers a technique from nothing, but more of its rules need rejecting: 27 of 54 after review against the stated policy.

## Human review

The reviewer's policy (stated in the decisions file, the same for every run):
- **Hardened:** approve if the rule passed the checks and adds no false alarm.
- **Written:** approve if the rule passed the checks, raises no false alarm on unseen legitimate commands, and catches at least 80% of unseen variations, or has none to measure and is tightly scoped on reading.

A third rule, for both arms: reject a rule that fires on everyday legitimate commands checked by hand, even when they aren't in the benign set.

Result: **34 of 63 approved** (7 of 9 hardened, 27 of 54 written) and 29 rejected, plus 1 outage
run rejected as unusable.

Review also caught two things the gate couldn't:
- **A written rule that requires both `Image` and `OriginalFileName`:** it would stay silent on logs without the second field, so it was rejected.
- **Three rules that fire on everyday `reg query`, `reg add` and `reg delete` commands:** two hardened, one written, all found by testing four hand-written administrator commands. All three were rejected, so 2 of the 3 hardened runs that gained on unseen variations were not approved.

The second shows the limit of a fixed set of look-alike commands. It is suggested as an
addition to the held-out benign set, re-scored on the saved rules without re-running the agent.

## Cost and time

- **Cost: $0.** Free models only (L16). The binding constraint is the provider's daily request limit, 1,000 calls.
- **Model calls per run:** 8.0 hardened, 11.0 written. **[pending: tokens per approved rule from `detectforge export`]**
- **Time per run, dominated by free-tier response time:** about 5 minutes hardened, 2 minutes written.

## Dev ablation: model-call budget for writing

Run on the dev split only (9 rules, 2 runs each, so 18 runs per budget), after the test split was done. The question:
does a larger budget turn the "ran out of calls" failures into passes, and does it help on unseen
variations?

| Budget | Passed the checks | Failures from the budget | Unseen caught, mean (16 runs) | Runs with new unseen false alarms | Model calls in total |
|---|---|---|---|---|---|
| 15 (frozen) | 10 / 18 | 8 | 77% | 4 | 212 |
| 25 | **17 / 18** | 0 | 71% | 2 | 216 |

- **More calls buy passes, not generalization.** At 15 calls, every failure was the budget running out. At 25, 17 of 18 passed, at about the same total cost, because runs that pass stop early.
- **The unseen score did not rise:** 71% vs 77%, within the run-to-run spread on 16 runs. The extra calls let the agent satisfy the checks on what it can see, which says nothing about what it can't (L11).
- **The test split stays at 15 calls.** Choosing a budget because it scores better on test would tune on test data. This ablation is reported next to the main result, never in its place.

## Not yet measured **[pending]**

- **Memorization probe (L7):** whether the model recalls each technique's SigmaHQ rule.
- **Mutation behavior check in the VM (L5):** whether a sample of mutations still runs.
- **Dev vs test agreement:** dev 77% and test 78% on written rules are consistent, so the dev results predicted the test results.
