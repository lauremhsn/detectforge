# Report draft: Security, Failure analysis, Limitations

Draft text for the final report. Numbers marked **[re-run]** come from the dev runs on the
rebalanced split and will be filled in once those runs are done. Sources: `docs/threat-model.md`,
`docs/failure-matrix.md`, `docs/limitations.md` (each claim there has its test or data).

---

## Security

### Threat model

DetectForge turns untrusted text into a detection rule that a security team will deploy, so the
question is not whether the language model can be manipulated, but what a manipulated model can
achieve. We treat the model itself as untrusted: everything it reads (a pasted threat report,
community rule text, attacker-controlled command lines in the logs) may contain instructions, and
everything it writes is checked by code and decided by a human.

We protect four assets: **the approval decision** (a wrong approval means a SOC trusts a rule that
misses the attack or floods analysts with false alarms), **the held-out evaluation data** (a leak
would inflate our headline result), **secrets** (the model API key, tracing keys, reviewer keys),
and **the host**. We consider six attackers: a poisoned community rule, a malicious report or
request, an attacker who plants text in the logs, a misbehaving model, an unauthorized UI user, and
a secret leaking through output or git.

### Defenses

The central design choice is **least privilege for the agent**. It has five typed tools
(`search_reference_rules`, `inspect_schema`, `validate_rule`, `run_tuning_set`, `submit`) and no file,
shell, network, approve or deploy tool. Its only path to an effect is `submit`, which hands the rule
to a deterministic quality gate, and the result stays *proposed* until a reviewer decides. So even
an injected instruction the model obeys can at most produce a bad proposal, which the gate and a
human then examine with evidence the agent never controlled.

| Threat | Defense |
|---|---|
| Injected text makes the agent approve or deploy | No such tool exists; unknown tools and arguments are refused; only a reviewer can change a rule's status. |
| The agent reads held-out data | Held-out events never enter the tools' context; no tool takes a split; error messages never echo data; traces exclude it. |
| Injected text is read as instructions | Rule text is wrapped as quoted data, event data reaches the model only inside JSON tool results, and the system prompt says never to follow instructions found there. |
| A deliberately weak rule passes | Held-out scores and new held-out false alarms are computed afterwards, without the agent, and shown to the reviewer. |
| The reviewer is misled by formatted text ("Approve now" links, a bold "APPROVED") | All untrusted text is escaped before display, so it reads literally. |
| Unauthorized approval | Approving needs a personal reviewer key; the decision is recorded under the key's owner; keys are compared in constant time; repeated wrong keys lock decisions. |
| Secret leaks | Keys are masked types, provider errors keep only the status code, a test scans every tracked file for keys, and the SigmaHQ release is pinned by checksum. |

Every row has an automated regression test (13 threats, listed with their tests in the threat
model). The tests use a *scripted* model that obeys every injection: they prove what an obedient
model cannot do, rather than how often a real model tries. The "injected report" demo shows the
real model's behavior: the report maps to the right technique and the embedded instruction has no
effect.

### Residual risk

A real model can still follow injected text and, for example, propose a weak rule. That is
contained rather than prevented: the proposal is scored on held-out data it never saw and decided by
a human. Reviewer keys are stored in plain text in the environment file and lockout is per process;
a production deployment would use single sign-on and a secrets manager.

---

## Failure analysis

Our rule was that **every failure found becomes a regression test**, and that nothing fails
silently: a run either passes the gate or ends as *needs human review* with its reasons. We logged
28 failures on real runs and real data (failure matrix, Part 1). Grouped by cause, they tell a
consistent story.

**1. The agent optimizes the tuning score, not the behavior.** Given mutated attacks to fit, the
model's first instinct was to memorize them: it listed the exact zero-width spaces and look-alike
letters our mutations used (D1, D24), shortened an option to a bare two-letter value that matches
inside ordinary words (D7), or copied test-specific strings. Each of these scored well on tuning and
would generalize badly. Prompting helped only partly (the writing prompt's first version still
copied look-alike characters); what closed them reliably were **deterministic lint checks in the
gate** (unusual characters, short bare values, copied strings) that reject the rule and say why.

**2. "Improvements" that quietly narrow a rule.** Several revisions looked better on our data while
becoming worse in deployment: adding `OriginalFileName` as an extra *requirement* makes a rule
silent on logs that lack the field (D2), and one run "corrected" a reference link to a URL that
doesn't exist (D23). The harness cannot measure what isn't in its events, so the gate enforces
**broaden, never narrow**: every original field and exclusion must stay, metadata must be unchanged,
and newly required fields raise a warning.

**3. False alarms the agent could not see.** The most consequential failure class (D5, D8, D11, D12):
hardened rules that passed every tuning check but fired on legitimate commands in the held-out
benign set, such as `reg query …\Run`. In the dev write runs, 4 of 7 written rules did the same. The
root cause was the data, not the agent: the tuning split contained no benign events, so the gate's
"no new false alarms" check measured nothing. The gate now warns when that is the case, the
reviewer sees held-out false alarms in red, and the benign set has been split into tuning and
held-out near-misses. **[re-run]**: false alarms after the split.

**4. Sigma semantics the model gets wrong.** Two subtle mistakes produced rules that look right but
match nothing or too little: regex escapes written twice (`\\b` searches for a literal backslash,
D13) and case-sensitive regexes on case-insensitive Windows command lines (`[/-]tn\b` misses `/TN`,
D25). The first is caught because the rule then detects 0% of unmutated attacks; the second by a
dedicated gate check.

**5. Model unreliability.** Free models stopped without submitting (D10, 3 of 4 runs at one point),
answers were cut off by the output limit, and the provider was sometimes unavailable. These are
handled by budgets, a reminder when an answer is cut off, a fallback model, retries with backoff,
and, as a last resort, *needs human review* with the best attempt so far (D17).

**6. Integrity of the checks themselves.** Some failures were in what we *reported* or in the
checking machinery, not in the agent: a coverage verdict that judged a technique by one weak rule while
another caught everything (D21); the risk that a code change silently moves a published number (D22);
an invalid CI workflow file that silently switched off every CI run for a day (D27); and a new
exclusion check that blocked safe exclusions because it counted attacks the rule had already missed
(D28). CI now recomputes the community-rule baseline on every push, workflow files are parsed by the
test suite, and every check of the gate has a regression test, because a wrong evaluator is as
misleading as a wrong agent.

**What this suggests.** Of the 28 failures, most were closed by deterministic code (gate checks,
data checks, CI), and only a handful by prompt changes, several of which needed a code check behind
them anyway. For agentic detection engineering, the reliability comes less from a better prompt than
from a strict, explainable evaluator the agent must satisfy, with a human deciding on evidence the
agent cannot touch.

---

## Limitations

**Evasion resistance is measured, not guaranteed.** Following Uetz et al., no rule can anticipate
every evasion. We measure resistance to the five command-line transforms of their taxonomy
(insertion, substitution, omission, reordering, recoding) and raise it where possible; other
evasions (renamed binaries, different parent processes) are outside this measure.

**The held-out set is uneven.** Held-out mutation types are omission, insertion and recoding; the
agent tunes on substitution and reordering. Some types don't apply to some binaries (insertion does
not preserve behavior for every program), so a few rules have no held-out mutation at all: their
held-out score is reported as *n/a* and left out of averages, with the count shown next to every
mean. Recoding has very few mutations, so we do not report it as a separate result. Because
community rules already catch all omission variants, the headline compares rules on **insertion**
(unseen and hard), with omission serving as a no-regression check. Several techniques have no
tuning mutation, so their rules are hardened without feedback on variants.

**Benign data is small and synthetic.** Hard negatives are written from LOLBAS and SigmaHQ
`falsepositives:` notes, a few per technique. False-alarm rates rest on few events, and initially
did not trip community rules at all; they detect over-broad agent rules but cannot show that tuning
*reduces* false alarms.

**Synthetic attacks.** Base attacks are Atomic Red Team command lines rather than captured logs, and
mutations are checked for preserved behavior on a sample in a Windows VM, not exhaustively.

**One model, few runs.** All results use one free model (with a fallback) and three runs per
configuration; other models may behave differently, and free-tier latency inflates time per rule.
The model may have seen SigmaHQ rules during training; the memorization probe reports memorized and
clean techniques separately. **[re-run]**

**Gate thresholds are set by hand** (80% tuning resistance, no new false alarms). Recomputing the
dev runs at 60–100% gives the same pass rate, because every proposed rule reached 100% on tuning: the
threshold is not what limits quality, false alarms are.

**Scope.** Windows process-creation rules only, evaluated with our own Python implementation of
Sigma matching (rules must also convert to a SIEM query language, but are not executed in a SIEM).
Reviewer authentication is key-based, not single sign-on.
