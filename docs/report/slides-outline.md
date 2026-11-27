# Slide outline: DetectForge (Dec 5)

About 15 minutes of slides plus an 8-minute live demo, then questions. One idea per slide; the
visual carries it and the words are the speaker notes. Numbers are from the test split, run once after
the prompts were frozen; **[final]** marks a number to refresh from the three-arm runner after the
corpus run. Theme: the app's "forge" palette (warm stone background, charcoal ink, ember accent, steel
blue), so the slides and the live demo look like one product.

---

## 1. Title
**DetectForge: attackers disguise, your rules should still fire.**
- Visual: the landing page's replay console (screenshot), product name, course, date.
- Say: "Detection teams trust that having a rule means being covered. We measured whether that holds,
  and built an agent that closes the gaps, with a person approving every change."

## 2. The problem
**A rule existing is not the same as being covered.**
- Visual: one command, three versions: `schtasks /create …` caught; `schtasks /"create" …` and
  `schtasks -create …` missed. Windows runs all three the same.
- Number: 129 of 292 widely used Sigma rules beaten by five simple tricks (Uetz et al., USENIX Security 2024).
- Number: in our library, community rules as published catch **82%** of disguised attacks they were
  never tested on; 10 of 24 measured rules can be slipped past.

## 3. Who it's for and their workflow
**SOC lead, detection engineer, approver, manager.**
- Visual: four role cards with the question each one asks (Posture, Threats, Rules/Review, Reports).
- Say: today a detection engineer tests a rule by hand: write dozens of variations, replay, edit,
  re-check for false alarms. DetectForge does that loop; the human keeps the decision.

## 4. What DetectForge does
**Find → Attack → Forge → Check → Approve → Export.**
- Visual: the forge-loop graphic from the landing page; the human step highlighted.
- Say: hardening an existing community rule comes first; writing a new rule is the fallback when none
  exists. It improves the rules a SIEM runs; it is not a SIEM.

## 5. Why an agent, not a script or a chatbot
**The fix depends on what slipped past, and only measuring shows that.**
- Visual: one hardening trajectory: measure → read the misses → edit → re-test → refused by a check →
  fix → pass (a real run's steps, from the Review page).
- Say: a script can't know which edit closes a gap without opening another; a chatbot answers once.
  The agent chooses its next step from tool results. Fixed checks and a person, not the model, decide
  what ships. Five narrow tools; it can't deploy or read held-out data.

## 6. Architecture
**A thin agent inside deterministic walls.**
- Visual: the architecture diagram (docs/architecture.md): intake → SigmaHQ index → harness (our Sigma
  matcher) → agent with 5 tools → 16-check quality gate → review queue → export; tracing and
  provenance underneath.
- Say: everything that judges is deterministic and tested (393 tests); the model only proposes.

## 7. How we evaluate (the professor's question)
**Judged on what the agent never saw.**
- Visual: a 2×2: variation types (agent tunes on substitution + reordering; judged on insertion,
  omission, recoding) × techniques (dev for iterating; test run once after freezing).
- Say: three arms: community rules as published, the same rules hardened by the agent, rules the
  agent wrote with the community rules hidden. 3 runs per setup, mean and spread.

## 8. Results: hardening
**Better where it was needed, without new false alarms.**
- Visual: before/after bars.
- Numbers: agent effect on the rules it worked on **50% → 72%** of unseen variations (3 rules, 9 runs,
  0 new false alarms); system view over all 15 test rules **82% → 86%** (12 rules needed nothing).
  **[final]**
- Honest line: one rule gained in 2 of 3 runs and not the third; one gained only on what it saw.

## 9. Results: writing from scratch
**0% → 78% with the community rules hidden.**
- Visual: bars for written with variations (72%) and zero-shot (95%), with the caveat.
- Numbers: 45 of 54 passed the checks, 27 approved by a reviewer. **[final]**
- Say: zero-shot looks better only because its unseen variations are mostly the easy type; the main
  weakness of writing is generalising to disguises it never saw (16 of the failures).

## 10. Evaluating the agent itself
**Not just its rules: what it did on the way.**
- Visual: a small table.
- Numbers: 0 of 63 runs ever saw held-out data; 0 rules approved without a person; 82% of refused
  submissions fixed and passed; pass@3 94% vs all-3 72% (honest spread); 0 rationales claiming more
  than their own test showed.

## 11. Does it hold in the real world?
**Same answer in a real SIEM, and a look beyond the dataset.**
- Visual: two panels.
- SIEM parity: in a real Elasticsearch, all **27/27** community rules exported as EQL fire on exactly
  the same events as our tests; Lucene export loses matches (case-sensitive), so we export EQL.
- Beyond the data: 29 everyday admin commands not in the dataset: community rules fire on none; 3
  agent rules on test did, and the reviewer rejected all three.

## 12. Why a human approves every change
**The rejection that proves the point.**
- Visual: the reg.exe case: the fix catches the disguised `reg save` but also fires on
  `reg query HKLM\SECURITY\Policy`; every automatic check passed; the reviewer rejected it.
- Say: harder to evade tends to mean broader; a fixed test set can't see everything. The agent
  proposes, a person decides, and the reason is kept in the audit trail.

## 13. Reliability, AgentOps and security
**It fails loudly and safely.**
- Visual: three columns.
- Reliability: retries, fallback model, budgets; a run that can't finish ends as "needs human review",
  never silently; provenance on every run.
- AgentOps: every model and tool call traced (latency, tokens, retries, errors); the Lab; cost ≈ $0
  on free models, about $0.04 to $0.55 per approved rule on paid ones.
- Security: threat reports and rules are data, not instructions (injection tested); least-privilege
  tools; reviewer keys; 29 failures found on real runs, each with a regression test.

## 14. Live demo (8 minutes)
Follow demo/README.md: landing → Posture → Threats with the **injected report** (failure case) →
Rules test bench (the highlighted disguise) → Review (route badge, story, the everyday-command check)
→ **vague request** (failure case) → **API failure** on the command line (failure case) → Lab.
Backup: the deployed snapshot site, and screenshots on the next slide in case the network fails.

## 15. Limitations, honestly
- Windows process creation only; generated variations from Atomic Red Team, not a breach.
- Agent rules with regexes don't port cleanly to Elastic (21 of 26 refused); our "deployable" check is
  too weak.
- Few runs on a free model; memorization probe and VM check **[final]**.
- Only rules a team can see improving get hardened; tuning-only testing hides gaps (Certutil 50% unseen).

## 16. Closing
**"DetectForge doesn't claim rules are evasion-proof. It measures how well each rule holds up, raises
it where it can, proves it on variations the agent never saw, and leaves every decision to a person."**
- Visual: the live link and a QR code to the deployed app.
- Next steps: SIEM integration, a dialect-aware deployable check, scheduled re-validation (built,
  nightly), Linux.

---

## Backup slides (for questions)
- **B1. Splits and why:** which types and techniques are held out, and why insertion is the headline.
- **B2. The 16 quality checks** and the real failure behind each.
- **B3. Budget ablation:** 25 calls raise the pass rate (10/18 → 17/18) but not the unseen score.
- **B4. Label agreement:** model rater vs dataset author 91%, kappa 0.66, and the rubric ambiguity.
- **B5. Cost table:** tokens per approved rule and the paid-model estimate.
- **B6. Prior work:** Uetz et al. (AMIDES), SIGMERGE, CTI-REALM, IntelEX: to our knowledge none repairs
  existing rules with a held-out evaluation and human approval.
