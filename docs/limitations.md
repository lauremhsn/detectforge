# Known limitations and assumptions

Each item: what it is, what it does to the results, and what to do about it: **fix** (before the
test runs), **ablation** (measure its effect), or **report** (state it in the limitations section).
The recommendation is a proposal; the decision column records what was agreed.

Numbers are from the committed evaluation data (`data/eval/`) and the saved dev runs.

## Data

| # | Limitation | Effect on results | Recommendation | Decision |
|---|---|---|---|---|
| L1 | **No benign events in the tuning split.** All 34 class-A hard negatives are `heldout`, so the agent and the gate never see a legitimate command while tuning. | 5 dev rules (2 hardened, 3 written) fire on legitimate activity that was only caught on held-out data. The gate's "0 false alarms" is untested during tuning (it warns about this). | **Fix**: split the hard negatives into tune / held-out (about half each, per technique), before the hardening freeze. | pending |
| L2 | **The hard negatives don't trip community rules.** 0 of 27 community rules raise a false alarm on them, so the week-1 "hard enough" check is not met. | False-alarm results only show whether hardening *adds* false alarms, not whether it reduces them. Tuning (exclusions) can't be shown to help. | **Fix**: add near-miss negatives from each rule's SigmaHQ `falsepositives:` field until most techniques have one that fires the community rule. Also: 29 extra everyday look-alikes outside the dataset (`data/eval/extra_lookalikes.yml`) re-score every saved rule; community rules fire on none, agent rules on 3 (test) and 8 (dev), approved ones on none. | pending |
| L3 | **Few benign events:** 34 class A (1-3 per technique), 6 ambiguous (class B, excluded). | A false-alarm rate per rule rests on 1-3 events, so it's noisy. | **Fix** with L1/L2 (aim for 4+ per technique), then **report** the counts. | pending |
| L4 | **Unbalanced mutation types.** Recoding has 1 mutation in total, reordering 10; held-out is insertion (54) + recoding (1). | The held-out result is in effect "insertion only"; recoding's 0% is one event. Per-type claims for recoding and reordering can't be made. | **Fix** if the mutation engine can produce more recoding variants (IP / base64 / env-variable forms); otherwise **report** and don't show recoding as its own bar. Rules with no held-out mutations are n/a and left out of the held-out mean (15 of 27 community rules have any); report that count next to the mean. | pending |
| L4b | **Some rules have no tuning variation** (the new split leaves 3 dev and 4 test rules with none). | They can't be hardened (nothing to improve against); a rule is still written for them from the base attacks alone, zero-shot. Mixed in, they would pull the written arm's average down for a reason other than learning from feedback. | **Report** the written arm as two subsets, with variations and zero-shot (the `zero_shot` column and `subsets` in `detectforge export`), each with its count. The gate's resistance check has nothing to measure for them; say so. | agreed |
| L5 | **Mutations not yet checked in the VM** for preserved behavior (only a sample is planned). | A mutation that breaks the command would count as an "evasion" that isn't one. | **Fix**: run the planned sample and report the share that still works. | pending |
| L6 | **Base attacks are Atomic Red Team command lines**, not captured Sysmon logs. | Real logs may differ in fields (e.g. `OriginalFileName`, quoting, full paths). | **Report**; VM capture for a sample if time allows. | pending |

## Method

| # | Limitation | Effect on results | Recommendation | Decision |
|---|---|---|---|---|
| L7 | **Memorization not measured yet.** The model may know the SigmaHQ rules. | Hardening scores could partly reflect recall, not reasoning. | **Fix**: run the memorization probe; report memorized vs clean techniques separately. | pending |
| L8 | **One free model** (Nemotron Ultra, with Gemma as the fallback); free-tier latency and availability vary. | Results may not carry to other models; time per rule includes queueing. | **Report**; the optional local-model run would be an **ablation** only if time allows. | pending |
| L9 | **Only 5 Uetz transforms.** No rule is evasion-proof; other evasions (renamed binaries, other parents) aren't measured. | "Evasion resistance" means resistance to these 5 types. | **Report** (already the project's framing). Binary renaming stays an optional, separately labelled extension. | pending |
| L10 | **Gate thresholds are set by hand** (80% tuning resistance, 0 false alarms). | A different threshold changes the pass rate. | **Report**, with the ablation (`detectforge eval gate-thresholds`): on the dev runs every proposed rule reached 100% on tuning, so the pass rate is the same at 60-100%; false alarms, not the threshold, are what limit quality. | pending |
| L11 | **Written rules generalize worse:** they miss held-out quote insertions that hardened rules catch. | A real finding, not a bug: writing from scratch has no community rule's structure to build on. | **Report** as a result. Deliberately *not* fixed in the prompt: naming the held-out type would leak it. | pending |
| L12 | **Our matcher is a Python reimplementation** of Sigma matching; SIEM parity is checked by conversion (the rule must convert to Lucene), not by running in a SIEM. | A rule could behave differently in Elastic in edge cases (regex flavour, case handling). | **Measured** in a real Elasticsearch 8.15 (`scripts/elastic_parity.py`, ECS mapping, 300 events). **EQL export: all 27 community rules fire on exactly the same events as our matcher.** Lucene export: only 16 of 27, because pySigma's Lucene query matches command lines case-sensitively (the rule says `hklm`, the attack `HKLM`); 251 event matches lost. Agent rules: 26 of 40 approved rules use regexes; Elastic's EQL refuses 21 of them (`\/` escapes, `(?i)`, `\b`), so our `deployable` check (it converts) is too weak. **Fix:** export EQL by default (done in the UI), and make `deployable` check the regex dialect Elastic accepts (core change: after the corpus run). | measured |
| L13 | **Process creation only** (Sysmon 1: CommandLine, Image, ParentImage, OriginalFileName). | Coverage claims are limited to that log source; Windows 4688 logs lack some fields (the gate warns when a rule newly requires one). | **Report**. | pending |
| L14 | **Few runs so far:** 1 run per dev rule and prompt version; the plan is 3 per configuration on the test rules. | No spread yet; dev numbers are indicative only. | **Fix** by the planned test runs (`--repeat 3`); `detectforge export` reports mean and spread. | pending |

## Product

| # | Limitation | Effect | Recommendation | Decision |
|---|---|---|---|---|
| L15 | **Reviewer keys live in `.env`** on one machine: no single sign-on, no roles. | Fine for a demo and a small team, not for an organisation. | **Report** (future work: SSO). | pending |
| L16 | **Cost is $0 on free models**, so "cost per accepted rule" is reported in model calls and tokens. | No dollar figure to compare against paid models. | **Reported**: tokens per approved rule, and an estimate at two illustrative price tiers (results.md, Cost): under $0.06 per approved rule on a small model, under $0.60 on a large one. | done |
| L17 | **Keyword search** for SigmaHQ rules (word overlap, not semantic). | A request worded differently from rule titles may miss a rule; technique search is unaffected. | **Report**. | pending |
| L18 | **Rules are picked for hardening by their tuning score.** A rule that catches every tuning variation (or has none) is skipped, even when it misses unseen ones (test: Certutil 50%, PowerShell Download Pattern 67%, Bitsadmin 62% unseen). | Only 3 of 18 test rules were hardened; real gaps go unworked, because the agent may not see held-out data to find them. | **Report** as a result (tuning-only testing hides gaps). Future work: more tuning variation types per rule, so selection sees more. | pending |
