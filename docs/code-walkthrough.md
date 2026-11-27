# DetectForge — Code Walkthrough

*Status as of Nov 9, 2026 (updated with the missing-field fixes and cloud deploy). Written so that the whole team can follow every design decision, see what
exists versus what is planned, and decide what comes next.*

---

## 1. The one-paragraph version

Today the code can do the deterministic half of DetectForge without any AI: **find** a community
Sigma rule in SigmaHQ, **validate** it adversarially by replaying it against attack events and their
mutated variants plus benign look-alikes, and **compare** two versions of the same rule (before vs
after hardening) to show exactly which evasions were closed and what changed. Hardening is still done
by hand in the UI; the agent that will do it automatically is the next thing to build. Everything is
reachable three ways: Python functions, a command line (`detectforge ...`), and a small UI.

```
                         ┌──────────────── exists today ────────────────┐   ┌──── next ────┐
 request ──► FIND ──────► VALIDATE ──────────► HARDEN ──────► RE-VALIDATE ──► APPROVE ► TUNE
 (technique)  SigmaHQ      harness run()        (manual in UI;  compare()       review UI   FP tuning
              search       → Scorecard          agent = W4)     → before/after  (W5)        module
                                                                                      ▲
                     no usable rule ──► WRITE NEW RULE (fallback, §7c) ───────────────┘
```

---

## 2. Where everything lives

```
src/detectforge/
  schemas.py          The shared data shapes (the interface contract): Event, Scorecard, RuleRecord
  events.py           Read/write event files (one JSON object per line)
  config.py           All settings in one place (.env / environment variables)
  rules/
    parse.py          Turn rule text into a rule object; reject anything out of scope
    validate.py       "Is this rule OK?" → errors and warnings
    lint.py           Broaden-never-narrow and overfitting checks (unusual characters, copied strings)
    stamp.py          Id, status, author and date of an agent-written rule, set by code
    convert.py        Translate a rule into an Elastic query (for a real SIEM later)
  harness/
    matcher.py        The engine: does this rule fire on this event?
    run.py            Run a rule over many events → Scorecard
    compare.py        Run two versions of a rule → before/after HardeningReport
  reference/
    sigmahq.py        Download the pinned SigmaHQ release and build our index of rules
    index.py          Search that index by technique / keywords
  ui/app.py           The Streamlit UI (Find → Validate → Harden → Review tabs)
  review.py           Human review: list runs, open one, record approve/reject
  intake.py           Plain-language request → ATT&CK techniques (model, checked; keyword fallback)
  provenance.py       Which prompt, model, budgets, code and data produced a run (setup key)
  eval/export.py      Every saved run as CSV + per-setup summary (mean, spread, cost per approved rule)
  eval/thresholds.py  Gate threshold ablation, recomputed from saved runs
  agent/tools.py      The 5 typed tools the agent may call, with least-privilege context
  gate.py             Quality gate: accept, or "needs human review" with reasons
  llm.py              Provider-agnostic LLM client (OpenRouter / local), retries, fallback model
  agent/loop.py       The agent loop: harden a rule, or write a new one (fallback)
  agent/runner.py     Chooses the path (harden or write), splits the data, saves each run
  agent/batch.py      Run every rule of a selection (e.g. the dev rules): harden it, or write one instead
  tracing.py          Langfuse tracing of every model and tool call (no-op when not configured)
  cli.py              The `detectforge` command line
data/fixtures/        17 hand-written test events + 3 test rules
docs/interfaces.md    The interface contract and open questions
docs/failure-matrix.md  Every failure found or handled, what the system does, and its regression test
docs/threat-model.md  What we protect, from whom, and the test behind each defence
docs/limitations.md   Known limitations and assumptions, and what to do about each
docs/architecture.md  Components, one agent run, the evaluation boundary, deployment, design decisions
Dockerfile, docker-compose.yml  The UI and the CLI in one image (`docker compose up`)
tests/                352 automated tests (run on every push by GitHub Actions)
```

Rule of thumb for the architecture: **every number is computed once, in the library**. The CLI, the
UI and the tests all call the same functions, so they can never disagree.

---

## 3. The data: what goes in

### 3.1 Events (`schemas.py → Event`)

One event = one process starting on a Windows machine, the way Sysmon records it (Event ID 1).
Stored one per line in a `.jsonl` file:

```json
{"event_id": "st-002", "image": "C:\\Windows\\System32\\schtasks.exe",
 "command_line": "schtasks.exe /\"create\" /tn \"Updater\" ...",
 "parent_image": "C:\\Windows\\System32\\cmd.exe",
 "label": "attack", "technique": "T1053.005", "transform": "insertion",
 "base_id": "st-001", "split": "tune"}
```

| Field | Meaning |
|---|---|
| `image`, `command_line`, `parent_image` | What actually ran (required). |
| `original_file_name`, `parent_command_line` | Optional Sysmon fields. `original_file_name` is the name compiled into the binary, so it survives renaming (`schtasks.exe` copied to `notepad.exe` still says `schtasks.exe`). |
| `label` | `attack` or `benign` (benign = "hard negative": legit activity that looks suspicious). |
| `technique` | ATT&CK id, e.g. `T1053.005` = scheduled task. |
| `transform` | Which Uetz mutation produced it: `none` (original) or one of the 5 types. |
| `base_id` | Which original event it was mutated from. Originals point to themselves. |
| `split` | `tune` (the agent may see it) or `heldout` (only for final evaluation). |
| `verified` | Optional: `true`/`false` once the VM confirmed the command still behaves like the original; empty = not checked. |

The model **rejects** bad events on load (unknown fields, wrong labels, a mutation that claims to be
its own base, etc.) and tells you the exact line number. This catches mistakes in the attack data early.

**Design choice — `base_id` points to itself for originals** (rather than being empty). Grouping by
`base_id` then gives "the original + all its variants" with no special case. *Open question, pending team sign-off.*

**Design choice — 5 Sysmon fields, 2 of them optional.** We started with 3 (the original design), then
measured that 717 of the 1,297 SigmaHQ rules used a field we didn't have (`OriginalFileName` in 559,
`ParentCommandLine` in 75). Adding those two drops it to 175. They're optional so older event files stay
valid; `null` means "not captured". *Pending: confirm the attack-data pipeline can capture them.*

### 3.2 The fixture dataset (`data/fixtures/`)

Hand-written, synthetic, **not** VM-verified. Only for building and testing until the real
mutations exist. 17 events:

| Technique | Attacks | Benign (hard negatives) |
|---|---|---|
| T1053.005 schtasks | 1 original + insertion, substitution, omission, reordering | `/query`, a vendor updater creating a task, `/change /disable` |
| T1105 certutil download | 1 original + all 5 mutation types | `-hashfile`, `-urlcache * delete`, `-verify -urlfetch` |

Split by mutation type, as in our evaluation design: insertion/substitution/omission → `tune`;
reordering/recoding → `heldout`.

Plus 3 fixture rules: two "literal" rules written like typical community rules (they match exact
strings such as `' /create '`, so they miss mutations on purpose) and one "robust" schtasks rule.
The literal → robust pair is our built-in before/after example.

---

## 4. Rules: parse, validate, convert (`rules/`)

### 4.1 `parse.py → load_rule(rule_yaml)`

Turns rule text into a pySigma rule object, or raises `RuleError` with a readable reason. It treats
the text as **untrusted** (rules will come from the internet and from the LLM):

- refuses rules over 64 KB,
- only accepts a single YAML document that is a mapping,
- uses pySigma (the official Sigma library) to parse it,
- **enforces scope**: `logsource` must be `category: process_creation, product: windows`.
  A registry rule, say, is rejected rather than silently scoring 0.

### 4.2 `validate.py → validate_rule(rule_yaml) → ValidationResult(valid, errors, warnings)`

The answer to "can we use this rule?". It checks, in order:
1. it parses and is in scope (above);
2. our harness can actually evaluate it (some rare Sigma features aren't supported — see 5.1);
3. pySigma's own quality checks (≈25 of them, e.g. "a detection is defined but never used");
4. fields the rule uses that our events don't have (e.g. `User`, `IntegrityLevel`), split into two cases:
   - **harmless → warning**: the field is only an alternative (OR), so the rule still matches through
     other fields; it just loses whatever that branch would catch;
   - **blocking → error**: the rule *requires* the field (AND, or alone), so it **can never fire** on our
     events. Its score would measure a missing column, not evasion resistance.

**How "can never fire" is decided** (`matcher.can_fire`): each check on a missing field has a known
outcome (the field is absent, so "equals X" is false and "is null" is true); every other check is
treated as "could go either way"; the AND/OR/NOT tree is then evaluated. If it can't be true, the rule
can't fire. This is never wrong when it says "can never fire"; it can only be over-optimistic for
odd rules whose other checks contradict each other.

**Design choice — two pySigma checks are switched off** (ATT&CK and D3FEND tag checks) because they
download MITRE data from the internet at runtime. A validator that depends on the network is not
deterministic and hangs in CI. Errors = "high severity" issues; everything else is a warning.

### 4.3 `convert.py → convert_rule(rule_yaml, "lucene" | "eql")`

Translates a rule into an Elastic query using the official pySigma Elastic backend. Not used in the
pipeline yet — it's there for the stretch goal (shadow-deploy to a real SIEM) and to prove rules are
deployable.

---

## 5. The harness (`harness/`) — the heart of the "adversarial validation"

### 5.1 `matcher.py` — does a rule fire on an event?

pySigma parses a rule's `detection:` block and its `condition:` into a tree of AND / OR / NOT and
"field equals value" checks. The matcher walks that tree once, turns it into a Python function, and
then calls that function on each event.

Sigma semantics we implement (from the Sigma spec):
- plain values match the **whole** field, **case-insensitively**, with `*` and `?` wildcards;
- modifiers like `contains`, `startswith`, `endswith`, `windash`, `base64` are expanded by pySigma
  into wildcards/lists before we see them, so we inherit the official behavior;
- `re` (regex, run with a 1 s time limit per event), `cased`, `exists`, `null`, number comparisons, `1 of` / `all of` / `them`, `not`;
- **fields we don't have** (e.g. `User`), or optional fields left empty, are treated as *absent*:
  they never match a value.

Not supported (the rule comes back as invalid with a clear message): `fieldref`, `cidr`, `expand`,
correlation rules. None of the 1,297 SigmaHQ process-creation rules needs them.

**Design choice — our own pure-Python matcher** instead of replaying logs through a real SIEM or
Chainsaw/Zircolite. It's fast (milliseconds), deterministic, has no infrastructure, and runs in CI.
The cost is that we must match Sigma's semantics ourselves; `tests/test_matcher.py` pins about 35 of these
behaviors down so they can't drift.

### 5.2 `run.py → run(rule_yaml, events) → Scorecard`

The frozen interface the evaluation uses directly. For one rule and a list of events:

| Scorecard field | Meaning |
|---|---|
| `valid`, `error` | Could the rule be evaluated? If not, why (and all counts are 0). |
| `hits` / `misses` | Attack events the rule caught / missed. |
| `false_alarms` | Benign events the rule fired on. |
| `matched_event_ids` | Every event it fired on. |
| `per_transform` | The same counts broken down by mutation type (always all 6 keys). |

Two safety properties:
- a bad rule **never crashes** the harness — you get `valid: false` and a reason;
- error messages describe the **rule only, never event contents**. This matters because the agent must
  never see held-out data, "including in error messages" (agent design rule).

### 5.3 `compare.py → compare(before_yaml, after_yaml, events) → HardeningReport` *(new)*

The headline result of the project in one function. Runs both versions on the same events and reports:
- **evasion resistance** before / after / delta = fraction of *mutated* attacks still detected
  (the unmutated originals are reported separately in the `none` row);
- the same per mutation type;
- false alarms before / after;
- **which events changed**: attacks newly caught, attacks **lost** (a regression — must never be
  hidden), false alarms gained, false alarms removed.

On the fixtures, literal → robust schtasks rule: evasion resistance **25% → 100%**, 3 attacks newly
caught, 0 lost, false alarms unchanged (1).

**Design choice — evasion resistance counts mutations only.** Catching the original attack is the
bare minimum; the question the project answers is "does it still catch the variants?". *The
metrics module should use the same definition, or we should agree on a different one.*

---

## 6. Finding existing rules (`reference/`)

### 6.1 `sigmahq.py` — getting the community rules

- Downloads **one pinned SigmaHQ release** (`r2026-07-01`, `sigma_all_rules.zip`).
- Checks its **SHA-256 checksum** against the value GitHub published; refuses anything else.
- Reads the zip **in memory**, never unpacks it to disk.
- Keeps only Windows process-creation rules, drops deprecated ones, and for each rule records: id,
  title, techniques (from its `attack.tXXXX` tags), false-positive notes, which fields it uses,
  which of those our events lack, whether our harness can run it, and whether it **can fire** at all.
  A rule is **usable** (a candidate for hardening) if both are true.
- Writes the result to `data/sigmahq/index.jsonl` (not committed to git). The UI builds it
  automatically on first launch if it's missing.

Result: **1,297 rules indexed, all evaluable, 1,239 usable.** 175 rules still use a field we don't
have: 117 harmlessly, 58 can never fire (mostly `IntegrityLevel`, `User`). Unusable rules sort last.

**Design choices.** Pinning a release makes experiments reproducible and lets the memorization probe
compare against a fixed set. The checksum and in-memory reading are supply-chain hygiene: the zip is
external input. Rule text is explicitly marked untrusted (it will be shown to the LLM as data).

### 6.2 `index.py → ReferenceIndex.search(technique, query, limit, exclude_technique)`

- **By technique**: rules tagged with the exact technique first, then the parent/child technique
  (e.g. `T1053` for `T1053.005`) as "related".
- **By keywords**: scores word overlap with title (counts double), description and detection logic.
  With a technique, keywords only re-order the results.
- **Tie-breaks**: usable rules first, then general rules before campaign-specific ones (SigmaHQ's "emerging threats" folder),
  rules with fewer techniques first (focused beats "APT kitchen sink"), then status and severity.
- **`exclude_technique`** (for the secondary "written" arm only): hides the whole technique family
  *and* every rule with no ATT&CK tag. The second part fixes a real leak we found: some untagged
  rules are about scheduled tasks and would let the agent copy a same-technique rule.

---

## 6b. Intake: from a request in plain words to techniques (`intake.py`) *(new)*

The first pipeline step. The user types what they want to detect ("scheduled-task persistence", or a
pasted short threat report); intake returns the ATT&CK technique(s) it's about, with how many SigmaHQ
rules each has, so the user goes straight to Find. Design:
- **The model interprets, code verifies.** The model can only answer through one typed tool
  (`propose_coverage`), and every technique it proposes must exist in the SigmaHQ index; invented or
  mistyped ids are dropped and listed as "ignored".
- **Vague requests get a question**, not a guess ("make us secure" → "which behaviour?").
- **The request is untrusted** (a pasted report may contain "ignore your instructions"): it's quoted as
  data, the model can only reply through the tool, and code validates the reply. The worst an injection
  can do is produce a wrong *suggestion* that a human sees, never an action.
- **Graceful degradation**: if the model is down, out of quota, or replies without the tool, intake
  falls back to a keyword search of the index (filler words like "detect", "attackers" ignored; weak
  matches → a question instead of a guess).

`uv run detectforge intake "deleting shadow copies before ransomware"` (add `--no-model` for the
keyword search only). In the UI: the box at the top of the Find tab.

---

## 7. The UI (`ui/app.py`) *(new)*

Start it from the repo root:

```bash
uv run --group ui python -m streamlit run src/detectforge/ui/app.py --server.address localhost
```

Opens at http://localhost:8501 (bound to your machine only, telemetry off). It can also be deployed
for free on Streamlit Community Cloud (see the README): there it builds the SigmaHQ index itself on
first launch, and `src/detectforge/ui/requirements.txt` lists its dependencies.

The UI is organised around what people come to do, not around pipeline steps (`ui/navigation.py`).
Each section opens with its name and one line on what it's for; buttons jump between sections
(e.g. a verdict's "Harden it →" opens that rule on the Harden step).

| Section | File | What it shows |
|---|---|---|
| Product page | `home_page.py` | The landing page in front of the app (no app tabs): the problem, a real before/after case (community rule, the agent's fix, the reviewer's rejection), how it works, why it's agentic, who it's for, scope. Its numbers come from `results.py`, which computes the frozen test-split results from the saved runs exactly as the report does. Written as fixed HTML; the network background is an SVG data URI because Streamlit strips inline SVG. |
| Navigation | `navigation.py`, `app.py` | The top bar (Posture, Threats, Rules, Review with the number waiting, Reports, Lab, Settings). The page is also in the URL (`?page=...`), so links can be shared and the product page can link into the app. |
| Test bench | `bench.py` | Which events rules are replayed on. Product pages never ask: a rule is tested on every attack and look-alike of its own technique (opening a rule sets it). The Lab's Test bench tab narrows it (one technique, tuning or held-out only, another file). Kept in plain session keys so it survives moving between areas. |
| Technique names | `techniques.py` | Plain names, attacker goals and icons for ATT&CK ids ("📌 Persistence with scheduled tasks (T1053.005)"), used everywhere a technique is shown. |
| Posture | `coverage_page.py` | Headline numbers, each with what it means; a coverage map grouped by attacker goal, coloured by what the rules catch today (an approved fix counted at what it really catches); **What to work on next**, ranked by risk (share that slips past × severity); technique cards; the before/after chart of the versions in use (approved first, never simply the newest run); every rule. |
| Threats | `request_page.py`, `intake_panel.py` | Examples and threat-report templates run in one click (including an injected report); one card per technique with a verdict computed by the harness, never by the model. |
| Rules | `rules_page.py`, `testbench.py` | ① Pick by technique name, SigmaHQ search, an imported Sigma file or a sample; ② Test: what slipped past first, then every event grouped under its base attack, with the text the rule looks for highlighted (`testbench.py` builds case-insensitive patterns from the rule's CommandLine values; the verdict always comes from the harness); ③ Harden: existing proposals for this rule, the agent with its cost, or a hand edit, and a before/after grid on the same events. |
| Review | `review_tab.py`, `review_visuals.py`, `lookalikes.py` | One card per rule (attempts grouped, shown as pills); a route badge (hardened / written from scratch); the verdict, which now also checks the proposal against everyday commands **outside the dataset** (`data/eval/extra_lookalikes.yml`); found → changed → result from recorded numbers; the agent's explanation as escaped points (bold stays literal so model text can't pose as a banner); unseen variations as bars; checks as chips; the full evidence folded away; Approve / Reject. |
| Reports | `reports_page.py` | A manager or engineer report from chosen sections, previewed and downloaded as Markdown. |
| Lab | `operations_page.py` | The three arms with what each number means, agent metrics (`agent_metrics_test.json`), the budget ablation, agent activity, prompt versions, failures grouped by check, every run, and the test bench. |
| Settings | `settings_page.py` | Reviewers by name (never keys), how approval works and would work in a company, where workspace data lives, the gate thresholds and model settings (read-only). |

It is a **thin layer over the library** (no logic of its own) and shows held-out events to the human
only; the agent itself still receives just the tuning split.

**Review (`review.py`).** A decision is appended to `data/runs/<trace_id>.review.json`, so the full
history is kept (a later rejection doesn't erase an earlier approval, it's added after it). An approved
rule is copied to `data/runs/approved/`, ready to deploy; a later rejection removes that copy. Only
well-formed trace ids become file names, so a crafted id can't read or write elsewhere. Approving a
rule the gate didn't accept is allowed (a human overrides the gate) but the UI asks for a reason.

**Who may approve (`review.decide`).** A typed name proves nothing, so approving needs a personal
**reviewer key**, set in `.env` as `DETECTFORGE_REVIEWER_KEYS=name:key,name:key` (16+ characters
each). The decision is recorded under the name the key belongs to. With no keys set, the buttons are
switched off (this is how the public deployment stays read-only). Keys are compared in constant
time, 5 wrong keys within a minute lock decisions for a minute, and the key is cleared from the page
after each use. Model and SigmaHQ text in the UI is escaped (`ui/components.md`), so an injected
"Approve now" link or a bold "APPROVED" banner shows as plain text. All of this is in
[threat-model.md](threat-model.md). The same check runs from the command line:
`detectforge review approve|reject <trace-id prefix> -m "why"` asks for the key (or reads
`DETECTFORGE_REVIEWER_KEY`); the key is never a command-line argument, which would land in shell history.

**"Ask the agent" is off by default.** The deployed app is public; if the button worked there,
anyone could spend the free model quota. It only works when `DETECTFORGE_UI_ALLOW_AGENT_RUNS=true`
*and* an LLM key are in `.env` (so: locally). Otherwise it shows why it's unavailable.

**Machine note:** Windows Smart App Control on your laptop blocks some compiled files (pandas'
`sparse` DLL and the `streamlit.exe` launcher). That's why tables are drawn as markdown instead of
Streamlit's pandas-based tables, and why we start it with `python -m streamlit`. We did not change
your security settings.

**Example you can reproduce in 1 minute:** Find → T1053.005 → first result *"Schtasks Creation Or
Modification With SYSTEM Privileges"* (real SigmaHQ rule) → Validate: **0/5 attacks detected**. Why:
it looks for `' SYSTEM '` with a space on both sides, and our attack ends with `/ru SYSTEM`. That is
an evasion by argument order on the *unmutated* attack. Harden: change `' /create '` → `'create'`,
`'/ru '` → `'ru '`, `' SYSTEM '` → `'SYSTEM'` → **5/5 detected, 0 false alarms**. That is exactly
the story DetectForge tells — but note this is on fixtures, not evidence yet.

---

## 7b. The agent's tools and the quality gate (`agent/tools.py`, `gate.py`) *(new)*

The LLM loop doesn't exist yet, but everything it will be allowed to *do* does. The model never
touches data or code directly: it can only call these five tools, each with a typed (Pydantic) input
and output that becomes the JSON schema the model sees (`tool_schemas()`).

| Tool | What the agent gets |
|---|---|
| `search_reference_rules(technique?, query?, limit≤10)` | Community rules' detection logic, usable flag, missing fields, documented false positives. |
| `inspect_schema()` | The 5 usable fields with descriptions, the required logsource, 3 example attack and 3 benign tuning events. |
| `validate_rule(rule_yaml)` | Errors/warnings (same as §4.2). Free to call. |
| `run_tuning_set(rule_yaml)` | On the **tuning split only**: detections, evasion resistance per transform, the missed attacks and false alarms (with command lines), and the comparison with the original rule. **Budgeted** (default 5 runs). |
| `submit(rule_yaml, rationale)` | Hands the rule to the quality gate; returns which checks passed. Max 3 submissions. |

**Least privilege is structural, not a promise in the prompt.** The runner builds a `ToolContext`
with only tuning events; giving it a held-out event raises an error. So no tool, output or error
message *can* reveal held-out data. Empty per-transform rows are hidden too, otherwise they would
name the held-out mutation types. The written-arm exclusion is set by the runner; the agent has no
argument for it. There is no tool to deploy, choose a split or pass events.

**Every call goes through `dispatch()`**, which never crashes: an unknown tool, malformed JSON, a
wrong or extra argument, an exhausted budget, or an unexpected bug all come back as an error result
the model can read. An unexpected bug says only "internal error in <tool>", with no details. Each
call is recorded (tool, ok, latency, error), which is what tracing will build on.

**Quality gate (`gate.check`)**, runs every check so the reviewer sees all reasons at once:
- valid (§4.2), and detects every *unmutated* attack;
- **deployable**: converts to an Elastic Lucene query with the official pySigma backend (configurable
  targets). All 1,297 SigmaHQ rules pass; it catches agent rules a real SIEM can't run, e.g. the
  `|cased` modifier, which our harness accepts but Lucene can't express;
- evasion resistance ≥ 80% on the mutations (configurable);
- hardening: **no attack the original caught is lost, and no new false alarms** (existing ones are
  left for the tuning step); writing a new rule: false alarms ≤ 0 (configurable);
- hardening: **broaden, never narrow** (`rules/lint.py`): every field and every exclusion of the
  original must still be there. These cover what our scores can't see: a branch on a field our events
  lack (e.g. `Hashes`), or a filter for a false positive our benign events don't contain. Exclusions
  are compared by field + value (ignoring case and the filter's name), so renaming is fine; removing
  is not;
- **regexes ignore case** (`case_insensitive_regexes`): a new `|re` pattern with letters must start
  with `(?i)`. Sigma regexes are case-sensitive while Windows command lines aren't, so `[/-]tn\b`
  misses `/TN`; found on a real written rule;
- hardening: **metadata unchanged** (`keeps_original_metadata`): id, author, date and references stay
  as in the original. Only the detection logic should change; a real run "corrected" a reference link
  to a URL that doesn't exist, which a reviewer focused on detection could easily miss;
- **not overfitted** (`rules/lint.py`): the rule may not add **unusual characters** (invisible or
  look-alike Unicode, written literally or as `\u`/`\x` escapes) that the original didn't have. Found on
  the first real dev run: the agent "hardened" a Run-keys rule by listing the exact zero-width spaces,
  soft hyphens and look-alike letters our mutations used, scoring 100% on tuning while memorising the
  test. That rule is now rejected. Characters the original already had (21 SigmaHQ rules contain some)
  are fine;
- **warning only, `no_copied_test_strings`**: new command-line strings of 12+ characters copied verbatim
  from the tuning attacks (e.g. a test task name or file path). Sometimes legitimate (a registry path), so
  it's shown to the reviewer as a warning and never fails the gate by itself. Program names
  (`Image`, `OriginalFileName`) are never flagged: naming the binary is the most legitimate signal.
- **too broad, `no_short_bare_values`** (blocking): a new command-line value of only one or two letters
  or digits with no delimiter. Found on the first new-split dev run: the agent turned `'/ru '` into
  `'ru'`, which also matches "run", "true", "group", so the rule fires on almost any schtasks command.
  Our few hard negatives didn't show it in a score. Three letters is the limit because 3-letter values
  (`add`, `set`, `cmd`) appear in 74 SigmaHQ rules, while only 19 of 1,297 use 1–2 letter ones. The
  agent sees the reason and can add the delimiter back (`'/ru '`, `' -ru '`).

- **warning only, `no_new_required_fields`** (hardening): a field the original could do without is now
  *required* (e.g. `OriginalFileName` added with AND next to `Image`). The rule then stays silent on logs
  that don't record that field, such as Windows Security event 4688 instead of Sysmon. Found on a real
  dev run; it's a warning because adding a requirement is sometimes intended. "Required" uses the same
  reasoning as "can never fire": if the log lacked this field, could the rule still fire?
- **evaluable**: a rule can be valid Sigma and still unusable, e.g. a regex so slow it would hang (see
  §5.1, regex time limit). The gate stops there and says why.

Checks are either **blocking** (fail the gate) or **warnings** (shown in the Review tab, never fail it).

**What the gate can't see: held-out false alarms.** All benign events are currently in the held-out
split, so the gate checks false alarms on zero benign events during hardening. After the run, the
held-out evaluation does count them, and any **new** held-out false alarm is shown as a red warning
in the Review tab (plus a "False alarms (held-out)" metric) and named in the `harden-selection`
summary. Found on the new-split dev run: the hardened Run-keys rule passed the gate but raised 2 new
false alarms on held-out look-alikes (reading a Run key with `reg query`). This is a warning for
the human, not a gate check, because the agent must never be scored on held-out data. The gate also
adds a warning, `false_alarms_tested`, whenever it has no benign events to test against: "0 new false
alarms" on 0 benign events is untested, not clean.

**Best attempt.** When no submission is accepted, the run returns the best version the agent tested or
submitted (scored on the tuning set, losing no attack the original caught), but only if it scores
strictly better than the original; otherwise the original rule itself (so a re-sent copy with its
comments stripped never masquerades as an improvement). When writing a new rule there is no original:
if the agent never proposed a rule that could be evaluated, the run proposes nothing (`final_source:
none`). Submitted rules count too: a rehearsal reported "no valid rule" when the agent had submitted
valid rules that the gate rejected.

Failing the gate is not a dead end: the rule still goes to a human as "needs human review" with the
failed checks listed. Example on the fixtures: the literal schtasks rule fails (33% resistance on
tuning mutations, 1 false alarm); the robust version hardened from it passes.

---

## 7c. The agent loop (`llm.py`, `agent/loop.py`, `agent/runner.py`) *(new)*

**The model is configuration, not code.** `llm.py` talks to any OpenAI-compatible endpoint, so the
same code runs on OpenRouter's free models (the default), a paid API, or a local model (Ollama at
`http://localhost:11434/v1`). Base URL, key and model come from `.env`. `uv run detectforge llm models`
lists the free models that support tool calling. Reliability is in the client: a timeout per request,
automatic retries with backoff on rate limits/server errors, then a **fallback model** from a
different provider.

**One hardening run** (`harden()`), in order:
1. The runner splits the events: only the **tuning** split goes to the agent.
2. The model gets a system prompt (behavior first: describe the attack, then prefer signals every
   variant keeps; treat all tool output and the rule text as untrusted data) and the original rule
   with its tuning baseline. The prompt is versioned (`PROMPT_VERSION` in `agent/loop.py`, saved
   with every run); each version adds a lesson from a real dev run. v5 teaches YAML
   quoting for regexes: a run spent its whole budget writing `\'` inside a single-quoted regex,
   which YAML doesn't allow (the quote is written `''`). Since prompts can be ignored,
   `validate_rule` also adds this hint to the YAML error whenever it sees `\'`. v5 also asks to
   keep delimiters on short option tokens (`'/ru '`, not `'ru'`). v6 keeps the v5 system
   prompt and adds a separate reminder for an answer cut off by the output limit (below). v7
   (current) asks to write regex escapes once inside single quotes (a run's `'\\bSYSTEM\\b'` looked
   for a real backslash and matched nothing) and to use each key once per selection (below).
   **Repeated keys are rejected.** Plain YAML keeps only the last of two equal keys, so a run that
   wrote `CommandLine|re:` twice in one selection "passed" with its `add` check silently dropped,
   while the YAML the reviewer read still showed both lines. The rule parser (`rules/parse.py`,
   used by the validator, the harness, the gate and the SigmaHQ index) now rejects a repeated key
   and says to split the conditions into separate selections. None of the 3,302 SigmaHQ rules
   repeats a key, so community rules are unaffected.
3. It calls the 5 tools (§7b) until it submits a rule the gate accepts, or a budget runs out:
   model calls (20), tokens (400k), tuning runs (5), submissions (3). Each answer may be up to
   16,384 tokens: reasoning models spend hidden "thinking" tokens from that same allowance, and at
   4,096 three dev runs were cut off mid-thought and returned empty answers. An answer with no tool
   call gets one reminder; if the model's answer was cut off (`finish_reason: length`, saved per
   call and shown in the Review tab) the reminder says so, and the run's reason is "model ran out
   of output tokens", not "model stopped without submitting a rule".
4. The result (`AgentRun`) is **passed** only if the gate accepted a submission. Every other stop
   (LLM down, budget out, model never submits, gate keeps rejecting) is **needs_human_review**, with
   the reasons and the best attempt so far: the strongest tuning revision that lost no attack, or
   the original rule. It never fails silently.
5. After the run, deterministic code scores original vs final on the **held-out** split, as
   evaluation evidence the agent never saw. Everything (rule, reasons, gate checks, every model and
   tool call with latency and tokens) is saved to `data/runs/<trace_id>.json` + `.yml`, together with
   the **whole conversation**: the instructions, every message and tool call the model made, and every
   tool result it received. It only ever holds what the agent saw (tuning data), and the Review tab can
   replay it step by step ("Show the agent's conversation"), which is how we debug *why* a run went
   wrong, not just *that* it did.

```bash
uv run detectforge harden --rule data/fixtures/rules/schtasks_create_literal.yml \
  --technique T1053.005 --events data/fixtures/events.jsonl
```

**First real run** (free `nvidia/nemotron-3-ultra-550b-a55b:free`, fixtures): the agent replaced
`CommandLine|contains: ' /create '` with a regex accepting `/` or `-` and optional quotes around
`create`. Tuning evasion resistance 33% → 100%; **held-out 0% → 100%** (a reordering it never saw);
false alarms unchanged; 4 model calls, 13k tokens, 83 s. One fixture run, not evidence yet.

**Running a whole selection** (`agent/batch.py`): `detectforge harden-selection --split dev` reads the
evaluation manifest (`data/eval/selection.yml`) and hardens each rule of that split, one agent run per
rule. Two design points:
- **Each rule is tested only on its own attacks.** Two rules for the same technique can target
  different behaviours (e.g. "unusual schedule types" vs "task running as SYSTEM"). Testing one on the
  other's attacks would mark it as missing them and push the agent to broaden it beyond its intent. The
  manifest lists each rule's base attacks; the runner keeps those (plus their mutations).
- **Every rule is checked against all benign events**, whatever technique they were collected for: a
  legitimate command is a false alarm for any rule that fires on it. Example from the real data:
  `reg query ...\Run /v OneDrive` was collected for registry dumping (T1003.002), but it's exactly what
  an over-broad Run-keys persistence rule (T1547.001) would wrongly fire on.
- **Model calls are spent only where they can help.** A rule with no mutations to test, or that already
  detects every tuning mutation, is skipped. `--limit` caps the number of agent runs, and the batch
  stops at the first "model unavailable" (e.g. the free daily limit) instead of failing every rule.
- **Nothing is paid for twice.** Every run saves its *provenance* (`provenance.py`): prompt version,
  model and fallback, budgets, a fingerprint of the code that can change a result (everything except
  the UI), of the starting rule and of the events it was scored on, plus the git commit (for humans
  only). Together these form a *setup key*. Re-running a batch reuses saved runs with the same setup
  key instead of calling the model again, so a batch that stopped halfway (quota, crash) just carries
  on. A run cut short because the model was unavailable doesn't count as done. `--repeat 3` gives 3
  runs per rule for the evaluation, counting the ones already saved. Change the prompt, model, budgets,
  gate code or data, and the key changes: older runs are never mixed into new results.
- **The quota is planned, not discovered.** `--dry-run` shows which rules would run and the worst-case
  number of calls without contacting the model. `--max-calls N` caps the whole batch: a run starts only
  if its full budget still fits on top of the calls the finished runs actually spent. `--rule-id` runs
  only some rules. `detectforge llm quota` shows the calls
  saved in today's runs (UTC, when OpenRouter's free limit resets) and the key's tier, without spending a
  call. Example: with the budget at 10 calls per rule, the 4 improvable dev rules need at most 40 of the
  50 free daily calls; at the default 20 they could need 80.

**Writing a new rule: the fallback** (`write_rule` in `agent/loop.py`, `cover` in `agent/runner.py`).
Hardening comes first; writing is only for a technique with no usable community rule.
- **Code decides the path, never the model.** `find_usable_rule` takes the best-ranked rule tagged with
  exactly this technique that is *usable* (evaluable and able to fire on our fields). Rules of a parent
  or sibling technique (T1053 for T1053.005) don't count: they target another behavior. None found →
  write. `detectforge cover --technique T…` runs this choice and prints which path it took and why.
- **Same loop, same tools, same gate, same budgets.** Only the instructions differ (`write-v1`, versioned
  apart from the hardening prompt). Both prompts share one block of Sigma lessons from real runs
  (quoting, escapes, one key per selection, no `|cased`, no copied characters), so a lesson added once
  reaches both. The hardening prompt's text is byte-for-byte unchanged by this split.
- **The agent can't copy a community rule.** Search hides every rule of the technique's family and
  untagged rules (`exclude_technique`), so what it writes is its own. This is also exactly the condition
  of the "agent-written" evaluation arm, so the arm measures the real fallback, not a variant of it.
- **The gate is stricter**: with no original to compare with, it requires *no* false alarms (not "no
  new ones") and flags every unusual character or short value, not only new ones.
- **"Before" is having no rule**: 0% evasion resistance, no false alarms (`harness.run.no_rule`), so the
  before/after, the held-out evaluation and the Review tab work the same way. The Review tab shows the
  new rule whole ("New rule", path "write") instead of a diff.
- **The agent-written arm**: `detectforge harden-selection --split dev --write` writes one rule per
  selected rule, on that rule's own attacks, with the same quota protections (reuse, `--max-calls`,
  `--dry-run`). Nothing is skipped as "already detects every mutation", so it costs more: on the dev
  rules, 8 runs and up to 80 model calls, more than one day of the free tier (spread it over days with
  `--max-calls 40`; finished runs are reused).

---

## 7d. Tracing (`tracing.py`) *(new)*

Every run is one **trace** in Langfuse, using the run's own `trace_id` (the same id as the file in
`data/runs/`), so a saved run and its dashboard view always match:

```
harden (agent)            input: technique + original rule; output: status, reasons, final rule
├── llm (generation)      messages in, content/tool calls out, model, token usage, fallback flag
├── tool:run_tuning_set   arguments in, result out; ERROR level if the call failed
├── llm (generation)
├── tool:submit
└── quality_gate          (only when no submission was accepted) why it failed
```

- **On only when configured**: set `LANGFUSE_PUBLIC_KEY` and `LANGFUSE_SECRET_KEY` (and `LANGFUSE_HOST`
  for a self-hosted server; the default is Langfuse's free cloud). Without them it's a no-op, and the
  run file still records every call with latency and tokens.
- **Can never break a run**: if Langfuse is down or misconfigured, the error is logged once and the
  run continues. A real error in our own code is still raised, never hidden by tracing.
- **No held-out data and no secrets** in traces: only what the agent itself sees is traced; the held-out
  evaluation runs after the trace ends.
- `detectforge harden` prints the trace link at the end.

---

## 8. Command line, tests, CI

```bash
uv sync --all-groups                      # install (incl. UI)
uv run pytest                             # 352 tests
uv run detectforge harden --rule RULE.yml --technique T1053.005 --events EVENTS.jsonl
uv run detectforge cover --technique T1053.005 --events EVENTS.jsonl   # harden, or write if no usable rule
uv run detectforge write --technique T1053.005 --events EVENTS.jsonl   # always write (community rules hidden)
uv run detectforge harden-selection --split dev   # every improvable dev rule, saved for review
uv run detectforge harden-selection --split dev --write   # agent-written arm
uv run detectforge review list --pending          # runs waiting for a decision (current prompts)
uv run detectforge review approve 8e3abcbe -m "why"   # or reject; asks for your reviewer key
uv run detectforge export                        # every run as CSV + per-setup summary (data/exports)
uv run detectforge eval gate-thresholds          # ablation: saved rules passing at 60-100% (no model)
uv run detectforge llm models
uv run detectforge validate RULE.yml
uv run detectforge harness RULE.yml EVENTS.jsonl
uv run detectforge compare BEFORE.yml AFTER.yml EVENTS.jsonl --split heldout --technique T1053.005
uv run detectforge sigmahq fetch
uv run detectforge sigmahq search --technique T1053.005 --query "schtasks create"
uv run detectforge convert RULE.yml --target lucene
```

Tests by file: `test_matcher` (Sigma semantics), `test_harness` (scorecards on fixtures, bad rules,
no data leaks in errors), `test_compare` (before/after numbers, regressions reported), `test_reference`
(index building, search ranking, exclusion, tampered zip rejected), `test_rules` (validate/convert/CLI),
`test_schemas` (bad events rejected), `test_fixtures` (data sanity + "hard negatives must cause false
alarms"), `test_ui` (UI renders, its numbers match the library, review approve flow, agent button off by default), `test_review` (decisions, history, approved copies, safe file names), `test_batch` (per-rule scoping, quota-saving skips, early stop), `test_agent_tools` (contracts,
held-out isolation, budgets, malformed calls), `test_gate` (pass/fail reasons), `test_lint` (dropped fields/exclusions, deployability, memorised characters, copied strings), `test_agent_loop`
(a scripted fake model drives every stop reason, held-out isolation end to end, client fallback),
`test_eval_gate` (recomputed Arm 1 must match the committed results; changes are named rule by rule), `test_demo` (the demo's vague report, injected report, API failure and evasion caught), `test_ui_product` (coverage verdicts from the harness, strongest rule not first hit, guided jumps between sections, coverage report, agent operations),
`test_contracts` (frozen snapshot of the shared formats and function signatures, interfaces.md matches the code, committed data is one consistent dataset, saved results still load, CLI JSON and exit codes; refresh after an agreed change with `UPDATE_CONTRACTS=1 uv run pytest tests/test_contracts.py`),
`test_security` (an obedient model following injected rules and events, YAML tags, escaped display, five tools with no network or file writes, reviewer keys and lockout, API key never saved or printed, no secret tracked by git),
`test_write_rule` (path chosen by code, writing loop, same-technique rules hidden, no-rule baseline,
agent-written arm batch),
`test_tracing` (trace shape, failures marked, no held-out data traced, the real Langfuse SDK exporting
to memory, a broken backend never breaking a run), `test_config`.

GitHub Actions runs lint (ruff) + all tests on every push and pull request.

---

## 9. Known limitations (be ready to explain these)

1. **Free models change.** OpenRouter's free list and limits (20/min, 50/day) can change; the exact
   model is recorded in every run. Local Ollama is the fallback if limits block the experiments.
2. **Fixture data only.** 17 synthetic events; real results need the real mutations + VM checks.
3. **Missing Sysmon fields.** Mostly fixed: with the two optional fields, 175 of 1,297 rules still use
   a field we don't have; 117 harmlessly, and the 58 that can never fire are excluded as unusable.
   Only real if the attack data actually captures the two fields.
4. **Regex time limit (fixed).** Rule regexes now run through the `regex` module with a 1-second limit
   per event; a pattern with catastrophic backtracking (e.g. `(a|aa)+$`) makes the rule unevaluable
   with a clear message instead of hanging a batch. The limit is time-based, so on a much slower
   machine a borderline regex could time out where it wouldn't on ours; 1 s is far above any normal
   rule's cost (microseconds).
5. **Keyword search is simple** word overlap, not semantic search. Fine for technique-driven search.
6. **Written rules are only as good as their tuning data.** The writing prompt (`write-v2`) is frozen
   (`tests/test_prompt_freeze.py` fails if its text changes; a change needs `write-v3`). On the dev
   rules it copied no test characters and every run submitted, but most written rules fired on
   legitimate activity the agent never saw (no benign events in the tuning split yet), and they miss
   held-out quote insertions more often than hardened community rules do.

---

## 10. Decisions waiting on us

| # | Decision | My recommendation | Who |
|---|---|---|---|
| 1 | `base_id == event_id` for originals | Yes | Team sign-off |
| 2 | `original_file_name`, `parent_command_line` added as optional event fields | Done in code | Confirm the attack data captures them |
| 3 | Add `derived_from` (SigmaHQ id) to RuleRecord | Yes — links each "after" to its "before" | Both |
| 4 | Evasion resistance = mutated attacks only | Yes | Metrics module must match |
| 5 | What counts as a "usable" existing rule | Implemented: evaluable + can fire, tagged with exactly this technique (parent/sibling techniques don't count) | Done |
| 6 | Who decides harden vs write-new | Implemented: deterministic code (`find_usable_rule`), never the model | Done |
| 7 | Which LLM / provider and budget per rule | Decided: OpenRouter free models first, local fallback | Done |

## 11. What's next (W4, Nov 10–16)

1. ~~Agent tools~~ — done (§7b), plus quality gate v0.
2. ~~Agent loop v1~~ — done (§7c), hardening path.
3. ~~Tracing~~ — done (§7d).
4. **Integration test** on the real mutations for 2 techniques (needs the data by ~Nov 13).
5. The UI's Harden tab gets an "ask the agent" button that fills the editor.
