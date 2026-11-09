# DetectForge — Code Walkthrough

*Status as of Nov 9, 2026 (updated with the missing-field fixes and cloud deploy). Written so that both of us can follow every design decision, see what
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
 (technique)  SigmaHQ      harness run()        (manual in UI;  compare()       review UI   Laure's
              search       → Scorecard          agent = W4)     → before/after  (W5)        module
                                                                                      ▲
                     no usable rule ──► WRITE NEW RULE (fallback, W6) ────────────────┘
```

---

## 2. Where everything lives

```
src/detectforge/
  schemas.py          The shared data shapes (the contract with Laure): Event, Scorecard, RuleRecord
  events.py           Read/write event files (one JSON object per line)
  config.py           All settings in one place (.env / environment variables)
  rules/
    parse.py          Turn rule text into a rule object; reject anything out of scope
    validate.py       "Is this rule OK?" → errors and warnings
    convert.py        Translate a rule into an Elastic query (for a real SIEM later)
  harness/
    matcher.py        The engine: does this rule fire on this event?
    run.py            Run a rule over many events → Scorecard
    compare.py        Run two versions of a rule → before/after HardeningReport
  reference/
    sigmahq.py        Download the pinned SigmaHQ release and build our index of rules
    index.py          Search that index by technique / keywords
  ui/app.py           The Streamlit UI (Find → Validate → Harden tabs)
  cli.py              The `detectforge` command line
data/fixtures/        17 hand-written test events + 3 test rules
docs/interfaces.md    The interface contract and open questions for Laure
tests/                109 automated tests (run on every push by GitHub Actions)
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

The model **rejects** bad events on load (unknown fields, wrong labels, a mutation that claims to be
its own base, etc.) and tells you the exact line number. This catches mistakes in Laure's data early.

**Design choice — `base_id` points to itself for originals** (rather than being empty). Grouping by
`base_id` then gives "the original + all its variants" with no special case. *Open question for Laure.*

**Design choice — 5 Sysmon fields, 2 of them optional.** We started with 3 (as in CLAUDE.md), then
measured that 717 of the 1,297 SigmaHQ rules used a field we didn't have (`OriginalFileName` in 559,
`ParentCommandLine` in 75). Adding those two drops it to 175. They're optional so older event files stay
valid; `null` means "not captured". *Laure to confirm she can capture them.*

### 3.2 The fixture dataset (`data/fixtures/`)

Hand-written, synthetic, **not** VM-verified. Only for building and testing until Laure's real
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
- `re` (regex), `cased`, `exists`, `null`, number comparisons, `1 of` / `all of` / `them`, `not`;
- **fields we don't have** (e.g. `User`), or optional fields left empty, are treated as *absent*:
  they never match a value.

Not supported (the rule comes back as invalid with a clear message): `fieldref`, `cidr`, `expand`,
correlation rules. None of the 1,297 SigmaHQ process-creation rules needs them.

**Design choice — our own pure-Python matcher** instead of replaying logs through a real SIEM or
Chainsaw/Zircolite. It's fast (milliseconds), deterministic, has no infrastructure, and runs in CI.
The cost is that we must match Sigma's semantics ourselves; `tests/test_matcher.py` pins about 35 of these
behaviors down so they can't drift.

### 5.2 `run.py → run(rule_yaml, events) → Scorecard`

The frozen interface Laure uses directly. For one rule and a list of events:

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
  never see held-out data, "including in error messages" (CLAUDE.md §8).

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
bare minimum; the question the project answers is "does it still catch the variants?". *Laure's
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

## 7. The UI (`ui/app.py`) *(new)*

Start it from the repo root:

```bash
uv run --group ui python -m streamlit run src/detectforge/ui/app.py --server.address localhost
```

Opens at http://localhost:8501 (bound to your machine only, telemetry off). It can also be deployed
for free on Streamlit Community Cloud (see the README): there it builds the SigmaHQ index itself on
first launch, and `src/detectforge/ui/requirements.txt` lists its dependencies.

| Area | What it shows |
|---|---|
| Sidebar | Which events file; filter by technique and split; pipeline status (✅ built, 🟡 manual, ⏳ planned). Picking a rule auto-scopes the events to its technique. |
| 1 · Find | Search SigmaHQ by technique + keywords; table of candidates with "fields missing from events"; rule details (marked untrusted); or pick a fixture rule. "No usable rule" message = where the write-new-rule fallback will start. |
| 2 · Validate | The "before": validation errors/warnings, then the scorecard: detected, evasion resistance, false alarms, per-mutation table, and every event with DETECTED / MISSED / FALSE ALARM. |
| 3 · Harden | Before on the left, an editable "after" on the right. Every edit re-runs `compare`: evasion resistance with delta, per-mutation before/after, and lists of newly caught / LOST attacks and false-alarm changes. In W4 the agent fills this editor instead of you. |

It is **read-only over the library** (no logic of its own), shows held-out events to the human only,
and is the seed of the review UI (approve/reject comes in W5).

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

## 8. Command line, tests, CI

```bash
uv sync                                   # install
uv run pytest                             # 109 tests
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
alarms"), `test_ui` (UI renders and its numbers match the library), `test_config`.

GitHub Actions runs lint (ruff) + all tests on every push and pull request.

---

## 9. Known limitations (be ready to explain these)

1. **No agent yet.** Hardening is manual. This is the critical path for W4.
2. **Fixture data only.** 17 synthetic events; real results need Laure's mutations + VM checks.
3. **Missing Sysmon fields.** Mostly fixed: with the two optional fields, 175 of 1,297 rules still use
   a field we don't have; 117 harmlessly, and the 58 that can never fire are excluded as unusable.
   Only real if Laure actually captures the two fields in her events.
4. **Regex timeouts.** A pathological regex written by the agent could make the harness hang
   (Python regexes have no timeout). Planned for the W6 security work.
5. **Keyword search is simple** word overlap, not semantic search. Fine for technique-driven search.
6. **"Usable rule" is defined but not yet wired to a fallback**: usable = evaluable and can fire. The
   UI shows "No usable rule found" when no result is usable; the write-new-rule path itself is W6.

---

## 10. Decisions waiting on us

| # | Decision | My recommendation | Who |
|---|---|---|---|
| 1 | `base_id == event_id` for originals | Yes | Laure to confirm |
| 2 | `original_file_name`, `parent_command_line` added as optional event fields | Done on our side | Laure: can she capture them? |
| 3 | Add `derived_from` (SigmaHQ id) to RuleRecord | Yes — links each "after" to its "before" | Both |
| 4 | Evasion resistance = mutated attacks only | Yes | Laure's metrics must match |
| 5 | What counts as a "usable" existing rule | Implemented: evaluable + can fire. Open: count parent/child technique matches too? | Us |
| 6 | Who decides harden vs write-new | Deterministic code, not the LLM | Us |
| 7 | Which LLM / provider and budget per rule | Decide before W4 agent work | Us |

## 11. What's next (W4, Nov 10–16)

1. **Agent tools** as typed functions: `inspect_schema`, `validate_rule`, `run_tuning_set` (tuning
   split only — enforced in code), `submit`.
2. **Agent loop v1** for the hardening path: given an existing rule and its tuning scorecard, propose
   a revision, re-validate, repeat up to the budget; output = best version + before/after report.
3. **Tracing** (Langfuse) of every model and tool call.
4. **Integration test** on Laure's real mutations for 2 techniques (needs her data by ~Nov 13).
5. The UI's Harden tab gets an "ask the agent" button that fills the editor.
