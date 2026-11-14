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
                     no usable rule ──► WRITE NEW RULE (fallback, W6) ────────────────┘
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
    convert.py        Translate a rule into an Elastic query (for a real SIEM later)
  harness/
    matcher.py        The engine: does this rule fire on this event?
    run.py            Run a rule over many events → Scorecard
    compare.py        Run two versions of a rule → before/after HardeningReport
  reference/
    sigmahq.py        Download the pinned SigmaHQ release and build our index of rules
    index.py          Search that index by technique / keywords
  ui/app.py           The Streamlit UI (Find → Validate → Harden tabs)
  agent/tools.py      The 5 typed tools the agent may call, with least-privilege context
  gate.py             Quality gate: accept, or "needs human review" with reasons
  llm.py              Provider-agnostic LLM client (OpenRouter / local), retries, fallback model
  agent/loop.py       The hardening loop; agent/runner.py splits data and saves each run
  tracing.py          Langfuse tracing of every model and tool call (no-op when not configured)
  cli.py              The `detectforge` command line
data/fixtures/        17 hand-written test events + 3 test rules
docs/interfaces.md    The interface contract and open questions
tests/                160 automated tests (run on every push by GitHub Actions)
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
- evasion resistance ≥ 80% on the mutations (configurable);
- hardening: **no attack the original caught is lost, and no new false alarms** (existing ones are
  left for the tuning step); writing a new rule: false alarms ≤ 0 (configurable).

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
   with its tuning baseline.
3. It calls the 5 tools (§7b) until it submits a rule the gate accepts, or a budget runs out:
   model calls (20), tokens (400k), tuning runs (5), submissions (3).
4. The result (`AgentRun`) is **passed** only if the gate accepted a submission. Every other stop
   (LLM down, budget out, model never submits, gate keeps rejecting) is **needs_human_review**, with
   the reasons and the best attempt so far: the strongest tuning revision that lost no attack, or
   the original rule. It never fails silently.
5. After the run, deterministic code scores original vs final on the **held-out** split, as
   evaluation evidence the agent never saw. Everything (rule, reasons, gate checks, every model and
   tool call with latency and tokens) is saved to `data/runs/<trace_id>.json` + `.yml`.

```bash
uv run detectforge harden --rule data/fixtures/rules/schtasks_create_literal.yml \
  --technique T1053.005 --events data/fixtures/events.jsonl
```

**First real run** (free `nvidia/nemotron-3-ultra-550b-a55b:free`, fixtures): the agent replaced
`CommandLine|contains: ' /create '` with a regex accepting `/` or `-` and optional quotes around
`create`. Tuning evasion resistance 33% → 100%; **held-out 0% → 100%** (a reordering it never saw);
false alarms unchanged; 4 model calls, 13k tokens, 83 s. One fixture run, not evidence yet.

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
uv run pytest                             # 160 tests
uv run detectforge harden --rule RULE.yml --technique T1053.005 --events EVENTS.jsonl
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
alarms"), `test_ui` (UI renders and its numbers match the library), `test_agent_tools` (contracts,
held-out isolation, budgets, malformed calls), `test_gate` (pass/fail reasons), `test_agent_loop`
(a scripted fake model drives every stop reason, held-out isolation end to end, client fallback),
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
4. **Regex timeouts.** A pathological regex written by the agent could make the harness hang
   (Python regexes have no timeout). Planned for the W6 security work.
5. **Keyword search is simple** word overlap, not semantic search. Fine for technique-driven search.
6. **"Usable rule" is defined but not yet wired to a fallback**: usable = evaluable and can fire. The
   UI shows "No usable rule found" when no result is usable; the write-new-rule path itself is W6.

---

## 10. Decisions waiting on us

| # | Decision | My recommendation | Who |
|---|---|---|---|
| 1 | `base_id == event_id` for originals | Yes | Team sign-off |
| 2 | `original_file_name`, `parent_command_line` added as optional event fields | Done in code | Confirm the attack data captures them |
| 3 | Add `derived_from` (SigmaHQ id) to RuleRecord | Yes — links each "after" to its "before" | Both |
| 4 | Evasion resistance = mutated attacks only | Yes | Metrics module must match |
| 5 | What counts as a "usable" existing rule | Implemented: evaluable + can fire. Open: count parent/child technique matches too? | Us |
| 6 | Who decides harden vs write-new | Deterministic code, not the LLM | Us |
| 7 | Which LLM / provider and budget per rule | Decided: OpenRouter free models first, local fallback | Done |

## 11. What's next (W4, Nov 10–16)

1. ~~Agent tools~~ — done (§7b), plus quality gate v0.
2. ~~Agent loop v1~~ — done (§7c), hardening path.
3. ~~Tracing~~ — done (§7d).
4. **Integration test** on the real mutations for 2 techniques (needs the data by ~Nov 13).
5. The UI's Harden tab gets an "ask the agent" button that fills the editor.
