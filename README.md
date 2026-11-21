# DetectForge

**Are we actually covered, and can we prove it?** DetectForge is an agentic system that checks a
team's detection rules against realistic attacker variation and closes the gaps it measures. For a
requested ATT&CK technique it:

1. **finds** existing community Sigma rules (SigmaHQ) for the technique;
2. **measures** how well each rule holds up when an attacker varies the command line, using the five
   evasion types of Uetz et al. (USENIX Security 2024): insertion, substitution, omission, reordering
   and recoding;
3. **hardens** the rule with an LLM agent that revises it, re-tests every revision, and stops when a
   deterministic quality gate passes or its budget runs out;
4. **writes a new rule** only as a fallback, when no usable community rule exists;
5. **routes every proposal to a human**, with evidence and before/after scores. The agent can only
   propose; it never approves or deploys.

DetectForge does not claim to make rules evasion-proof. It measures each rule's **evasion resistance**
(the share of behavior-preserving attack variants it still detects) and raises it where it can, on
variant types the agent never saw while working.

EECE 798S Agentic Systems, Fall 2026. Scope: Windows process-creation rules (Sysmon Event ID 1).

## How it works

```
request ─▶ find rules ─▶ validate (baseline) ─▶ harden ─▶ re-validate ─▶ quality gate ─▶ human review ─▶ approved/
                              │                   ▲            │
                              │                   └── revise ◀─┘   (tuning split only, budgeted)
                              └─ no usable rule ─▶ write a new rule (same loop)
```

- **Deterministic core.** The harness replays a rule on labelled events and returns a scorecard; the
  gate and the before/after comparison are plain code. The model only proposes rule text.
- **Fair evaluation.** Events are split by mutation type: the agent tunes on some types and is scored
  afterwards on the others (held-out), which it never sees, not even in error messages.
- **One agent, five typed tools:** `search_reference_rules`, `inspect_schema`, `validate_rule`,
  `run_tuning_set`, `submit`. No file, network, approve or deploy tool.
- **Every model and tool call is traced** (latency, tokens, retries, failures) and saved with the run.

More: [architecture](docs/architecture.md) · [code walkthrough](docs/code-walkthrough.md) · [interfaces](docs/interfaces.md) ·
[failure matrix](docs/failure-matrix.md) · [threat model](docs/threat-model.md)

## Setup

Requires [uv](https://docs.astral.sh/uv/) (it installs Python 3.12 itself) and git.

```bash
git clone <repository-url> detectforge
cd detectforge
uv sync --all-groups
cp .env.example .env
uv run pytest
```

All tests run offline with a scripted fake model: no key, no network, no quota.

### Keys (`.env`)

| Setting | Needed for | How to get it |
|---|---|---|
| `OPENROUTER_API_KEY` | agent runs, model-based intake | Free account at [openrouter.ai](https://openrouter.ai); free models only (about 50 requests a day) |
| `DETECTFORGE_REVIEWER_KEYS` | Approve / Reject in the UI | `name:key` pairs, 16+ characters each: `uv run python -c "import secrets; print(secrets.token_urlsafe(24))"` |
| `LANGFUSE_PUBLIC_KEY`, `LANGFUSE_SECRET_KEY` | tracing to Langfuse (optional) | Free cloud tier or self-hosted; runs are saved locally either way |
| `DETECTFORGE_UI_ALLOW_AGENT_RUNS` | the "Ask the agent" button | `true` locally; keep `false` on any public deployment |

`.env` is git-ignored, and a test fails if a key ever appears in a tracked file.

## Try it in 5 minutes (no key needed)

```bash
# Score a rule on the synthetic fixture events (prints a scorecard as JSON)
uv run detectforge harness data/fixtures/rules/schtasks_create_literal.yml data/fixtures/events.jsonl

# Before/after: a literal community-style rule vs a behavior-based revision of it
uv run detectforge compare data/fixtures/rules/schtasks_create_literal.yml \
  data/fixtures/rules/schtasks_create_robust.yml data/fixtures/events.jsonl --technique T1053.005

# Download the pinned SigmaHQ release (checksum-verified) and search it
uv run detectforge sigmahq fetch
uv run detectforge sigmahq search --technique T1053.005 --query "schtasks create"

# Map a plain-language request to techniques (keyword search, no model)
uv run detectforge intake "detect scheduled-task persistence" --no-model
```

### The UI

```bash
uv run --group ui python -m streamlit run src/detectforge/ui/app.py --server.address localhost
```

It opens at http://localhost:8501. A top bar holds four product areas, organised around what you
came to do, plus a Lab for the research side:

| Area | Question it answers |
|---|---|
| **Posture** (home) | Where are we weak, and can we prove it? One sentence on the state of coverage, then a card per technique that needs attention (weakest first), each opening its weakest rule; before/after chart; every rule as a table; downloadable coverage report |
| **Threats** | A new threat came in: are we covered? Paste a request or threat report; get a verdict per technique (covered / evadable / not covered) and the next step |
| **Review** | What's waiting for me, and is it safe to ship? An inbox of proposals; for the open one a plain-language verdict, the numbers that decide it (unseen variations caught, new false alarms, quality checks), the change, deeper evidence folded away; Approve / Reject with your reviewer key |
| **Rules** | Pick a rule → test it against evasions → harden it (by hand or with the agent); export as Sigma YAML or an Elastic query |
| **Lab** | How the agent behaves: runs, pass rate per prompt version, model calls, tokens, failures, today's quota; what's built. Which events rules are tested on is set in the sidebar |

Approved rules are written to `data/runs/approved/`. A guided demo is in [demo/README.md](demo/README.md).

### With Docker

No Python setup needed, only Docker. Keys still come from `.env`.

```bash
docker compose up --build                                  # UI at http://localhost:8501
docker compose run --rm cli sigmahq fetch                  # any detectforge command
docker compose run --rm cli eval community --check
```

The image runs as an unprivileged user and contains no secrets (`.env`, git history and local runs
are excluded). Agent runs, review decisions and the SigmaHQ index are kept in Docker volumes across
restarts; CI builds the image on every push. To share one review queue with a local checkout instead,
add `-f docker-compose.yml -f docker-compose.share-runs.yml` (uses `./data/runs`; Docker Desktop must
be allowed to share the project folder).

## Reproducing the evaluation

The evaluation data and the Arm 1 results are committed under `data/eval/`, so steps 1–2 only need
re-running to rebuild them.

**1. Rule set and attack data**

```bash
uv run detectforge sigmahq fetch          # SigmaHQ index (data/sigmahq/, not committed)
uv run detectforge dataset select         # rules + base attacks from Atomic Red Team (selection_config.yml)
uv run detectforge dataset mutate         # behavior-preserving mutations of each base attack
uv run detectforge dataset negatives      # benign hard negatives (LOLBAS and SigmaHQ false-positive notes)
```

**2. Arm 1: community rules as-is** (the "before"; no model)

```bash
uv run detectforge eval community         # writes data/eval/results/arm1_community.json
uv run --group analysis python analysis/plot_arm1.py
```

**3. Arm 2: agent-hardened rules** (the "after"; needs `OPENROUTER_API_KEY`)

```bash
uv run detectforge llm quota                                         # calls used today (no model call)
uv run detectforge harden-selection --split dev --dry-run            # what would run, at no cost
uv run detectforge harden-selection --split dev --max-calls 40       # dev rules; held-out scored afterwards
uv run detectforge harden-selection --split test --repeat 3          # test rules, 3 runs each, once frozen
```

**4. Arm 3: agent-written rules** (same rules, their technique's community rules hidden)

```bash
uv run detectforge harden-selection --split dev --write --max-calls 40
```

Each run is saved to `data/runs/<trace_id>.json` with its **provenance**: prompt version, model,
budgets, a fingerprint of the code and the events, and the git commit. Re-running a batch reuses
finished runs with the same setup, so a batch can be spread over several days of free quota. Commit
before an evaluation run so the recorded commit matches the code.

Review the runs in **Review**, or from the terminal (same reviewer-key check):

```bash
uv run detectforge review list --pending                        # trace prefix, technique, held-out before -> after
uv run detectforge review reject 13bf08a0 -m "misses /TN"       # or approve; asks for your reviewer key
```

Export every run for the report (one row per run, model call and tool call; mean and spread, gate
pass rate and cost per approved rule per prompt version and model):

```bash
uv run detectforge export                                       # writes data/exports/
uv run detectforge eval gate-thresholds                         # how results depend on the 80% gate
```

Single rules:

```bash
uv run detectforge cover --technique T1053.005 --events data/eval/base_events.jsonl --events data/eval/mutations.jsonl
uv run detectforge harden --rule-id <sigmahq-rule-id> --technique T1053.005 --events data/eval/mutations.jsonl
```

`cover` lets the code choose the path: harden the best usable community rule, or write one if none
exists.

## Reliability and security

- **Never fails silently.** A run either passes the gate or ends as *needs human review* with its
  reasons and its best attempt. Budgets cap model calls, tokens, tuning runs and submissions.
- **Model failures:** timeouts, retries with backoff, a fallback model, and graceful degradation
  (intake falls back to keyword search). See the [failure matrix](docs/failure-matrix.md): every failure
  found on a real run has a regression test.
- **Untrusted input:** rule text, event command lines, threat reports and model output are data, never
  instructions, and are shown to the reviewer as plain text. See the [threat model](docs/threat-model.md).

## Tests and CI

```bash
uv run pytest            # unit, integration, security and contract tests (offline)
uv run ruff check .      # lint
uv run ruff format --check .
```

GitHub Actions runs lint and every test on each push and pull request. The shared formats (events,
scorecards, rule records) are pinned by a contract snapshot: an intended change is made with
`UPDATE_CONTRACTS=1 uv run pytest tests/test_contracts.py`, and the snapshot is committed with it.

## Layout

```
src/detectforge/
  schemas.py      shared interfaces: Event, Scorecard, RuleRecord, ValidationResult
  harness/        Sigma matcher over events, run() -> Scorecard, before/after compare
  rules/          parse (scope and size limits), validate (pySigma), convert, overfitting linter
  reference/      SigmaHQ release fetch, index and search
  dataset/        rule selection, Atomic Red Team base attacks, mutations, hard negatives
  eval/           metrics and evaluation arms
  agent/          typed tools, the loop (harden or write), runner, batch over a selection
  gate.py         deterministic quality gate
  intake.py       plain-language request -> ATT&CK techniques
  review.py       human decisions (reviewer keys), approved rules
  llm.py          OpenAI-compatible client (OpenRouter free models by default)
  tracing.py      Langfuse tracing (off unless configured)
  provenance.py   which setup produced each run
  ui/             Streamlit UI
  cli.py          the `detectforge` command
data/fixtures/    synthetic events and rules for development (not for reported results)
data/eval/        evaluation rule selection, events and results
docs/             architecture, walkthrough, interfaces, failure matrix, threat model
analysis/         figures, generated from committed results
tests/
```

## Deploying the UI (Streamlit Community Cloud, free)

1. Sign in at https://share.streamlit.io with GitHub (admin rights on the repo, e.g. your fork).
2. Create app → repository, branch, main file `src/detectforge/ui/app.py`; Python 3.12 under
   Advanced settings.
3. Cloud installs `src/detectforge/ui/requirements.txt` (a test keeps it in sync with `pyproject.toml`).

Leave `DETECTFORGE_UI_ALLOW_AGENT_RUNS` and `DETECTFORGE_REVIEWER_KEYS` unset there: the public app is
then read-only and can't spend the model quota.

## Data

Only public or synthetic data: SigmaHQ rules, Atomic Red Team tests, LOLBAS, and synthetic events.
Attack commands are executed only in an isolated Windows evaluation VM, never on a development machine.

## License

See [LICENSE](LICENSE).
