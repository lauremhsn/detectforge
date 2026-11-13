# DetectForge

An agentic system that measures how well Sigma detection rules hold up under realistic command-line
evasion, fixes the gaps, and routes every fix to a human for approval. EECE 798S Agentic Systems, Fall 2026.

Status: week 1. Interfaces, Sigma tooling (validate/convert), and harness v0 are in place. The agent
loop arrives in week 2.

## Setup

Requires [uv](https://docs.astral.sh/uv/). uv installs Python 3.12 automatically.

```bash
uv sync
cp .env.example .env   # fill in keys when the agent loop lands
uv run pytest
```

## Usage

```bash
# Is a rule parseable, in scope (Windows process_creation), and evaluable?
uv run detectforge validate data/fixtures/rules/schtasks_create_literal.yml

# Score a rule against labeled events (prints a Scorecard as JSON)
uv run detectforge harness data/fixtures/rules/schtasks_create_literal.yml data/fixtures/events.jsonl

# Before/after report for two versions of the same rule (evasion resistance per transform,
# newly detected / lost attacks, false-alarm changes); optional --split / --technique filters
uv run detectforge compare data/fixtures/rules/schtasks_create_literal.yml \
  data/fixtures/rules/schtasks_create_robust.yml data/fixtures/events.jsonl --technique T1053.005

# Run the agent to harden an existing rule (needs OPENROUTER_API_KEY in .env; free models by default).
# Only the tuning split reaches the agent; the held-out split is scored afterwards for evaluation.
uv run detectforge harden --rule data/fixtures/rules/schtasks_create_literal.yml \
  --technique T1053.005 --events data/fixtures/events.jsonl
uv run detectforge llm models   # free models that support tool calling

# Convert to an Elastic query (lucene or eql)
uv run detectforge convert data/fixtures/rules/certutil_download_literal.yml --target lucene

# Download the pinned SigmaHQ release (r2026-07-01, checksum-verified) and index its
# Windows process-creation rules into data/sigmahq/ (not committed)
uv run detectforge sigmahq fetch

# Search reference rules by ATT&CK technique and/or text; --exclude-technique drops the
# whole technique family plus untagged rules (used for the "written" arm)
uv run detectforge sigmahq search --technique T1053.005 --query "schtasks create"
```

Each indexed rule records whether the harness can evaluate it and which of its fields are missing
from the event schema (`unmapped_fields`).

From Python:

```python
from detectforge.events import load_events
from detectforge.harness import run

card = run(open("rule.yml").read(), load_events("events.jsonl"))
print(card.hits, card.misses, card.false_alarms, card.per_transform["insertion"])
```

## UI

A minimal local UI over the same library functions (find → validate → harden, before/after):

```bash
uv run --group ui python -m streamlit run src/detectforge/ui/app.py --server.address localhost
```

It opens at http://localhost:8501, bound to localhost only. On first launch without an index it
downloads and indexes the pinned SigmaHQ release (~20 s).

### Deploy (Streamlit Community Cloud, free)

1. Sign in at https://share.streamlit.io with GitHub (you need admin rights on the repo, e.g. your fork).
2. Create app → repository, branch, main file path `src/detectforge/ui/app.py`; Python 3.12 under
   Advanced settings.
3. Cloud installs `src/detectforge/ui/requirements.txt` (keep it in sync with `pyproject.toml`; a test
   checks this) and runs from the repo root, so `data/fixtures/` is found.

The app holds no secrets and only shows public SigmaHQ rules and synthetic fixture events.

## Layout

```
src/detectforge/
  schemas.py        frozen interfaces: Event, Scorecard, RuleRecord, ValidationResult
  events.py         JSONL load/dump
  config.py         settings from env / .env
  rules/            parse (scope + size limits), validate (pySigma), convert (Elastic backends)
  harness/          matcher (Sigma semantics over events), run() -> Scorecard
  reference/        SigmaHQ release fetch + index, search_reference_rules backend
  ui/               Streamlit UI (optional `ui` dependency group)
  agent/            typed tools, hardening loop, runner (tuning split only)
  gate.py           quality gate for submitted rules
  llm.py            provider-agnostic LLM client (OpenRouter free models by default)
  tracing.py        Langfuse tracing of runs (off unless LANGFUSE_* keys are set)
  cli.py
data/fixtures/      synthetic events and fixture rules (see its README)
docs/interfaces.md  interface contract and open questions
tests/
```

See [docs/code-walkthrough.md](docs/code-walkthrough.md) for a guided tour of the code and
[docs/interfaces.md](docs/interfaces.md) for the event format, harness contract, and matching semantics.
