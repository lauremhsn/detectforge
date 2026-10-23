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

# Convert to an Elastic query (lucene or eql)
uv run detectforge convert data/fixtures/rules/certutil_download_literal.yml --target lucene
```

From Python:

```python
from detectforge.events import load_events
from detectforge.harness import run

card = run(open("rule.yml").read(), load_events("events.jsonl"))
print(card.hits, card.misses, card.false_alarms, card.per_transform["insertion"])
```

## Layout

```
src/detectforge/
  schemas.py        frozen interfaces: Event, Scorecard, RuleRecord, ValidationResult
  events.py         JSONL load/dump
  config.py         settings from env / .env
  rules/            parse (scope + size limits), validate (pySigma), convert (Elastic backends)
  harness/          matcher (Sigma semantics over events), run() -> Scorecard
  cli.py
data/fixtures/      synthetic events and fixture rules (see its README)
docs/interfaces.md  interface contract and open questions
tests/
```

See [docs/interfaces.md](docs/interfaces.md) for the event format, harness contract, and matching semantics.
