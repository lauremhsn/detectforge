# Report draft: Users, Agentic justification, System design

Draft text for the final report. Numbers marked **[re-run]** come from the dev runs on the
rebalanced split and are filled in once those runs are done; the current values are from the
earlier dev runs (`detectforge export`). Sources: `docs/architecture.md`, `docs/code-walkthrough.md`,
the code.

---

## Users and workflow

Detection teams deploy community Sigma rules and treat "we have a rule for this technique" as
"we are covered". Uetz et al. showed that assumption fails often: 129 of 292 widespread Windows
process-creation rules can be evaded with five simple command-line transforms. DetectForge serves the
people who have to close that gap:

| User | Their question | Where DetectForge answers it |
|---|---|---|
| SOC lead | Where are we weak, and can we prove it to an auditor? | Posture: coverage per technique, a downloadable report |
| Detection engineer | A new threat came in: are we covered? Can this rule be made harder to evade? | Threats, Rules: a measured verdict, then hardening |
| Senior reviewer | Is this proposed change safe to ship? | Review: a verdict, the evidence, approve or reject with a personal key |
| Platform owner | What does the agent cost, and does it fail? | Lab, traces, an export of every run |

The workflow mirrors how a detection engineer already works, with the slow parts automated:
**request → find existing rules → measure them against attacker variations → harden (or, if no rule
is usable, write one) → human approval**. The interface is not a chatbot: chat-like input is used only
for the request; decisions happen in a review queue with evidence.

## Why an agent

Most of DetectForge is deliberately *not* agentic. Searching rules, generating variations, replaying
rules on events, scoring them and deciding whether a proposal is acceptable are all deterministic code,
because those steps must be reproducible and auditable. The language model is used in exactly two
places, where deterministic code cannot do the job:

1. **Turning a request or threat report into ATT&CK techniques.** Free text varies too much for keyword
   rules alone; the model answers through one typed tool, and every technique it names is checked
   against the rule index (keyword search is the fallback).
2. **Revising a detection rule.** Hardening is an open-ended design task: the agent must understand the
   attack behavior, read which variations the rule misses, and rewrite its logic around signals every
   variant keeps, without breaking what already works or adding false alarms. There is no fixed recipe;
   it needs several rounds of *propose → test → read the feedback → revise*. That loop, driven by tool
   results rather than by a fixed script, is what makes it agentic.

The agent's autonomy is bounded on purpose. It chooses which tool to call and how to revise the rule,
but it cannot see held-out data, cannot approve or deploy anything, and works within budgets. Code
decides whether its proposal is good enough to show as "passed", and a human decides whether it ships.

## Architecture

```
request ─▶ intake (LLM) ─▶ reference index ─▶ runner: harden or write?
                                                   │
                     tuning split only ─▶  agent loop (LLM) ◀─▶ 5 typed tools ─▶ harness, gate, index
                                                   │
                                     proposal or best attempt + full trace
                                                   │
             held-out split ─▶ runner scores before/after (no agent) ─▶ saved run + provenance
                                                   │
                                     Review (human, reviewer key) ─▶ approved/
```

The components that produce numbers (reference index, dataset, harness, quality gate, evaluation) are
plain, tested Python with no model involved. The **harness** replays a Sigma rule over JSON events and
returns a scorecard (hits, misses, false alarms, per evasion type); every number in the UI, the CLI and
the report comes from it. The **quality gate** is the deterministic referee: validity, deployability
(the rule must convert to an Elastic query), evasion resistance on the tuning variations, no lost
attacks, no new false alarms, broaden-never-narrow (every original field, exclusion and metadata kept),
and an overfitting linter (no characters or strings copied from the test attacks, no over-short values,
case-insensitive regexes).

## Agent design

- **One agent, typed tools.** A single agent with five tools, each with a Pydantic schema:
  `search_reference_rules`, `inspect_schema`, `validate_rule`, `run_tuning_set` and `submit`. Unknown
  tools and arguments are refused and fed back to the agent. A multi-agent design was not needed: the
  task is one coherent revision loop, and splitting it would add coordination without adding evidence.
- **Behavior-first prompting.** The prompt asks the agent to describe the attack behavior before
  writing, and to key on signals every variant must keep (the executable, short essential tokens)
  rather than literal strings.
- **The prompt evolved from failures.** Each version (harden-v1 to v7, write-v1 to v2) was a response
  to a failure on real dev runs, logged in the failure matrix: copied look-alike characters, invalid
  regex escapes, answers cut off by the output limit. Where a check could be written in code, it went
  into the gate instead, so it doesn't depend on the model following instructions.
- **Two paths.** If a usable community rule exists, the agent hardens it (the main path); only if none
  exists does it write a new one, with that technique's community rules hidden so the agent-written
  arm can't copy them.
- **Budgets and termination.** Per run: model calls (10 when hardening, 15 when writing), tokens,
  tuning runs, submissions, output length, timeouts. A run ends when the gate accepts a submission or a
  budget runs out; in the second case it is saved as *needs human review* with its best attempt and the
  reasons. Nothing fails silently.
- **Frozen before testing.** The writing prompt (write-v2) and the hardening prompt (harden-v7) are
  frozen by a test that fails if their text changes, before the test-technique runs.

## Reliability and AgentOps

- **Schema-validated outputs:** every tool input and every saved run is a Pydantic model.
- **Retries, fallback, degradation:** the client retries with backoff, then falls back to a second
  model; intake degrades to keyword search; a run that can't finish is saved for human review.
- **Tracing:** every model and tool call is recorded with latency, tokens, retries, fallbacks and
  errors, in the saved run file and optionally in Langfuse. `detectforge export` turns all runs into
  tables with mean and spread per configuration.
- **Provenance:** each run records the prompt version, model, budgets and fingerprints of the code, the
  starting rule and the events, so results from different setups are never mixed, and finished runs
  with the same setup are reused instead of re-run.
- **Regression gates:** 26+ failures found on real runs each have a regression test; CI recomputes the
  community-rule baseline on every change and fails on any difference.

## Real-world constraints

| Constraint | How it is handled |
|---|---|
| **Cost** | Free models only (an OpenRouter free model with a free fallback); the constraint is requests per day, shown against today's usage. Mean model calls per run: about 8 for hardening and writing; per approved rule: 32 (hardening) and 65 (writing). **[re-run]** |
| **Latency** | About 4 minutes per hardening run and 3 per written rule on free-tier models, dominated by model response time. **[re-run]** |
| **Privacy** | Only public (SigmaHQ, Atomic Red Team, LOLBAS) and synthetic data. Runs locally; the API key and reviewer keys stay in the environment file and never reach saved runs, traces or logs. |
| **Human approval** | The agent can only propose. Approving needs a personal reviewer key, and the decision is recorded under its owner. |
| **Security** | The agent is treated as untrusted: least-privilege tools, untrusted text quoted as data and escaped in the UI, no path to held-out data (see the Security section). |
