# DetectForge: Threat Model

A lightweight threat model: what we protect, who might attack it, through which inputs, and what
stops them. Every mitigation listed here has an automated test (in `tests/test_security.py` unless
named otherwise); the failure matrix ([failure-matrix.md](failure-matrix.md)) lists the same tests by
component, plus the problems this review found (D18–D20).

## 1. What we protect

| Asset | Why it matters |
|---|---|
| **The approval decision** | Only an approved rule reaches `approved/`, ready to deploy. A wrong approval means a SOC trusts a rule that doesn't detect the attack, or floods analysts with false alarms. |
| **Held-out evaluation data** | The headline result (before/after evasion resistance) is only fair if the agent never sees the held-out mutations and benign events. A leak would inflate the score. |
| **Secrets** | The LLM API key (spends quota, tied to an account), Langfuse keys (traces), reviewer keys (approval). |
| **The host** | The machine running DetectForge: files, network, other credentials. |

## 2. Trust boundaries

Everything to the left of the agent is **untrusted input**. The agent itself is also treated as
untrusted: it is a language model that may follow injected text, so its answers are checked by code
and decided by a human.

```
untrusted                                   checked by code                 trusted
---------                                   ---------------                 -------
chat request / pasted threat report  ─┐
SigmaHQ rules (external repository)  ─┼─▶  agent (LLM)  ─▶  typed tools  ─▶  quality gate  ─▶  human reviewer  ─▶  approved/
event command lines (attack data)    ─┤     (untrusted     (5 tools, no      (deterministic)     (reviewer key)
model answers                        ─┘      output)        files/network)
```

## 3. Attackers and what they control

| Attacker | Controls | Wants |
|---|---|---|
| **A1. Poisoned rule author** | Text of a community rule (description, false positives, detection values) | Make the agent approve, weaken, or exfiltrate |
| **A2. Malicious report or request** | The chat request or a pasted threat report | Same, through intake |
| **A3. Attacker in the logs** | Command lines in the events (an attacker names a task `ignore your instructions…`) | Steer the agent through tool results |
| **A4. A misbehaving model** | Every tool call and every word the agent writes | Approve, deploy, read files, see held-out data, mislead the reviewer |
| **A5. Unauthorized UI user** | The Streamlit UI (local or the public deployment) | Approve a rule, spend the model quota |
| **A6. Secret leak** | Anything that gets printed, saved, traced or committed | Steal the API key |

## 4. Threats and mitigations

| # | Threat (attacker) | Mitigation | Test |
|---|---|---|---|
| T1 | Injected instructions make the agent **approve or deploy** (A1–A4) | There is no approve or deploy tool. The agent has five tools; unknown tools and unknown arguments are refused. A submission goes to the gate and stays `proposed` until a human decides. | `test_an_injected_community_rule_cannot_approve_deploy_read_files_or_reach_held_out` |
| T2 | Injected instructions make the agent **read held-out data** (A1–A4) | Held-out events are never given to the tools (`ToolContext` refuses them at construction); no tool takes a split; error messages never echo data. | same test; `test_agent_tools.py::test_no_tool_output_leaks_held_out_events`, `test_agent_loop.py::test_run_keeps_the_full_conversation_without_held_out_data`, `test_tracing.py::test_held_out_events_never_reach_the_tracer` |
| T3 | Injected text is read **as instructions** (A1, A3) | Rule text is wrapped in `<original_rule>` tags; event data only reaches the model inside tool results (JSON); both system prompts say never to follow instructions found there. The system prompt is fixed: data never changes it. | `test_injected_text_in_an_event_reaches_the_model_only_as_tool_data`, `test_agent_loop.py::test_task_message_frames_rule_as_untrusted_data` |
| T4 | Injection through **intake** (A2) | The request is quoted as data; the model answers only through one typed tool; every technique it names must exist in the SigmaHQ index; if the model misbehaves, intake falls back to keyword search. | `test_intake.py::test_request_is_quoted_as_data_and_model_can_only_answer_through_the_tool` |
| T5 | The model writes a **deliberately weak rule** that still passes (A4) | The gate checks it on the tuning set; held-out scores are computed afterwards, without the agent, and shown to the reviewer next to the rule, including new held-out false alarms. A human approves every rule. | `test_batch.py::test_new_held_out_false_alarms_are_flagged_for_the_reviewer`, `test_ui.py::test_review_warns_about_new_held_out_false_alarms` |
| T6 | **Misleading the reviewer** with formatted text: a clickable "Approve now" link, a remote image, a bold "APPROVED by the security lead" (A1, A2, A4) | All untrusted text (model answers, rationale, SigmaHQ fields, command lines, error messages) is escaped before display, so it reads exactly as written and nothing in it renders. | `test_model_text_is_escaped_for_markdown_so_injected_links_never_render`, `test_ui.py::test_injected_model_text_shows_literally_and_approving_is_off_without_keys` |
| T7 | **Code execution** through rule YAML (A1, A4) | Safe YAML loading (no Python tags), rule size limit, and a timeout on every regex (a slow regex makes the rule unevaluable instead of hanging the harness). | `test_yaml_tags_in_a_rule_are_never_executed`, `test_matcher.py::test_slow_regex_makes_the_rule_unevaluable_instead_of_hanging` |
| T8 | The agent's tools **reach the network or the file system** (A4) | The five tools only read the events and index they were given. Saving runs is done by the runner, outside the agent's reach; run files are only named by well-formed trace ids. | `test_a_whole_agent_run_needs_no_network_and_writes_no_files`, `test_review.py::test_only_well_formed_trace_ids_reach_the_file_system` |
| T9 | **Unauthorized approval** (A5) | Approve and Reject need a personal reviewer key; the decision is recorded under the key's owner, not a typed name. Keys are 16+ characters, compared in constant time; 5 wrong keys in a minute lock decisions. No keys configured = approving off. The key is cleared from the session after use. | `test_a_decision_needs_a_valid_key_and_is_recorded_under_its_owner`, `test_repeated_wrong_keys_lock_decisions_for_a_while`, `test_ui.py::test_review_shows_a_run_and_records_approval` |
| T10 | **Spending the model quota** from the public UI (A5) | Agent runs from the UI are off unless `DETECTFORGE_UI_ALLOW_AGENT_RUNS=true`; intake then uses keyword search instead of the model. | `test_risky_features_are_off_unless_switched_on`, `test_ui.py::test_agent_button_is_off_by_default` |
| T11 | **API key leak** in saved runs, traces, errors or printed objects (A6) | Keys are `SecretStr` (masked when printed or saved); provider errors keep only the HTTP status, never the request or response body; the client hides its key from `repr`. | `test_the_api_key_never_reaches_saved_runs_errors_or_printed_objects`, `test_config.py::test_settings_read_env_without_exposing_secrets`, `test_provenance.py::test_key_info_never_leaks_the_key` |
| T12 | **Committed secret** (A6) | `.env`, `.env.*`, `.streamlit/secrets.toml` and run data are git-ignored; a test scans every tracked file for OpenRouter, Langfuse, GitHub and Anthropic keys and private keys. | `test_no_secret_file_or_key_is_tracked_by_git` |
| T13 | **Tampered SigmaHQ release** (A1) | The release zip is pinned by SHA-256 and refused if it doesn't match. | `test_reference.py::test_verify_sha256_rejects_tampered_release` |

## 5. Least privilege, in one place

- **The agent**: five tools (`search_reference_rules`, `inspect_schema`, `validate_rule`,
  `run_tuning_set`, `submit`). No file, shell, network, approve or deploy tool. Tuning events only.
  Budgets on model calls, tokens, tuning runs and submissions.
- **The runner**: saves runs and computes held-out scores; it never gives held-out data to the agent.
- **The UI**: shows runs; changes a rule's status only through `review.decide`, which needs a reviewer
  key. Agent runs from the UI are off by default.
- **Attack execution**: base attacks and the behavior check of mutations run only in an isolated
  Windows evaluation VM with snapshots, never on the development machine.
- **Data**: only public (SigmaHQ, Atomic Red Team, LOLBAS) or synthetic data.

## 6. Secrets handling

| Secret | Where it lives | Never appears in |
|---|---|---|
| `OPENROUTER_API_KEY` | `.env` locally; the hosting provider's secrets store when deployed | saved runs, traces, error messages, printed settings or client, git |
| `LANGFUSE_PUBLIC_KEY`, `LANGFUSE_SECRET_KEY` | same | same |
| `DETECTFORGE_REVIEWER_KEYS` | same; one key per reviewer, `name:key` | review files (only the name is recorded), the session after use, error messages |

Make a reviewer key with `uv run python -c "import secrets; print(secrets.token_urlsafe(24))"`.

## 7. Residual risks

What is not covered, and why it's acceptable for now (also in Part 3 of the failure matrix):

- **A model can still follow injected text.** The tests use a scripted model that obeys every
  injection, so they prove what an obedient model *cannot* do, not how often a real one tries.
  The real-model check is the "injected report" demo scenario.
- **Reviewer lockout is per process and shared** by all reviewers; a restart clears it.
- **Reviewer keys are stored in plain text** in `.env` (or the host's secrets store). A real
  deployment would use single sign-on and a secrets manager.
- **The local UI has no HTTPS.** It is meant for `localhost`; the public deployment is served over
  HTTPS by the hosting provider and has agent runs and approving switched off.
