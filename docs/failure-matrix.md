# DetectForge: Failure Matrix

What can go wrong, how we notice, what the system does about it, and which automated test keeps it
fixed. Rule of the project: **every failure we discover becomes a regression test**, and nothing
fails silently: a run either passes the quality gate or ends as **needs human review** with its reasons.

- **Part 1** lists failures we actually hit on real agent runs or real data, in the order found.
- **Part 2** is the matrix of failure modes the system is built to handle, by component.
- **Part 3** lists known gaps: what is not handled yet, and why.

Tests are named `file::test`; all of them run in CI on every push (`uv run pytest`).

---

## Part 1. Failures found on real runs

| # | What happened | Root cause | What we changed | Guarded by |
|---|---|---|---|---|
| D1 | The agent "hardened" a Run-keys rule by listing the exact zero-width spaces, soft hyphens and look-alike letters our mutations used: 100% on tuning, by memorising the test. | Nothing stopped a rule from copying test-specific characters. | Gate check `no_unusual_characters` (blocking); prompt v3. Characters the original rule already had are allowed (21 SigmaHQ rules have some). Seen again on Nov 16 (`ᵃ`, `ᵈ` in a Direct Autorun revision): blocked. | `test_lint.py::test_gate_rejects_memorised_characters_but_only_warns_on_copied_strings`, `test_unusual_characters_found_in_escapes_and_literals`, `test_characters_the_original_already_had_are_fine` |
| D2 | A revision added `OriginalFileName` with AND next to `Image`, so the rule would stay silent on logs without that field (e.g. Windows Security 4688). | Adding a required field looks like a harmless extra check. | Gate warning `no_new_required_fields`; prompt v4 (add new fields as alternatives, OR). | `test_lint.py::test_gate_warns_when_hardening_adds_a_required_field` |
| D3 | Unchanged rules with `null` exclusions were reported as having "dropped" them. | pySigma's `SigmaNull` has no stable text form, so the comparison never matched. | Exclusions compared by field + value with `null` handled. | `test_lint.py::test_identical_rule_drops_nothing` |
| D4 | A batch could hang on one rule. | A regex with catastrophic backtracking (e.g. `(a|aa)+$`). | Rule regexes run with a 1 s time limit per event; the rule becomes "unevaluable" with a clear reason. | `test_matcher.py::test_slow_regex_makes_the_rule_unevaluable_instead_of_hanging`, `test_lint.py::test_gate_reports_a_rule_too_slow_to_evaluate` |
| D5 | A Run-keys rule would have looked free of false alarms although it fires on `reg query ...\Run /v OneDrive`. | That benign event was collected for another technique (T1003.002), and each rule was only checked against its own technique's benign events. | Every rule is checked against **all** benign events. | `test_batch.py::test_every_rule_is_checked_against_all_benign_events` |
| D6 | A run spent its whole budget on invalid YAML. | The agent wrote `\'` inside a single-quoted regex; YAML has no such escape. | Prompt v5; the validator's YAML error adds a hint when it sees `\'`. | `test_rules.py::test_backslash_quote_in_yaml_gets_a_hint` |
| D7 | The agent turned `'/ru '` into `'ru'`, which also matches "run", "true", "group". | No check for values too short to be specific; our benign events didn't contain such words. | Gate check `no_short_bare_values` (blocking) for new 1–2 character values without a delimiter (3-letter values like `add` appear in 74 SigmaHQ rules, so 3+ is allowed); prompt v5. | `test_lint.py::test_short_bare_values_flags_new_letters_without_a_delimiter`, `test_gate_rejects_short_bare_values` |
| D8 | A hardened Run-keys rule passed the gate but raised 2 new false alarms on held-out benign events. | All benign events are in the held-out split, so the gate (tuning only) saw none. | Red warning in the Review tab and a note in the batch summary listing the new held-out false alarms. Not a gate check: the agent must never be scored on held-out data. | `test_ui.py::test_review_warns_about_new_held_out_false_alarms`, `test_batch.py::test_new_held_out_false_alarms_are_flagged_for_the_reviewer` |
| D9 | The 4 improvable dev rules could need 80 model calls at the default budget; the free tier allows 50 a day. | The quota was only discovered by running out. | `--dry-run` (worst case, no model call), `--max-calls`, `--rule-id`, `detectforge llm quota`, and reuse of runs with the same setup key. | `test_provenance.py::test_dry_run_needs_no_model_and_spends_nothing`, `test_max_calls_only_starts_runs_whose_whole_budget_fits`, `test_rerunning_a_batch_reuses_runs_with_the_same_setup`, `test_runs_cut_short_by_the_model_are_not_reused` |
| D10 | 3 of 4 runs ended with "model stopped without submitting a rule". | A reasoning model spent its whole 4,096-token answer allowance on hidden thinking and returned nothing; the reason given was wrong. | Allowance raised to 16,384; the cut-off (`finish_reason: length`) is saved per call, shown in the Review tab, gets its own reminder, and is named as the stop reason. Prompt v6. | `test_agent_loop.py::test_answers_cut_off_by_the_output_limit_are_named_as_such`, `test_a_cut_off_answer_can_recover_after_the_reminder` |
| D11 | A Run-keys revision "passed" with held-out evasion resistance 67% → 100%, but fired on harmless `reg query` commands. The reviewer rejected it. | The agent wrote `CommandLine|re:` twice in one selection. Plain YAML keeps only the last of two equal keys, so the `add` check was silently dropped while the YAML still showed it. | The rule parser rejects a repeated key and says to use separate selections; prompt v7. None of the 3,302 SigmaHQ rules repeats a key. | `test_rules.py::test_a_key_repeated_in_one_selection_is_rejected` |
| D12 | Same setup as D11: the gate reported "0 new false alarms" for that rule. | There were 0 benign events in the tuning split, so the check measured nothing. | Gate warning `false_alarms_tested` when there are no benign events to test against. | `test_gate.py::test_zero_benign_events_is_flagged_not_reported_as_clean` |
| D13 | Every revision of a Schtasks rule detected 0% of attacks. | The agent wrote `'\\bSYSTEM\\b'` in single quotes, where a backslash is literal: the regex looked for a real backslash and matched nothing. | Prompt v7 (write regex escapes once). The gate's `detects_unmutated_attacks` already stops such a rule from passing. | Prompt only (see Part 3) |
| D14 | `--max-calls 30` skipped a rule saying "0 calls left" when 5 were unused. | The cap counted every run's whole budget, not what it spent. | The cap counts calls actually spent. | `test_provenance.py::test_max_calls_only_starts_runs_whose_whole_budget_fits` |
| D15 | Runs printed "Failed to export spans" when Langfuse wasn't running. | Tracing backend unreachable. | Nothing to change: the run continued and every call is also saved in the run file. | `test_tracing.py::test_broken_backend_never_breaks_a_run`, `test_tracing_falls_back_to_noop_if_langfuse_cannot_start` |
| D16 | After a merge-conflict resolution the package failed to import. | A stray `main` left in an import line. | Fixed; any import error fails every test, so CI catches it on push. | Whole suite (CI) |
| D17 | A rehearsal of the write-new-rule path (real data, scripted model) reported "the agent produced no valid rule" for a rule whose submissions the gate had rejected. | "Best attempt" only remembered rules tested with `run_tuning_set`, not rules submitted directly. | Every tested or submitted version is scored on the tuning set (with the harness, not the tool's output); the reviewer gets the best one with the gate's real reasons. Applies to hardening too. | `test_write_rule.py::test_a_rule_the_gate_rejected_is_still_the_best_attempt` |
| D18 | Security review: the agent's rationale, the intake model's answer and SigmaHQ descriptions were rendered as Markdown. An injected rationale could show a clickable "Approve now" link, load a remote image, or a bold "APPROVED by the security lead" that looks like DetectForge's own message. | Untrusted text passed straight to `st.markdown` / `st.warning` / `st.write`. | Every untrusted string goes through `md()`, which escapes all punctuation, so it reads exactly as written and nothing in it renders. | `test_security.py::test_model_text_is_escaped_for_markdown_so_injected_links_never_render`, `test_ui.py::test_injected_model_text_shows_literally_and_approving_is_off_without_keys` |
| D19 | Security review: printing the LLM client (a traceback, a log line, a debugger) showed the API key. | The client is a dataclass, and its default `repr` includes every field. | The key field is left out of `repr`. | `test_security.py::test_the_api_key_never_reaches_saved_runs_errors_or_printed_objects` |
| D20 | Security review: anyone who could open the Review tab could approve a rule under any name, because the reviewer was a free-text field. | A name identifies; it doesn't authenticate. | Approving needs a personal reviewer key (`DETECTFORGE_REVIEWER_KEYS`); the decision is recorded under the key's owner; no keys = approving off; repeated wrong keys lock decisions for a minute. | `test_security.py::test_a_decision_needs_a_valid_key_and_is_recorded_under_its_owner`, `test_repeated_wrong_keys_lock_decisions_for_a_while`, `test_ui.py::test_review_shows_a_run_and_records_approval` |
| D21 | The New request page said T1053.005 was caught "0 of 23" on the real data, though other community rules for it catch 17 alone and all 23 together. | The verdict used the first rule search returned, not the best one. | The verdict replays every usable rule tagged with the technique, names the strongest single rule, and reports what all of them catch together. (The agent's own choice of rule to harden is unchanged.) | `test_ui_product.py::test_a_technique_is_judged_by_its_strongest_rule_not_the_first_one_found` |
| D22 | (Prevention) A code change could silently move a reported number, e.g. a matcher fix changing which mutations a rule detects. | Results are only recomputed when someone reruns them. | CI recomputes Arm 1 on every push and fails on any difference, naming the rule and the number; an intended change commits the new results with it. | `test_eval_gate.py`, CI job `eval-gate` |

---

## Part 2. Failure modes the system handles

### Model provider (LLM)

| Failure | How we notice | What the system does | Test |
|---|---|---|---|
| Primary model down, rate-limited (429), timeout | SDK error after its own retries | Same request to the fallback model; the run records `used_fallback` | `test_agent_loop.py::test_client_falls_back_when_primary_fails` |
| Primary and fallback both fail | `LLMError` | Run stops as needs human review with "LLM unavailable" and the original (or best attempt so far) | `test_agent_loop.py::test_client_raises_when_both_models_fail`, `test_llm_failure_returns_original_for_human_review`, `test_best_attempt_survives_a_later_failure` |
| Model unavailable in the middle of a batch (daily limit) | `LLMError` on a run | The batch stops instead of failing every remaining rule; that run is not reused later | `test_batch.py::test_batch_stops_when_the_model_is_unavailable`, `test_provenance.py::test_runs_cut_short_by_the_model_are_not_reused` |
| No API key | Settings | Clear error before any call | `test_agent_loop.py::test_client_requires_an_api_key` |
| Answer cut off by the output limit | `finish_reason: length` | Specific reminder, then named stop reason (D10) | `test_agent_loop.py::test_answers_cut_off_by_the_output_limit_are_named_as_such` |
| Key or secret in an error message | n/a | Errors are built without the key; settings hide secrets | `test_provenance.py::test_key_info_never_leaks_the_key`, `test_config.py::test_settings_read_env_without_exposing_secrets` |

### Agent behaviour

| Failure | How we notice | What the system does | Test |
|---|---|---|---|
| Answers with text, never calls a tool | No tool call in the answer | One reminder, then needs human review | `test_agent_loop.py::test_model_that_never_calls_tools_is_nudged_then_stopped` |
| Malformed tool call (bad JSON, unknown tool, wrong arguments) | Schema validation (Pydantic) | Error returned to the model as the tool result; the loop continues | `test_agent_loop.py::test_malformed_tool_call_is_reported_back_and_loop_continues`, `test_agent_tools.py::test_malformed_calls_return_errors` |
| Loops forever / spends too much | Budgets: model calls, tokens, tuning runs, submissions | Stops at the first exhausted budget, needs human review | `test_agent_loop.py::test_model_call_budget_is_enforced`, `test_agent_tools.py::test_tuning_budget_is_enforced`, `test_failed_submissions_are_limited` |
| Submits a rule the gate rejects | Gate result | Reasons returned to the agent; after the submission budget, needs human review with the gate's reasons | `test_agent_loop.py::test_rejected_submissions_end_in_review_with_gate_reasons` |
| Rewrites the rule without improving it | Tuning score not better than the original | The original rule is returned, not a rewritten copy | `test_agent_loop.py::test_no_improvement_returns_the_original_not_a_rewritten_copy` |
| Overfits to the tuning attacks | Gate lint checks | Blocks memorised characters (D1), too-short values (D7); warns on copied strings | see D1, D7 |
| Narrows the rule (drops a field or an exclusion) | Gate lint checks | Blocking: hardening may broaden, never narrow | `test_lint.py::test_dropping_an_untestable_branch_is_flagged`, `test_dropping_an_exclusion_is_flagged`, `test_gate_flags_narrowing_when_hardening` |
| Loses an attack the original caught, or adds a false alarm | Before/after comparison | Blocking gate checks | `test_gate.py::test_regression_against_original_fails`, `test_compare.py::test_regression_is_reported_as_lost` |
| Writes a rule a real SIEM can't run | Conversion to Elastic Lucene | Blocking gate check `deployable` | `test_lint.py::test_gate_rejects_rules_elastic_cannot_run` |
| Model gives a different result on the same setup | Repeated runs | Evaluation uses 3 runs per setup (`--repeat 3`), reporting mean and spread | `test_provenance.py::test_repeat_only_runs_what_is_missing` |

### Writing a new rule (fallback)

| Failure | How we notice | What the system does | Test |
|---|---|---|---|
| The model decides to write a rule when a community rule exists (or the reverse) | n/a | Not possible: code chooses the path (`find_usable_rule`); only a usable rule tagged with exactly this technique counts | `test_write_rule.py::test_the_path_is_chosen_by_code_not_the_model` |
| The agent copies the community rule it was supposed to replace | Search exclusion | Every rule of the technique's family (and untagged rules) is hidden from search | `test_write_rule.py::test_writing_hides_every_rule_of_the_technique_family` |
| The agent never proposes a usable rule | No valid version tested or submitted | Needs human review with nothing proposed (`final_source: none`), never an empty "pass" | `test_write_rule.py::test_writing_that_never_produces_a_rule_proposes_nothing` |
| The model fails mid-run | `LLMError` | Best version so far goes to review | `test_write_rule.py::test_writing_keeps_its_best_valid_version_when_the_model_fails` |
| Held-out data reaches the writing agent | Same runner split as hardening | Held-out scored afterwards against "no rule" | `test_write_rule.py::test_written_runs_are_saved_and_scored_on_held_out_without_the_agent_seeing_it` |
| A lesson fixed in one prompt but not the other | Shared block of Sigma lessons | Both prompts are built from the same text | `test_write_rule.py::test_both_prompts_share_the_lessons_from_real_runs` |

### Rule content

| Failure | How we notice | What the system does | Test |
|---|---|---|---|
| Invalid YAML or invalid Sigma | Parser / pySigma | Clear error (with a hint for `\'`) | `test_rules.py::test_validate_reports_parse_errors`, `test_backslash_quote_in_yaml_gets_a_hint` |
| Repeated key silently dropping a condition | Parser | Rejected (D11) | `test_rules.py::test_a_key_repeated_in_one_selection_is_rejected` |
| Rule outside scope (not Windows process creation) | Parser | Rejected with the expected logsource | `test_reference.py::test_build_index_filters_scope_and_reports_skips` |
| Rule needs a field our logs never have | `can_fire` analysis | Error if it can never fire; warning if the field is optional | `test_rules.py::test_validate_rejects_rule_that_can_never_fire`, `test_validate_warns_when_missing_field_is_harmless` |
| Invalid regex, unsupported modifier | Matcher compile | Rule error, scorecard marked invalid | `test_matcher.py::test_invalid_regex_is_rule_error`, `test_unsupported_modifier_is_rule_error`, `test_harness.py::test_invalid_rules_return_invalid_scorecard` |
| Regex too slow (ReDoS) | 1 s time limit | Rule unevaluable, gate says why (D4) | `test_matcher.py::test_slow_regex_makes_the_rule_unevaluable_instead_of_hanging` |
| Oversized rule | Size check (64 KB) | Rejected before parsing | `test_harness.py::test_invalid_rules_return_invalid_scorecard` |

### Data and evaluation integrity

| Failure | How we notice | What the system does | Test |
|---|---|---|---|
| Held-out events reach the agent (tools, errors, traces, saved conversation) | Tool context only receives tuning events | Held-out is evaluated after the run, by deterministic code | `test_agent_tools.py::test_context_refuses_held_out_events`, `test_no_tool_output_leaks_held_out_events`, `test_agent_loop.py::test_runner_never_sends_held_out_events_and_evaluates_them_separately`, `test_run_keeps_the_full_conversation_without_held_out_data`, `test_tracing.py::test_held_out_events_never_reach_the_tracer` |
| Error messages leak event contents | n/a | Harness errors never include event text | `test_harness.py::test_error_messages_do_not_leak_event_contents` |
| Duplicate event ids, bad event lines | Loader | Clear error with the line number | `test_harness.py::test_duplicate_event_ids_raise`, `test_schemas.py::test_load_events_reports_bad_line` |
| Hard negatives not hard enough | Community rule must raise some false alarms | Test fails if they don't | `test_fixtures.py::test_hard_negatives_trigger_a_community_style_rule` |
| Split leaks across transform types | Split by transform type | Test fails on overlap | `test_fixtures.py::test_split_is_by_transform_type` |
| Dev and test techniques overlap (same rule family) | Selection builder | Rejected | `test_dataset_selection.py::test_dev_test_family_overlap_is_rejected` |
| Rule that fires on nothing chosen for evaluation | Selection builder | Rejected | `test_dataset_selection.py::test_rule_that_fires_on_nothing_is_rejected` |
| Old and new runs mixed in results | Setup key (prompt, model, budgets, code, rule, events) | Runs reused only with the same key | `test_provenance.py::test_setup_key_changes_with_anything_that_can_change_the_result` |
| A rule scored on another rule's attacks | Per-rule base attacks | Each rule tested only on its own attacks | `test_batch.py::test_scoping_to_unknown_base_attacks_is_rejected`, `test_scoping_keeps_benign_events` |
| No tuning attacks for a technique | Runner | Rejected before any model call | `test_agent_loop.py::test_runner_rejects_technique_without_tuning_attacks` |

### Security

| Failure | How we notice | What the system does | Test |
|---|---|---|---|
| Prompt injection in a rule or tool output | n/a (untrusted by design) | Rule text is framed as data in tags; the system prompt says never to follow instructions in it; the agent can only propose, the gate and a human decide | `test_agent_loop.py::test_task_message_frames_rule_as_untrusted_data` |
| Prompt injection in a chat request | n/a | Request quoted as data; the model can only answer through one typed tool | `test_intake.py::test_request_is_quoted_as_data_and_model_can_only_answer_through_the_tool` |
| Vague request | Intake | Asks a clarifying question instead of guessing | `test_intake.py::test_vague_request_gets_a_question`, `test_keyword_fallback_asks_when_nothing_matches` |
| Tampered SigmaHQ release | SHA-256 of the pinned zip | Refused | `test_reference.py::test_verify_sha256_rejects_tampered_release`, `test_cli_fetch_refuses_unpinned_zip` |
| Path traversal through a run id | Trace id format check | Only 32-hex ids become file names | `test_review.py::test_only_well_formed_trace_ids_reach_the_file_system` |
| Unexpected exception details shown to the model | Tool dispatcher | Generic error, details only in logs | `test_agent_tools.py::test_unexpected_failure_does_not_leak_details` |
| Agent deploys a rule | n/a | Not possible: no deploy tool; approval writes to `approved/` only after an authenticated human decides | `test_review.py::test_approval_is_recorded_and_the_rule_is_copied`, `test_ui.py::test_agent_button_is_off_by_default` |
| Injected community rule, and a model that obeys it (calls `approve_rule`, `deploy_rule`, `read_file`, asks for the held-out split) | Tool dispatcher | Unknown tools and unknown arguments are refused; the submission still goes through the gate and stays `proposed`; held-out data never reaches the model | `test_security.py::test_an_injected_community_rule_cannot_approve_deploy_read_files_or_reach_held_out` |
| Injected text in an event's command line | n/a | Reaches the model only inside a tool result (JSON data), never in the instructions | `test_security.py::test_injected_text_in_an_event_reaches_the_model_only_as_tool_data` |
| YAML tags in a rule (`!!python/object/apply:os.system`) | Safe YAML loader | Rule rejected, nothing executed | `test_security.py::test_yaml_tags_in_a_rule_are_never_executed` |
| The agent's tools reach the network or write files | n/a | They can't: the five tools only read the events they were given (checked with network and file writes blocked) | `test_security.py::test_the_agent_has_exactly_five_tools_and_none_takes_a_split_path_or_url`, `test_a_whole_agent_run_needs_no_network_and_writes_no_files` |
| Injected Markdown in model or SigmaHQ text shown to the reviewer (D18) | n/a | Escaped: shown word for word, nothing renders | `test_ui.py::test_injected_model_text_shows_literally_and_approving_is_off_without_keys` |
| Someone approves without being a reviewer (D20), or guesses keys | Reviewer key check | Refused; constant-time comparison; 5 wrong keys in a minute lock decisions | `test_security.py::test_a_decision_needs_a_valid_key_and_is_recorded_under_its_owner`, `test_repeated_wrong_keys_lock_decisions_for_a_while`, `test_reviewer_keys_are_parsed_strictly_and_errors_never_echo_a_key` |
| API key leaks into saved runs, error messages or printed objects (D19) | n/a | Keys are `SecretStr`; provider errors keep only the HTTP status; the client hides its key | `test_security.py::test_the_api_key_never_reaches_saved_runs_errors_or_printed_objects`, `test_config.py::test_settings_read_env_without_exposing_secrets`, `test_provenance.py::test_key_info_never_leaks_the_key` |
| A secret is committed | Scan of every tracked file | `.env`, `.streamlit/secrets.toml` and run data are git-ignored; no tracked file may contain an OpenRouter, Langfuse, GitHub or Anthropic key or a private key | `test_security.py::test_no_secret_file_or_key_is_tracked_by_git` |
| Risky features on by default | n/a | Agent runs from the UI and approving are both off until configured | `test_security.py::test_risky_features_are_off_unless_switched_on` |

### Storage, UI, tracing

| Failure | How we notice | What the system does | Test |
|---|---|---|---|
| Corrupted or unreadable run file | Validation on load | Skipped and logged, never fatal | `test_review.py::test_unreadable_files_are_skipped_not_fatal` |
| Old run format (no conversation saved) | Missing field | Still opens, with a note | `test_ui.py::test_old_runs_without_a_conversation_still_open` |
| Approval later reversed | Decision history | History kept; approved copy withdrawn | `test_review.py::test_a_later_rejection_keeps_history_and_withdraws_the_approval` |
| Tracing backend down or misconfigured | Tracer error | Logged once; the run continues (D15) | `test_tracing.py::test_broken_backend_never_breaks_a_run`, `test_tracer_swallows_its_own_errors_but_not_the_runs` |
| Missing or outdated SigmaHQ index | Index loader | Actionable error ("run sigmahq fetch") | `test_reference.py::test_missing_index_has_actionable_error`, `test_old_index_format_must_be_rebuilt` |

---

## Part 3. Known gaps (not handled yet)

| Gap | Effect | Current mitigation | What would close it |
|---|---|---|---|
| No benign events in the tuning split | The agent never sees false alarms while hardening; the gate's false-alarm checks measure nothing (D8, D12) | Gate warning `false_alarms_tested`; held-out false alarms shown to the reviewer | Split benign events per technique into tune and held-out, keeping variants of one command (same `base_id`) on the same side |
| A technique with no held-out mutations (Shadow Copies, T1490) | No held-out score for that rule ("n/a") | Reported as n/a, never as 0% or 100% | Add held-out mutations for it, or report it separately |
| Double-escaped regex (D13) has no automatic check | The agent can waste calls on a rule that matches nothing | Prompt v7; the gate blocks such a rule from passing | A reliable check is hard: doubled backslashes are legitimate in Windows paths (`\\System32`), so a heuristic would give false hints |
| Same setup, different result (model randomness) | One run can pass and the next fail (Schtasks SYSTEM: passed under v5, 0% under v6) | 3 runs per setup in the evaluation | Report mean and spread; not a bug to fix |
| Quota counter sees only saved agent runs | Intake requests, the deployed app and other machines sharing the key are not counted | `llm quota` also shows OpenRouter's own usage figure | Count intake calls too |
| Writing a new rule is checked with a scripted model only | Real-model behavior of `write-v1` unknown | End-to-end rehearsal on the real data with a fake model | Real dev runs, then freeze `write-v1` before the agent-written arm runs on the test rules |
| The agent-written arm costs more than a day of free quota | Dev rules alone: 8 runs, up to 80 calls (nothing is skipped) | `--max-calls 40` per day; finished runs are reused | Spread over days, or a second key on another team member's account |
| Prompt injection resistance depends on the model | A model could still follow injected text, e.g. write a deliberately weak rule | Tests show that even a model that obeys every injection can only propose; the gate and a human decide, and held-out scores are computed without the agent | Run the injected-report demo case on the real model and record what it does |
| Reviewer lockout is per process and shared | A restart clears it; one person guessing locks out every reviewer for a minute | Keys are 16+ characters, so guessing is impractical anyway | Per-reviewer accounts with a proper login (e.g. single sign-on) on a real deployment |
| Reviewer keys sit in `.env` in plain text | Anyone who can read the machine's `.env` can approve | `.env` is git-ignored and checked by a test; keys are per person and can be changed at any time | A secrets manager, and storing key hashes instead of keys |

---

## Adding a row

When a run fails in a new way: find the root cause in the saved conversation (Review tab, "Show the
agent's conversation"), fix it in code where possible (a prompt change alone can be ignored by the
model), add a test whose docstring starts with `Regression:` and says what happened, then add a row
to Part 1. If it can't be fixed yet, add it to Part 3 with what it would take.
