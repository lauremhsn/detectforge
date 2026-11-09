# Interfaces (week 1 freeze)

Source of truth: [`src/detectforge/schemas.py`](../src/detectforge/schemas.py). Any change needs
agreement from both Marwa and Laure. Status: **draft, waiting on Laure's sign-off.**

## Event

One JSON object per line (JSONL, UTF-8). Unknown keys are rejected.

| Field | Type | Notes |
|---|---|---|
| `event_id` | string, non-empty | Unique within a file. |
| `image` | string | Sysmon `Image` (full path). |
| `command_line` | string | Sysmon `CommandLine`. |
| `parent_image` | string | Sysmon `ParentImage`. |
| `original_file_name` | string, optional | Sysmon `OriginalFileName` (name compiled into the binary; survives renaming). Omit or `null` if not captured. |
| `parent_command_line` | string, optional | Sysmon `ParentCommandLine`. Omit or `null` if not captured. |
| `label` | `attack` \| `benign` | |
| `technique` | `T####` or `T####.###` | For benign events: the technique the event resembles. |
| `transform` | `none` \| `insertion` \| `substitution` \| `omission` \| `reordering` \| `recoding` | Uetz et al. taxonomy. |
| `base_id` | string | The event this one was mutated from. **Unmutated events point to themselves** (`base_id == event_id`), so grouping by `base_id` gives each base with all its variants. |
| `split` | `tune` \| `heldout` | |

Sigma field mapping used by the harness: `Image → image`, `CommandLine → command_line`,
`ParentImage → parent_image`, `OriginalFileName → original_file_name`,
`ParentCommandLine → parent_command_line`. A field that is `null`/omitted, and every other Sigma field
(e.g. `User`, `IntegrityLevel`), is treated as absent: it never matches a value, matches `null`, and
matches `|exists: false`.

`validate_rule` tells the two cases apart: if the rule can still match through other fields, a missing
field is a warning ("harmless"); if the rule depends on it (AND, or alone), it is an error ("can never
fire") and the rule is not a usable candidate for hardening.

## Harness

```python
from detectforge.harness import run
scorecard = run(rule_yaml: str, events: list[Event]) -> Scorecard
```

- Rule problems (bad YAML, invalid Sigma, unsupported feature, logsource other than
  `process_creation`/`windows`, rule over 64 KiB) never raise: they return `valid=False` with `error` set
  and all counts zero.
- Input problems (duplicate `event_id`s) raise `ValueError`.
- Error messages describe the rule only, never event contents, so a held-out scorecard leaks nothing
  beyond its counts.
- The harness does not filter events. Pass only the events you want scored (e.g. one technique, one split).

CLI equivalent: `uv run detectforge harness RULE.yml EVENTS.jsonl`.

### Matching semantics

Following the Sigma spec: plain values match the whole field value, case-insensitively, with `*`/`?`
wildcards; `contains`/`startswith`/`endswith`/`all`/`windash`/`base64`/`base64offset`/`cased`/`re`
(`i`, `m`, `s`), `exists`, `null`, `gt/gte/lt/lte`, `1 of`/`all of`/`them`, `and`/`or`/`not` are supported.
Regexes use search (unanchored) semantics. Keyword detections match if any mapped field contains the keyword.
Not supported (rule comes back `valid=False`): `fieldref`, `cidr`, `expand` placeholders, correlation rules.

## Scorecard

| Field | Meaning |
|---|---|
| `valid` | Rule could be evaluated. |
| `error` | Why not, when `valid` is false. |
| `hits` | Attack events the rule matched. |
| `misses` | Attack events the rule did not match. |
| `false_alarms` | Benign events the rule matched. |
| `matched_event_ids` | All matched events (attack and benign), in input order. |
| `per_transform` | For each of the six transform values (always all six keys): `attacks`, `hits`, `misses`, `benign`, `false_alarms`. |

Evasion resistance for a transform = `per_transform[t].hits / per_transform[t].attacks` (computed in the
metrics module, not the harness).

## Rule record

`rule_yaml`, `source` (`community`|`adapted`|`written`), `technique`, `trace_id`, `version` (≥ 1),
`status` (`proposed`|`approved`|`rejected`, default `proposed`).

## Open questions for Laure

1. **Base IDs**: OK with unmutated events having `base_id == event_id` (rather than null)?
2. **Extra Sysmon fields (added as optional, please confirm)**: `original_file_name` and
   `parent_command_line` are now optional event fields. Can you capture them from Sysmon for every event?
   Measured on SigmaHQ r2026-07-01: before, 717 of 1,297 Windows process-creation rules used a field we
   lacked (`OriginalFileName` in 559, `ParentCommandLine` in 75). With the two fields: 175 still use a
   missing field; 117 of those are harmless, 58 can never fire (mostly `IntegrityLevel`, `User`).
3. **Behavior verification**: should events carry a flag recording whether the mutation was confirmed in the VM?
4. **Binary renaming** (optional extension): it changes `image`, not just `command_line`. Use a separate
   transform value (e.g. `renaming`), reported separately from the five Uetz types?
