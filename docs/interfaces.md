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
| `label` | `attack` \| `benign` | |
| `technique` | `T####` or `T####.###` | For benign events: the technique the event resembles. |
| `transform` | `none` \| `insertion` \| `substitution` \| `omission` \| `reordering` \| `recoding` | Uetz et al. taxonomy. |
| `base_id` | string | The event this one was mutated from. **Unmutated events point to themselves** (`base_id == event_id`), so grouping by `base_id` gives each base with all its variants. |
| `split` | `tune` \| `heldout` | |

Sigma field mapping used by the harness: `Image → image`, `CommandLine → command_line`,
`ParentImage → parent_image`. Every other Sigma field (e.g. `OriginalFileName`, `User`) is treated as
absent: it never matches a value, matches `null`, and matches `|exists: false`.

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
2. **Extra Sysmon fields**: many SigmaHQ process-creation rules also use `OriginalFileName`,
   `ParentCommandLine`, `User`, `IntegrityLevel`, `CurrentDirectory`. Today the harness treats them as absent, which
   can make community rules look weaker than they are in a real SIEM. Should we add `original_file_name`
   and `parent_command_line` to the event now, while it is cheap?
3. **Behavior verification**: should events carry a flag recording whether the mutation was confirmed in the VM?
4. **Binary renaming** (optional extension): it changes `image`, not just `command_line`. Use a separate
   transform value (e.g. `renaming`), reported separately from the five Uetz types?
