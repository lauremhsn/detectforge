# Fixture dataset

Synthetic, hand-written events for developing the harness and the agent before the real mutation set
exists. **Not VM-verified**: the mutated command lines have not been run to confirm they keep the
original behavior. Do not use these events for reported results.

- `events.jsonl`: 17 events, two techniques.
  - T1053.005 (schtasks): 1 base attack, 4 mutations, 3 hard negatives (`/query`, a vendor updater
    creating a task, `/change /disable`).
  - T1105 (certutil download): 1 base attack, 5 mutations, 3 hard negatives (`-hashfile`,
    `-urlcache * delete`, `-verify -urlfetch`).
  - Split by transform type: insertion/substitution/omission are `tune`; reordering/recoding are `heldout`.
- `rules/`: fixture Sigma rules written for this project in the style of community rules (not copied
  from SigmaHQ). `*_literal.yml` match exact argument strings and miss some transforms on purpose;
  `schtasks_create_robust.yml` is a behavior-based variant.
