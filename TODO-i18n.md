# Korean -> English pass — DONE (2026-10-13)

No Korean is left in any tracked source file: comments, docstrings,
agent-facing strings and detector regexes are all English.

```bash
grep -rlP '[\x{AC00}-\x{D7A3}]' --include='*.py' .     # -> nothing
```

## How the last two files were verified

`tools.py` (445 lines) and `ledger.py` (2018 lines) were patched from a
pristine copy with line-addressed hunks, then checked with:

1. `python3 -m py_compile` — syntax.
2. **Token identity** — the token stream with comments dropped and adjacent
   string literals collapsed is identical to the pre-translation file
   (`CODE IDENTICAL` for both files).
3. **Format identity** — per logical line, the sequence of `%`-specs and the
   multiset of f-string `{expr}`s is unchanged, so no reworded sentence lost or
   reordered an argument.
4. `./run-tests.sh` — exit 0.
5. **Behaviour snapshot** — a fixed scenario (surface add/reach/set, controls,
   25 `verdict` calls across confirm/reject klasses/blocked/queues/track,
   population, coverage/graveyard/resisted/worklist/status_block, and every
   read-only tool) recorded as structure only, diffed before vs after. The only
   deltas are the two intended vocabulary changes below.

## Deliberate behaviour changes

| where | before | after | why |
|---|---|---|---|
| `ledger.POP_MEMBER_STATES` | Korean words | `unanalysed / safe / suspect / promoted / void` | the prompt in `agent_sdk.py` already told the agent `=safe` / `=suspect`, so every such member state was being **rejected** |
| `ledger.DEFAULT_STAGES` | Korean words | `static-confirm / trigger / measure / impact / boundary/submission` | the same words the prompt uses |
| `tools.py` surface reach ↔ `ledger.surface_reach` | Korean phrase | `"is not in the census table"` | a generator/matcher pair; moved together |
| detector regexes (`_CLOSURE_RX`, `_DF_RE`, `_RACE_RE`, `_SOLE_*`, `_ADMIN`/`_LOWER`, seed_goal, prose detector) | Korean + English alternatives | English only; an English term added only where one was missing | the agent writes English now. Korean text in **old** ledgers no longer triggers them |
| claim word tokenizer (`ledger.py`) | Latin + Hangul (U+AC00..U+D7A3) letters, 3+ | `[^\W\d_]{3,}` | any Unicode letter, so old Korean claims still tokenize |
| none-word tuples (`_NONE_OWNER`, `depends_on`, `_NA_DELTA`) | Korean "none"/"n/a" | `nothing` / `not-applicable` | a tuple element cannot be dropped without changing code tokens |

## Still true

- Prefix matchers come in pairs: `graveyard[` / `question` / `  this sample`
  are matched on; `startswith("R-A reopen")` in `ledger.py` still has no
  generator anywhere — a dead one-sided matcher.
- `verdict` (838 lines) and `_reject_gate` (546 lines) can now be refactored —
  that was held back only to keep the token-identity proof possible.

## Related, not part of this

- `runlog.py` is missing the decision-trace API that upstream has
  (`decision`, `decision_digest`, `decision_read`, `_decisions_path`,
  `_run_key`) — 384 lines here against 492 upstream.
- Next port phase: `mutate.py` + `mutbench.py`, the recall dashboard.
  `mkpe.py` already emits an import directory and `.pdata`, so a synthetic
  answer key needs no target material.
