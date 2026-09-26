```
   ██╗  ██╗██╗   ██╗███╗   ██╗████████╗ █████╗ ██╗██╗     
   ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔══██╗██║██║     
   ███████║██║   ██║██╔██╗ ██║   ██║   ███████║██║██║     
   ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══██║██║██║     
   ██║  ██║╚██████╔╝██║ ╚████║   ██║   ██║  ██║██║███████╗
   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝
                                        Autonomous Vulnerability Finding
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣶⠦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢦⠙⢷⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⣄⡙⣄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⠔⠒⠢⣄⡀⢀⡠⠖⠐⠲⣄⠀⢀⡴⠚⠉⠀⣀⣀⠉⠢⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡤⢄⡀⢠⠮⠀⢀⣀⣀⣀⣹⡮⠤⠤⠤⠤⠬⠧⠋⠀⠀⢠⠊⠀⠀⠹⣆⠈⠢⡀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⠖⠒⠉⠉⠉⠉⠉⠉⠒⠒⠤⣄⡀⠀⠀⠀⠀⠀⠀⠀⡼⠃⢀⣠⠽⢷⠚⠙⠏⠀⠀⢀⣀⡠⠤⠤⠤⠤⠤⢤⡀⠀⠀⢣⡀⠀⠀⢀⣿⠀⠀⢈⣳⡄
⠀⠀⠀⠀⠀⠀⢀⠔⠋⠀⠈⢆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣹⠦⡀⠀⢀⡠⢾⢀⡴⠋⠀⠀⠸⣀⣀⡼⠞⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠑⢄⠀⠀⠛⠷⠶⠟⢁⡠⠖⠋⠁⠀
⠀⠀⠀⠀⠀⠰⡏⠀⠀⠀⠀⠈⢣⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⠁⠀⠈⠳⣏⠀⢸⣼⡴⠒⠋⠘⠒⢿⡉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⣲⠄⣀⠤⠒⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠳⣄⠀⠀⠀⠈⢧⠀⠀⠀⠀⠀⠀⠀⢀⡜⠁⠀⠀⠀⠀⠈⢦⠘⢿⣀⠀⠀⠀⠀⠀⢹⣄⣠⠔⠂⠉⠲⣄⠀⠀⠀⠀⠀⠀⢀⠞⠁⡴⠃⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣤⠀⠀⠈⢇⠀⠀⠀⠀⠀⣠⠎⠀⠀⠀⠀⠀⢀⣠⠞⠁⠀⠀⠉⠓⠒⠢⠤⠤⢿⣁⣀⠀⠀⠀⠈⢷⠀⠀⠀⠀⠀⣏⠴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢄⡀⠸⡄⠀⠀⠀⡴⠁⠀⠀⢀⣠⠴⠚⠋⠳⣄⡀⠀⠀⠀⠀⠀⡰⠋⠉⠆⠀⠀⠉⠓⠦⣀⠈⡗⠦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣙⣤⣧⣀⣀⡞⢀⣠⠴⠚⠉⠀⠀⠀⠀⠀⠀⠉⠓⠲⠤⢤⣀⣻⡄⢀⡄⠀⠀⠀⠀⡀⠈⢦⡇⢸⡈⠳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣠⠔⠊⠉⠀⠀⠀⠀⠀⠀⠈⠙⠓⢤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠒⣶⡞⠉⠁⠈⠉⣻⠀⠀⠳⣦⣹⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣀⠈⠓⢄⠀⠀⠀⠀⣠⣴⠖⠂⠒⠒⠤⣀⠀⠀⡜⠁⠀⠀⠀⢀⡴⠁⠀⠀⠀⠈⠙⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣴⡟⢁⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⠋⡝⢿⣄⠀⠱⣤⣀⣜⡟⠁⠀⠀⠀⠀⠀⠈⠳⣤⡇⠀⠀⣀⡴⠋⠀⠀⠀⠀⠀⠀⢀⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⡼⠋⣴⠏⠀⢻⠀⠀⢠⡾⠋⠙⢷⡀⠀⠈⣿⣆⠻⠈⣿⠀⠀⠀⠈⠙⠒⠤⠤⣀⣀⣀⣀⣀⣀⣸⠧⠔⠊⠁⠀⣰⠒⠲⡀⠀⠀⢀⡞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⡇⠀⣟⣀⣠⡾⠀⠀⢿⡁⠀⠀⣸⡇⠀⠀⠘⠿⣶⣶⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠤⣄⠀⠀⠀⠀⠀⠀⢸⠃⠀⢀⡇⠀⣠⠞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠹⡦⣌⣉⡉⠀⠀⠀⠈⠷⠶⠼⠋⠀⠀⠀⣀⣠⡴⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠁⠀⠈⢱⠀⠀⠀⠀⠀⠘⢷⣠⡾⣀⠔⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠹⣴⣹⣯⣏⠙⢒⣶⡶⠶⢶⠒⠉⡿⠭⠴⢾⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣷⣀⢀⣼⠇⠀⠀⠀⠀⢀⣀⠭⠚⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣸⡟⣠⠿⢦⡎⠀⠀⠀⠀⠑⠾⠀⠀⠀⠸⡄⠀⠀⠀⠀⢀⡄⠀⠀⠀⠀⠀⠀⠈⠙⠛⠁⢀⣀⠤⠔⠚⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣀⡼⣿⠻⣼⠋⠀⠀⠀⠀⠀⠀⠀⠀⢠⠀⠀⠀⠀⢧⠀⠀⠀⢰⡋⠀⠀⠀⢀⣀⠤⠤⠒⠒⠋⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢠⡟⠁⡇⠘⣦⡃⠀⠀⠀⠀⠀⠀⠀⠀⢀⡞⠳⡀⠀⠀⢸⠀⠀⠀⡎⢳⣠⠔⠊⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠈⢷⡀⠳⠤⢿⣧⡄⠀⠀⠀⠀⠀⠀⠀⡼⠀⠀⢱⣄⡴⠋⠀⠀⣰⠁⠀⢷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢨⠿⣄⠀⠀⠀⠉⠙⠒⠒⠒⠒⠒⠒⠓⠒⠒⠉⠁⠀⠀⢀⣴⠃⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⡎⠀⢀⣥⠟⠁⠈⠉⠀⠀⠒⠒⠒⠦⢤⣀⣀⣀⠤⠔⠒⠉⠀⠀⠀⠀⡞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢧⠶⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣄⠀⠀⠀⠀⠀⠀⢀⠜⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⠶⣤⣤⡤⠞⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
```

# huntail

An autonomous binary vulnerability-analysis harness built on the Claude Agent SDK.

The deep-sea fish it is named for hunts with its **tail**: the tail carries a
lure, and what the lure attracts is what gets eaten. That is the shape of this
harness. The analyst does not produce findings — it produces claims, and the tail
is the adversarial panel those claims have to swim into. What survives the panel
is a finding. What does not is a ledger row with a reason attached.

Its structure resembles a CTF exploitation harness, but **the pressure runs the
opposite way.**

|                | CTF harness                       | huntail                                          |
|----------------|-----------------------------------|------------------------------------------------|
| Goal           | a flag (a binary success signal)  | a verdict: **confirmed / rejected / unanalysed** |
| Failure it stops | rabbit holes                    | **false positives** and fake coverage           |
| Gate           | no exploitation without a hypothesis | **no confirmation unless the anchor verifies against the binary** |
| Ledger         | hypotheses and failure fingerprints | **an exhaustive table, evidence strength, controls, a graveyard** |

## Why only precision is tightened

On function-level vulnerability-adjudication benchmarks, **frontier models run a
33-45% false-positive rate**, and some classify **69% of all samples as
vulnerable**. Recall is already in the 0.9s. The bottleneck is not the ability to
find things; it is **the ability not to emit the wrong ones.** So every gate in
this harness is built in the one direction: making a confirmation harder to
reach.

What was borrowed, and what implements it here:

| Result borrowed | What corresponds to it here |
|---|---|
| Naptime's **perfect verification** — structure the task so the answer is checked automatically and with certainty | **machine anchor verification** (`evidence.py`). The static-binary equivalent of a sanitizer |
| Naptime — **many independent trajectories** beat one long run (pass@20 >> pass@1) | independent sampling plus consensus scoring |
| COTS binary agents — just attaching a toolset lifted Claude Code's F1 by **+0.214**; half of 33 tools were navigation | a navigation tool family, so the model spends its turns judging rather than re-deriving |
| The same work — a **stop-time verifier** against plan-only exits, and **pre-compaction checkpointing** | a `Stop` gate, a `PreCompact` hook, an on-disk ledger, a `note` tool |
| Adversarial stage gates — kill rates of 63% / 42%, and **a context-asymmetric cold-start refuter is the highest-value signal** | `refuter.py`. The refuter sees only the claim and the evidence |
| The same work — ten unanimous reviewers approved an OpenSSL padding oracle that **did not exist**, and one measurement killed it | a failed refutation is not a pass; a measurement-based rejection requires a positive control |
| Web benchmarks — a classification whose precision matters belongs to **a deterministic node, not an LLM** | anchor verification, control-code decoding and relocation are all Python. The model only judges |
| Variant analysis is where LLMs genuinely work (the seed removes the ambiguity) | a seeded variant-hunting mode |
| Accuracy drops 13.9-85% on long tasks from context length alone | the ledger and the notes live outside the context |

That table describes the harness as a whole. This repository is being published
in pieces — see *What is in this commit* below for what is actually here yet.

## The adversarial panel

A verdict is not something an analyst records. It is what survives a panel, and
every member of that panel has a **different mandate** and a **deliberately
restricted view**.

```
                    analyst  (has tools, writes the ledger)
                       │
        confirm ───────┼─────── reject            weak impact
           │           │           │                   │
      refuter.py       │    interrogator.py      escalator.py
   "unsure => kill"    │  "unsure => the         "delta zero is not
                       │   rejection does         a destination — but
                       │   not stand"             never invent a principal"
                       │
                  (same row argued N times)
                       │
                 adjudicator.py
        "confirm | reject | exhaust" — the only device that terminates
```

- **Context asymmetry is the point.** The three attackers receive the claim and
  the submitted evidence only — never the reasoning that produced it, never each
  other's verdicts. An independent look that lands somewhere else is worth more
  than agreement from someone who already read your argument.
- **The mandates are deliberately asymmetric.** A false confirmation costs triage
  time; a false rejection loses the bug permanently. So the refuter kills when
  unsure and the interrogator breaks the rejection when unsure.
- **One device pushes up.** Every other gate pushes down, which is how a harness
  ends up stopping at "delta zero". The escalator's question is not "is there a
  delta" but *"for which principal, path, consumer or window is the delta
  nonzero?"*
- **The adjudicator is the only member that sees everything**, and it is the only
  one allowed to end a row. Adding more attackers does not help: nine judges are
  worth ~2.18 effective votes, and splitting model families buys a correlation
  drop of 0.047. What was missing was not another opinion but a terminator.

## Two contracts the code enforces rather than documents

**1. Undecidable is a third state.** A checker that returns nothing has *not*
returned a verdict.

Once upon a time the interrogator failed to emit JSON and the agent was told "the
interrogator broke your rejection"; the counters agreed. The result was that
`failed` read 0 in every run — a malfunction had never once been counted as one —
and the agent, unable to tell "my argument was wrong" from "the checker returned
nothing", burned rounds resubmitting the same claim in different words.

So every adversary returns `None` plus a `fault` when it cannot decide, and every
single return path passes through one enforcement point (`_normalize`). The rule
had lived in comments and tests before that, resting only on control flow — which
means it broke silently the moment a new fault path was added, and `None` is
falsy, so the consumer read it as a verdict.

**2. A verdict is submitted through a tool, not written as prose.** Asking a
model in a prompt to "emit exactly one JSON object" guarantees nothing; `tools=`
is a structural parameter of the request and changes the output format itself.
Measured: of 20 confirmations killed by the refuter, **4 (20%) were actually
parse failures**, all laundered into `refuted`. The adversaries now get a
submission tool with a typed schema — and no ledger access, because they still
only read and judge.

## What is in this commit

The deterministic substrate, the adversarial panel, and the agent loop that
wires them together — the harness now runs end to end.

The substrate and the panel:

| File | What it is |
|---|---|
| `pe.py` | Read-only PE32+ parser, `.pdata` function bounds, disassembly, and **cross-build anchor relocation** (rip-relative and rel32 masked, so "the code moved" and "the code changed" stop being the same observation) |
| `evidence.py` | The anchor gate. Parses `0xADDR mnem ops` citations out of evidence text and verifies each against the measured build |
| `jsonscan.py` | Brace-balanced JSON extraction. Replaced a regex that could not read nested objects |
| `submit.py` | The adversaries' typed submission channel (per-session server and bucket) |
| `refuter.py` | Refute-or-Promote. Kill mandate |
| `interrogator.py` | Break-or-Sustain. The mirror, with the inverted mandate |
| `escalator.py` | The only upward pressure. Never invents a principal |
| `adjudicator.py` | The terminator. `confirm / reject / exhaust` |
| `doctrine.py` | False-positive pressure on the analyst's own prose: absence claims, hedges, decompiler-only basis, negatives without a control |
| `verifier_guard.py` | **A verifier that has not passed its positive control has no right to emit a result.** A broken verifier and a clean target produce the same output |
| `config.py` | Every knob is an environment variable, and **every gate can be turned off** — a gate you cannot disable cannot be measured |
| `mkpe.py` | Builds a minimal valid PE32+ so the anchor gate can be tested against a real image without shipping one |

The loop that wires the panel to the gates:

| File | What it is |
|---|---|
| `agent_sdk.py` | The agent loop. Registers the tool surface, runs the analyst against the gates, and calls the panel on every `verdict` — the entry point (`python3 agent_sdk.py <binary> [corpus.c]`) |
| `ledger.py` | The ledger. Lives on disk, not in context: the exhaustive surface table, candidate lifecycle (proposed → refuted / promoted), the graveyard, coverage accounting, and the machine-verified anchors stored with every confirmation |
| `tools.py` | The tool registry — 31 tools, 20 read-only: identity, navigation (`census`/`callers`/`callees`/`callpath`/`func_at`), code (`disassemble` for adjudication, `decompile` for navigation), the deterministic nodes (`anchor`, `dispatch_table`), and the ledger tools (`surface`/`verdict`/`control`) |
| `nav.py` `xref.py` `authz.py` | Capstone-level navigation the registry builds on: function bounds, direct-call cross-references, and reachability from an authorization boundary |
| `runlog.py` | One metrics line per run; notes the analyst leaves outside the context |

The measurement side of `tools.py` — the IDA worker, the kernel debugger and
the guest-VM probe — is per-lab and **off by default** (`USE_IDA` degrades to a
"USE_IDA=0" reply, `ALLOW_*` stay disabled). A skeleton run touches none of it;
the capstone disassembler plus the anchor gate plus the panel need nothing there.

Still to come: the regression benchmark. Its harness is portable, but its answer
key was the confirmations and kills of a specific target — which is target
material — so it arrives rebuilt against a synthetic image, not lifted.

```bash
pip install -r requirements.txt
./run-tests.sh
```

## What this repository does not contain

Target material. No binaries under analysis, no decompilation corpora, no
ledgers, run transcripts, findings or reports — those are per-target and stay
local. The incidents cited throughout the comments are kept because **the reason
a gate exists is the most load-bearing part of it**; the targets they happened on
are not.
