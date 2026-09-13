#!/usr/bin/env python3
# adjudicator.py — the **adjudicator.** The only device that breaks the loop.
#
# Why (measured across the ledger):
#   The interrogator's rate of breaking rejections was 64%, 72% and 88% on three
#   separate targets. A broken rejection goes back to ASK, the next round's
#   analyst rejects it again, and it breaks again. Individual rows hit the same
#   question **four or five times** — 6 rows on one target, 8 on another.
#   `attempts` was counted and **there was no forced termination point.**
#
# The literature names exactly this missing part:
#   - Refute-or-Promote (arXiv 2604.19049) — the same structure we have, except it
#     has a `judge/adjudicator`. Our own notes had marked that as absent and left
#     "whether to add an adjudicator" undecided.
#   - MAD with Adaptive Stability Detection (arXiv 2510.12697) — the key parts are
#     a round cap and **a defined output on non-convergence**. We had the cap but
#     not the second half, which is how it became infinite retry.
#   - Nine Judges, Two Effective Votes (arXiv 2605.29800) — **adding judges or
#     diversifying models is a dead end**: nine judges are worth 2.18 effective
#     votes, and splitting families buys a correlation drop of only 0.047.
#     => Do not attach more adversaries. Add one **terminator**.
#
# Its role is the **opposite** of the other three.
#   refuter / interrogator / escalator : they attack. Their context is
#                                        **deliberately blinded** (anti-collusion).
#   adjudicator                        : it terminates. It is **the only agent
#                                        here that sees the whole record**, and
#                                        the very fact that the earlier
#                                        adversaries knew nothing of each other is
#                                        what makes that record worth something.
#
# Operator decision: the adjudicator is allowed to `confirm`.
#   The original design recommendation was `reject|exhaust` only (never open the
#   precision direction). The operator chose to run it with confirm for a day and
#   score it afterwards. So:
#     - every decision records `decided_by='adjudicator'` plus the full history
#     - the conductor digest displays those separately
#     - there is a scoring hook to audit them
#   => the audit table alone is enough to revert this or narrow the permission.
import asyncio

import jsonscan
import submit

VERDICTS = ("confirm", "reject", "exhaust")

PROMPT = """You are an ADJUDICATOR. A single row in a vulnerability ledger has been argued
{n} times and has never terminated. Your decision ends it.

You are NOT another attacker. Three adversaries already ran, and each of them was
DELIBERATELY BLIND — the refuter never saw the analyst's reasoning, the interrogator never saw
the rejecter's, and none of them saw each other. That blindness is what made their verdicts
independent. It is also why they never converged: nobody was in a position to weigh them
together. YOU ARE. You are the only agent here holding the whole record.

So do not re-run their arguments. Weigh them.

WHAT ENDLESS ARGUMENT USUALLY MEANS — check these before deciding:
1. The two sides are answering DIFFERENT QUESTIONS. One argues the mechanism is real, the other
   argues it is unreachable. Both can be right; the row is then a confirm with a reachability
   caveat, or an exhaust, but never an endless loop.
2. A MEASUREMENT NOBODY MADE is load-bearing for both sides. That is `exhaust` — say what the
   measurement is.
3. One side is arguing from a TOOL LIMITATION, not from the code (a gate that could not express
   the shape). Do not treat a harness limitation as evidence about the binary.
4. The claim MUTATED between attempts. If attempt 4 is not the same claim as attempt 1, the row
   was never actually contested — say so and pick the claim that the evidence supports.

DECIDING
- `confirm` — the defect stands. You are ending the adversarial process, so hold this to the
  standard the refuter would have: a named mechanism, an anchor, and who can reach it.
- `reject` — the rejection stands. The row closes as a negative and counts toward coverage.
- `exhaust` — neither can be established from what exists. Name the missing observation.
  THIS IS A REAL ANSWER, not a failure. Choosing it when you cannot name a decisive anchor is
  more valuable than a coin flip, because the loop stops either way.

You have read-only tools. Use them to check the ONE thing that decides it — not to redo the
whole analysis. If after that you still cannot name a decisive anchor, the answer is `exhaust`.

Then SUBMIT by calling the `submit_verdict` tool EXACTLY ONCE:
  submit_verdict(verdict=…, reason=…, decisive=…, residual_risk=…)
The tool call IS the decision. Body text is not read.

ROW      : {target}
CLAIM    : {claim}
ATTEMPTS : {n}

===== FULL HISTORY (nobody before you saw this) =====
{history}
====================================================
{nudge}"""


def build_prompt(target, claim, history, n, nudge=""):
    return PROMPT.format(target=target, claim=(claim or "(none recorded)")[:1200],
                         history=(history or "(empty)")[:12000], n=n, nudge=nudge)


def _normalize(d):
    """A fault NEVER becomes a verdict — the same single enforcement point the
    other adversaries have."""
    if d.get("fault"):
        d["verdict"] = None
        return d
    raw = d.get("verdict")
    v = str(raw or "").strip().lower()
    if v not in VERDICTS:
        # Outside the vocabulary is not a verdict. We do not read 'confirm-ish'
        # as confirm — that kind of leniency is exactly what this repository has
        # been losing to.
        # Capture `raw` BEFORE overwriting the key: reading it back afterwards
        # reports "returned None" for every out-of-vocabulary answer, which hides
        # the one fact the operator needs (what the model actually said).
        d["verdict"] = None
        d["fault"] = "bad_verdict"
        d["reason"] = ("Adjudicator returned %r, which is not one of %s — UNDECIDABLE."
                       % (raw, "|".join(VERDICTS)))
        return d
    d["verdict"] = v
    # A confirm requires a decisive anchor. Without one it is downgraded to
    # exhaust (the same discipline the escalator has).
    if v == "confirm" and not str(d.get("decisive") or "").strip():
        d["verdict"] = "exhaust"
        d["downgraded_from"] = "confirm"
        d["reason"] = ("(downgraded: confirm with no decisive anchor) "
                       + str(d.get("reason") or ""))[:900]
    return d


def parse_verdict(text, bucket=None):
    if bucket:
        d = dict(bucket); d["via"] = "tool"; d.pop("fault", None)
        return _normalize(d)
    d, fault, why = jsonscan.parse_last(text, "verdict")
    if fault == "no_json":
        return _normalize({"verdict": None, "fault": "no_json",
                           "reason": "The adjudicator never submitted a decision — UNDECIDABLE. "
                                     "This is a malfunction; the row stays open."})
    if fault == "bad_json":
        return _normalize({"verdict": None, "fault": "bad_json",
                           "reason": "Adjudicator output could not be parsed (%s)." % why})
    d.setdefault("via", "text")
    return _normalize(d)


async def run(server, target, claim, history, n, model=None, max_turns=30,
              tools=(), cwd=None, timeout=900, _retry=1, _nudge=""):
    """Independent session. A failure is (None, reason) — a malfunction is never
    laundered into a decision."""
    from claude_agent_sdk import (ClaudeSDKClient, ClaudeAgentOptions,
                                  AssistantMessage, TextBlock)
    _sub_srv, _bucket = submit.make("adjudicated")
    _tools = list(tools) + [submit.TOOL_FQN]
    opts = ClaudeAgentOptions(
        model=model, system_prompt="You are an adjudicator. Terse. Decide, do not re-argue.",
        cwd=cwd, mcp_servers={"vuln": server, "submit": _sub_srv},
        tools=_tools, allowed_tools=_tools, permission_mode="acceptEdits",
        max_turns=max_turns, setting_sources=[],
    )
    out = []
    try:
        async def _go():
            async with ClaudeSDKClient(options=opts) as c:
                await c.query(build_prompt(target, claim, history, n, nudge=_nudge))
                async for msg in c.receive_response():
                    if isinstance(msg, AssistantMessage):
                        for b in msg.content:
                            if isinstance(b, TextBlock):
                                out.append(b.text)
        await asyncio.wait_for(_go(), timeout=timeout)
    except asyncio.TimeoutError:
        return None, f"adjudicator timed out ({timeout}s)"
    except Exception as e:
        return None, f"adjudicator failed to run: {type(e).__name__}: {e}"
    v = parse_verdict("\n".join(out), _bucket)
    if v.get("fault") and _retry > 0:
        return await run(server, target, claim, history, n, model=model, max_turns=max_turns,
                         tools=tools, cwd=cwd, timeout=timeout, _retry=_retry - 1,
                         _nudge=submit.RETRY_NUDGE)
    return v, "\n".join(out)[-1500:]
