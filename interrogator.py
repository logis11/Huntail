#!/usr/bin/env python3
# interrogator.py — the **Break-or-Sustain gate.** The mirror of `refuter.py`.
#
# Why it is needed — the pressure only existed on one side:
#   confirm -> an independent refuter comes to kill it (kill mandate: unsure => refuted)
#   reject  -> nothing but the static gate, and whatever the gate could not
#              decide went through
# Both defaults point **the same way (reject)**. That asymmetry is a leftover
# from the precision-only era; the objective function changed to "find as much as
# possible" and this was the one thing that never got flipped.
# Measured: of 262 rejections, **10 (3.8%)** were verified negatives.
#
# The mandate is inverted. The refuter kills when unsure (a false positive is
# expensive). The interrogator says **"when unsure, the rejection does not
# stand"** — a false rejection loses the bug **permanently**. A rejection that
# does not stand does not become a confirmation; it returns to `ASK`/`blocked`.
# The only thing lost is triage time.
#
# The context asymmetry carries over unchanged: the interrogator **cannot see the
# rejecter's reasoning.** It sees the claim and the evidence the rejection
# submitted, and nothing else.
import asyncio
import jsonscan
import submit

# The ways a rejection collapses — not generic theory, things this project has
# actually run into.
BREAK_CLASSES = {
    "wrong_pair":       "The guard/sink pair is not the one the claim is about. Is the dangerous "
                        "operation the claim names the same one the rejection verified? "
                        "(Real case: the claim was 'user pointer dereference' but the declared "
                        "sink was `mov rdx, r13`.)",
    "other_constructor": "A DIFFERENT constructor of the same object sets that field differently — "
                        "half the population is exempt. Were all constructors enumerated?",
    "door_only":        "The check happens ONCE at open/create and never per-operation. "
                        "Was it verified to reapply on each operation?",
    "indirect_entry":   "A function pointer, vtable, dispatch table or callback reaches the sink "
                        "while BYPASSING that guard. `callers()` only sees direct calls.",
    "double_fetch":     "The value checked and the value used are DIFFERENT reads. If it is a user "
                        "buffer, it can change in between.",
    "race_partner":     "An asynchronous partner (cancel routine, completion routine, work item, "
                        "DPC, timer, PnP) mutates that state. Is the rejection only looking at a "
                        "single request?",
    "bound_wrong":      "The guard dominates the sink but the BOUNDARY CONSTANT is wrong. "
                        "Dominance proves execution, not constraint.",
    "signed_compare":   "The comparison is signed, so a negative input passes the bound.",
    "window_too_short": "'There is/isn't a check' was judged inside a FIXED-SIZE window. It may sit "
                        "one hop away (thunk, helper).",
    "not_measured":     "This is a static rejection. Does the handler actually EXECUTE at all? "
                        "If it returns early, that is unmeasured, not clean.",
}

PROMPT = """You are an INTERROGATOR. Someone REJECTED a vulnerability candidate — they claim
it is NOT a bug. Your job is to BREAK THAT REJECTION. You are not reviewing it; you are
attacking the reasons it was dismissed.

You have deliberately been given ONLY the claim and the evidence the rejecter submitted.
You cannot see how they reasoned. That is the point.

MANDATE — if you are NOT SURE the rejection holds, the rejection DOES NOT STAND.
This is the mirror of the refuter's mandate, and the asymmetry is deliberate: a false
confirmation costs triage time, but a false rejection loses the bug permanently. A rejection
that does not stand does NOT become a confirmation — it goes back to the open-question queue.

Work it with the tools. Check, in this order — the cheap breaks come first:
{classes}

Then SUBMIT your verdict by calling the `submit_verdict` tool EXACTLY ONCE:
  submit_verdict(sustained=…, klass=…, reason=…, next_method=…)
The tool call IS the verdict. Do not write it as prose or JSON in the body —
text is not read. Call the tool, then stop.

TARGET   : {target}
CLAIM (the alleged vulnerability): {claim}
REJECTION EVIDENCE (as submitted):
{evidence}
GATE RECORD (what the machine actually verified — note what it did NOT verify):
{gate}
{nudge}"""


def _fmt():
    return "\n".join(f"  {i+1}. {k} — {v}" for i, (k, v) in enumerate(BREAK_CLASSES.items()))


def build_prompt(target, claim, evidence, gate, nudge=""):
    return PROMPT.format(nudge=nudge, classes=_fmt(), keys="|".join(BREAK_CLASSES), target=target,
                         claim=claim, evidence=(evidence or "(none supplied)")[:4000],
                         gate=(gate or "(no gate record — that is itself grounds for suspicion)")[:2000])


# The `_JSON` regex was removed: `[^{}]*` could not read nested objects and
# dropped valid responses as no_json. `jsonscan` does it by brace balance.


# This is the spot where **a malfunction used to be laundered into a result.**
#   The interrogator twice failed to emit JSON, and the agent was told "the
#   interrogator broke your rejection"; the counters went up as broke/killed too.
#   That is why `failed` was **0 in every single run**. The agent could not tell
#   "my argument was wrong" from "the checker returned nothing", so it burned
#   rounds resubmitting the same claim in different words.
#   => Undecidable is a **third state**. Put None in the verdict key and attach a
#      fault. (A reason string alone cannot carry unknown — the consumer reads
#      the key as a bool.)
def parse_verdict(text, bucket=None):
    """A parse failure lands as **the rejection not standing** (mirror of the refuter)."""
    if bucket:
        # Submitted through the tool — no parsing at all. The API guaranteed the shape.
        d = dict(bucket); d["via"] = "tool"; d.pop("fault", None)
        return _normalize(d)
    # Fallback: the tool was not called. Keep the old path but mark it via `via`.
    d, fault, why = jsonscan.parse_last(text, "sustained")
    if fault == "no_json":
        return _normalize({"sustained": None, "fault": "no_json", "klass": None,
                "reason": "The interrogator never submitted a verdict — UNDECIDABLE. This is a malfunction, not a collapsed rejection.",
                "next_method": ""})
    if fault == "bad_json":
        return _normalize({"sustained": None, "fault": "bad_json", "klass": None,
                "reason": "Interrogator output could not be parsed (%s) — UNDECIDABLE." % why,
                "next_method": ""})
    d.setdefault("via", "text")
    return _normalize(d)


def _normalize(d):
    """Make the tool path and the text path pass through the **same rules**."""
    if d.get("fault"):
        # **Single enforcement point** — a fault NEVER becomes a verdict.
        #   This invariant used to rest only on **control flow** (the fault
        #   returns did not go through `_normalize`). It lived in the comments
        #   and the tests but had no enforcement point in the code, which means
        #   adding a new fault path without knowing the rule breaks it silently —
        #   and None is falsy, so the consumer reads it as a verdict. That is the
        #   very laundering these files exist to stop. **Now every return passes
        #   through here.**
        d["sustained"] = None
        return d
    d["sustained"] = bool(d.get("sustained", False))     # the default is False
    return d


async def run(server, target, claim, evidence, gate, model=None, max_turns=25,
              tools=(), cwd=None, timeout=900, _retry=1, _nudge=""):
    """Run the interrogation in an independent session. On failure, (None, reason) —
    the gate does NOT treat "the run failed" as "the rejection passed"."""
    from claude_agent_sdk import (ClaudeSDKClient, ClaudeAgentOptions,
                                  AssistantMessage, TextBlock)
    # Session-private submission channel. It does not touch the ledger; it is
    # only this call's return channel.
    _sub_srv, _bucket = submit.make("sustained")
    _tools = list(tools) + [submit.TOOL_FQN]
    opts = ClaudeAgentOptions(
        model=model, system_prompt="You are an adversarial interrogator. Terse. Tool-first.",
        cwd=cwd, mcp_servers={"vuln": server, "submit": _sub_srv},
        # Pass **both** `tools=` and `allowed_tools=` (measured).
        #   `allowed_tools` alone is not a restriction — it is a permission
        #   allowlist, so Bash stayed alive. `tools=` alone gets MCP calls
        #   blocked on permissions. Both together is the only working shape:
        #     allowed_tools=RO            -> MCP=yes **BASH=yes**  (hole)
        #     tools=RO                    -> MCP calls block on permission
        #     tools=RO + allowed_tools=RO -> MCP returns data, no Bash/Write  OK
        tools=_tools, allowed_tools=_tools, permission_mode="acceptEdits",
        max_turns=max_turns, setting_sources=[],
    )
    out = []
    try:
        async def _go():
            async with ClaudeSDKClient(options=opts) as c:
                await c.query(build_prompt(target, claim, evidence, gate, nudge=_nudge))
                async for msg in c.receive_response():
                    if isinstance(msg, AssistantMessage):
                        for b in msg.content:
                            if isinstance(b, TextBlock):
                                out.append(b.text)
        await asyncio.wait_for(_go(), timeout=timeout)
    except asyncio.TimeoutError:
        return None, f"interrogator timed out ({timeout}s)"
    except Exception as e:
        return None, f"interrogator failed to run: {type(e).__name__}: {e}"
    v = parse_verdict("\n".join(out), _bucket)
    if v.get("fault") and _retry > 0:
        return await run(server, target, claim, evidence, gate, model=model,
                         max_turns=max_turns, tools=tools, cwd=cwd, timeout=timeout,
                         _retry=_retry - 1, _nudge=submit.RETRY_NUDGE)
    return v, "\n".join(out)[-1500:]
