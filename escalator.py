#!/usr/bin/env python3
# escalator.py — the **escalator.** The only device in this harness that pushes
# a finding **up**.
#
# Why it is needed — all the pressure ran downward:
#   confirm -> the refuter comes to kill it        (down)
#   reject  -> the interrogator comes to kill it   (down)
#   the four doctrine checks, anchors, the graveyard, the CFG gate  (all down)
#   **devices that push a weakly-stated finding up = zero**
# So the harness just stopped at "delta zero". There are verdicts closed that way
# in the ledger.
#
# Meanwhile every finding in this project that produced value came from **turning
# the question once at that exact point**:
#   An ownership check that was skipped was confirmed all the way to measurement,
#   and then a single request over the loopback path returned the same body, so
#   the delta was zero and the author downgraded it to "not a CVE" himself.
#   Instead of dropping it there, the question changed to
#   **"for WHICH principal is the delta nonzero?"** Enumerating every ACE of the
#   object's security descriptor showed a sandbox capability SID explicitly
#   granted, and that sandbox was blocked on the other axis (loopback) — so
#   unreachable-by-the-normal-path and allowed-here held in one and the same
#   process, and the delta was real.
#   That one move revived a dead finding, and until now **a human had to make it
#   by hand every time.**
#
# The mandate differs from both the refuter's and the interrogator's:
#   refuter:      "when unsure, kill"
#   interrogator: "when unsure, the rejection does not stand"
#   escalator:    **"do not accept delta zero as a destination."** But it must
#   **never invent a principal** — if it enumerates and finds nothing, the right
#   answer is `escalated=false` **naming what was enumerated.**
#   (A fabricated principal is worse than a false positive: the next round builds
#   on top of it.)
#
# Context asymmetry as before: the escalator cannot see the verdict's reasoning.
# It sees the claim, the evidence and the impact.
import asyncio
import jsonscan
import submit

# The axes that have **actually flipped** a delta that looked like zero. Not
# generic theory — things this project went through.
LIFT_AXES = {
    "principal_sd_ace":  "Parse the object's security descriptor and read EVERY ACE. Read the ACE "
                         "list not as 'who can write this' but as 'WHICH SANDBOX CAN GET OUT "
                         "THROUGH THIS DOOR'. If some principal is granted access here yet is "
                         "blocked on the path it would otherwise use (network / loopback / "
                         "isolation), the delta is real for that principal.",
    "restricted_token":  "Even inside one principal set, the presence of a restricted SID or a "
                         "lockdown token has decided allow-vs-deny before. Split 'all of them' "
                         "from 'only some' — if it splits, the headline must be rewritten on "
                         "that axis.",
    "other_consumer":    "Is there ANOTHER consumer of that data outside this image (a user-mode "
                         "engine, another driver, a boot-time restore path)? The one consumer we "
                         "measured may not be the ceiling.",
    "timing_window":     "Is there a window in which the normal path is CLOSED (pre-boot, service "
                         "stopped, immediately after servicing)? Inside that window the delta is "
                         "not zero.",
    "cross_session":     "Does the normal path break across a session / container / silo boundary? "
                         "One machine holds several isolation boundaries.",
    "write_vs_read":     "Even when the READ delta is zero, the delta for WRITE, INVALIDATE or "
                         "PREEMPT may not be. Did you look at the opposite-direction operation on "
                         "the same surface?",
    "aggregate_to_specific": "A global aggregate has no owner, but if a SPECIFIC principal's state "
                         "can be inferred back out of it, it is an oracle. Can you distinguish a "
                         "third outcome (condition-not-met vs. request-denied)?",
    "chain_input":       "Does this capability become the INPUT to another defect? Even with a "
                         "standalone delta of zero it has value as a primitive (e.g. arbitrary key "
                         "preemption -> input control over another parser).",
}

PROMPT = """You are an ESCALATOR. A finding has been judged and its impact came out WEAK —
delta zero, no owner, or a low grade. Your job is NOT to check whether it is correct.
Someone else already did that. Your job is to find out whether it was UNDERVALUED.

You have deliberately been given ONLY the claim, the evidence, and the impact assessment.
You cannot see how they reasoned. That is the point.

MANDATE — do not accept "delta is zero" as a terminal answer. The question is not
"is there a delta" but **"for WHICH PRINCIPAL, path, consumer or window is the delta nonzero"**.
This exact pivot has revived a finding that its own author had already written off.

BUT — and this decides whether you are useful or harmful — **do not invent a principal.**
If you enumerate and find nothing, say so and name what you enumerated. A fabricated principal
is worse than a false positive: the next session builds on top of it.

Work it with the tools. Check these axes, cheapest first:
{axes}

Then SUBMIT your verdict by calling the `submit_verdict` tool EXACTLY ONCE:
  submit_verdict(escalated=…, axis=…, principal=…, reason=…, next_method=…, enumerated=…)
The tool call IS the verdict. Do not write it as prose or JSON in the body —
text is not read. Call the tool, then stop.

TARGET   : {target}
CLAIM    : {claim}
EVIDENCE (as submitted):
{evidence}
IMPACT AS JUDGED (owner / delta / boundary — this is what you are attacking):
{impact}
{nudge}"""


def _fmt():
    return "\n".join(f"  {i+1}. {k} — {v}" for i, (k, v) in enumerate(LIFT_AXES.items()))


def build_prompt(target, claim, evidence, impact, nudge=""):
    return PROMPT.format(nudge=nudge, axes=_fmt(), keys="|".join(LIFT_AXES), target=target, claim=claim,
                         evidence=(evidence or "(none supplied)")[:4000],
                         impact=(impact or "(no impact record — that alone is grounds to escalate)")[:1500])


# The `_JSON` regex was removed: `[^{}]*` could not read nested objects and
# dropped valid responses as no_json. `jsonscan` does it by brace balance.


def parse_verdict(text, bucket=None):
    """A parse failure is **undecidable** — neither an escalation nor a
    non-escalation.

    The direction is the same as before: reading a failure as "escalated" puts
    **a principal that does not exist** into the ledger. A fault never becomes
    escalated=True.
    What changed is the **bookkeeping**. A malfunction used to land as
    escalated=False and be counted as `held` (the escalator looked and did not
    lift it) — so `escalations.failed` was always 0 and the row looked reviewed
    and was never retried. The same laundering was found in the refuter and the
    interrogator, and all three were made symmetric.
    """
    if bucket:
        # Submitted through the tool — no parsing at all. The API guaranteed the shape.
        d = dict(bucket); d["via"] = "tool"; d.pop("fault", None)
        return _normalize(d)
    # Fallback: the tool was not called. Keep the old path but mark it via `via`.
    d, fault, why = jsonscan.parse_last(text, "escalated")
    if fault == "no_json":
        return _normalize({"escalated": None, "fault": "no_json", "axis": None, "principal": None,
                "reason": "The escalator never submitted a verdict — UNDECIDABLE. We do not invent one.",
                "next_method": "", "enumerated": ""})
    if fault == "bad_json":
        return _normalize({"escalated": None, "fault": "bad_json", "axis": None, "principal": None,
                "reason": "Escalator output could not be parsed (%s) — UNDECIDABLE." % why,
                "next_method": "", "enumerated": ""})
    d.setdefault("via", "text")
    return _normalize(d)


def _normalize(d):
    """Make the tool path and the text path pass through the **same rules**.

    In particular the principal check is **not waived when submitted through the
    tool.** Waiving it lets an empty string through because the schema says
    `principal: str`, and a principal that does not exist enters the ledger —
    the exact failure this file exists to prevent.
    """
    if d.get("fault"):
        # **Single enforcement point** — a fault NEVER becomes a verdict.
        #   This invariant used to rest only on **control flow** (the fault
        #   returns did not go through `_normalize`). It lived in the comments
        #   and the tests but had no enforcement point in the code, which means
        #   adding a new fault path without knowing the rule breaks it silently —
        #   and None is falsy, so the consumer reads it as a verdict. That is the
        #   very laundering these files exist to stop. **Now every return passes
        #   through here.**
        d["escalated"] = None
        return d
    d["escalated"] = bool(d.get("escalated", False))
    if d["escalated"] and not (d.get("principal") or "").strip():
        # An escalation without a principal is not an escalation.
        d["escalated"] = False
        d["reason"] = ("Answered 'escalated' but left principal empty — recorded as NO "
                       "escalation. " + (d.get("reason") or ""))[:400]
    return d


async def run(server, target, claim, evidence, impact, model=None, max_turns=25,
              tools=(), cwd=None, timeout=900, _retry=1, _nudge=""):
    """Run the escalation attempt in an independent session. On failure, (None, reason)."""
    from claude_agent_sdk import (ClaudeSDKClient, ClaudeAgentOptions,
                                  AssistantMessage, TextBlock)
    # Session-private submission channel. It does not touch the ledger; it is
    # only this call's return channel.
    _sub_srv, _bucket = submit.make("escalated")
    _tools = list(tools) + [submit.TOOL_FQN]
    opts = ClaudeAgentOptions(
        model=model, system_prompt="You are an adversarial escalator. Terse. Tool-first. "
                                   "You never invent a principal you did not verify.",
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
                await c.query(build_prompt(target, claim, evidence, impact, nudge=_nudge))
                async for msg in c.receive_response():
                    if isinstance(msg, AssistantMessage):
                        for b in msg.content:
                            if isinstance(b, TextBlock):
                                out.append(b.text)
        await asyncio.wait_for(_go(), timeout=timeout)
    except asyncio.TimeoutError:
        return None, f"escalator timed out ({timeout}s)"
    except Exception as e:
        return None, f"escalator failed to run: {type(e).__name__}: {e}"
    v = parse_verdict("\n".join(out), _bucket)
    if v.get("fault") and _retry > 0:
        return await run(server, target, claim, evidence, impact, model=model,
                         max_turns=max_turns, tools=tools, cwd=cwd, timeout=timeout,
                         _retry=_retry - 1, _nudge=submit.RETRY_NUDGE)
    return v, "\n".join(out)[-1500:]
