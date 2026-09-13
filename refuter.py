# refuter.py — the Refute-or-Promote gate.
#
# Basis: the adversarial stage-gate methodology reports kill rates of
#   Stage A 63% / Stage B 42% / 79-83% overall.
# That is, **four out of five confirmation candidates die**. This harness had no
# such pressure: `doctrine.py` only questions itself with regexes, and the same
# context that produced a claim evaluates it. The core observation of that work
# lands exactly there:
#
#   "Cold-start agents that independently reach a different conclusion provide
#    higher-value signal than consensus among informed agents."
#   And: ten reviewers unanimously approved an OpenSSL padding oracle that did
#   not exist, and what killed it was **one measurement**.
#
# So the refuter here is:
#   (1) **Context-asymmetric** — it receives the claim and the evidence only. No
#       reasoning trace, no conversation history.
#   (2) **Kill-mandated** — when unsure, `refuted` is the default.
#   (3) **Read-only tools** — it cannot record a verdict itself, only a reason.
#   (4) (optional) **Cross-model** — one model family misses correlated errors
#       that came from its training data together.
#
# KILL_CLASSES are not generic theory: they are the reasons candidates in this
# project have actually died.
import asyncio
import jsonscan
import submit

KILL_CLASSES = {
    "unreachable":        "No path from any ingress reaches this code (show it by enumerating callers)",
    "guarded":            "A check sits on the path — this is not absence, not even under-application",
    "delta_zero":         "The normal path or a shipped tool already yields the same result",
    "by_design":          "Vendor documentation states this behaviour explicitly",
    "anchor_stale":       "The cited anchor is not from the measured build",
    "decompiler_artifact": "The decompiler invented it (pointer arithmetic rendered as truncation)",
    "impact_unproven":    "The behaviour is real but THE IMPACT CLAIM IN FRONT OF YOU does not "
                          "hold — the named owner does not own it, the delta is not beyond what "
                          "the legitimate path already gives, or the boundary is not the one "
                          "crossed. (The claim ALWAYS carries owner/delta/boundary, so 'no impact "
                          "was argued' is not a possible state; do not use this class for that.)",
    "not_controlled":     "The attacker cannot steer that value (constant / fixed sentinel)",
    "gated_off":          "Disabled in the default configuration",
}

PROMPT = """You are a REFUTER. Someone claims to have found a vulnerability in a binary.
Your job is to KILL the claim. You are NOT reviewing it — you are attacking it.

You have deliberately been given ONLY the claim and its cited evidence. You cannot see how
they reached it. That is the point: an independent look that lands somewhere else is worth
more than agreement from someone who already read their reasoning.

KILL MANDATE — if you are not sure, the verdict is REFUTED. A false confirmation costs more
than a missed bug. Roughly four out of five candidates die here; that is the expected rate,
not a failure.

THE IMPACT CLAIM (owner / delta / boundary) — the harness required this BEFORE calling you,
so it is always present. Attack it as a claim, not as an absence:
{impact}

YOU CAN MEASURE, NOT ONLY READ. Two tools fire at a real kernel in an isolated guest VM:
`ioctl(where='guest', ...)` sends a real request, and `kd(cmds=...)` stops the guest kernel and
answers with SYMBOLS. Use them when the claim rests on runtime behaviour — a claim that
survives your reading but dies on the wire is the most valuable kill you can produce, and one
that you tried to break BY MEASURING and could not is worth far more than one you merely
failed to argue away.
Two rules: (a) if a tool answers "not ready"/"unmeasured", that is the HARNESS failing, NOT
evidence against the claim — never convert it into a kill; (b) say in `reason` whether your
verdict is from reading or from measurement, so the next round knows which it was.

Work the claim with the tools. Check, in this order — the cheap kills come first:
{classes}

Then SUBMIT your verdict by calling the `submit_verdict` tool EXACTLY ONCE:
  submit_verdict(refuted=…, klass=…, reason=…, would_change_my_mind=…)
The tool call IS the verdict. Do not write it as prose or JSON in the body —
text is not read. Call the tool, then stop.

TARGET  : {target}
CLAIM   : {claim}
EVIDENCE (as submitted):
{evidence}
ANCHOR CHECK (machine-verified against the measured build):
{anchors}
{nudge}"""


def _fmt_classes():
    return "\n".join(f"  {i+1}. {k} — {v}" for i, (k, v) in enumerate(KILL_CLASSES.items()))


def _fmt_impact(impact):
    """The refuter used not to receive this, and wrote `impact_unproven` to mean
    "no argument was made". The gate now forces the three terms **before** the
    refuter runs, so they always arrive filled in."""
    if not isinstance(impact, dict) or not impact:
        return ("(none — the impact gate did not run. If this says none, DO NOT kill on "
                "impact_unproven: the harness never asked for it.)")
    L = []
    for k in ("owner", "delta", "boundary", "principal"):
        if impact.get(k):
            L.append("  %-9s %s" % (k + ":", str(impact[k])[:400]))
    for k in ("delta_kind", "grade_cap", "sole_claim", "enumerated", "out_of_scope"):
        if impact.get(k):
            L.append("  [%s] %s" % (k, str(impact[k])[:300]))
    return "\n".join(L)


def build_prompt(target, claim, evidence, anchors, impact=None, nudge=""):
    return PROMPT.format(nudge=nudge, classes=_fmt_classes(), keys="|".join(KILL_CLASSES),
                         target=target, claim=claim,
                         evidence=(evidence or "(none supplied)")[:4000],
                         anchors=(anchors or "(not machine-verified)")[:2000],
                         impact=_fmt_impact(impact))


# The `_JSON` regex was removed: `[^{}]*` could not read nested objects and
# dropped valid responses as no_json. `jsonscan` does it by brace balance.


# This is the spot where **a malfunction used to be laundered into a result.**
#   The interrogator twice failed to emit JSON, and the agent was told "the
#   interrogator broke your rejection"; the counters went up as broke/killed
#   too. That is why `failed` was **0 in every single run**. The agent could not
#   tell "my argument was wrong" from "the checker returned nothing", so it
#   burned rounds resubmitting the same claim in different words.
#   => Undecidable is a **third state**. Put None in the verdict key and attach
#      a fault. (A reason string alone cannot carry unknown — the consumer reads
#      the key as a bool.)
def parse_verdict(text, bucket=None):
    if bucket:
        # Submitted through the tool — no parsing at all. The API guaranteed
        # the shape.
        d = dict(bucket); d["via"] = "tool"; d.pop("fault", None)
        return _normalize(d)
    # Fallback: the tool was not called. Keep the old path but mark it via `via`.
    d, fault, why = jsonscan.parse_last(text, "refuted")
    if fault == "no_json":
        return _normalize({"refuted": None, "fault": "no_json", "klass": None,
                "reason": "The refuter never submitted a verdict — UNDECIDABLE. This is a malfunction, not a refutation.",
                "would_change_my_mind": ""})
    if fault == "bad_json":
        return _normalize({"refuted": None, "fault": "bad_json", "klass": None,
                "reason": "Refuter output could not be parsed (%s) — UNDECIDABLE." % why,
                "would_change_my_mind": ""})
    d.setdefault("via", "text")
    return _normalize(d)


def _normalize(d):
    """Make the tool path and the text path pass through the **same rules**.
    If the two diverge, "submitting through the tool relaxes the checks" becomes
    a bypass."""
    if d.get("fault"):
        # **Single enforcement point** — a fault NEVER becomes a verdict.
        #   This invariant used to rest only on **control flow** (the fault
        #   returns did not go through `_normalize`). It lived in the comments
        #   and the tests but had no enforcement point in the code, which means
        #   adding a new fault path without knowing the rule breaks it silently —
        #   and None is falsy, so the consumer reads it as a verdict. That is
        #   the very laundering these files exist to stop. **Now every return
        #   passes through here.**
        d["refuted"] = None
        return d
    d["refuted"] = bool(d.get("refuted", True))      # kill mandate: the default is True
    return d


async def run(server, target, claim, evidence, anchors, impact=None, model=None, max_turns=25,
              tools=(), cwd=None, timeout=900, _retry=1, _nudge=""):
    """Run the refutation in an independent session. On failure, (None, reason) —
    the gate does NOT treat "the run failed" as "the claim passed"."""
    from claude_agent_sdk import (ClaudeSDKClient, ClaudeAgentOptions,
                                  AssistantMessage, TextBlock)
    # Session-private submission channel. It does not touch the ledger; it is
    # only this call's return channel.
    _sub_srv, _bucket = submit.make("refuted")
    _tools = list(tools) + [submit.TOOL_FQN]
    opts = ClaudeAgentOptions(
        model=model, system_prompt="You are an adversarial reviewer. Terse. Tool-first.",
        cwd=cwd, mcp_servers={"vuln": server, "submit": _sub_srv},
        # Pass **both** `tools=` and `allowed_tools=` (measured).
        #   `allowed_tools` alone is not a restriction — it is a permission
        #   allowlist, so Bash stayed alive. `tools=` alone gets MCP calls
        #   blocked on permissions. Both together is the only working shape:
        #     allowed_tools=RO            -> MCP=yes **BASH=yes**  (hole)
        #     tools=RO                    -> MCP calls block on permission
        #     tools=RO + allowed_tools=RO -> MCP returns data, no Bash/Write  OK
        tools=_tools, allowed_tools=_tools, permission_mode="acceptEdits",
        max_turns=max_turns, setting_sources=[],      # no doctrine either — a pure cold start
    )
    out = []
    try:
        async def _go():
            async with ClaudeSDKClient(options=opts) as c:
                await c.query(build_prompt(target, claim, evidence, anchors, impact, nudge=_nudge))
                async for msg in c.receive_response():
                    if isinstance(msg, AssistantMessage):
                        for b in msg.content:
                            if isinstance(b, TextBlock):
                                out.append(b.text)
        await asyncio.wait_for(_go(), timeout=timeout)
    except asyncio.TimeoutError:
        return None, f"refuter timed out ({timeout}s)"
    except Exception as e:
        return None, f"refuter failed to run: {type(e).__name__}: {e}"
    v = parse_verdict("\n".join(out), _bucket)
    if v.get("fault") and _retry > 0:
        # Silence is usually transient. Ask **once** more — if the second
        # attempt is also broken, report it as a malfunction.
        return await run(server, target, claim, evidence, anchors, impact, model=model,
                         max_turns=max_turns, tools=tools, cwd=cwd, timeout=timeout,
                         _retry=_retry - 1, _nudge=submit.RETRY_NUDGE)
    return v, "\n".join(out)[-1500:]
