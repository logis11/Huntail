# submit.py — the adversaries' **verdict submission channel.**
#
# Why:
#   All three adversaries used to be **asked** in the prompt to "emit exactly one
#   JSON object", and Python scraped it back out with a regex. That medium
#   guarantees no format. Measured: of 20 confirmations killed by the refuter,
#   **4 (20%) were actually parse failures** and all four were laundered into
#   `refuted` (`klass=None` is the fingerprint).
#
#   The analyst never had this problem — it has **tools**, so the API guarantees
#   the shape. An instruction in a prompt is text the model may or may not
#   follow; `tools` is a structural parameter of the request and changes the
#   output format itself.
#   => Give the adversaries **one submission tool** too. It does not touch the
#      ledger; it is only a return channel.
#
# Every session gets **its own server and its own bucket.** A global bucket mixes
# results as soon as two adversaries run at the same time. Do not lean on "the
# gate awaits them one at a time today" — that is an accident, and it breaks
# **silently** the moment anything runs in parallel.
#
# The absence of ledger access is the point. The bucket is just this call's
# return value; it reaches neither `state/*.json` nor the ledger's in-memory
# state. The adversary still only reads and judges.

TOOL = "submit_verdict"
TOOL_FQN = "mcp__submit__" + TOOL

# Per-role schema. Key names must match the existing parsers (consumers read
# them by those names).
SPECS = {
    "refuted": {
        "schema": {"refuted": bool, "klass": str, "reason": str,
                   "would_change_my_mind": str},
        "desc": ("Submit your refutation verdict. THIS TOOL CALL IS THE VERDICT — do not write "
                 "it as prose in the body; body text is not read. Call it exactly once "
                 "(if you call it more than once, only the last call counts).\n"
                 "refuted: true if you are NOT SURE (kill mandate).\n"
                 "klass: one of unreachable | guarded | delta_zero | by_design | anchor_stale | "
                 "decompiler_artifact | impact_unproven | not_controlled | gated_off. "
                 "May be null when refuted=false.\n"
                 "reason: one or two sentences citing what you ACTUALLY looked at.\n"
                 "would_change_my_mind: what evidence would let this claim survive."),
    },
    "sustained": {
        "schema": {"sustained": bool, "klass": str, "reason": str, "next_method": str},
        "desc": ("Submit your interrogation verdict. THIS TOOL CALL IS THE VERDICT — do not "
                 "write it as prose in the body. Call it exactly once.\n"
                 "sustained: does the rejection hold? FALSE if you are not sure "
                 "(the rejection does not stand).\n"
                 "klass: the single reason the rejection breaks. null if it holds.\n"
                 "reason: one or two sentences citing what you ACTUALLY looked at.\n"
                 "next_method: the single concrete observation that would settle it."),
    },
    # The adjudicator. Its role is the **opposite** of the other three: it does
    # not attack, it terminates.
    # `verdict` must have three slots. Offering only confirm/reject launders
    # "cannot be decided" into one of them, and that is exactly what this
    # repository has repeatedly lost (same reason as the fault contract).
    "adjudicated": {
        "schema": {"verdict": str, "reason": str, "decisive": str, "residual_risk": str},
        "desc": ("Submit the FINAL decision for this row. THIS TOOL CALL IS THE DECISION — do "
                 "not write it as prose in the body. Call it exactly once.\n"
                 "verdict: exactly one of 'confirm' | 'reject' | 'exhaust'.\n"
                 "  confirm — the defect stands. Say so only if the evidence in front of you "
                 "carries it; you are ENDING the adversarial process, not starting it.\n"
                 "  reject  — the rejection stands and the row closes as a negative.\n"
                 "  exhaust — NEITHER can be established from what exists. This is the honest "
                 "answer when the disagreement is about a measurement nobody made. It is not a "
                 "failure and it is not a rejection.\n"
                 "reason: two or three sentences. Name WHICH prior verdict you are overruling "
                 "and why that one was wrong — not a summary of everything.\n"
                 "decisive: the single anchor / observation that decided it (VA or measurement). "
                 "If you cannot name one, the answer is almost certainly 'exhaust'.\n"
                 "residual_risk: what would still overturn your decision. Required."),
    },
    "escalated": {
        "schema": {"escalated": bool, "axis": str, "principal": str, "reason": str,
                   "next_method": str, "enumerated": str},
        "desc": ("Submit your escalation verdict. THIS TOOL CALL IS THE VERDICT — do not write "
                 "it as prose in the body. Call it exactly once.\n"
                 "escalated: was this undervalued? DO NOT INVENT A PRINCIPAL — if you "
                 "enumerated and found nothing, the correct answer is false with `enumerated` "
                 "filled in.\n"
                 "axis: the single axis that flipped it. null if none.\n"
                 "principal: the principal / path / consumer / window for which the delta is "
                 "nonzero. REQUIRED when escalated=true — an empty value is not counted as an "
                 "escalation.\n"
                 "reason / next_method / enumerated: one or two sentences each."),
    },
}

# Appended to the retry prompt when a session ended without calling the tool.
# Resending the identical prompt breaks the second time for the same reason.
RETRY_NUDGE = (
    "\n\n=== RETRY ===\n"
    "Your previous attempt ended WITHOUT calling the `%s` tool. A verdict is accepted "
    "ONLY through that tool call — JSON written in the body is not read. Keep the "
    "investigation short this time and make sure you call the tool exactly once."
    % TOOL
)


def make(key):
    """Build a (server, bucket) pair private to this session. Never shared."""
    from claude_agent_sdk import tool, create_sdk_mcp_server
    if key not in SPECS:
        raise ValueError("unknown verdict key: %r" % key)
    spec = SPECS[key]
    bucket = {}

    @tool(TOOL, spec["desc"], spec["schema"])
    async def _submit(a):
        # Last call wins — the same convention as "use the last match" from the
        # regex days.
        bucket.clear()
        bucket.update({k: v for k, v in (a or {}).items() if v is not None})
        return {"content": [{"type": "text",
                             "text": "Verdict accepted. If you have nothing further, end the session."}]}

    srv = create_sdk_mcp_server(name="submit", version="1.0.0", tools=[_submit])
    return srv, bucket
