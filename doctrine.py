# doctrine.py — false-positive pressure.
#
# The counterpart of a CTF harness's `intent.py`. There, the thing being caught
# was "an exotic technique the puzzle author never intended". What is caught here
# is different — **premature confirmation** and **the illusion of strong evidence.**
#
#   (1) "there is no check" phrasing -> present the two-forms table, demand disassembly
#   (2) hedging ("probably", "seems") -> demand a CONFIRMED / INFERRED marking
#   (3) confirming from decompiler output alone -> recall the two-way decompiler errors
#   (4) a negative conclusion -> interrogate whether a positive control exists
#
# The patterns are English-only. They used to carry Korean alternations as well,
# from when the analyst's notes were written in Korean; the harness is English
# end to end now, so those branches could never fire. Where a Korean branch was
# the only one covering a concept — a bare "there is no check", "probably" in the
# guessing sense, "could not be reached" — the English side was widened to cover
# it rather than losing the detection.
import re

STATE = {"flags": []}

# (1) absence claims
_ABSENCE = re.compile(
    r"\bno\s+(bounds|length|access|auth|permission)\s+check|\bmissing\s+check|"
    r"\bno\s+(check|guard|validation)\b|\bthere\s+is\s+no\s+check|"
    r"\bunvalidated\b|\bno\s+bounds\b|"
    r"\bunchecked\b|\bwithout\s+(any\s+)?(check|validation)", re.I)

# (2) hedges
_HEDGE = re.compile(
    r"\bprobably\b|\blikely\b|\bseems?\b|\bappears?\b|\bshould\s+be\b|"
    r"\bpossibly\b|\bpresumably\b|\bapparently\b|\bI\s+(think|believe|suspect)\b|"
    r"\bmy\s+guess\b|\bpresumed\b|\bsuggests?\s+that\b|"
    r"\bin\s+theory\b|\bmight\s+(be|work)\b", re.I)

# (3) leaning on the decompiler
_DECOMP_ONLY = re.compile(
    r"decompil|Hex-?Rays|pseudo-?code|\bIDA\s+output\b", re.I)

# (4) negative conclusions
_NEGATIVE = re.compile(
    r"\bdid\s+not\b|\bblocked\b|\bfailed\b|\bnot\s+reproduc|"
    r"\bunreachable\b|\b(not|never)\s+reach|\bcould\s+not\s+be\s+reached\b|"
    r"\bdoes\s+not\s+work\b|\bno\s+effect\b", re.I)

# AV/EDR blocked the probe and it never reached the ledger.
#   In one measurement run, an AV product quarantined the dropped probe
#   executable (behavioural detection on a freshly built unsigned EXE issuing
#   device requests) and the agent **silently pivoted** to in-memory compilation.
#   The measurement succeeded, but the ledger can no longer tell
#   "blocked, then bypassed" from "just worked".
#   A block is itself a negative control result — it has to be recorded.
_AVBLOCK = re.compile(
    r"contains a virus|virus or potentially unwanted|Real Protect|McAfee|"
    r"quarantin|\bthreat\s+(detected|found)\b|"
    r"blocked by (?:your )?(?:antivirus|AV|EDR|Defender)", re.I)
_PIVOT = re.compile(r"Add-Type\s+-TypeDefinition|reflect(?:ively)?\s+(?:load|compile)|"
                    r"in-?memory\s+(?:compile|load)", re.I)


def _fmt(tag, body):
    return f"[doctrine:{tag}] {body}"


def check(text, ledger):
    """Look at one model utterance and return the push-backs, if any, as strings.

    `ledger` is the harness ledger module. Only four things are used from it, so
    a stub with the same shape works: `STATE["hedges"]` (int, incremented),
    `STATE["disasm"]` (truthy once anything has been disassembled),
    `has_control(kind)` and `has_disasm(target)`.
    """
    out = []
    t = text or ""

    if _ABSENCE.search(t):
        out.append(_fmt("absence",
            "You are about to write 'there is no check'. That sentence is almost always wrong — "
            "real defects are not ABSENCE but UNDER-APPLICATION. Rule out both forms first:\n"
            "  (a) HALF THE POPULATION EXEMPT — the check IS in the function but a type flag "
            "short-circuits it. Enumerate EVERY CONSTRUCTOR of that object and see whether the "
            "value each one sets exempts the check.\n"
            "  (b) CHECKED ONCE AT THE DOOR — checked at open/create and never on later "
            "operations. When a permission carries a SCOPE but is gated only by an ACL, nothing "
            "enforces that scope.\n"
            "Before writing absence: (1) type EVERY term of the guard FROM DISASSEMBLY, and "
            "(2) run a BEHAVIOUR-BASED xref including wrappers. Grepping the name alone misses "
            "wrappers."))

    if _HEDGE.search(t):
        ledger.STATE["hedges"] += 1
        out.append(_fmt("hedge",
            "You used a hedge. Mark EVERY sentence CONFIRMED or INFERRED. "
            "If you cannot quote the original code, do not write CONFIRMED. "
            "Stacking inferences as if they were confirmations drags the whole report's "
            "credibility down with them."))

    if _DECOMP_ONLY.search(t) and not ledger.STATE["disasm"]:
        out.append(_fmt("basis",
            "You are leaning on decompiler output but have not disassembled anything yet. "
            "The decompiler is wrong in BOTH directions — it drops probe/range checks entirely, "
            "and it renders pointer arithmetic as truncation, INVENTING defects that are not "
            "there. Anything that changes a verdict must be checked with disassemble."))

    if _NEGATIVE.search(t) and not ledger.has_control("positive"):
        out.append(_fmt("positive-control",
            "You are about to report a negative result. THERE IS NO POSITIVE CONTROL IN THE "
            "LEDGER. A broken harness and an absent vulnerability produce the same output — "
            "record 'under conditions that should work, it IS observed' first via "
            "control(kind='positive'). And did you confirm the target EXECUTED AT ALL "
            "(exit code)?"))

    if _AVBLOCK.search(t):
        out.append(_fmt("probe-blocked",
            "AV/EDR appears to have blocked the probe. THAT IS ITSELF A MEASUREMENT RESULT.\n"
            "  - Record it FIRST with `control(kind='negative', what=..., "
            "result='probe blocked by <product>')`. If you pivot to another method without "
            "recording it, the ledger cannot distinguish 'blocked, then bypassed' from "
            "'just worked'.\n"
            "  - The bypass itself is not forbidden — this is your own target on your own "
            "machine. But leave the FACT AND METHOD of the bypass in a note. The next "
            "operator hits the same wall.\n"
            "  - Operational suggestion: adding a dedicated probe directory to the AV "
            "exclusion list makes the bypass unnecessary.")
        )

    if _PIVOT.search(t) and not ledger.has_control("negative"):
        out.append(_fmt("pivot",
            "You are pivoting to in-memory compilation / reflective loading. If that is "
            "because an earlier execution was blocked, RECORD THAT BLOCK FIRST with "
            "control(kind='negative'). A pivot that never reaches the ledger makes the "
            "conditions of that measurement unreproducible later."))

    return out


def gate_absence_claim(target, basis, ledger):
    """Checkpoint right before a confirmation: block an absence claim when
    (a) nothing was disassembled, or (b) no all-executable-section xref was run.

    (b) comes from a real failure. On one driver the agent wrote
    "SeSinglePrivilegeCheck is absent from the 23 .text import calls" — **the call
    was in PAGE.** That image had 12 KB of `.text` against 32 KB of `PAGE`, and
    all five authorization calls were in `PAGE`.
    **An absence is only evidence if its coverage is stated.**
    """
    if not (basis == "disassemble" or ledger.has_disasm(target)):
        return ("You are trying to CONFIRM an absence/no-check claim without disassembling. "
                f"Run disassemble('{target}'), type EVERY term of the guard at instruction "
                "level, then confirm again. A check you cannot see in the decompiler is not "
                "the same as a check that is not there.")
    if hasattr(ledger, "has_xref") and not ledger.has_xref():
        return ("This is an absence claim and you have NEVER run an all-executable-section "
                "xref. Run import_xref(names='authz') first — driver code is scattered across "
                "`.text` / `PAGE` / `INIT` / `fothk`, and looking only at `.text` misses "
                "authorization checks entirely (this really happened: all 5 authorization "
                "calls of one driver were in PAGE). "
                "Which names you swept, in which sections, is half of an absence argument.")
    return None


def looks_like_absence(claim):
    return bool(_ABSENCE.search(claim or ""))
