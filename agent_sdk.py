# agent_sdk.py — the vulnerability-analysis harness (Claude Agent SDK, on the
# subscription auth path).
#
# The direction of pressure is **suppressing false positives.** That is not a
# preference, it is a measured problem: on function-level vulnerability
# adjudication benchmarks frontier models run a 33-45% false-positive rate, and
# some classify 69% of all samples as vulnerable. Recall is not the bottleneck,
# **precision** is. So every gate here is built in one direction only: making a
# confirmation harder to reach.
#
# Four gates, all of which really block:
#   G0 the evidence is empty                      -> deny
#   G1 **machine anchor verification** — is that
#      instruction really at the cited address?   -> deny
#   G2 an absence claim with no disassembly       -> deny
#   G3 a scenario that is already dead            -> deny (nothing is
#                                                    resurrected from the
#                                                    graveyard)
#   G4 **an independent refuter** (context
#      asymmetry)                                 -> refuted means deny plus a
#                                                    graveyard row
# The stop gate: a run cannot end while the exhaustive table is open or an
# anchor-unverified confirmation is still standing.
import asyncio, os, re, sys, time

_LEAKED = os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ.pop("ANTHROPIC_AUTH_TOKEN", None)

from claude_agent_sdk import (
    ClaudeSDKClient, ClaudeAgentOptions, HookMatcher,
    tool, create_sdk_mcp_server,
    AssistantMessage, TextBlock, ToolUseBlock, ResultMessage,
)

import json
import config, tools as T, ledger, doctrine, runlog, evidence, refuter, interrogator, escalator
import adjudicator

STATE = {"calls": 0, "nudges": [], "stop_blocks": 0}
VERDICT = "mcp__vuln__verdict"


def _text(s):
    return {"content": [{"type": "text", "text": s if isinstance(s, str) else str(s)}]}


def _mk(name, desc, schema):
    """A thin wrapper onto execute_tool. None and empty arguments are dropped."""
    @tool(name, desc, schema)
    async def _f(a, _n=name):
        return _text(T.execute_tool(_n, {k: v for k, v in a.items() if v not in (None, "")}))
    return _f


TOOLDEFS = [
    _mk("binary_info",
        "Identity and layout of the MEASURED build: version, CodeView GUID, sections, "
        "mitigations, and whether the corpus was produced from a different build. "
        "Call FIRST — a claim is only valid for the build you measured.", {}),
    _mk("surface",
        "Enumeration table. action='add' registers items as UNAUDITED; action='set' moves one. "
        "Items are NEVER removed — coverage is computed from this table.\n"
        "★ action='incidental' (name=, found_while=) marks a row you hit WHILE WORKING ON SOMETHING "
        "ELSE. Use it — do not suppress the find. The single best defect of this project so far was "
        "discovered that way: the seed said 'look at the feature gates' and the agent noticed an AVL "
        "node lifetime bug instead. Widening the table for its own sake is waste, but a row you "
        "stumbled into while digging is the product of real work: it is exempt from the "
        "denominator-inflation warning and the worklist ranks it up. found_while= must say what you "
        "were doing when you hit it — that sentence is what separates the two.\n"
        "REACHABILITY IS A FIELD, not prose. Every item carries reach ∈ "
        "user-direct | user-triggerable-async | kernel-only | unknown. Default is 'unknown' and "
        "leaving it there BLOCKS completion — an unknown-reach item makes the denominator false. "
        "action='reach' updates it (name=, reach=, why=). "
        "kernel-only items stay on the table: they are the RACE PARTNER pool, not noise "
        "(a PnP thread is what freed the object in the one confirmed UAF this project has).\n"
        "action='async' enumerates asynchronous entry points (cancel/completion/work item/DPC/"
        "timer/PnP) — those are reach='user-triggerable-async'.\n"
        "action='race' registers a TWO-TERM item: a=, b=, shared=. A race is a property of a "
        "PAIR plus shared state, so a single-request table cannot hold it — and what a table "
        "cannot hold never gets counted as unanalysed either.",
        # `found_while` was missing from the schema. `action='incidental'` is the channel
        #   through which this project's best defect was found, and the handler reads
        #   `a.get("found_while")` — but with nothing in the schema **the model had no way
        #   to learn the argument's name** (it existed only in the prose description).
        #   Same class as the 17-argument accident below; a schema test now checks every
        #   tool mechanically.
        {"action": str, "items": list, "kind": str, "name": str, "status": str, "why": str,
         "reach": str, "a": str, "b": str, "shared": str, "found_while": str}),
    _mk("sink_gates",
        "What DOMINATES a sink — the opposite direction from a guard you already picked. "
        "Enumerates every cmp/test/call that gates the sink. This is the ONE-HOP move: when a "
        "rejection comes back as 'dominates_only' (the guard you named does not constrain the "
        "sink), use this to find the guard that actually does, or to prove none exists. "
        "Empty result is NOT 'no guard' — the check may live in the caller.",
        {"target": str, "sink": str, "max_span": int}),
    _mk("guards",
        "Scans the MEASURED image for places where a guard is UNDER-APPLIED rather than "
        "absent — the doctrine this harness pushes hardest. Four deterministic shapes: a "
        "ProbeForRead/Write that a branch SKIPS on some paths (RequestorMode==KernelMode, "
        "length==0), an object opened with AccessMode=KernelMode (access check skipped "
        "entirely), a METHOD_NEITHER handler with no Probe* at all, and a write performed "
        "AFTER the 'buffer too small' decision. Takes no arguments — it sweeps every runtime "
        "function. These are CANDIDATES, not verdicts: anchor each one with disassemble and "
        "ask sink_gates whether the guard actually dominates. A zero result WITH zero Probe* "
        "calls means THE AXIS DOES NOT APPLY to this image, not that it is clean.", {}),
    _mk("ioctl",
        "SEND A REAL IOCTL. This is the only tool that MAKES a measurement — measure() only "
        "grades one. Sends the request TWICE with different output-buffer fill bytes so "
        "measure(action='classify') can tell 'the kernel wrote this' from 'my fill byte'.\n"
        "Every run also emits three controls — something that must OPEN, something that must be "
        "DENIED (err=5), and something that must be ABSENT (err=2) — and REFUSES to return "
        "results if any disagrees: a broken probe and a locked-down driver look identical. "
        "The denial control differs by where: the host uses PhysicalDrive0 (denied only because "
        "the caller is unelevated); the guest is elevated, so it provisions its own denied file. "
        "A control that passes without separating DENIED from ABSENT has proven nothing.\n"
        "device='\\\\.\\name', code=CTL_CODE (hex ok), input=hex bytes, inlen=, outlen=, "
        "access= (default GENERIC_READ|WRITE).\n"
        "where='host' (default) fires at THIS analyst machine — a bugcheck kills the harness "
        "and the ledger with it. where='guest' fires inside the isolated VMware guest: same "
        "code, same three controls, only the transport differs, and a crash costs a snapshot "
        "\nprincipal='low' (guest only) runs the SAME probe from a NON-ELEVATED token "
        "(schtasks /ru 'NT AUTHORITY\\LOCAL SERVICE', /rl LIMITED). Use it for any claim of "
        "the form 'a lower-privileged principal reaches this' — the default guest transport "
        "runs ELEVATED (High+Administrators) and CANNOT support that claim. The result carries "
        "the token it actually ran as, and the call FAILS rather than returning data if the "
        "token turns out not to be low.\n"
        "revert. USE where='guest' FOR ANYTHING THAT MIGHT BUGCHECK — hesitating on the host "
        "is how a static guess hardens into a verdict without ever being measured.\n"
        "host needs ALLOW_PROBE=1, guest needs ALLOW_VM_PROBE=1 (separate on purpose: different "
        "risk, and one flag would open the host when you meant the guest).\n"
        "'guest not ready' is UNMEASURED, never clean.\n"
        "\n★★ aux= AND fh= BUILD REQUESTS A FLAT HEX BLOB CANNOT EXPRESS. Many drivers take a "
        "request struct holding an INTERIOR USER POINTER (a UNICODE_STRING, a nested buffer) or "
        "a FILE HANDLE — neither address exists until runtime, so you cannot write it into "
        "input=. The probe builds them for you:\n"
        "  aux=[{'at': <byte offset in input where the pointer goes>, 'hex': '<that buffer\\'s "
        "contents>', 'lenat': <optional offset to write UNICODE_STRING Length AND "
        "MaximumLength>}]\n"
        "  fh =[{'at': <offset for the HANDLE>, 'path': '<file to open>', 'acc': "
        "<DesiredAccess>}]  — use this when the driver derives the key FROM THE HANDLE, which "
        "no string can reproduce.\n"
        "The probe allocates each aux buffer, writes its address at 'at', frees them after, and "
        "reports the handle open result per entry. THIS IS THE TOOL FOR 'the request has a "
        "pointer at +0x180' — an err=87 from omitting it is a HARNESS ARTEFACT, not a clean "
        "negative, and this ledger has recorded exactly that mistake.\n"
        "★ A status code alone is not a measurement. An early return with 0 bytes written is "
        "UNMEASURED, never clean.",
        {"device": str, "code": str, "input": str, "inlen": str, "outlen": str,
         "access": str, "fills": list, "where": str, "target": str,
         "principal": str, "aux": list, "fh": list}),
    _mk("kd",
        "STOP THE GUEST KERNEL AND ASK IT — WinDbg/kd over KDNET, with SYMBOLS. ioctl() fires a "
        "request and shows you the RESULT; this shows you WHY that result happened. Run any kd "
        "command chain: x nt!<sym>, u, dt, !object, !devobj, dd/db, bp+g. The gdb/debugStub axis "
        "has no symbols and makes you derive module bases by scanning pages backwards; here the "
        "names resolve.\n"
        "Every run also emits two controls — a symbol that MUST resolve (nt!NtCreateFile) and a "
        "bogus one that MUST NOT — and REFUSES to return output if either disagrees: a debugger "
        "that never broke in and a symbol that genuinely does not exist look identical.\n"
        "It HALTS the guest to answer, then resumes it and VERIFIES the resume by asking the "
        "guest itself (a 'qd' in the command chain is not proof it resumed). Break-in is forced "
        "by loading a driver in the guest, because kd's -b/-bonc silently never break in.\n"
        "cmds='<kd commands separated by ;>', timeout= seconds (default 300), target= the image "
        "Module-list commands (lm, !drvobj) need a '.reload' first in the same chain — an "
        "empty lm is NOT proof the driver is absent.\n"
        "this measurement is about (so the ledger can bind it).\n"
        "Needs ALLOW_KDNET=1 — separate from ALLOW_PROBE/ALLOW_VM_PROBE on purpose: this one "
        "STOPS the machine rather than shooting at it, and a guest left halted kills every other "
        "measurement in the round.\n"
        "'not ready' / 'never broke in' is UNMEASURED, never clean.\n"
        "The harness KEEPS this output: read a location, apply a treatment, read it again, "
        "and feed both values to measure(action='before_after') - that is a GRADED "
        "measurement, not just a trace, and it is the shape that settles 'does the "
        "attacker's action actually reach this state'.",
        {"cmds": str, "timeout": str, "target": str}),
    _mk("kdscan",
        "KEEP A BREAKPOINT ALIVE UNTIL A SAMPLE MATCHES YOUR CONDITION. kd() stops the guest "
        "once, answers, and leaves; this one arms a conditional breakpoint, LETS THE GUEST RUN "
        "AGAIN, and waits for the moment the condition is true. Questions of the shape 'does "
        "this underflow ever actually happen' / 'what is the distribution of this field' cannot "
        "be answered any other way.\n"
        "DO NOT try to do this with kd(cmds='bp ...; g') - kd() now REFUSES a top-level g, "
        "because it appends its own 'qd': the guest resumes, the debugger detaches, the "
        "breakpoint evaporates, and you get NO error and NO output. That silence is "
        "indistinguishable from 'measured, zero hits' and it cost three rounds on 2026-09-13.\n"
        "bp='FLTMGR!Foo+0x181' (breakpoint expression), dump='<kd commands to print when the "
        "condition holds>', cond='<kd expression>' (omit to just collect ctrl_n samples), "
        "ctrl_dump='<what to print for samples OUTSIDE the condition>' (defaults to dump - keep "
        "the SAME fields, that is how you see whether your target was even in the sample space), "
        "ctrl_n=6, wait_s=240, stim_ps1='<PowerShell body>' to drive the guest while the "
        "breakpoint is armed (the harness delivers it as ASCII+CRLF and runs it with -File; do "
        "not hand-roll that), target='<image>'.\n"
        "READ THE VERDICT, DO NOT RESTATE IT AS A RESULT. Three values:\n"
        "  hit        - a matching sample exists. Quote the dump.\n"
        "  no-match   - samples outside the condition were seen and none matched. THIS, and only "
        "this, is a negative.\n"
        "  UNMEASURED - not even a non-matching sample appeared. Your stimulus never reached that "
        "code. Writing this down as a negative manufactures a false denominator.\n"
        "Even on 'no-match', look at the control samples: if the field your predicate keys on is "
        "trivial in every one of them (all zero, say), the target was never in the sample space "
        "and you are still UNMEASURED.\n"
        "The breakpoint is always removed - on a hit by the breakpoint command itself, otherwise "
        "by a forced break-in - and the removal is proven, because a breakpoint left behind "
        "freezes the guest for every later round.",
        {"bp": str, "dump": str, "cond": str, "ctrl_dump": str, "ctrl_n": str,
         "wait_s": str, "stim_ps1": str, "stim_timeout": str, "target": str}),
    _mk("record",
        "PUT ON THE LEDGER THE THINGS THAT ARE NOT VERDICTS. Until 2026-09-14 the ledger had "
        "exactly two row shapes - 'one defect claim about one target image' and 'one graded "
        "observation' - and three kinds of real, measured output had nowhere to land. Five of "
        "them leaked into reports/unrecordable/ in a single night, and one of those was that "
        "night's STRONGEST finding.\n"
        "kind='population' - the shape this methodology actually cares about: a guard that is "
        "present in 1 of 11 sibling call sites. Pass query_a + set_a (the whole population), "
        "query_b + set_b (the ones carrying the property), differentiator (the one-line "
        "predicate that decides a member), and later member_state='0x140057D00=safe 0x...=suspect'. "
        "THE HARNESS COMPUTES THE INTERSECTION - you do not declare it, because a declared "
        "intersection is a self-report. Members default to `unanalysed` and every render prints how "
        "many are still unanalysed, so a PARTIAL census can never read as a closed one.\n"
        "  ★ invariant=<one sentence> marks the census PATCH-ANCHORED: the population that must "
        "enforce an invariant a vendor just restored (a fixed bug's siblings). Once tagged, you "
        "cannot close it as a complete fix with a bare verdict — you must file the closing verdict "
        "with completes=<this census name>, and it passes ONLY when unanalysed=0 AND the closure "
        "interrogator SUSTAINED it. This exists because a QUIC census was closed 'no siblings, "
        "complete fix' while set_b had missed a member; the interrogator broke it but too late.\n"
        "kind='posture' - a measured property with NO defect claim attached: an access-mask "
        "constant, a transfer method, a flag. verdict() could only take it as 'blocked' "
        "(= 'I could not decide'), which is false: you DID decide, just not about a defect. "
        "Pass subject, prop, value, derivation, and body_read=0 when you measured the posture "
        "but did not read the handler body - that limitation is PRESERVED and shown again if "
        "the row is ever promoted.\n"
        "kind='os_fact' - a fact about an OS routine that is not keyed to your target image "
        "(e.g. nt!NtSetEaFile validates the EA buffer on its BUFFERED arm and not on the "
        "others). Every ledger row is per-target, so such facts got re-derived once per target. "
        "These go to a SHARED file visible from every target. Pass routine, arm, validated, "
        "omitted, applies_to, anchors. Call it with no arguments to READ what is already known "
        "before you re-derive anything.\n"
        "NONE of these three can carry confirmed/rejected. Promotion still goes through verdict() and "
        "still faces its gates (basis, controls, debt cap). This is material preservation, "
        "not a back door around judgement.",
        {"kind": str, "name": str, "query_a": str, "set_a": str, "query_b": str, "set_b": str,
         "differentiator": str, "member_state": str, "subject": str, "prop": str, "value": str,
         "derivation": str, "body_read": str, "routine": str, "arm": str, "validated": str,
         "omitted": str, "applies_to": str, "anchors": str, "image": str, "build": str,
         "note": str, "target": str}),
    _mk("measure",
        "Runtime measurement gates. A static rejection is not a clean measurement.\n"
        "action='classify' (a=, b= hex of the output buffer from TWO runs with DIFFERENT fill "
        "bytes, status=, info=) grades it clean|unmeasured|overreport|leak|blocked. Single-fill "
        "judgement is REFUSED: if the kernel writes your fill byte you will call it unwritten. "
        "An early return with 0 bytes written is UNMEASURED, never clean.\n"
        "action='kernel_ptrs' (buf=) scans for leaked kernel pointers. "
        "action='armed' records that the guarded path was actually entered.\n"
        "action='before_after' (before=, after=, control_before=, control_after=) grades a "
        "CONTROLLED BEFORE/AFTER observation - read a kernel location, apply the treatment, "
        "read it again, and read the SAME location on an arm where you did NOT apply it. "
        "This is the third evidence shape and the one that actually broke a defect here; "
        "without the control arm the grade is 'uncontrolled', because a value that drifts on "
        "its own is indistinguishable from one your treatment changed. Values are grounded "
        "by matching them against the kd output THIS harness captured.\n"
        "verdict(basis='measured') is REFUSED unless a measurement record exists for that "
        "target — otherwise 'I measured it' is self-report.",
        {"action": str, "target": str, "a": str, "b": str, "buf": str, "status": str,
         "info": str, "neither": bool, "name": str, "precondition": str, "why": str,
         "before": str, "after": str, "control_before": str, "control_after": str}),
    _mk("census",
        "Function-family population and how much of each family is NOT on the surface table. "
        "Use it to pick where to hunt: an unlisted family is definitely unaudited.", {}),
    _mk("find_funcs", "Regex over function NAMES. The cheapest way to scope a subsystem.",
        {"pattern": str, "limit": int}),
    _mk("func_at", "Which function encloses a VA, and the offset into it.", {"va": str}),
    _mk("callers", "Direct callers of a function (from the decompiled corpus). "
                   "Indirect/dispatch-table calls are NOT in this graph.", {"target": str}),
    _mk("callees", "What a function calls.", {"target": str}),
    _mk("callpath", "Shortest call path src→dst. Reachability is the #1 reason candidates die — "
                    "settle it before building an argument on top.",
        {"src": str, "dst": str, "maxdepth": int}),
    _mk("decompile", "Decompiled body of one function. DECOMPILER OUTPUT IS NOT EVIDENCE — "
                     "it drops checks and it invents defects. Navigate with it, decide elsewhere.",
        {"target": str}),
    _mk("disassemble",
        "Instruction listing from the MEASURED build. Accepts a symbol name or 0xVA; if the "
        "corpus came from another build the address is re-derived automatically and the move is "
        "reported. Bare 0x addresses are read as MEASURED-build coordinates and used as given — "
        "pass from_corpus=1 only for an address you took from the old build. "
        "This is what a verdict must rest on. "
        "★ image='nt' reads a SECOND IMAGE instead (see the images/crossref tools). In a second "
        "image only export names and 0xVA resolve, and every citation from it MUST be tagged "
        "`nt!0xVA mnem ops` — an untagged address is verified against the measured driver and "
        "will fail there, which is the correct behaviour, not a bug.",
        {"target": str, "count": int, "from_corpus": int, "image": str}),
    _mk("corpus_grep", "Regex over the whole decompiled corpus, grouped by function.",
        {"pattern": str, "limit": int}),
    _mk("dispatch_table",
        "Decode a dispatch table (IOCTL/vtable) deterministically: control code → devtype, "
        "function, transfer method, required access, handler symbols. Do not count these by hand.",
        {"va": str, "probe": str, "stride": int, "count": int, "code_off": int,
         "handler_offs": str}),
    _mk("double_fetch",
        "Double-fetch (TOCTOU) candidates by CFG dataflow: a user-controlled slot read once "
        "for a check and again for the use. Controls are enforced (synthetic positive + three "
        "negatives incl. a real binary) — a broken detector cannot emit results.\n"
        "★ LIMIT: lineage is seeded from `entry rdx = IRP` (WDM dispatch). **Fast-I/O paths are "
        "structurally invisible** — FastIoDeviceControl has no IRP and takes user buffers as "
        "direct arguments. A 0 on a fast-io / METHOD_NEITHER target means OUT OF RANGE, not "
        "clean. There, walk the argument registers by hand from the handler entry.",
        {"limit": int}),
    _mk("anchor",
        "Machine-check cited anchors against the measured build (cites='0xADDR mnem ops ...'), "
        "or re-derive old-build addresses into this build (relocate='0x... 0x...'). "
        "Run this on your evidence BEFORE calling verdict — the gate runs it anyway.",
        {"cites": str, "relocate": str}),
    _mk("find_bytes",
        "Byte-pattern search over the measured build's executable sections; '??' is a wildcard. "
        "This is the fallback when address re-derivation fails: a recompile changes every byte "
        "(register allocation, stack slots) while struct offsets and immediates survive. "
        "e.g. cmp dword [r+0x2d4], 0x0FFFFFFF → hex='d4020000ffffff0f'.",
        {"hex": str, "limit": int, "code_only": int, "image": str}),
    _mk("images",
        "Second-image registry. action='list' shows every loaded image WITH ITS BUILD IDENTITY "
        "(base, timestamp, CodeView GUID, export count); action='add' loads one (name=, path=). "
        "Why this exists: the harness used to see exactly one PE, so any claim whose truth lives "
        "in the callee — does nt!MmCreateSection reference that handle at KernelMode or at the "
        "caller's mode? does nt!RtlCheckTokenMembership(NULL,...) check the impersonation level? "
        "— died as BLOCKED no matter how completely you read the driver. Register the image and "
        "the question becomes answerable. Anchors you cite from it are verified against THAT "
        "file, and the build identity is written to the ledger so the verification is reproducible.",
        {"action": str, "name": str, "path": str}),
    _mk("crossref",
        "Cross the image boundary by name. Give name='MmCreateSection' and it finds which "
        "registered image exports it and disassembles the body there. This is the move you could "
        "not make before: `call qword ptr [rip+0x2058b]` told you the import NAME, never what the "
        "callee does with the arguments. Forwarder exports are reported as forwarders, not "
        "silently resolved. Cite results as `nt!0xVA mnem ops`.",
        {"name": str, "image": str, "count": int}),
    _mk("note",
        "Durable scratch outside the context window. action='write' appends, 'read' reads back. "
        "Findings you only hold in context are lost when the context is compacted.",
        {"action": str, "key": str, "text": str}),
    _mk("control",
        "Record a control arm. kind='positive' (the harness detects the thing when it IS there), "
        "'negative' (the gate really is enforced), 'swap' (the signal follows the condition). "
        "A negative result without a positive control is not evidence.",
        {"kind": str, "what": str, "result": str}),
    _mk("verdict",
        "Judgement ledger. action='confirm'|'reject'|'blocked'|'scope'|'goal'|'track'|'gate_blocked'|'reopen'|'anchors'|'asks'|'exhaust'|'worklist'|'unfinished'|'status'|'lead'|'leads'|'reaudit'|'resisted'. "
        "\n★★ action='confirm' REQUIRES depends_on= — the EXACT ids of the rows/verdicts whose "
        "REACHABILITY or AVAILABILITY this claim borrows (the trigger path, the caller population, "
        "the principal that can drive it). Write depends_on='none' if the claim is self-contained, "
        "and say it EXPLICITLY the same way owner='none' is said. Ids must match exactly — a fuzzy "
        "dependency is not checkable. If a named id is already rejected you get a QUESTION, not a "
        "refusal: a rejection often NARROWS a claim rather than contradicting it (a sibling caller "
        "ruled out, a wider variant killed), and only you can say which. This exists because two "
        "wcifs confirmations were filed on premises this same ledger had ALREADY killed and nothing "
        "noticed — every other gate here is claim-local. Declaring the dependency is also what lets "
        "`dependency_audit()` re-flag this row if the premise dies LATER. "
        "\n★★ action='leads' IS YOUR WORK LIST WHEN A ROW IS ALREADY OPEN. When an independent interrogator BREAKS one of your rejections, that rejection is still recorded - but the break is filed as a LEAD with the interrogator's own next_method attached. Measured in this project: 243 rejections were broken, 43 of them sit in the ledger as rejections anyway, and 31 of those were never touched again. A broken rejection is the single most defect-dense population here - an adversary already read your evidence and said the negative does not stand. Close one with action='lead', id=<lead id>, how='refuted'|'measured'|'reinterrogated', why=... . THERE IS NO 'exhausted' EXIT: a lead closes only when the refuter killed the axis, a measurement split it, or you refiled the rejection and the interrogator could NOT break it this time. Leads whose klass is wrong_pair are NOT in this queue - those are guard/sink declaration problems, not defects."
        "\n★ action='reaudit' lists the GRAVEYARD RE-AUDIT QUEUE. A rejection is defended only ONCE, at the moment it is filed - nothing re-examines it afterwards, so a wrong negative is a permanent loss. Measured in this ledger: only 34% of buried rows were ever sustained by an interrogator, and 25 rows sit there that an interrogator BROKE or that their own author WITHDREW - still reading as clean negatives to you. Call it when you arrive, when a new measurement lands, or when the build changes. Clearing one of those is not a resurrection, it is bookkeeping.\n★★ action='resisted' IS THE QUEUE THIS HARNESS DID NOT HAVE: ROWS SOMEBODY ALREADY TRIED TO KILL AND FAILED. Every adversary here pushes DOWN - the refuter kills confirmations, the interrogator breaks rejections - but until now a FAILED kill left no trace you could act on. It counts three axes on the same row: (1) your rejection was DENIED by the reject gate, (2) the CFG REFUTED the guard/sink pair you declared yet the rejection was recorded anyway, (3) an interrogator BROKE it. Measured in this project: 30 rows resisted 2+ kill attempts, one of them 12 times ACROSS THREE DIFFERENT klasses, and 23 of 30 resisted on more than one axis. A single denial is often just paperwork - but a row you attacked under guarded, then impact_unproven, then state_precondition, and which survived all three, is telling you the death hypotheses are the thing that is wrong, not the paperwork. THERE IS NO AUTOMATIC PROMOTION: this is a re-analysis list, not a list of confirmations. Close a row by refiling a rejection that meets the requirement, by confirming it if the reason it will not die is that it is a defect, or by action='exhaust'. Rows carrying a lead id are closed in the LEAD queue instead - two queues must not ask for the same work twice.\n\n★ action='track' (name=, stage=, note=) is how depth accumulates ACROSS sessions. A finding is not one verdict, it is a ladder: static-confirm -> trigger -> measure -> impact -> boundary/submission. Three of this project's confirmed rows (S7-D4, S9-D4, S10-VA1) are the SAME investigation at three rungs, but the ledger counted them as three unrelated verdicts, so six sessions each redid rung-one work instead of climbing six rungs. Register the track, move its stage when you actually advance it, and MOVE IT BACK when a refutation knocks it down. The next session's carry-over block leads with this table.\n"
        "\n★ completes=<census name> — attach to a reject/blocked/track that closes a PATCH-ANCHORED "
        "census (one filed via population(invariant=...)) as a complete fix / no surviving variant. "
        "The closure is REFUSED unless that census has unanalysed=0 AND its closing narrative was SUSTAINED "
        "by the interrogator. Enumeration incompleteness (a member set_b never listed) does not show up "
        "as unanalysed, so the SUSTAINED interrogation — not the member count — is the real gate. If it is "
        "refused, the census is not done: add the missed sibling to set_b and re-run the interrogator.\n"
        "\n★ action='anchors' (evidence='0x... 0x...') asks the ledger where those addresses ALREADY "
        "appear — in a filed verdict's evidence, an open question, the graveyard, a taxonomy report. "
        "Anchors are the only key that survives rephrasing, so this is the one lookup that catches "
        "'I am about to re-derive something this ledger already answered'. It also runs AUTOMATICALLY "
        "on every confirm/reject and on every ASK, so read that block when it appears.\n"
        "\n★ action='reopen' (id=, ground=, why=, evidence=) to RE-TRY a scenario the graveyard has "
        "locked. ground is one of: 'new_evidence' (an anchor the killed record does not contain), "
        "'category_error' (the kill's klass does not address what the claim asserts — name the klass "
        "in why=), 'precondition_resolved' (the precondition the kill rested on has since been "
        "measured). Rewording is NOT a ground; if you have re-phrased the same argument twice, the "
        "problem is your method, not your sentence. The reopen is recorded on the graveyard entry and "
        "buys exactly ONE retry — the refuter still runs.\n"
        "\n★ action='gate_blocked' (gate=, why=, would_be=) when a gate STRUCTURALLY prevents a judgement "
        "you believe is correct — an unresolvable precondition, a checker that cannot express your "
        "argument. This channel exists because when the only escape was a detour, a session took it: "
        "the function-pointer precondition blocked absence-form rejections and the agent spent two "
        "sessions on a different axis instead. Report it, then either find another basis or file "
        "'blocked' with a reason. Quietly moving to an easier axis is the worst outcome, and it is "
        "For klass='guarded' you may declare a GUARD SET with `guards='0x…,0x…'` when the "
        "invariant is established by SEVERAL blocks together rather than one dominating branch "
        "— a chain of comparisons, or a different check on each ingress. The gate then computes "
        "a CUT instead of dominance: every path from the function entry to the sink must cross "
        "one of your blocks, at least one edge out of them must avoid the sink, and the checked "
        "value must reach the sink operand. Declaring extra blocks does NOT make this easier — "
        "the gate reports the minimal cut and an adversary reviews anything beyond it. With a "
        "single guard the behaviour is identical to `guard=`.\n"
        "invisible in the ledger. Use kind='taxonomy' for the worse case: the ledger has NO SLOT for what you measured (this has happened - 'the OOB read is real but gated off by a default-ON feature, and no klass expresses that conjunction'). That report is routed to the conductor, which writes it to reports/unrecordable/ so it survives outside the schema. Pass evidence= with your anchors. A truth with no slot is the most expensive thing you can lose.\n"
        "★ action='goal' FIRST, before anything else: state this session's objective in one line "
        "(text=, kind='judge'|'measure'|'both'). The finish gate then checks it. This exists because "
        "a 120-minute session once ended in 19 minutes having tidied the table: the processing rate "
        "was already 100% from previous sessions, so the gate let it stop, and the task the seed "
        "actually asked for was checked by nothing. Tidying the table is not closing the objective."
        "\n★ action='worklist' answers the question you should be asking whenever the table is "
        "large: NOT 'what is left' but 'what is worth re-opening'. It ranks rows by whether they "
        "can MOVE THE GRADE of a finding you already hold — rows on a confirmed defect's chain, "
        "weak rejections (klass asserted but no CFG verdict and no interrogation), unprivileged "
        "reach, blocked rows whose next step is already written, half-closed scopes. Rows that "
        "are exhausted, kernel-only or already confirmed drop out. Auditing everything is not "
        "the goal and never was; closing one row to the end is."
        "\n★ action='blocked' takes `next=` — THE ONE NEXT STEP, >=40 chars, naming a VA or a "
        "symbol ('disassemble 0x14004efc0 and check whether SdbpInitializeSearchDBContext admits a "
        "caller-chosen absolute directory into v15[12*i+2]'). reason= says why you could not "
        "settle it; next= says what would settle it, and it is a FIELD, not prose, because prose "
        "cannot be selected mechanically: this ledger measured 498 blocked rows and every "
        "predicate for 'the reason contains a next step' either matched 56% of them or dropped "
        "the very rows that were one disassembly from a finding. A row with next= is ranked up "
        "for the next session and listed by action='unfinished'; a row without it joins a "
        "reservoir of hundreds that nobody returns to.\n"
        "\n★ action='unfinished' (n=, offset=) ENUMERATES that reservoir — every blocked row, "
        "aliases and exhausted rows dropped, next=-bearing rows first, with reach, unjudged "
        "anchors and the first sentence of each reason. It tells you the reservoir's true size "
        "before it shows you a page of it. Use it when the goal is open and you are choosing what "
        "to work: these rows are analysis that already happened and stopped one step short."
        "\n★★ A REJECTION KILLS ONE CLAIM, NOT THE SURFACE. Measured 2026-08-31: 73 of 73 "
        "rejected surfaces had been closed on a SINGLE claim — one case rebutted one sink inside "
        "a shared classifier and closed the whole major handler while its own note still listed "
        "three unexamined sinks. So a surface row now goes to rejected ONLY when you first declare its "
        "denominator with action='scope' (target=, items=['0xVA name', ...], method=<how you "
        "enumerated it — behaviour-based, not name xref>) and then adjudicate EVERY item. "
        "Each reject must name which candidate it kills: item='<label>' or sink=<VA>. "
        "Until the last one falls the surface stays unanalysed(blocked) with the remaining candidates "
        "listed for you. This is not bureaucracy: 'this one path is guarded' and 'this surface is "
        "clean' are different claims, and only the first one is what your evidence supports.\n"
        "★ A gate that CANNOT DECIDE does not pass you — it ASKS. A reject that the gate cannot "
        "verify comes back as '[REJECTION HELD - QUESTION]' with a concrete next method, is NOT counted as "
        "a judgement, and stays in the open-question queue. action='asks' lists open questions; "
        "answer one by re-rejecting the same target after doing what the method says. "
        "If no method is left, action='exhaust' (target=, reason=, tried=) records METHOD "
        "EXHAUSTED — the third terminal state. It is NOT a rejection and never counts as a "
        "verified negative. Laundering exhaustion into a rejection makes the whole table a lie. "
        "You cannot finish while questions are open.\n"
        "basis ∈ decompile|disassemble|measured|doc. Every confirm is anchor-checked and then "
        "handed to an independent refuter that is trying to kill it. 'blocked' keeps the item "
        "as unanalysed and REQUIRES reason= : what you would have to look at next to move it to "
        "confirmed or rejected.\n"
        "★ REJECTS ARE GATED TOO. A rejection needs klass= (why it dies) because each class "
        "carries a DIFFERENT measurement obligation: guarded | unreachable | not_controlled | "
        "no_sink | by_design | delta_zero | decompiler_artifact | second_site | "
        "bounded_absence | state_precondition | callsite_guarded | gated_off | "
        "impact_unproven. Anchors in evidence are "
        "machine-checked for rejects exactly as for confirms.\n"
        "  The last four exist because sessions kept measuring TRUE things the taxonomy could "
        "not hold, and the report came back to the operator 8 times unresolved while the row "
        "stayed BLOCKED. Each still carries an obligation:\n"
        "  second_site (origin_id=<an EXISTING verdict id on this ledger>) — another site of a "
        "defect already filed; grade follows the parent, never counted as a new confirmation.\n"
        "  bounded_absence (scope=<the range you actually enumerated>) — 'absent WITHIN THIS "
        "RANGE'. Absence without its range is a global absence claim, which is much stronger.\n"
        "  state_precondition (sink= + >=2 conditional-branch anchors) — TWO readings, one slot, "
        "because the obligation is identical: (a) the guard constrains the STATE in which the "
        "sink is reachable, not the sink's operand; (b) the dangerous EDGE is infeasible because "
        "every predecessor establishes the invariant. Either way 'no state makes this dangerous' "
        "is an exhaustive claim over the branches that produce that state, so enumerate them. "
        "If you were about to ask for 'control-flow-exclusion' or 'infeasible-edge', this is it.\n"
        "  callsite_guarded (callsite=<a `call` anchor> + guard=) — a shared helper where no "
        "per-caller guard can dominate globally, but THIS caller's guard dominates THIS call. "
        "It scopes the claim: the helper's other callers stay unaudited and are not covered.\n"
        "  gated_off (gate= + a `call` anchor + a conditional-branch anchor) — the dangerous "
        "arm sits behind a feature/config gate whose DEFAULT picks the safe arm. Two anchors "
        "because 'a gate exists' and 'the default is safe' are different facts. A WIL feature's "
        "compiled default is a byte in its descriptor and its override is a registry key: read "
        "them, do not assert them.\n"
        "  impact_unproven (sink= + scope=) — the sink runs but nothing reads its effect. That "
        "is an absence claim, so name the range you swept. Filed once as 'no consumer reads it' "
        "when a consumer existed, because the sweep had been run on the WRONG OFFSET; naming "
        "the range is what makes that visible.\n"
        "  Before filing kind='taxonomy' ('no slot exists'), check these six — the last four "
        "taxonomy reports on wcifs.sys were all two of them.\n"
        "klass='guarded' additionally REQUIRES guard=<VA of the conditional branch> and "
        "sink=<VA of the dangerous operation>: the harness computes CFG dominance and will "
        "REFUSE the rejection if the branch does not actually separate the sink. "
        "'A guard exists' and 'the guard dominates every path to the sink' are different claims "
        "and the second one is computable — so it is not yours to assert.\n"
        "★★ A CONFIRM ALSO NEEDS ITS IMPACT, and this is not paperwork — it is the step where "
        "findings are actually won or lost. owner= who owns these bytes (no owner means no "
        "boundary to violate, so say owner='none' and the grade is capped); delta= what the "
        "attacker gets BEYOND what the legitimate path already gives them (a bypass with delta 0 "
        "is a real code defect and a non-issue; delta='n/a: <why>' when the comparison does not "
        "apply, which is the STRONGER class); boundary= the boundary crossed, in the vendor's own "
        "language. If delta is 0 the gate hands it back — not to reject it, but to make you ask "
        "the question that has actually revived dead findings: NOT 'is there a delta' but 'for "
        "WHICH PRINCIPAL is the delta nonzero'. Parse the object's SD, read every ACE, and look "
        "for a principal that is granted access here yet blocked on the path it would otherwise "
        "use. Answer in principal=. An honest 'none, having enumerated X' also passes.\n"
        "★ One more sentence is gated on its own because it decides the grade by itself: any "
        "EXHAUSTIVENESS claim inside the impact — 'the only consumer is user mode', 'no kernel "
        "reader', 'nothing else maps it'. That is an absence claim wearing an impact field's "
        "clothes, and until now neither the absence gate (it reads only `claim`) nor the "
        "escalator (it fires only on delta 0) was looking at it. Back it with a behaviour-based "
        "sweep recorded through import_xref, or pass enumerated='<what you swept and how>'. "
        "Writing 'what I verified is X, the rest is unaudited' passes freely — that is a "
        "different and honest claim, and it is usually the true one.",
        # **17 arguments the handlers read were missing from the schema** — gate_blocked's
        #   gate/kind/why/would_be, track's name/stage/note, exhaust's tried/method and
        #   more. The SDK passes undeclared keys through, so it "worked" — but with
        #   nothing in the schema the agent **had no way to learn the names** (only what
        #   the prose happened to mention was discoverable). Two rounds in a row filed
        #   "this channel is unreachable". The schema is now matched to the handlers.
        {"action": str, "id": str, "target": str, "claim": str, "basis": str,
         "evidence": str, "evidence_ids": str, "reason": str, "klass": str,
         "guard": str, "guards": str, "sink": str, "items": list, "method": str, "item": str,
         "owner": str, "delta": str, "boundary": str, "principal": str,
         # The boundary becomes **a column.** Prose `boundary=` stays as one sentence of
         #   vendor language; the policy decision is made by these two tokens
         #   (`ledger.PRINCIPAL_LATTICE`).
         "from_principal": str, "to_principal": str,
         "enumerated": str,
         # gate_blocked
         "gate": str, "kind": str, "why": str, "would_be": str,
         # track
         "name": str, "stage": int, "stages": str, "note": str, "text": str,
         # reopen
         "ground": str, "gid": str,
         # lead — **the way to close a lead.** Undeclared, the agent does not know the
         #   argument exists and the lead queue becomes read-only: another graveyard.
         "how": str,
         # exhaust / asks / unfinished
         "tried": str, "n": int, "of": str, "offset": int,
         # The 'next single step' column for `blocked`. It was measured that a machine
         #   cannot extract it from the prose reason: any predicate either catches 56% of
         #   all blocked rows, or, if grounded, drops the rows that need recovering. So the
         #   writer declares it.
         "next": str,
         # When four klass values were added, **their mandatory arguments were left out
         #   again** — the exact failure the comment above warns about, repeated in the
         #   same file. The gate demands these names for second_site / bounded_absence,
         #   and with nothing in the schema the agent could not learn them.
         "origin_id": str, "scope": str, "callsite": str, "branches": str,
         "depends_on": str}),
    _mk("import_xref",
        "Import cross-references across EVERY executable section (.text / PAGE / INIT / fothk), "
        "not just .text. names='authz' (privilege/token/SD APIs) | 'probe' (user-pointer "
        "validation) | 'all' | a comma-separated substring filter. Always reports WHICH sections "
        "it swept — coverage is half the evidence for an absence claim. "
        "This exists because a run once wrote 'SeSinglePrivilegeCheck is absent from all 23 .text "
        "import calls' and failed to close its own kill condition: the call was in PAGE. That "
        "image is .text 12KB / PAGE 32KB with ALL FIVE authorization calls in PAGE. "
        "Absence claims and klass='no_sink'/'unreachable' rejections are gated on having run this.",
        {"names": str}),
    _mk("priorart",
        "Record a prior-art search BEFORE confirming. what= (device name / IOCTL code / handler "
        "name you searched), where= (source), result= (what you found). Confirms are GATED on "
        "this. A finding whose 32 anchors all machine-verified and which survived the refuter was "
        "still worthless because it was published in 2024 with a public PoC and a documented name "
        "(IOCTL_KSEC_IPC_SET_FUNCTION_RETURN). Code-only gates cannot catch that. "
        "'did not search' and 'searched, found nothing' are completely different values.\n"
        "\u2605 axis= is REQUIRED and is one of device | ioctl | symbol \u2014 one record per axis. "
        "The confirm gate derives which axes this target actually has (a device name, a control "
        "code, a handler/struct symbol) and checks that YOU SEARCHED THAT EXACT STRING. A single "
        "blanket record no longer opens the gate. If an axis truly does not apply, file it with "
        "result='n/a: <why>'.",
        {"what": str, "where": str, "result": str, "axis": str}),
    _mk("authz_reach",
        "Does a handler REACH an authorization API? Call-graph BFS over every executable "
        "section. targets=<comma VAs>, controls=<comma VAs of handlers KNOWN to authorize>, "
        "optional apis=, depth=. This is the A-13 measurement generalized: 'authorization is "
        "checked once at the door and never per-operation' is the most common real defect, and "
        "it is computable. A '0 authorization APIs' result WITHOUT controls is not evidence — "
        "a broken analyzer and an absent check look identical.",
        {"targets": str, "va": str, "controls": str, "apis": str, "depth": int}),
    _mk("run_python", "Write a measurement script to work/ and run it (cwd=work).",
        {"code": str, "filename": str, "timeout": int}),
]

SERVER = create_sdk_mcp_server(name="vuln", version="2.0.0", tools=TOOLDEFS)
ALL_TOOLS = [f"mcp__vuln__{n}" for n in T.TOOLS]
RO_TOOLS = [f"mcp__vuln__{n}" for n in T.READONLY]
# The refuter alone gets the **measurement tools** (`ioctl` + `kd`).
#   Why: until now the refuter killed on reading alone. With no way to disprove by
#   measurement it could issue a "this was never measured" kill, but it could not
#   **re-measure and overturn.**
#   It does not get `run_python` / `Bash` — a refuter re-measures, it does not
#   write new tooling. With the gates off the tool refuses with "unmeasured", and
#   that refusal is not grounds for a kill.
REFUTER_TOOLS = RO_TOOLS + [f"mcp__vuln__{n}" for n in ("ioctl", "kd")]


# ── G1: machine anchor verification ──────────────────────────────────────
def _anchor_gate(inp):
    p = T.TARGET.get("_pe")
    if p is None:
        return None, []
    res, summ = evidence.check(p, inp.get("evidence", ""), alt=T.TARGET.get("_alt"),
                               images=T.images_all())
    rep = evidence.render(res, summ)
    if summ["cites"] == 0:
        return ("The evidence contains ZERO verifiable anchor citations. In this domain every "
                "basis is re-derivable in the form `0xADDR  mnem ops` — anything not written "
                "that way is a summary, not a citation. Paste the lines disassemble gave you, "
                "verbatim.", [])
    if summ["failed"]:
        return ("Anchors were NOT verified against the measured build:\n" + rep +
                "\n\nBefore confirming, re-derive the addresses for THIS build with "
                "disassemble and fix your citations.", [])
    return None, [{"va": r["va"], "insn": r["actual"], "status": r["status"]} for r in res]


async def gate_verdict(input_data, tool_use_id, context):
    """The gate body is `_gate_verdict`. This catches an exception and turns it
        into **a deny.**

    If a PreToolUse hook dies with an exception the CLI simply lets the call
        through — **a malfunction becomes a pass.** A one-line bug in `seen_scenario`
        (`sorted(set(...)[:12])`) really did raise on every legitimate confirmation,
        and those confirmations went into the ledger without passing a single gate.
        The refuter never ran either.
        The failure class this whole harness exists to stop was present in the
        harness itself."""
    try:
        return await _gate_verdict(input_data, tool_use_id, context)
    except Exception as e:
        import traceback
        traceback.print_exc()
        runlog.bump("gate_errors")
        return {"systemMessage": "verdict blocked: internal gate error",
                "hookSpecificOutput": {"hookEventName": "PreToolUse",
                                       "permissionDecision": "deny",
                                       "permissionDecisionReason":
                                           f"The gate could not adjudicate due to an internal "
                                           f"error: {type(e).__name__}: {e}. "
                                           "A MALFUNCTION IS NOT A PASS — fix the harness and "
                                           "confirm again."}}


def deny_msg(reason, target="", act="", klass=""):
    runlog.bump("gate_denials")
    try:
        ledger.record_denial(target or "(adversary path)", reason, act=act, klass=klass)
    except Exception:
        pass
    return {"systemMessage": f"verdict blocked: {reason[:80]}",
            "hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


async def _interrogate(tgt, inp, gate_rec, force=False):
    """Attach an independent interrogator to a rejection. If the rejection does
        not stand, return a deny — which sends it back as an ASK.

    The mandate is the **inverse** of the refuter's: when unsure, the rejection
        does not stand. A false confirmation costs triage time; a false rejection
        loses the bug permanently.
    """
    st = ledger.STATE.setdefault(
        "interrogs", {"run": 0, "broke": 0, "sustained": 0, "failed": 0, "skipped": 0})
    import random
    # force: a case the gate **could not express** must not be skipped by the
    #   sampling rate. A skip also returns `None`, so the caller cannot tell it from
    #   "the interrogation passed" — the moment INTERROGATE_RATE drops, an
    #   inexpressible rejection **passes with no verification at all.**
    #   (The same no-op-that-returns-success class this repo keeps hitting.)
    if not force and random.random() > config.INTERROGATE_RATE:
        st["skipped"] += 1
        ledger.mark_interrogated(tgt, None, vid=(inp or {}).get("id"))
        return None
    st["run"] += 1
    print(f"\033[96m[interrogate] {tgt} — independent interrogator starting "
          f"(model={config.INTERROGATOR_MODEL or 'inherit'})\033[0m")
    v, raw = await interrogator.run(
        SERVER, tgt, inp.get("claim", ""), inp.get("evidence", ""),
        json.dumps(gate_rec, ensure_ascii=False)[:2000] if gate_rec else "",
        model=config.INTERROGATOR_MODEL, tools=RO_TOOLS, cwd=config.WORK_DIR,
        max_turns=config.INTERROGATOR_TURNS, timeout=config.INTERROGATOR_TIMEOUT)
    if v is None:
        st["failed"] += 1
        ledger.save()
        return deny_msg(f"Could not run the interrogator: {raw}. AN EXECUTION FAILURE IS NOT "
                        "A PASS — a broken harness and 'the rejection is correct' produce the "
                        "same output. Fix it and reject again (if you truly cannot run it, "
                        "disable with GATE_INTERROGATE=0 and say so in the report).")
    runlog.transcript(f"[interrogate] {tgt} {v}")
    ledger.count_via("interrogs", v)
    # Separated first here for the same reason. Without this line, sustained=None
    #   reads as "the rejection does not stand", so a malfunction gets reported as a
    #   **rejection collapse.** One axis died that way twice.
    if v.get("fault"):
        st["failed"] += 1
        ledger.save()
        print(f"\033[93m[interrogate] FAULT [{v.get('fault')}] — not a result\033[0m")
        return deny_msg(
            f"The interrogator FAILED TO PRODUCE A VERDICT ({v.get('fault')}): "
            f"{v.get('reason')}\n"
            "One retry gave the same result. THIS IS A MALFUNCTION, NOT AN INTERROGATION "
            "RESULT — your rejection was not broken. Resubmitting the same rejection in "
            "different words will fail the same way. "
            "Report it with gate_blocked(kind='tool') and move to another row. "
            "Recorded in the ledger as interrogs.failed.")
    if not v.get("sustained"):
        st["broke"] += 1
        # A broken rejection is not recorded as a verdict, so `mark_interrogated` has no
        #   row to attach to. 213 sets of grounds vanished without a trace that way (the
        #   transcript is truncated every round). They go to a separate record rather than
        #   the ledger — the consumer is the next round's analyst, not the orchestrator.
        try:
            ledger.record_break(tgt, v, inp)
        except Exception as _e:
            print("\033[93m[breaks] failed to record: %s\033[0m" % _e)
        ledger.save()
        print(f"\033[91m[interrogate] BROKE [{v.get('klass')}] "
              f"{v.get('reason','')[:120]}\033[0m")
        _prec = ""
        try:
            _prec = ledger.rules_for(v.get("klass"))
        except Exception:
            pass
        # Redesigned: **a broken rejection is no longer blocked at submission time.**
        #   Old behaviour: deny -> the analyst tried to rebuild the pair on the spot and
        #   got stuck in a loop.
        #   New behaviour: the rejection is filed as usual but **is not a product**
        #   (`session_products()` does not count anything marked `broke`), so it alone
        #   cannot end a round. Putting the block on **the exit rather than the verdict**
        #   stops cheap rejections without creating a loop.
        #
        #   But **the grounds must still reach the analyst.** Losing that while making it
        #   non-blocking deletes "why it broke" — which removes the learning, not the
        #   loop. (A regression caught exactly this: the precedent recovery was not being
        #   attached to the teardown text.) On the non-blocking path it rides along in the
        #   tool result — the grounds are put in the stash.
        _brk_msg = (
            f"[REJECTION RECORDED, BUT AN INTERROGATOR BROKE IT] "
            f"[{v.get('klass')}] {v.get('reason')}\n"
            f"Next method: {v.get('next_method') or '(the interrogator gave no method)'}{_prec}\n"
            "This rejection IS in the ledger — you are not blocked. But it is NOT a product: "
            "a broken rejection does not end the session. Either answer the break, or take "
            "another row all the way through an adversary.")
        try:
            ledger.mark_interrogated(tgt, v, broke=True, note=_brk_msg,
                                     vid=(inp or {}).get("id"))
        except TypeError:
            ledger.mark_interrogated(tgt, v)
        if getattr(config, "FINISH_ON_PRODUCT", True):
            return None            # let it through; grounds ride in the stash
        return deny_msg(
            f"An independent interrogator BROKE this rejection — [{v.get('klass')}] {v.get('reason')}\n"
            f"Next method: {v.get('next_method') or '(the interrogator gave no method)'}{_prec}\n"
            "A rejection that does not stand does NOT become a confirmation — it returns to "
            "the open-question queue. The interrogator never saw your reasoning; resubmitting "
            "the same evidence will break it again.")
    st["sustained"] += 1
    try:
        ledger.mark_interrogated(tgt, v, broke=False, vid=(inp or {}).get("id"))
    except TypeError:
        ledger.mark_interrogated(tgt, v)
    print(f"\033[92m[interrogate] SUSTAINED — {v.get('reason','')[:120]}\033[0m")
    return None


async def _adjudicate(tgt, inp, n_attempts):
    """Break the loop. Not an adversary but **a terminator** — the only member of
        the panel that sees the whole history.

    Measured: an interrogator teardown rate of 64-88%. A broken rejection goes
        back as an ASK, the next round rejects it again, and it breaks again. The same
        question came round 4-5 times on 6 rows of one target and 8 of another.
        `attempts` was only being counted — **there was no forced end point.**
        The literature: Refute-or-Promote keeps a judge (this harness had none),
        MAD-Stability demands **a defined output on non-convergence**, and the Nine
        Judges result disproves the add-more-judges direction.
        => no extra adversary; one terminator.
    """
    hist = ledger.history_for(tgt)
    print(f"\033[95m[adjudicate] {tgt} — {n_attempts} unresolved attempts => adjudicator starting "
          f"(may confirm={config.ADJUDICATOR_MAY_CONFIRM})\033[0m")
    runlog.bump("adjudications_run")
    v, raw = await adjudicator.run(
        SERVER, tgt, inp.get("claim", ""), hist, n_attempts,
        model=config.ADJUDICATOR_MODEL, tools=RO_TOOLS, cwd=config.WORK_DIR,
        max_turns=config.ADJUDICATOR_TURNS, timeout=config.ADJUDICATOR_TIMEOUT)
    if v is None:
        runlog.bump("adjudications_failed")
        return deny_msg(f"Could not run the adjudicator: {raw}. AN EXECUTION FAILURE IS NOT A "
                        "DECISION — the row stays open. Fix it, or set GATE_ADJUDICATE=0 and "
                        "say so in the report.")
    ledger.record_adjudication(tgt, v, n_attempts, raw)
    runlog.transcript(f"[adjudicate] {tgt} {v}")
    if v.get("fault"):
        runlog.bump("adjudications_failed")
        print(f"\033[93m[adjudicate] FAULT [{v.get('fault')}] — not a decision\033[0m")
        return deny_msg(f"The adjudicator FAILED TO PRODUCE A DECISION ({v.get('fault')}): "
                        f"{v.get('reason')}\nTHIS IS A MALFUNCTION, NOT A DECISION. The row "
                        "stays open. Report it with gate_blocked(kind='tool').")
    dec = v.get("verdict")
    # The authority switch. It was a one-day decision, so it is pinned in config
    # rather than in code.
    if dec == "confirm" and not config.ADJUDICATOR_MAY_CONFIRM:
        dec = "exhaust"
        v["downgraded_from"] = "confirm(no_authority)"
        ledger.record_adjudication(tgt, dict(v, verdict=dec), n_attempts, raw)
    runlog.bump("adjudicated_" + str(dec))
    print(f"\033[92m[adjudicate] {str(dec).upper()} — {str(v.get('reason'))[:120]}\033[0m")
    if dec == "reject":
        return None            # the rejection stands - recorded on the normal path
    if dec == "exhaust":
        ledger.verdict({"action": "exhaust", "target": tgt,
                        "reason": "[adjudicator] " + str(v.get("reason"))[:400],
                        "tried": "%d attempts; decisive anchor not establishable" % n_attempts})
        return deny_msg("The adjudicator ENDED this row as EXHAUSTED after %d attempts: %s\n"
                        "Missing observation: %s\nThis is NOT a rejection and NOT a defect — "
                        "the row is closed as unaudited-with-reason. Do not re-argue it; the "
                        "loop is what it was closed for. Move to another row."
                        % (n_attempts, v.get("reason"), v.get("decisive") or "(not named)"))
    # confirm — the adjudicator issued a confirmation. Mark it **auditably** and
    # let it through.
    ledger.stash_adjudication(tgt, {
        "verdict": "confirm", "decisive": v.get("decisive"), "reason": v.get("reason"),
        "residual_risk": v.get("residual_risk"), "attempts": n_attempts})
    return None


async def _run_escalator(inp, tgt, impact_json, blocking):
    """The only device that pushes **upward** — the opposite direction from the
        refuter and the interrogator.

    blocking=True  (a rejection with klass='delta_zero') — if it escalates, that
        rejection is **reversed.** A delta-zero rejection is exactly where findings
        died in this project.
        blocking=False (a confirmation with weak impact) — nothing is reversed. The
        confirmation itself is valid and only its grade is low, so the escalation
        result is **attached** and no more.
    """
    st = ledger.STATE.setdefault(
        "escalations", {"run": 0, "lifted": 0, "held": 0, "failed": 0, "skipped": 0})
    import random
    if random.random() > config.ESCALATE_RATE:
        st["skipped"] += 1
        return None
    st["run"] += 1
    print(f"\033[95m[escalate] {tgt} — escalator starting "
          f"(model={config.ESCALATOR_MODEL or 'inherit'}, blocking={blocking})\033[0m")
    v, raw = await escalator.run(
        SERVER, tgt, inp.get("claim", ""), inp.get("evidence", ""), impact_json,
        model=config.ESCALATOR_MODEL, tools=RO_TOOLS, cwd=config.WORK_DIR,
        max_turns=config.ESCALATOR_TURNS, timeout=config.ESCALATOR_TIMEOUT)
    if v is None:
        st["failed"] += 1
        ledger.save()
        print(f"\033[91m[escalate] failed to run: {raw[:160]}\033[0m")
        return None                      # an escalator fault does not block the verdict (a false escalation costs more)
    runlog.transcript(f"[escalate] {tgt} {v}")
    ledger.stash_escalation(tgt, v)
    # Separate the fault first: escalated=None is falsy, which is where a
    # malfunction used to be counted as 'held'.
    if v.get("fault"):
        st["failed"] += 1
        ledger.save()
        print(f"\033[93m[escalate] FAULT [{v.get('fault')}] — not a result\033[0m")
        return {"escalated": False, "fault": v.get("fault"),
                "note": ("The escalator FAILED TO PRODUCE A VERDICT (%s). One retry gave the "
                         "same result. This is a MALFUNCTION, not 'nothing to escalate' — the "
                         "impact of this row remains UNASSESSED. Recorded in "
                         "escalations.failed." % v.get("fault"))}
    if v.get("escalated"):
        st["lifted"] += 1
        ledger.save()
        print(f"\033[95m[escalate] LIFTED [{v.get('axis')}] "
              f"principal={str(v.get('principal'))[:80]}\033[0m")
        if blocking:
            return deny_msg(
                f"The escalator OVERTURNED this delta-zero rejection — [{v.get('axis')}]\n"
                f"Principal / path for which the delta is NONZERO: {v.get('principal')}\n"
                f"Basis: {v.get('reason')}\n"
                f"next method: {v.get('next_method') or '(no method given)'}\n"
                "'delta 0' is not a terminal answer. Re-adjudicate with this principal substituted in — "
                "this exact pivot has revived a finding that had already been written off.")
        return None
    st["held"] += 1
    ledger.save()
    print(f"\033[92m[escalate] HELD — {str(v.get('enumerated'))[:100]}\033[0m")
    return None


# ── put an adversary on the prose that closes an axis too ────────────────────
# Why: the adversaries were attached to **verdicts** only — a confirmation to the
#   refuter, a rejection to the interrogator. But what closes an axis is not a
#   verdict: it is a `track` note or a `gate_blocked` why. Measured, one axis was
#   closed with
#     "remaining term is the live ForceAccessCheck/feature state,
#      which no open axis can read - treat as parked"
#   and **nobody read that sentence.** Two parts of it were wrong: the axis opened
#   with a single `vmrun start`, and the predicate was a register comparison, not
#   a feature gate. A sentence the interrogator would have seen as a verdict
#   passed because it was a track note.
# **It does not block.** Per this repo's standing conclusion — tightening gates
#   only costs recall — the result is recorded and handed to the analyst, who
#   judges. Same contract as the `_inexpr` path.
# Calibrated against the corpus: the first version was built from **one** example
#   and caught 7 of 29 notes (24%). The dominant idiom turned out to be the
#   "NO MEASUREMENT AXIS WAS OPEN THIS ROUND" family. Now 79%.
#   (Build a scanner and check **first** that the original defect hits.)
#   The Korean alternations this used to carry are gone — the harness is English
#   end to end, so they could never fire.
_CLOSURE_MARK = re.compile(
    r"CLOSED\s+NEGATIVE|closes?\s+NEGATIVE|\bparked\b|\bTerminal\b|"
    r"DO\s*NOT\s*RE-?OPEN|\bdo\s+not\s+reopen\b|"
    r"(no|any)\s+open\s+ax[ie]s|"      # the original case; a rewrite broke it and a regression caught it
    r"(no|any|every|all)\s+(open\s+)?(measurement\s+)?ax[ie]s(\s+(is|was|were|are))?\s+(open|closed)|"
    r"measurement\s+ax[ie]s\s+(are|is|was|were)\s+(all\s+)?closed|"
    r"all\s+measurement\s+axes|needs?\s+a\s+(measurement|runtime)\s+axis|"
    r"policy-closed|cannot\s+be\s+(measured|read)\s+without|"
    r"blocked-for-measurement|cannot\s+be\s+measured|needs?\s+measuring|"
    r"\bruntime\s+axis\b",
    re.I)


def _closure_text(inp):
    """Pull the **axis-closing prose** out of a `track` / `gate_blocked` input.
        None if there is none."""
    for k in ("note", "why", "reason", "claim"):
        t = (inp or {}).get(k)
        if isinstance(t, str) and _CLOSURE_MARK.search(t):
            return t
    return None


async def _interrogate_closure(tgt, inp, act):
    """Attach the interrogator to axis-closing prose. **It always returns None —
        it never blocks.**"""
    txt = _closure_text(inp)
    if not txt:
        return None
    st = ledger.STATE.setdefault("closure_interrogs",
                                 {"run": 0, "broke": 0, "sustained": 0, "failed": 0})
    st["run"] += 1
    runlog.bump("closure_interrog_run")
    name = (inp or {}).get("name") or (inp or {}).get("gate") or tgt
    claim = ("This axis is closed: %s (via action=%s on `%s`). "
             "The closure is the claim under test." % (txt[:400], act, name))
    print("\033[96m[interrogate-closure] %s - interrogating the axis-closing prose (%s)\033[0m"
          % (tgt, act))
    try:
        v, _raw = await interrogator.run(
            SERVER, tgt, claim, txt[:2000], "",
            model=config.INTERROGATOR_MODEL, tools=RO_TOOLS, cwd=config.WORK_DIR,
            timeout=getattr(config, "INTERROGATOR_TIMEOUT", 300))
    except Exception as e:
        st["failed"] += 1
        runlog.bump("closure_interrog_failed")
        print("\033[93m[interrogate-closure] failed (%s) - the closure stands as it is\033[0m"
              % type(e).__name__)
        return None
    # The return contract matches `_interrogate`: `v is None` means it failed to run,
    #   `fault` means it could not decide. **Neither is a pass** — the failure-equals-
    #   pass trap this repo keeps stepping on.
    if v is None or (v or {}).get("fault"):
        st["failed"] += 1
        runlog.bump("closure_interrog_failed")
        print("\033[93m[interrogate-closure] could not decide (%s) - that is uninterrogated, not 'the closure is right'\033[0m"
              % ((v or {}).get("fault") or "no-result"))
        _res, _detail = "UNJUDGED", str((v or {}).get("reason") or _raw or "")[:1200]
    else:
        broke = not v.get("sustained")
        st["broke" if broke else "sustained"] += 1
        runlog.bump("closure_interrog_broke" if broke else "closure_interrog_sustained")
        _res = "BROKE" if broke else "SUSTAINED"
        _detail = "klass=%s\n%s" % (v.get("klass"), str(v.get("reason") or "")[:1200])
        if broke:
            print("\033[91m[interrogate-closure] the interrogator broke this closure - "
                  "it does not block, but it is on the ledger. Reopening is the "
                  "analyst's call.\033[0m")
    # Record the cross-check result **per name** as well (the Move 2 gate reads it).
    #   The global counters (run/broke/sustained) cannot say *which* census was
    #   SUSTAINED, so the patch-anchored closure gate
    #   (`population_closure_status`) has nothing to hang on.
    st.setdefault("by_name", {})[str(name)] = _res
    # No silent no-ops: the result is written as a note. `tools._t_note` is the
    #   canonical channel (`ledger.note_write` **does not exist** — the first version
    #   called it and was about to swallow the failure in a try/except).
    try:
        import tools as _T
        _T._t_note({"action": "write",
                    "key": "CLOSURE-INTERROG-%s-%s" % (act, str(name)[:36]),
                    "text": "## Conclusion\nInterrogation of the closing prose: %s\n\n%s\n\nThe closure verbatim:\n%s\n\n%s"
                            % (_res, claim[:400], txt[:1200], _detail)})
    except Exception as _e:
        print("\033[93m[interrogate-closure] failed to write the note: %s\033[0m" % type(_e).__name__)
    return None


async def _gate_verdict(input_data, tool_use_id, context):
    inp = (input_data or {}).get("tool_input") or {}
    act = (inp.get("action") or "").lower()
    tgt = inp.get("target", "?")
    claim = inp.get("claim", "")
    basis = (inp.get("basis") or "decompile").lower()

    def deny(reason):
        runlog.bump("gate_denials")
        # Record what was blocked. All 21 denial paths in `_reject_gate` flow through
        #   here, so this single point observes the whole rejection gate. The blocking
        #   behaviour is unchanged.
        try:
            ledger.record_denial(tgt, reason, act=act, klass=inp.get("klass") or "")
        except Exception:
            pass
        return {"systemMessage": f"verdict blocked: {reason[:80]}",
                "hookSpecificOutput": {"hookEventName": "PreToolUse",
                                       "permissionDecision": "deny",
                                       "permissionDecisionReason": reason}}

    # An exact match is bypassed by a single stray character, so the comparison is
    #   made **after canonicalisation.** Measured: a real measurement-based rejection
    #   with `basis="measured on the live kernel, not inferred..."` skipped this gate
    #   entirely.
    # Attach an adversary to axis-closing prose (a track note, a gate_blocked why).
    # It does not block.
    if act in ("track", "gate_blocked", "exhaust") and getattr(
            config, "GATE_INTERROGATE_CLOSURE", True):
        await _interrogate_closure(tgt, inp, act)

    _bcanon = None
    try:
        _bcanon = ledger.normalize_basis(basis)[0]
    except Exception:
        _bcanon = (basis or "").lower()
    if act == "reject" and config.GATE_CONTROL_BEFORE_REJECT and _bcanon == "measured":
        if not ledger.has_control("positive"):
            return deny("You are rejecting on MEASURED evidence but there is NO POSITIVE "
                        "CONTROL in the ledger. Record 'under conditions that should work, it "
                        "IS observed' first via control(kind='positive'). A broken harness and "
                        "an absent defect produce the same output.")
    if act == "reject" and config.GATE_REJECT:
        try:
            ok, msg, _rec = ledger._reject_gate(tgt, inp)
        except Exception as e:
            ok, msg = True, "Internal error in the rejection gate (%s) — passed through, but UNVERIFIED." % e
        if not ok:
            return deny(msg)
        # Attach an **independent interrogator** to a rejection that passed the static
        #   gates — the mirror of the refuter.
        #   A row that fell out as an ASK is not yet a rejection, so it is not
        #   interrogated — except that the ASK bucket held **two different things**:
        #     `need_observation` (not enough observed) stays a question. An LLM looking at
        #     it would produce nothing.
        #     `inexpressible` (the analysis is finished but the gate model cannot express
        #     that shape) is different — 62 measured `dominates_only` rows were all this,
        #     and they went straight to the ASK queue **without any LLM ever seeing
        #     them**, so the next round hit the same rule again.
        #     Rather than piling on more machine rules, **the adversarial layer makes one
        #     holistic judgement.** No new role is created: the interrogator's mandate is
        #     already "when unsure, the rejection does not stand", which points the right
        #     way, and the fault contract carries over unchanged.
        # The adjudicator — once the same row has gone unresolved N times, call the
        #   terminator **instead of** the interrogator. Calling the interrogator again
        #   only reproduces the same teardown (measured teardown rate 64-88%).
        _prev = ledger._ask_for(tgt) or {}
        _natt = len(_prev.get("attempts") or [])
        if config.GATE_ADJUDICATE and _natt >= config.ADJUDICATE_AFTER:
            r = await _adjudicate(tgt, inp, _natt)
            if r is not None:
                return r
            # On confirm, `inp["_adjudicated"]` is attached and it passes through below.
            # On reject it goes down the rejection path as usual, skipping the interrogator
            # (it has already been terminated).
            _ask, _inexpr, _settled = None, False, True
        else:
            _ask = (_rec or {}).get("ask") if isinstance(_rec, dict) else None
            _inexpr = bool(_ask) and _ask.get("kind") == "inexpressible"
            _settled = False
        # Once adjudicated, the interrogator **does not run.** Otherwise it breaks a row
        #   the terminator just closed and the loop survives — which defeats the entire
        #   purpose of this wiring.
        # Redesigned: what the gate could not decide (`_ask`) is **evidence, not a
        #   denial.** Under GATE_COMPUTE_ONLY everything goes to the interrogator
        #   regardless of kind: `need_observation` was also the raw material of the
        #   pair-hunting loop, and an adversary judges that better than a machine rule.
        #   The gate's computation travels along in `_rec`.
        if getattr(config, "GATE_COMPUTE_ONLY", True) and _ask:
            _inexpr = True
        if config.GATE_INTERROGATE and not _settled and (not _ask or _inexpr):
            if _inexpr:
                # Hand over **what the machine could not do** as evidence. The interrogator does
                # not see the reasoning, but it cannot judge without the CFG facts the gate
                # computed.
                print(f"\033[96m[interrogate] {tgt} — a shape the gate could not express"
                      f"({_ask.get('cfg')}) => handing the holistic judgement to the adversarial layer\033[0m")
                runlog.bump("inexpressible_judged")
            r = await _interrogate(tgt, inp, _rec, force=_inexpr)
            if r is not None:
                return r
            if _inexpr:
                # The interrogator did not break the rejection => the gate merely could not
                # express it, and the rejection stands.
                # This fact used to be written **only into the hook-local dict `_rec`.** The tool
                #   side's `verdict()` recomputes `_reject_gate` from scratch, so the marking
                #   evaporated — the fingerprint was zero `passed_by` rows in the ledger against
                #   13 left in `pending_interrog`. Ten measured rows vanished that way. It is now
                #   handed over with the same stash pattern the adjudicator and escalator use.
                #   The ASK is not cancelled (operator decision): the interrogator's `sustained`
                #     means "could not break it", not "it is right", so promoting automatically
                #     would open a precision hole. The fact is relayed and **the analyst judges.**
                try:
                    ledger.stash_inexpr_pass(tgt, {"cfg": _ask.get("cfg"),
                                                   "klass": v.get("klass"),
                                                   "reason": v.get("reason")})
                except Exception as _e:
                    print("\033[93m[inexpr] stash failed: %s\033[0m" % _e)
                _rec.pop("ask", None)
                _rec["passed_by"] = "interrogator_over_inexpressible"
                _rec["gate_could_not_express"] = _ask.get("cfg")
                runlog.bump("inexpressible_sustained")
        # A `delta_zero` rejection is **exactly where a finding dies**, and this is the
        #   only place the escalator blocks. It asks a different question from the
        #   interrogator ("is it right?"): **for whom is the delta not zero?**
        # Trigger widened: across 37 rejections after this was wired, `delta_zero`
        #   appeared **zero times** — the grade actually collapses via `by_design`
        #   (19/37), which is the vendor's own rejection narrative.
        #   `by_design` and `delta_zero` block; `not_controlled` is only attached.
        _kl = (inp.get("klass") or "").lower()
        if (config.GATE_ESCALATE and not _settled
                and _kl in ("delta_zero", "by_design", "not_controlled")
                and not (isinstance(_rec, dict) and _rec.get("ask"))):
            if _kl == "not_controlled":
                await _run_escalator(inp, tgt, "rejection klass=not_controlled - reason=%s"
                                     % (inp.get("reason") or "")[:400], blocking=False)
            else:
                # Hand the control-identity observation to the escalator **as a fact.** The gate
                #   did not block, and "no control measured the same thing" is grounds to
                #   distrust a zero delta.
                _co = (_rec or {}).get("control_overlap") if isinstance(_rec, dict) else None
                _cotxt = ""
                if isinstance(_co, dict) and _co.get("verdict") == "no_overlap":
                    _cotxt = ("\nHARNESS OBSERVATION: the ledger has %d positive control(s) but "
                              "NONE of them shares a single anchor address with this claim. The "
                              "'measured zero delta' was never controlled AT THIS SITE."
                              % _co.get("n_controls", 0))
                elif isinstance(_co, dict) and _co.get("verdict") == "overlaps":
                    _cotxt = ("\nHARNESS OBSERVATION: a positive control shares anchors %s with "
                              "this claim (%s)." % (", ".join(_co.get("shared") or []),
                                                    _co.get("control", "")[:80]))
                r = await _run_escalator(inp, tgt, "rejection klass=%s - reason=%s%s"
                                         % (_kl, (inp.get("reason") or "")[:400], _cotxt),
                                         blocking=True)
                if r is not None:
                    return r
    if act != "confirm":
        return {}

    # G0
    if not inp.get("evidence"):
        return deny("evidence is empty. If you cannot write down the basis, it is INFERRED.")
    # G5 — prior art. There are things a gate that only reads code can never catch.
    #   One confirmation passed 32 machine-verified anchors and survived the refuter,
    #   and it was public work from the year before — the control code even had a
    #   published name.
    if config.GATE_PRIORART:
        # Checked per axis. It used to pass as long as `has_priorart()` was non-empty —
        #   the prompt demanded three axes while the code counted whether **any** record
        #   existed.
        _gaps = ledger.priorart_gaps(
            tgt, " ".join(str(inp.get(k) or "") for k in ("claim", "evidence", "target")))
        if not ledger.has_priorart() or _gaps:
            return deny(ledger.render_priorart_gaps(_gaps) if _gaps else
                        "You have NOT SEARCHED FOR PRIOR ART before confirming. "
                        "Record it with priorart(axis=..., what=..., where=..., result=...).")
    # G2
    if config.GATE_DISASM_BEFORE_ABSENCE and doctrine.looks_like_absence(claim):
        r = doctrine.gate_absence_claim(tgt, basis, ledger)
        if r:
            return deny(r)
    # G1
    if config.GATE_ANCHOR:
        why, anchors = _anchor_gate(inp)
        if why:
            return deny(why)
    else:
        anchors = []
    # ── G2' — **move the impact gate ahead of the refuter.**
    #
    #   An ordering inversion the measurement exposed: `_impact_gate`
    #   (owner/delta/boundary) only ran at `ledger.verdict()` **recording time** —
    #   i.e. after the refuter had already passed. But the refuter's kill classes
    #   include `impact_unproven`, and in one night **2 of 6** confirmation attempts
    #   died on exactly that.
    #   => the harness had the refuter adjudicate impact **before it had even asked
    #     for impact.** The agent never got the chance to supply
    #     owner/delta/boundary, and `refuter.build_prompt` did not take impact as an
    #     argument — because it did not exist.
    #
    #   The same wall blocked three successive instructions from the orchestrator —
    #   narrowed at 03:46, 06:38 and 08:05, never submitted. The agent's own note:
    #   *"The handler didn't refuse the
    #   supersede — it demanded the impact fields."*
    #
    #   `_impact_gate` is **a pure function** (it does not touch STATE), so calling it
    #   again here while leaving the recording-time call in place is safe. If it
    #   fails, the refuter is not run.
    impact = None
    if config.GATE_IMPACT_BEFORE_REFUTE:
        _iok, _inote, impact = ledger._impact_gate(inp)
        if not _iok:
            runlog.bump("impact_gate_denials")
            return deny(_inote)

    # G3
    dead = ledger.seen_scenario(tgt, claim)
    if dead and dead["state"] == "refuted":
        return deny(f"This scenario is already dead — [{dead['id']}] {dead['klass']}: "
                    f"{dead['reason'][:200]}\nTo raise this claim again you must first attach "
                    "NEW EVIDENCE THAT BREAKS THAT REFUTATION. Do not resurrect it from the "
                    "graveyard.")
    # G4
    if not config.GATE_REFUTE:
        ledger.stage(tgt, claim, anchors)
        return {}
    cand = ledger.open_candidate(tgt, claim, basis, inp.get("evidence"), anchors)
    ledger.STATE["refutes"]["run"] += 1
    print(f"\033[96m[refute] {cand['id']} {tgt} — independent refuter starting "
          f"(model={config.REFUTER_MODEL or 'inherit'})\033[0m")
    p = T.TARGET.get("_pe")
    rep = ""
    if p:
        res, summ = evidence.check(p, inp.get("evidence", ""), alt=T.TARGET.get("_alt"),
                               images=T.images_all())
        rep = evidence.render(res, summ)
    # Pass the impact **along with it.** Without that, all the refuter can say is
    #   "impact was not argued" — killing on grounds the claim had no chance to
    #   answer.
    v, raw = await refuter.run(SERVER, tgt, claim, inp.get("evidence"), rep,
                               impact=impact,
                               model=config.REFUTER_MODEL, tools=REFUTER_TOOLS,
                               cwd=config.WORK_DIR, max_turns=config.REFUTER_TURNS,
                               timeout=config.REFUTER_TIMEOUT)
    if v is None:
        ledger.STATE["refutes"]["failed"] += 1
        ledger.close_candidate(cand, "proposed", None, raw)
        ledger.save()
        return deny(f"Could not run the refuter: {raw}. AN EXECUTION FAILURE IS NOT A PASS — "
                    "a broken harness and an absent refutation produce the same output. Fix it "
                    "and confirm again (if you truly cannot run it, disable with GATE_REFUTE=0 "
                    "and say so in the report).")
    runlog.transcript(f"[refute] {cand['id']} {v}")
    ledger.count_via("refutes", v)
    # Separate undecidable (a malfunction) **first.** Without this line refuted=None
    #   is falsy, so a broken refuter simply passes the confirmation through — and in
    #   the other direction it used to be laundered as "it killed it".
    if v.get("fault"):
        ledger.STATE["refutes"]["failed"] += 1
        ledger.close_candidate(cand, "proposed", None, raw)
        ledger.save()
        print(f"\033[93m[refute] FAULT [{v.get('fault')}] — not a result\033[0m")
        return deny(f"The refuter FAILED TO PRODUCE A VERDICT ({v.get('fault')}): "
                    f"{v.get('reason')}\n"
                    "One retry gave the same result. THIS IS A MALFUNCTION, NOT A REFUTATION — "
                    "your confirmation is neither dead nor alive. Do not resubmit the same "
                    "argument in different words (that will not fix it). Recorded in the ledger "
                    "as refutes.failed. If you truly cannot run it, disable with GATE_REFUTE=0 "
                    "and say so in the report.")
    if v["refuted"]:
        ledger.STATE["refutes"]["killed"] += 1
        ledger.close_candidate(cand, "refuted", v.get("klass"), v.get("reason", ""),
                               impact=impact)
        print(f"\033[91m[refute] KILLED [{v.get('klass')}] {v.get('reason','')[:120]}\033[0m")
        # **File the resurrection condition in the open-question queue.** It used to
        #   appear in the context once and vanish, and of 11 confirmations the refuter
        #   killed, zero were ever resubmitted.
        try:
            _q = ledger.ask_refuted(tgt, claim, v.get("klass"), v.get("reason"),
                                    v.get("would_change_my_mind"))
        except Exception:
            _q = None
        _prec = ""
        try:
            _prec = ledger.rules_for(v.get("klass"))
        except Exception:
            pass
        return deny(f"An independent refuter KILLED this confirmation — [{v.get('klass')}] "
                    f"{v.get('reason')}{_prec}\n"
                    f"To revive it: {v.get('would_change_my_mind') or '(the refuter gave no condition)'}\n"
                    "The refuter never saw your reasoning. Resubmitting the same evidence will "
                    "kill it again.\n"
                    + (f"This revival condition is queued as open question `{_q['id']}` — "
                       "if you cannot satisfy it this session, the next one picks it up."
                       if _q else ""))
    ledger.STATE["refutes"]["survived"] += 1
    ledger.close_candidate(cand, "promoted", None, v.get("reason", ""))
    ledger.stage(tgt, claim, anchors, v)
    print(f"\033[92m[refute] SURVIVED — {v.get('reason','')[:120]}\033[0m")
    # A confirmation with weak impact (zero delta, no owner) gets the escalator.
    #   It **does not block** here: the confirmation is valid and only its grade is
    #   low, so the result is attached and no more.
    if config.GATE_ESCALATE:
        _d = str(inp.get("delta") or "").strip().lower()
        _o = str(inp.get("owner") or "").strip().lower()
        _weak = (_d in ("0", "none", "zero", "none") or _o in ("none", "none", "n/a", "-"))
        # An out-of-scope boundary (admin -> kernel) is **treated the same as weak
        #   impact**: the defect stands but the boundary drives its grade to zero, which
        #   is exactly where the escalator's question fits — "which lower principal
        #   reaches this sink?"
        # When the column exists, the column is canonical. While only a prose regex was
        #   consulted, 1 of 6 confirmations was caught.
        _fp, _tp = (inp.get("from_principal") or ""), (inp.get("to_principal") or "")
        if _fp and _tp:
            _oos = ledger.boundary_typed(_fp, _tp)[0] in ("no", "unknown")
        else:
            _oos = bool(ledger.scope_verdict({"boundary": inp.get("boundary"),
                                              "owner": inp.get("owner"),
                                              "principal": inp.get("principal")})[0])
        if _weak or _oos:
            await _run_escalator(inp, tgt,
                                 ("owner=%s · delta=%s · boundary=%s"
                                  % (inp.get("owner"), inp.get("delta"), inp.get("boundary")))
                                 + ("\nThe defect itself is CONFIRMED here; only the BOUNDARY "
                                    "is out of scope (admin->kernel is not a Windows security "
                                    "boundary). Do not re-litigate correctness — there is "
                                    "exactly one question: IS THERE A LOWER-PRIVILEGED "
                                    "PRINCIPAL THAT REACHES THE SAME SINK? Enumerate every ACE "
                                    "on the port/device SD, paths inside containers and "
                                    "AppContainer, and proxy calls from lower-privileged "
                                    "services." if _oos else ""),
                                 blocking=False)
    return {}


# ── PostToolUse: inject state and doctrine ───────────────────────────────
async def inject_state(input_data, tool_use_id, context):
    STATE["calls"] += 1
    name = (input_data or {}).get("tool_name", "")
    parts = []
    if STATE["nudges"]:
        parts.extend(STATE["nudges"]); STATE["nudges"].clear()
    if name == VERDICT or STATE["calls"] % 4 == 0:
        parts.append(ledger.status_block(STATE["calls"], config.MAX_TOOL_CALLS))
    # A metrics snapshot: on a timeout (SIGKILL) `finish()` never runs and the
    # `runs.jsonl` line is missing entirely.
    if STATE["calls"] % 5 == 0:
        try:
            runlog.snapshot(ledger.STATE, os.path.basename(T.TARGET.get("binary") or ""))
        except Exception:
            pass
    if not parts:
        return {}
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                   "additionalContext": "\n".join(parts)}}


# ── Stop: the exit checkpoint (no silent success) ────────────────────────
async def stop_gate(input_data, tool_use_id, context):
    # This used to let the run go **unconditionally** when `stop_hook_active` was
    #   set. That flag means "the stop hook already blocked once in this stop cycle",
    #   so whatever `STOP_BLOCKS` was set to, the **effective count was one.** One run
    #   took a single `stop blocked (1/2)` on that path and left with **zero verdicts
    #   in 23 minutes** against a 90-minute cap.
    #   An infinite loop is already prevented by the counter below — that is what
    #   STOP_BLOCKS is for.
    #   => do not return early on the flag; leave it to the counter.
    if not config.GATE_STOP or STATE["stop_blocks"] >= config.STOP_BLOCKS:
        return {}
    bad = ledger.can_finish()
    if not bad:
        return {}
    STATE["stop_blocks"] += 1
    runlog.bump("stop_blocks")
    msg = ("You cannot finish yet:\n" + "\n".join(f"  - {b}" for b in bad) +
           "\n\nZero confirmations is a legitimate outcome — but AN UNFILLED TABLE IS NOT AN "
           "OUTCOME.")
    print(f"\033[93m[stop-gate] stop blocked ({STATE['stop_blocks']}/{config.STOP_BLOCKS})\033[0m")
    return {"decision": "block", "reason": msg}


# ── PreCompact: checkpoint ───────────────────────────────────────────────
async def precompact(input_data, tool_use_id, context):
    ledger.save()
    # After compaction the model loses the earlier status block. Without clearing the
    #   delta cache it then receives only a "no change" line and **cannot see the
    #   state for the rest of the round.**
    ledger.status_reset("precompact")
    runlog.bump("compactions")
    print("\033[95m[compact] checkpointed the ledger to disk (just before context compaction)\033[0m")
    return {"hookSpecificOutput": {
        "hookEventName": "PreCompact",
        "additionalContext":
            "Pre-compaction checkpoint: the verdict ledger is on disk under state/ and your "
            "note-tool records survive too. After compaction, recover FIRST with "
            "verdict(action='status') and note(action='read'). "
            "Do not reconstruct a confirmation from memory."}}


SYSTEM = """You are an autonomous vulnerability analyst working on a compiled binary.
The goal is NOT to find something — it is to produce a defensible verdict for every item on
the surface table: confirmed / rejected / unanalysed.

Calibrate: on function-level vulnerability judgement, frontier models label roughly two thirds
of everything they read as vulnerable, at false-positive rates of 33-45%. Your prior that any
given piece of code is buggy should be much lower than it feels. A false positive costs more
than a missed bug.

DEPTH, NOT BREADTH — READ THIS BEFORE YOU REGISTER ANOTHER ROW
A 0-day does not fall out easily. If it were cheap, the vendor's own fuzzers and every other
researcher would already have it. What produces a finding here is ONE claim carried all the way
down — mechanism, reachability, the principal who can trigger it, the measurement that settles
it — not a wide table of things you looked at once.

So when the depth step in front of you is blocked, DO NOT substitute breadth for it. Measured
behaviour from this harness, three sessions running: ordered twice to produce two integers
inside a single function, the sessions instead enumerated an 18-member variant population and
grew the surface by +23, +9 and +12 while the live track stayed at stage 1 of 5. That is not
progress; it is the shape of avoidance, and it is legible in the ledger afterwards.

Concretely:
- Registering a row is CHEAP and adjudicating is EXPENSIVE, so a session that adds rows and
  settles none has made the denominator worse and the numerator unchanged.
- If your goal names one function and two integers, the deliverable is those two integers.
  A variant sweep is not a partial credit version of it.
- When a gate refuses you, the move is `gate_blocked` (which is honest and is read between
  sessions) or a different BASIS for the SAME row — not a different row.
- "I enumerated the population" is a denominator claim. It only has value once something in
  that population has been adjudicated.
- Finishing one row to a defensible verdict beats touching twenty. If you must choose, go down.

METHOD
1. binary_info first. A claim is valid only for the build you measured. If the corpus came from
   another build, every address must be re-derived — disassemble does that for you and says so.
2. census + surface(action='add') — enumerate BEFORE analysing. Coverage comes from that table.
   An item you cannot analyse becomes verdict(action='blocked'), never a silent deletion.
3. Navigate with find_funcs / callers / callees / callpath / decompile.
   DECIDE with disassemble. Settle reachability (callpath) before building an argument.
4. Quote anchors verbatim from disassemble output. Your evidence is machine-checked against the
   binary: a wrong address or a stale anchor is caught and the verdict is refused.
5. Every confirm is then handed to an independent refuter that has NOT seen your reasoning and
   is instructed to kill it. Expect most candidates to die there — that is the designed rate.
   Write the claim so that a cold reader with the same tools reaches the same place.
6. CROSS-IMAGE. When the truth of a claim lives in a callee — what nt!X does with the handle,
   the mode, the flags you passed it — do not assume the contract and do not settle for BLOCKED.
   Check images(action='list'); if the image is loaded, crossref(name='X') puts you inside it.
   Cite everything you read there as `nt!0xVA mnem ops`: tagged citations are verified against
   THAT file, untagged ones against the driver. Never state a kernel API's contract from memory —
   an assumed contract is the one thing in this harness that no gate can catch, because there is
   no byte in the measured image to check it against.

JUDGEMENT DOCTRINE
- "There is no check" is almost always wrong. Real defects are not ABSENCE but UNDER-APPLICATION:
    (a) half the population exempted — the check is there but short-circuited by a type flag.
        Enumerate every CONSTRUCTOR of the object.
    (b) checked once at the door — authorization at open/create and never per-operation. When a
        permission carries a SCOPE but is enforced by an ACL, nothing enforces the scope.
  Before writing absence: type every operand of the guard from DISASSEMBLY, and xref by
  BEHAVIOUR — callers() only sees direct calls, so wrappers and dispatch tables hide from it.
- The decompiler is wrong in both directions: it drops probe/range checks and it renders pointer
  math as truncation. Disassemble anything that changes a verdict.
- Mark every sentence CONFIRMED or INFERRED. Nothing to quote → INFERRED.
- Report negative results. "N of M were clean" is what makes coverage real.

WHAT KILLS CANDIDATES (check these yourself before claiming)
  unreachable · guarded · delta_zero (a shipped tool already does this) · by_design (documented)
  · anchor_stale · decompiler_artifact · impact_unproven · not_controlled (value is a constant)
  · gated_off (disabled by default)

MEASUREMENT DOCTRINE
- Positive control before any negative verdict — a broken harness and an absent bug look identical.
  Did the thing under test even execute? Check the exit code first.
- Measure the baseline before the treatment, and the delta against the legitimate path.
  If the same result is obtainable normally, the delta is zero and it is not a vulnerability.
- An oracle needs a THIRD outcome to separate "condition did not hold" from "request rejected".
- The signal may be TIME, not status code. Record (kind, status, elapsed).

Use note() for anything you must not lose to context compaction.
Be terse. Prefer acting via tools over long explanations."""

VARIANT_TASK = """
=== MODE: VARIANT HUNT ===
You are seeded with a confirmed finding. Variant analysis is where this kind of work actually
pays: the seed removes the ambiguity that makes cold discovery fail.

1. ROOT CAUSE — state the seed's invariant in one sentence: what did the code believe, and what
   broke it? Not the symptom, the belief.
2. SIBLING SEARCH — express that root cause as a mechanical query (corpus_grep / find_funcs /
   callers of the same sink) and run it over the WHOLE image. Register every hit on the surface
   table before judging any of them.
3. PER-SIBLING VERDICT — for each, the differentiator is usually a guard that exists on one path
   and not another. Disassemble both sides.
4. Report negatives explicitly: "N siblings, M carry the guard, K do not."

SEED:
{seed}
"""

def _axes_block():
    """**The harness itself states which measurement axes are open this round.**

    Why it was needed, from measurement: one target's previous rounds used
        `run_python 25 · note 24 · disassemble 23 · verdict 18` and **`ioctl` zero
        times.** The tool was there the whole time, but every run had
        `ALLOW_PROBE=0`, so all the agent ever learned was **"measurement is
        refused".** Open the axis and it still **does not try** — it has no way to
        know the axis opened (the tool description only says "ALLOW_*=1 is
        required").

    => the gate state is **computed from config** and put in the prompt. Writing it
        into the seed by hand is wrong: a seed goes stale while the gates change via
        the environment.
    """
    rows = [("host ioctl   ", config.ALLOW_PROBE, "ioctl(where='host', ...)",
             "fires at THIS analyst machine — a bugcheck kills the harness and the ledger"),
            ("guest ioctl  ", config.ALLOW_VM_PROBE, "ioctl(where='guest', ...)",
             "fires inside the isolated guest VM — a crash costs a snapshot revert, nothing more"),
            ("guest kernel ", config.ALLOW_KDNET, "kd(cmds='x nt!<sym>; u ...; dt ...')",
             "STOPS the guest kernel and answers WITH SYMBOLS, then resumes and verifies it")]
    open_ = [r for r in rows if r[1]]
    L = ["", "── MEASUREMENT AXES OPEN THIS ROUND (computed from the gates, not a guess) ──"]
    for name, on, call, why in rows:
        L.append("  %s : %-6s  %s" % (name, "OPEN" if on else "CLOSED",
                                      (call + "  — " + why) if on else "(do not try)"))
    if open_:
        L += [
            "",
            "This is not decoration. Previous rounds on this target made ZERO measurement calls",
            "because every gate was closed, so the habit you inherited is 'measurement is refused'.",
            "It is not refused now. When a claim rests on runtime behaviour — what the kernel",
            "actually does with your input, what a guard actually reads, whether an open actually",
            "happens — MEASURE IT instead of arguing from the decompiler. A decompiler drops checks",
            "and it invents defects; the wire does neither.",
            "A refusal that says 'not ready' or 'unmeasured' is the HARNESS failing, never evidence",
            "that the code is clean. Say so in the ledger and move on — do not convert it into a verdict.",
        ]
    else:
        L += ["", "All measurement axes are closed this round. Do not spend turns trying them;",
              "say `BLOCKED: no measurement axis open` where a claim needed one."]
    return "\n".join(L) + "\n"





async def run(binary, corpus, alt, seed=None):
    try:
        T.set_target(binary, corpus, alt)
    except Exception as e:
        print(f"\033[91m[!] failed to load the target: {e}\033[0m")
        return
    guid = ""
    if T.TARGET.get("_pe"):
        guid = T.TARGET["_pe"].codeview()[0] or ""
    loaded = ledger.attach(binary or corpus, guid)
    # The operator goal is installed **after attach**, and it arrives via the
    #   environment for a reason. The orchestrator wrote the goal into the state JSON,
    #   but
    #     (1) on first contact with a target that file **does not exist yet**, so
    #         json.load raised (and was silently swallowed), and
    #     (2) even when it did exist, the orchestrator's default `FRESH=1` made
    #         attach() discard it wholesale.
    #   So the goal only survived on `FRESH=0` rounds. When the stop gate cannot see
    #   the goal, "tidying the table" becomes the shortest path to the exit — one
    #   round ended that way in 19 minutes.
    _og = (os.environ.get("OPERATOR_GOAL") or "").strip()
    if _og:
        _ok = (os.environ.get("OPERATOR_GOAL_KIND") or "judge").strip()
        # `by` is **policy**: only an operator goal is locked by `set_goal` (see
        #   ledger.py). Hard-coding "operator" here promotes an orchestrator *suggestion*
        #   into a locked goal.
        _oby = (os.environ.get("OPERATOR_GOAL_BY") or "operator").strip()
        # This block used to **duplicate the body** of `seed_goal`, so the checks
        #   `seed_goal` performs (enforceability, prescribed-conclusion) **never ran in a
        #   real round** — `seed_goal` was only ever called from tests. The
        #   built-but-never-wired pattern again. It is funnelled through one place now.
        _gres = ledger.seed_goal(_og, _ok, by=_oby)
        print(f"\033[96m[goal] goal installed by={_oby} (kind={_ok}, independent of FRESH): {_og[:80]}\033[0m")
        if isinstance(_gres, dict) and _gres.get("_warn"):
            print("\033[93m%s\033[0m" % _gres["_warn"])
            runlog.bump("goal_warned")
    # Cross-image registration:
    #   `IMAGES=nt=/path/ntoskrnl.exe,apphelp=/path/apphelp.dll`
    #   With only the target image loaded, every claim that bottoms out in an `nt!`
    #   contract dies as BLOCKED. The kernel image has public PDB symbols, so it can
    #   be crossed into directly by export name.
    for _spec in [x.strip() for x in os.environ.get("IMAGES", "").split(",") if x.strip()]:
        if "=" not in _spec:
            print(f"\033[91m[images] the format is name=path: {_spec!r}\033[0m"); continue
        _n, _p = _spec.split("=", 1)
        try:
            _m = T.add_image(_n.strip(), _p.strip())
            ledger.record_image(_m)
            print(f"\033[96m[images] {_m['name']} ← {os.path.basename(_m['path'])} "
                  f"(base={_m['base']} guid={_m['guid'][:16]} {_m['exports']} exports) "
                  f"— tag citations as `{_m['name']}!0xVA`\033[0m")
        except Exception as _e:
            print(f"\033[91m[images] failed to register {_n}: {type(_e).__name__}: {_e}\033[0m")
    if loaded:
        pct, done, tot = ledger.coverage()
        print(f"\033[92m[ledger] restored the previous ledger — {tot} surface rows, {pct*100:.0f}% coverage, "
              f"{len(ledger.STATE['graveyard'])} graveyard rows "
              f"(FRESH={os.environ.get('FRESH','')!r} — this is **cumulative mode**)\033[0m")
    runlog.start(binary or corpus, config.RUN_TAG)
    runlog.mark_baseline(ledger.STATE)   # denials are cumulative; baseline this round

    opts = ClaudeAgentOptions(
        model=config.MODEL, system_prompt=SYSTEM + _axes_block(), cwd=config.WORK_DIR,
        mcp_servers={"vuln": SERVER},
        allowed_tools=["Bash", "Read", "Write", "Glob", "Grep"] + ALL_TOOLS,
        permission_mode="acceptEdits", max_turns=config.MAX_TURNS,
        resume=config.RESUME or None,
        hooks={
            "PreToolUse":  [HookMatcher(matcher=VERDICT, hooks=[gate_verdict],
                                        timeout=config.REFUTER_TIMEOUT + 120)],
            "PostToolUse": [HookMatcher(hooks=[inject_state])],
            "Stop":        [HookMatcher(hooks=[stop_gate])],
            "PreCompact":  [HookMatcher(hooks=[precompact])],
        },
        setting_sources=config.SETTING_SOURCES,
    )

    task = ["Analyze the target and produce a verdict for every surface item."]
    if binary:
        task.append(f"binary (MEASURED build): {binary}")
    if alt:
        task.append(f"alt build (the corpus came from this one): {alt}")
    if corpus:
        task.append(f"decompiled corpus: {corpus}  (navigation only — decide from disassembly)")
    task.append(f"work dir: {config.WORK_DIR}")
    if seed:
        task.append(VARIANT_TASK.format(seed=seed[:6000]))
    brief = os.path.join(os.path.dirname(os.path.abspath(binary or corpus)), "BRIEF.md")
    if os.path.exists(brief):
        print(f"[brief] {brief} applied")
        task.append("\n=== BRIEF (BRIEF.md from the target folder) ===\n" + open(brief).read().strip())
    if loaded and ledger.STATE["graveyard"]:
        # The old code attached "do not resurrect" to all of the most recent 12 rows.
        #   Measured, of 394 graveyard rows only **24 (6%) were refuter kills** — the
        #   other 370 were the analyst's own rejections. Their own verdicts came back in
        #   the same language as an adversary's and primed them against re-auditing.
        #   `graveyard_priming()` now splits the wording by origin and samples stratified
        #   by klass.
        _gp = ledger.graveyard_priming(12)
        if _gp:
            task.append("\n" + _gp)

    async with ClaudeSDKClient(options=opts) as client:
        await client.query("\n".join(task))
        final = None
        async for msg in client.receive_response():
            if isinstance(msg, AssistantMessage):
                # On a timeout (SIGKILL) no ResultMessage arrives. Tokens have to be accumulated
                #   here for the partial snapshot to be able to fill the cost columns.
                runlog.note_usage(getattr(msg, "usage", None))
                for b in msg.content:
                    if isinstance(b, TextBlock) and b.text.strip():
                        print(f"[think] {b.text.strip()}")
                        runlog.transcript(f"[think] {b.text.strip()}")
                        for n in doctrine.check(b.text, ledger):
                            print(f"\033[93m{n}\033[0m")
                            STATE["nudges"].append(n)
                    elif isinstance(b, ToolUseBlock):
                        runlog.tool(b.name)
                        line = f"[tool ] {b.name}({str(b.input)[:140]})"
                        print(line); runlog.transcript(line)
            elif isinstance(msg, ResultMessage):
                final = msg
                print(f"\n=== DONE: {msg.subtype} ===")

    ledger.save()
    print("\n" + ledger.status_block(STATE["calls"], config.MAX_TOOL_CALLS))
    print(runlog.summary(runlog.finish(final, None, ledger.STATE)))


def _usage():
    print("usage: python agent_sdk.py <binary> [corpus.c]\n"
          "       python agent_sdk.py --corpus <corpus.c>\n"
          "env  : ALT=<a PE of the same build as the corpus>  SEED=<variant-hunt seed file|string>\n"
          "       IMAGES=nt=/mnt/c/Windows/System32/ntoskrnl.exe[,name=path...]\n"
          "       FRESH=1 reset the ledger · GATE_REFUTE=0 disable the refuter · REFUTER_MODEL=<model>")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a]
    if not args:
        _usage(); sys.exit(1)
    if args[0] == "--corpus":
        b, c = None, args[1]
    else:
        b, c = args[0], (args[1] if len(args) > 1 else None)
    seed = os.environ.get("SEED", "")
    if seed and os.path.exists(seed):
        seed = open(seed, encoding="utf-8", errors="replace").read()
    if _LEAKED:
        print("\033[93m[!] ANTHROPIC_API_KEY  removed (if present, billing goes to the API instead of the subscription).\033[0m")
    asyncio.run(run(b, c, os.environ.get("ALT") or None, seed or None))
