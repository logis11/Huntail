# agent_sdk.py — 취약점 분석 하네스 (Claude Agent SDK, 구독 인증 경로).
#
# 압력의 방향: **위양성 억제**. 이건 취향이 아니라 측정된 문제다 —
# 함수 단위 취약점 판정 벤치마크에서 프런티어 모델의 위양성률은 33~45% 대이고,
# 어떤 모델은 전체 샘플의 69% 를 "취약함"으로 분류한다. 재현율이 아니라 **정밀도**가 병목이다.
# 그래서 이 하네스의 게이트는 전부 "확정을 어렵게" 만드는 쪽으로만 건다.
#
# 게이트 4단 (전부 실제 차단):
#   G0 근거 비어 있음                    → deny
#   G1 **앵커 기계 검증** — 인용한 주소에 정말 그 명령이 있는가 → deny
#   G2 부재 주장인데 디스어셈블 없음      → deny
#   G3 이미 죽은 시나리오                → deny (묘지에서 부활 금지)
#   G4 **독립 반박자** (컨텍스트 비대칭)  → 반박되면 deny + 묘지 등재
# 종료 게이트: 전수 표·앵커 미검증 확정이 남아 있으면 끝내지 못한다.
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
    """execute_tool 로 넘기는 얇은 래퍼. None/빈값 인자는 떨어뜨린다."""
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
        # ★ 2026-09-03: `found_while` 이 스키마에 없었다. `action='incidental'` 은 이 프로젝트
        #   최고의 결함이 발견된 채널인데, 핸들러는 `a.get("found_while")` 를 읽고 스키마에는
        #   없어서 **모델이 그 인자명을 알 길이 없었다**(설명 산문에만 있었다). 17개 인자 사고와
        #   같은 유형이다 — 이제 test_argschema.py 가 27개 툴 전부를 기계로 검사한다.
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
        "predicate that decides a member), and later member_state='0x140057D00=안전 0x...=의심'. "
        "THE HARNESS COMPUTES THE INTERSECTION - you do not declare it, because a declared "
        "intersection is a self-report. Members default to 미분석 and every render prints how "
        "many are still 미분석, so a PARTIAL census can never read as a closed one.\n"
        "  ★ invariant=<one sentence> marks the census PATCH-ANCHORED: the population that must "
        "enforce an invariant a vendor just restored (a fixed bug's siblings). Once tagged, you "
        "cannot close it as a complete fix with a bare verdict — you must file the closing verdict "
        "with completes=<this census name>, and it passes ONLY when 미분석=0 AND the closure "
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
        "NONE of these three can carry 확정/기각. Promotion still goes through verdict() and "
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
        "The closure is REFUSED unless that census has 미분석=0 AND its closing narrative was SUSTAINED "
        "by the interrogator. Enumeration incompleteness (a member set_b never listed) does not show up "
        "as 미분석, so the SUSTAINED interrogation — not the member count — is the real gate. If it is "
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
        "three unexamined sinks. So a surface row now goes to 기각 ONLY when you first declare its "
        "denominator with action='scope' (target=, items=['0xVA name', ...], method=<how you "
        "enumerated it — behaviour-based, not name xref>) and then adjudicate EVERY item. "
        "Each reject must name which candidate it kills: item='<label>' or sink=<VA>. "
        "Until the last one falls the surface stays 미분석(blocked) with the remaining candidates "
        "listed for you. This is not bureaucracy: 'this one path is guarded' and 'this surface is "
        "clean' are different claims, and only the first one is what your evidence supports.\n"
        "★ A gate that CANNOT DECIDE does not pass you — it ASKS. A reject that the gate cannot "
        "verify comes back as '[기각 보류 — 질문]' with a concrete next method, is NOT counted as "
        "a judgement, and stays in the open-question queue. action='asks' lists open questions; "
        "answer one by re-rejecting the same target after doing what the method says. "
        "If no method is left, action='exhaust' (target=, reason=, tried=) records METHOD "
        "EXHAUSTED — the third terminal state. It is NOT a rejection and never counts as a "
        "verified negative. Laundering exhaustion into a rejection makes the whole table a lie. "
        "You cannot finish while questions are open.\n"
        "basis ∈ decompile|disassemble|measured|doc. Every confirm is anchor-checked and then "
        "handed to an independent refuter that is trying to kill it. 'blocked' keeps the item "
        "as 미분석 and REQUIRES reason= : what you would have to look at next to move it to "
        "확정 or 기각.\n"
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
        # ★ 2026-09-03: 핸들러가 읽는 인자 **17개가 스키마에 없었다** — gate_blocked 의
        #   gate/kind/why/would_be, track 의 name/stage/note, exhaust 의 tried/method 등.
        #   SDK 가 미선언 키를 통과시켜서 '동작은 했지만', 스키마에 없으니
        #   에이전트가 **인자 이름을 알 길이 없었다**(산문에 적힌 것만 발견 가능).
        #   실제로 두 회차 연속 "이 채널은 도달 불가"로 신고됐다. 핸들러와 맞춘다.
        {"action": str, "id": str, "target": str, "claim": str, "basis": str,
         "evidence": str, "evidence_ids": str, "reason": str, "klass": str,
         "guard": str, "guards": str, "sink": str, "items": list, "method": str, "item": str,
         "owner": str, "delta": str, "boundary": str, "principal": str,
         # ★ 2026-09-10 — 경계를 **칸으로**. 산문 `boundary=` 는 벤더 언어 한 문장으로
         #   남기고, 정책 판정은 이 두 토큰이 한다(`ledger.PRINCIPAL_LATTICE`).
         "from_principal": str, "to_principal": str,
         "enumerated": str,
         # gate_blocked
         "gate": str, "kind": str, "why": str, "would_be": str,
         # track
         "name": str, "stage": int, "stages": str, "note": str, "text": str,
         # reopen
         "ground": str, "gid": str,
         # ★ 2026-09-07 lead — 리드를 닫는 **길**. 선언 안 하면 에이전트는 이 인자의
         #   존재를 모르고, 그러면 리드 큐는 읽기 전용이 된다(= 또 하나의 묘지).
         "how": str,
         # exhaust / asks / unfinished
         "tried": str, "n": int, "of": str, "offset": int,
         # ★ 2026-09-05 (C-037): blocked 의 '다음 한 걸음' 칸. 산문 사유에서는 기계가
         #   못 뽑는다는 것이 측정됐다(어떤 술어를 써도 blocked 의 56%가 걸리거나,
         #   접지형은 되찾아야 할 행을 떨어뜨린다). 그래서 쓰는 쪽이 선언한다.
         "next": str,
         # ★ 2026-09-05: 09-05 에 klass 넷을 늘리면서 **그 의무 인자를 또 안 넣었다** —
         #   바로 위 주석이 경고하는 그 실패를 같은 파일에서 반복했다.
         #   second_site/bounded_absence 는 게이트가 이 이름들을 요구하는데
         #   스키마에 없어서 에이전트가 이름을 알 길이 없었다.
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
# ★ 2026-09-05: 반박자만 **실측 도구**를 더 받는다 (`ioctl` + `kd`).
#   왜: 반박자는 지금까지 문서만 읽고 죽였다 — 실측으로 반증할 수단이 없어
#   "측정되지 않았다"는 킬을 낼 수는 있어도 **직접 재보고 뒤집을** 수는 없었다.
#   `run_python`/`Bash` 는 주지 않는다 — 반박자는 재보는 것이지 새 도구를 짜는 게 아니다.
#   게이트가 꺼져 있으면 툴이 "미측정"이라고 거부한다. 그 거부는 킬 사유가 아니다.
REFUTER_TOOLS = RO_TOOLS + [f"mcp__vuln__{n}" for n in ("ioctl", "kd")]


# ── G1: 앵커 기계 검증 ───────────────────────────────────────
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
    """게이트 본체는 _gate_verdict. 여기서 예외를 잡아 **deny 로** 바꾼다.

    PreToolUse 훅이 예외로 죽으면 CLI 는 그 호출을 그냥 통과시킨다 — 즉 **고장이 통과가 된다.**
    실제로 seen_scenario 의 한 줄 버그(`sorted(set(...)[:12])`)가 모든 정상 확정에서 터졌고,
    확정은 게이트를 하나도 거치지 않고 원장에 들어갔다. 반박자도 돌지 않았다.
    이 하네스 전체가 막으려는 실패 유형이 하네스 자신에게 있었다."""
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
        ledger.record_denial(target or "(적대자 경로)", reason, act=act, klass=klass)
    except Exception:
        pass
    return {"systemMessage": f"verdict blocked: {reason[:80]}",
            "hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


async def _interrogate(tgt, inp, gate_rec, force=False):
    """기각에 독립 심문자를 붙인다. 기각이 서지 않으면 deny 를 돌려준다(=ASK 로 되돌림).

    맨데이트가 반박자와 **반대**다: 애매하면 기각이 서지 않는다. 거짓 확정은 트리아지
    시간을 쓰지만 거짓 기각은 버그를 영구히 잃는다.
    """
    st = ledger.STATE.setdefault(
        "interrogs", {"run": 0, "broke": 0, "sustained": 0, "failed": 0, "skipped": 0})
    import random
    # ★ force: 게이트가 **표현 못 한** 건은 표본율로 건너뛰면 안 된다.
    #   건너뜀도 `None` 을 돌려주므로, 호출부는 "심문 통과"와 구분할 수 없다 —
    #   INTERROGATE_RATE 를 낮추는 순간 표현 불가 기각이 **아무 검증 없이 통과**한다.
    #   (이 저장소가 반복해서 당한 '성공을 반환하는 무동작' 계열이다.)
    if not force and random.random() > config.INTERROGATE_RATE:
        st["skipped"] += 1
        ledger.mark_interrogated(tgt, None, vid=(inp or {}).get("id"))
        return None
    st["run"] += 1
    print(f"\033[96m[interrogate] {tgt} — 독립 심문자 기동 "
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
    # ★ 같은 이유로 여기서도 먼저 가른다. 이 줄이 없으면 sustained=None 이
    #   "기각이 서지 않는다" 로 읽혀, 고장이 **기각 붕괴** 로 보고된다.
    #   09-02 ahcache S26-F10 이 정확히 이 경로로 두 번 죽었다.
    if v.get("fault"):
        st["failed"] += 1
        ledger.save()
        print(f"\033[93m[interrogate] FAULT [{v.get('fault')}] — 결과 아님\033[0m")
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
        # ★ 깨진 기각은 판정으로 기록되지 않으므로 `mark_interrogated` 가 붙일 행이 없다.
        #   그래서 지금까지 213건의 사유가 흔적 없이 사라졌다(transcript 는 회차마다 truncate).
        #   원장이 아니라 별도 기록부에 남긴다 — 소비자는 지휘자가 아니라 다음 회차 분석가다.
        try:
            ledger.record_break(tgt, v, inp)
        except Exception as _e:
            print("\033[93m[breaks] 기록 실패: %s\033[0m" % _e)
        ledger.save()
        print(f"\033[91m[interrogate] BROKE [{v.get('klass')}] "
              f"{v.get('reason','')[:120]}\033[0m")
        _prec = ""
        try:
            _prec = ledger.rules_for(v.get("klass"))
        except Exception:
            pass
        # ★ 2026-09-05 재설계 — **깨진 기각을 제출 시점에 막지 않는다.**
        #   옛 동작: deny → 분석가가 그 자리에서 다시 짝을 만들려다 루프에 갇혔다.
        #   새 동작: 기각은 그대로 등재되되 **산출물이 아니다**
        #   (`session_products()` 가 `broke` 인 것을 안 센다) ⇒ 이것만으로는 회차가 안 끝난다.
        #   차단을 **판정이 아니라 종료**에 걸면, 값싼 기각은 막으면서 루프는 안 생긴다.
        #
        #   ★★ 단 **사유는 반드시 분석가에게 간다.** 비차단으로 바꾸면서 이걸 놓치면
        #   "왜 깨졌는지"가 사라진다 — 그건 루프를 없애는 게 아니라 학습을 없애는 것이다.
        #   (T39 가 이 회귀를 잡았다: 선례 회수가 파기 문구에 안 붙는 상태였다.)
        #   차단하지 않는 경로에서는 툴 결과에 실어 보낸다 — stash 에 사유를 얹는다.
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
            return None            # 통과시킨다. 사유는 stash 로 툴 결과에 실린다.
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
    """★ 루프를 끊는다. 적대자가 아니라 **종결자**다 — 이 판에서 유일하게 전체 이력을 본다.

    실측(2026-09-04): 심문자 파기율 64~88%, 깨진 기각은 ASK 로 돌아가고 다음 회차가 다시
    기각하고 다시 깨진다. 같은 질문 4~5회가 ahcache 6건 · wcifs 8건. `attempts` 는 세기만
    했고 **강제 종료 지점이 없었다.**
    문헌: Refute-or-Promote 가 judge 를 두고(우리는 ❌였다), MAD-Stability 가
    **비수렴 시의 정의된 출력**을 요구하며, Nine Judges 는 판정자를 늘리는 방향을 반증한다.
    ⇒ 적대자를 더 붙이지 않고 종결자 하나.
    """
    hist = ledger.history_for(tgt)
    print(f"\033[95m[adjudicate] {tgt} — {n_attempts}회 미종결 ⇒ 판결자 기동 "
          f"(confirm 권한={config.ADJUDICATOR_MAY_CONFIRM})\033[0m")
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
        print(f"\033[93m[adjudicate] FAULT [{v.get('fault')}] — 결정 아님\033[0m")
        return deny_msg(f"The adjudicator FAILED TO PRODUCE A DECISION ({v.get('fault')}): "
                        f"{v.get('reason')}\nTHIS IS A MALFUNCTION, NOT A DECISION. The row "
                        "stays open. Report it with gate_blocked(kind='tool').")
    dec = v.get("verdict")
    # ★ 권한 스위치. 하루짜리 결정이라 코드가 아니라 config 로 잠근다.
    if dec == "confirm" and not config.ADJUDICATOR_MAY_CONFIRM:
        dec = "exhaust"
        v["downgraded_from"] = "confirm(no_authority)"
        ledger.record_adjudication(tgt, dict(v, verdict=dec), n_attempts, raw)
    runlog.bump("adjudicated_" + str(dec))
    print(f"\033[92m[adjudicate] {str(dec).upper()} — {str(v.get('reason'))[:120]}\033[0m")
    if dec == "reject":
        return None            # 기각이 선다 — 원래 경로로 기록된다
    if dec == "exhaust":
        ledger.verdict({"action": "exhaust", "target": tgt,
                        "reason": "[adjudicator] " + str(v.get("reason"))[:400],
                        "tried": "%d attempts; decisive anchor not establishable" % n_attempts})
        return deny_msg("The adjudicator ENDED this row as EXHAUSTED after %d attempts: %s\n"
                        "Missing observation: %s\nThis is NOT a rejection and NOT a defect — "
                        "the row is closed as unaudited-with-reason. Do not re-argue it; the "
                        "loop is what it was closed for. Move to another row."
                        % (n_attempts, v.get("reason"), v.get("decisive") or "(not named)"))
    # confirm — 판결자가 확정을 냈다. **감사 가능하게** 표시하고 통과시킨다.
    ledger.stash_adjudication(tgt, {
        "verdict": "confirm", "decisive": v.get("decisive"), "reason": v.get("reason"),
        "residual_risk": v.get("residual_risk"), "attempts": n_attempts})
    return None


async def _run_escalator(inp, tgt, impact_json, blocking):
    """★ L3 — 유일하게 **위로 미는** 장치. 반박자/심문자의 반대 방향.

    blocking=True  (기각 klass='delta_zero') — 승격되면 그 기각을 **되돌린다.**
                   델타 0 기각은 이 프로젝트에서 발견이 죽은 바로 그 자리다.
    blocking=False (확정인데 임팩트가 약함) — 되돌리지 않는다. 확정 자체는 유효하고
                   등급만 낮은 것이므로, 승격 결과를 **붙여만** 둔다.
    """
    st = ledger.STATE.setdefault(
        "escalations", {"run": 0, "lifted": 0, "held": 0, "failed": 0, "skipped": 0})
    import random
    if random.random() > config.ESCALATE_RATE:
        st["skipped"] += 1
        return None
    st["run"] += 1
    print(f"\033[95m[escalate] {tgt} — 승격자 기동 "
          f"(model={config.ESCALATOR_MODEL or 'inherit'}, blocking={blocking})\033[0m")
    v, raw = await escalator.run(
        SERVER, tgt, inp.get("claim", ""), inp.get("evidence", ""), impact_json,
        model=config.ESCALATOR_MODEL, tools=RO_TOOLS, cwd=config.WORK_DIR,
        max_turns=config.ESCALATOR_TURNS, timeout=config.ESCALATOR_TIMEOUT)
    if v is None:
        st["failed"] += 1
        ledger.save()
        print(f"\033[91m[escalate] 실행 실패: {raw[:160]}\033[0m")
        return None                      # 승격자 고장은 판정을 막지 않는다 (거짓 승격이 더 비싸다)
    runlog.transcript(f"[escalate] {tgt} {v}")
    ledger.stash_escalation(tgt, v)
    # ★ fault 를 먼저 가른다 (escalated=None 은 falsy — 고장이 'held' 로 세어지던 자리).
    if v.get("fault"):
        st["failed"] += 1
        ledger.save()
        print(f"\033[93m[escalate] FAULT [{v.get('fault')}] — 결과 아님\033[0m")
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
                f"다음 방법: {v.get('next_method') or '(no method given)'}\n"
                "'delta 0' is not a terminal answer. Re-adjudicate with this principal substituted in — "
                "this exact pivot has revived a finding that had already been written off.")
        return None
    st["held"] += 1
    ledger.save()
    print(f"\033[92m[escalate] HELD — {str(v.get('enumerated'))[:100]}\033[0m")
    return None


# ── 축을 닫는 서술에도 적대자를 붙인다 (2026-09-12) ──────────────────────────
# ★ 왜: 적대자는 **판정**에만 붙어 있었다 — 확정→반박자, 기각→심문자.
#   그런데 축을 닫는 것은 판정이 아니라 `track` 의 note 와 `gate_blocked` 의 why 다.
#   실측(09-12): `bfs-forceaccesscheck-arm` 이
#     "remaining term is the live ForceAccessCheck/feature state,
#      which no open axis can read - treat as parked"
#   로 닫혀 있었고 **아무도 그 문장을 보지 않았다.** 두 군데가 틀렸다 —
#   그 축은 `vmrun start` 한 번으로 열렸고, 술어는 기능 게이트가 아니라 레지스터 비교였다.
#   판정이었으면 심문자가 봤을 문장이 트랙 노트라서 통과했다.
# ★ **막지 않는다.** 이 저장소의 기존 결론대로(게이트를 조이면 리콜만 떨어진다)
#   결과를 기록해 분석가에게 넘기고 판단은 분석가가 한다 — `_inexpr` 경로와 같은 계약이다.
_CLOSURE_MARK = re.compile(
    # ★ 2026-09-12 코퍼스 보정: 첫 판은 예시 **하나**로 만들어 노트 29건 중 7건(24%)만 잡았다.
    #   지배 관용구는 "NO MEASUREMENT AXIS WAS OPEN THIS ROUND" 계열이었다. 79%로 올렸다.
    #   (escalation.md §5 — 스캐너를 만들면 원본 결함이 히트하는지 **먼저** 확인하라.)
    r"CLOSED\s+NEGATIVE|closes?\s+NEGATIVE|\bparked\b|\bTerminal\b|"
    r"DO\s*NOT\s*RE-?OPEN|재개봉\s*금지|재주문\s*금지|어떤\s*열린\s*축|"
    r"(no|any)\s+open\s+ax[ie]s|"            # ★ 원래 사례 - 재작성 때 깨뜨렸다가 회귀가 잡았다
    r"(no|any|every|all)\s+(open\s+)?(measurement\s+)?ax[ie]s(\s+(is|was|were|are))?\s+(open|closed)|"
    r"measurement\s+ax[ie]s\s+(are|is|was|were)\s+(all\s+)?closed|"
    r"all\s+measurement\s+axes|needs?\s+a\s+(measurement|runtime)\s+axis|"
    r"policy-closed|cannot\s+be\s+(measured|read)\s+without|"
    r"blocked-for-measurement|실측\s*(불가|필요)|런타임\s*축", re.I)


def _closure_text(inp):
    """`track`/`gate_blocked` 입력에서 **축을 닫는 서술**을 뽑는다. 없으면 None."""
    for k in ("note", "why", "reason", "claim"):
        t = (inp or {}).get(k)
        if isinstance(t, str) and _CLOSURE_MARK.search(t):
            return t
    return None


async def _interrogate_closure(tgt, inp, act):
    """축을 닫는 서술에 심문자를 붙인다. **항상 None 을 돌려준다(막지 않는다).**"""
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
    print("\033[96m[interrogate-closure] %s - 축을 닫는 서술에 심문자 기동 (%s)\033[0m"
          % (tgt, act))
    try:
        v, _raw = await interrogator.run(
            SERVER, tgt, claim, txt[:2000], "",
            model=config.INTERROGATOR_MODEL, tools=RO_TOOLS, cwd=config.WORK_DIR,
            timeout=getattr(config, "INTERROGATOR_TIMEOUT", 300))
    except Exception as e:
        st["failed"] += 1
        runlog.bump("closure_interrog_failed")
        print("\033[93m[interrogate-closure] 실패(%s) - 닫힘은 그대로 선다\033[0m"
              % type(e).__name__)
        return None
    # ★ 반환 규약은 `_interrogate` 와 같다: `v is None` = 실행 실패, `fault` = 판정 못 냄.
    #   **둘 다 '통과'가 아니다** — 이 저장소가 반복해서 밟은 '실패=통과' 함정이다.
    if v is None or (v or {}).get("fault"):
        st["failed"] += 1
        runlog.bump("closure_interrog_failed")
        print("\033[93m[interrogate-closure] 판정 못 냄(%s) - 미심문이지 '닫힘이 옳다'가 아니다\033[0m"
              % ((v or {}).get("fault") or "no-result"))
        _res, _detail = "UNJUDGED", str((v or {}).get("reason") or _raw or "")[:1200]
    else:
        broke = not v.get("sustained")
        st["broke" if broke else "sustained"] += 1
        runlog.bump("closure_interrog_broke" if broke else "closure_interrog_sustained")
        _res = "BROKE" if broke else "SUSTAINED"
        _detail = "klass=%s\n%s" % (v.get("klass"), str(v.get("reason") or "")[:1200])
        if broke:
            print("\033[91m[interrogate-closure] 심문자가 이 닫힘을 깼다 - 막지는 않지만 "
                  "원장에 남겼다. 다시 열지는 분석가가 정한다.\033[0m")
    # ★ 2026-09-24 — CI 결과를 **per-name** 으로도 남긴다(Move 2 게이트가 읽는다).
    #   전역 카운터(run/broke/sustained)만으로는 "어느 census 가 SUSTAINED 됐나" 를 알 수
    #   없어 patch-anchored 완결 게이트(`population_closure_status`)가 못 건다.
    st.setdefault("by_name", {})[str(name)] = _res
    # ★ 조용한 무동작 금지 - 결과를 노트로 남긴다. `tools._t_note` 가 정본 채널이다
    #   (`ledger.note_write` 는 **존재하지 않는다** - 첫 판에서 그걸 부르고 try/except 로
    #    삼킬 뻔했다).
    try:
        import tools as _T
        _T._t_note({"action": "write",
                    "key": "CLOSURE-INTERROG-%s-%s" % (act, str(name)[:36]),
                    "text": "## 결론\n닫힘 서술에 대한 심문 결과: %s\n\n%s\n\n닫힘 원문:\n%s\n\n%s"
                            % (_res, claim[:400], txt[:1200], _detail)})
    except Exception as _e:
        print("\033[93m[interrogate-closure] 노트 기록 실패: %s\033[0m" % type(_e).__name__)
    return None


async def _gate_verdict(input_data, tool_use_id, context):
    inp = (input_data or {}).get("tool_input") or {}
    act = (inp.get("action") or "").lower()
    tgt = inp.get("target", "?")
    claim = inp.get("claim", "")
    basis = (inp.get("basis") or "decompile").lower()

    def deny(reason):
        runlog.bump("gate_denials")
        # ★ 무엇을 막았는지 남긴다. `_reject_gate` 의 반려 21개가 전부 이 자리로 흐르므로
        #   여기 한 곳이면 기각 게이트 전체가 관측된다. 막는 동작은 그대로다. → R-05 / C-031
        try:
            ledger.record_denial(tgt, reason, act=act, klass=inp.get("klass") or "")
        except Exception:
            pass
        return {"systemMessage": f"verdict blocked: {reason[:80]}",
                "hookSpecificOutput": {"hookEventName": "PreToolUse",
                                       "permissionDecision": "deny",
                                       "permissionDecisionReason": reason}}

    # ★ 2026-09-07 — 정확일치는 오타 한 글자로 우회된다. **정본화 후** 비교한다.
    #   실측: `basis="measured on the live kernel, not inferred…"` 인 실측 기각이
    #   이 게이트를 통째로 건너뛰었다.
    # ★ 축을 닫는 서술(track note / gate_blocked why)에 적대자를 붙인다. 막지 않는다.
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
        # ★ 정적 게이트를 통과한 기각에 **독립 심문자**를 붙인다 (반박자의 거울).
        #   ASK 로 떨어진 건은 아직 기각이 아니므로 심문하지 않는다 —
        #   ★★ 단, 2026-09-04: 그 ASK 에는 **두 가지**가 섞여 있었다.
        #     `need_observation`(관측 부족)은 그대로 질문으로 둔다. LLM 이 봐도 나올 게 없다.
        #     `inexpressible`(분석은 끝났는데 게이트 모델이 그 모양을 표현 못 함)은 다르다 —
        #     실측 62건의 `dominates_only` 가 전부 여기였고, **어떤 LLM 도 본 적이 없이**
        #     ASK 큐로 직행해 다음 회차가 같은 규칙에 다시 부딪혔다.
        #     조건을 더 붙이는 대신(기계 규칙을 덕지덕지 늘리는 대신) **적대층이 한 번
        #     종합 판단**한다. 새 역할은 만들지 않는다: 심문자의 맨데이트가 이미
        #     "애매하면 기각이 서지 않는다"라 방향이 맞고, fault 계약도 그대로 쓴다.
        # ★ 판결자 — 같은 행이 N회 미종결이면 **심문자 대신** 종결자를 부른다.
        #   심문자를 또 부르면 같은 파기가 또 나올 뿐이다(실측 파기율 64~88%).
        _prev = ledger._ask_for(tgt) or {}
        _natt = len(_prev.get("attempts") or [])
        if config.GATE_ADJUDICATE and _natt >= config.ADJUDICATE_AFTER:
            r = await _adjudicate(tgt, inp, _natt)
            if r is not None:
                return r
            # confirm 이면 inp["_adjudicated"] 가 실려 아래로 통과한다.
            # reject 면 그대로 기각 경로로 간다 — 심문자는 건너뛴다(이미 종결됐다).
            _ask, _inexpr, _settled = None, False, True
        else:
            _ask = (_rec or {}).get("ask") if isinstance(_rec, dict) else None
            _inexpr = bool(_ask) and _ask.get("kind") == "inexpressible"
            _settled = False
        # ★ 판결이 났으면 심문자를 **돌리지 않는다.** 안 그러면 종결자가 끝낸 행을
        #   심문자가 다시 깨서 루프가 그대로 살아난다 — 이 배선의 목적 자체가 사라진다.
        # ★ 2026-09-05 재설계 — 게이트가 못 정한 것(`_ask`)은 **반려가 아니라 증거**다.
        #   GATE_COMPUTE_ONLY 면 종류를 가리지 않고 심문자에게 보낸다:
        #   `need_observation`(관측 부족)도 짝 탐색 루프의 원료였고, 그 판단은
        #   기계 규칙보다 적대자가 낫다. 게이트 계산 결과는 `_rec` 로 같이 넘어간다.
        if getattr(config, "GATE_COMPUTE_ONLY", True) and _ask:
            _inexpr = True
        if config.GATE_INTERROGATE and not _settled and (not _ask or _inexpr):
            if _inexpr:
                # 기계가 **무엇을 못 했는지**를 증거로 같이 넘긴다. 심문자는 추론 과정을
                # 못 보지만, 게이트가 계산한 CFG 사실은 봐야 판단이 가능하다.
                print(f"\033[96m[interrogate] {tgt} — 게이트가 표현 못 한 모양"
                      f"({_ask.get('cfg')}) ⇒ 적대층에 종합 판단을 맡긴다\033[0m")
                runlog.bump("inexpressible_judged")
            r = await _interrogate(tgt, inp, _rec, force=_inexpr)
            if r is not None:
                return r
            if _inexpr:
                # 심문자가 기각을 깨지 않았다 ⇒ 게이트가 표현 못 했을 뿐 기각은 선다.
                # ★ 2026-09-04 수정: 예전엔 이 사실을 **훅 지역 dict `_rec` 에만** 적었다.
                #   툴 쪽 `verdict()` 는 `_reject_gate` 를 처음부터 다시 계산하므로 그 표시가
                #   증발했다 — 원장에 `passed_by` 0건, `pending_interrog` 잔류 13건이 그 지문이다.
                #   실측 10건이 그렇게 사라졌다. 판결자·승격자가 쓰는 stash 패턴으로 건넨다.
                #   ★ ASK 를 취소하지는 않는다(운영자 결정 A안): 심문자의 `sustained` 는
                #     "옳다"가 아니라 "못 깼다"이므로 자동 승격은 정밀도 축을 연다.
                #     사실만 분석가에게 전달하고 **판단은 분석가가 한다.**
                try:
                    ledger.stash_inexpr_pass(tgt, {"cfg": _ask.get("cfg"),
                                                   "klass": v.get("klass"),
                                                   "reason": v.get("reason")})
                except Exception as _e:
                    print("\033[93m[inexpr] stash 실패: %s\033[0m" % _e)
                _rec.pop("ask", None)
                _rec["passed_by"] = "interrogator_over_inexpressible"
                _rec["gate_could_not_express"] = _ask.get("cfg")
                runlog.bump("inexpressible_sustained")
        # ★ L3 — `delta_zero` 기각은 **발견이 죽는 바로 그 자리**다. 여기서만 승격자가 막는다.
        #   심문자(옳은가)와 다른 질문을 한다: **누구에게는 델타가 0이 아닌가.**
        # ★ 트리거 확대(refs/01 · 04): 배선 이후 기각 37건에 `delta_zero` 는 **0건**이었고,
        #   실제로 등급이 깎이는 순간은 `by_design`(19/37)으로 온다 — 그게 벤더의 기각 서사 자체다.
        #   `by_design`/`delta_zero` 는 막고(blocking), `not_controlled` 는 붙여만 둔다.
        _kl = (inp.get("klass") or "").lower()
        if (config.GATE_ESCALATE and not _settled
                and _kl in ("delta_zero", "by_design", "not_controlled")
                and not (isinstance(_rec, dict) and _rec.get("ask"))):
            if _kl == "not_controlled":
                await _run_escalator(inp, tgt, "rejection klass=not_controlled - reason=%s"
                                     % (inp.get("reason") or "")[:400], blocking=False)
            else:
                # ★ 대조 대상 동일성(C-029)을 **사실로** 승격자에게 넘긴다. 게이트는 막지
                #   않았고, "같은 것을 잰 대조가 없다"는 관측은 델타 0을 의심할 근거다.
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
    # G5 — 선행연구. 코드만 보는 게이트로는 절대 못 잡는 것이 있다.
    #   ksecdd.sys 확정은 앵커 32건 기계검증 + 반박자 생존을 통과했는데
    #   2024년 공개물(KExecDD / SCRT blog)이었고, IOCTL 0x39006F 에는
    #   IOCTL_KSEC_IPC_SET_FUNCTION_RETURN 이라는 공개된 이름까지 있었다.
    if config.GATE_PRIORART:
        # ★ 축별로 본다. 예전엔 `has_priorart()` 가 비어 있지 않기만 하면 통과였다 —
        #   프롬프트는 3축을 요구했는데 코드는 기록이 **하나라도** 있는지만 셌다.
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
    # ── G2' — ★ 2026-09-04: **임팩트 게이트를 반박자 앞으로 옮긴다.**
    #
    #   측정으로 드러난 순서 뒤집힘: `_impact_gate`(owner/delta/boundary)는
    #   `ledger.verdict()` **기록 시점**에만 돌았다. 즉 반박자를 통과한 뒤였다.
    #   그런데 반박자의 킬 클래스에는 `impact_unproven` 이 있고, 실제로 오늘 밤
    #   확정 시도 6건 중 **2건이 그것으로 죽었다**(wcifs ATTACH-VECTOR / SILOUNION).
    #   ⇒ 하니스는 **임팩트를 요구하기도 전에** 반박자에게 임팩트를 판정시켰다.
    #     에이전트는 owner/delta/boundary 를 낼 기회조차 없었다.
    #     `refuter.build_prompt` 도 임팩트를 인자로 받지 않았다 — 존재하지 않았으니까.
    #
    #   같은 벽이 지휘자의 지시도 세 번 막았다(ahcache S9-D4 를 03:46/06:38/08:05 에
    #   점점 좁혀 지시했는데 매번 미제출). 에이전트 기록: *"The handler didn't refuse the
    #   supersede — it demanded the impact fields."*
    #
    #   `_impact_gate` 는 **순수 함수**다(STATE 를 안 건드린다) ⇒ 기록 시점의 호출을
    #   그대로 두고 여기서 한 번 더 불러도 안전하다. 실패하면 반박자를 태우지 않는다.
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
    print(f"\033[96m[refute] {cand['id']} {tgt} — 독립 반박자 기동 "
          f"(model={config.REFUTER_MODEL or 'inherit'})\033[0m")
    p = T.TARGET.get("_pe")
    rep = ""
    if p:
        res, summ = evidence.check(p, inp.get("evidence", ""), alt=T.TARGET.get("_alt"),
                               images=T.images_all())
        rep = evidence.render(res, summ)
    # ★ 임팩트를 **같이 넘긴다.** 안 넘기면 반박자는 "임팩트가 논증되지 않았다"밖에
    #   말할 수 없다 — 답할 기회가 없는 것을 근거로 죽이는 셈이다.
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
    # ★ 판정 불가(고장)를 **먼저** 가른다. 이 줄이 없으면 refuted=None 이 falsy 라
    #   고장난 반박자가 확정을 그냥 통과시킨다 — 원래는 반대로 '죽였다' 로 세탁됐다.
    if v.get("fault"):
        ledger.STATE["refutes"]["failed"] += 1
        ledger.close_candidate(cand, "proposed", None, raw)
        ledger.save()
        print(f"\033[93m[refute] FAULT [{v.get('fault')}] — 결과 아님\033[0m")
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
        # ★ 부활 조건을 **열린 질문 큐에 등재**한다. 예전엔 이 문장이 컨텍스트에 한 번 뜨고
        #   사라져서, 반박자에게 죽은 확정 11건 중 재제출 시도가 0건이었다(refs/01).
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
    # ★ L3 — 확정인데 임팩트가 약하면(델타 0 / 소유자 없음) 승격자를 붙인다.
    #   여기서는 **막지 않는다**: 확정 자체는 유효하고 등급만 낮은 것이므로, 결과를 붙여만 둔다.
    if config.GATE_ESCALATE:
        _d = str(inp.get("delta") or "").strip().lower()
        _o = str(inp.get("owner") or "").strip().lower()
        _weak = (_d in ("0", "없음", "zero", "none") or _o in ("none", "없음", "n/a", "-"))
        # ★ 범위 밖 경계(admin→kernel)는 **약한 임팩트와 같은 취급**을 받는다.
        #   결함은 섰는데 경계로 등급이 0이 되는 자리 — 승격자의 질문이 정확히 여기에 맞는다:
        #   "이 싱크에 닿는 더 낮은 권한은 누구인가."
        # ★ 칸이 있으면 칸이 정본. 산문 정규식만 보던 동안 확정 6건 중 1건만 걸렸다.
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


# ── PostToolUse: 상태·독트린 주입 ────────────────────────────
async def inject_state(input_data, tool_use_id, context):
    STATE["calls"] += 1
    name = (input_data or {}).get("tool_name", "")
    parts = []
    if STATE["nudges"]:
        parts.extend(STATE["nudges"]); STATE["nudges"].clear()
    if name == VERDICT or STATE["calls"] % 4 == 0:
        parts.append(ledger.status_block(STATE["calls"], config.MAX_TOOL_CALLS))
    # ★ 지표 스냅샷 — 타임아웃(SIGKILL)이면 finish() 가 안 돌아 runs.jsonl 줄이 통째로 없다.
    if STATE["calls"] % 5 == 0:
        try:
            runlog.snapshot(ledger.STATE, os.path.basename(T.TARGET.get("binary") or ""))
        except Exception:
            pass
    if not parts:
        return {}
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                   "additionalContext": "\n".join(parts)}}


# ── Stop: 종료 검문 (조용한 성공 방지) ───────────────────────
async def stop_gate(input_data, tool_use_id, context):
    # ★ 2026-09-04: 예전엔 `stop_hook_active` 면 **무조건** 놓아줬다. 그 플래그는
    #   "이 정지 사이클에서 스톱훅이 이미 한 번 막았다"는 뜻이라, 결과적으로
    #   `STOP_BLOCKS` 가 몇이든 **실효 1회**였다. msquic r1 이 그 경로로
    #   `종료 차단 (1/2)` 한 번만 맞고 **판정 0건에 23분**(cap 90분)으로 나갔다.
    #   무한루프는 아래 카운터가 이미 막는다 — 그게 STOP_BLOCKS 의 존재 이유다.
    #   ⇒ 플래그로 조기 반환하지 않고 카운터에 맡긴다.
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
    print(f"\033[93m[stop-gate] 종료 차단 ({STATE['stop_blocks']}/{config.STOP_BLOCKS})\033[0m")
    return {"decision": "block", "reason": msg}


# ── PreCompact: 체크포인트 ───────────────────────────────────
async def precompact(input_data, tool_use_id, context):
    ledger.save()
    # ★ 압축되면 모델은 앞의 status_block 을 잃는다. 델타 캐시를 안 비우면 그 뒤로
    #   '변동 없음' 한 줄만 받아 **그 회차 내내 상태를 못 본다.**
    ledger.status_reset("precompact")
    runlog.bump("compactions")
    print("\033[95m[compact] 원장을 디스크에 체크포인트했다 (컨텍스트 압축 직전)\033[0m")
    return {"hookSpecificOutput": {
        "hookEventName": "PreCompact",
        "additionalContext":
            "Pre-compaction checkpoint: the verdict ledger is on disk under state/ and your "
            "note-tool records survive too. After compaction, recover FIRST with "
            "verdict(action='status') and note(action='read'). "
            "기억에 의존해 확정을 재구성하지 마라."}}


SYSTEM = """You are an autonomous vulnerability analyst working on a compiled binary.
The goal is NOT to find something — it is to produce a defensible verdict for every item on
the surface table: 확정 / 기각 / 미분석.

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
    """★ **이번 회차에 어떤 실측 축이 열려 있는지 하니스가 직접 말해준다** (2026-09-05).

    왜 필요했나 — 측정으로 드러난 것: 이 표적의 이전 회차 툴 사용은
    `run_python 25 · note 24 · disassemble 23 · verdict 18` 이고 **`ioctl` 0회**다.
    툴은 내내 있었는데 모든 런이 `ALLOW_PROBE=0` 이었으므로 에이전트가 배운 것은
    **"실측은 거부된다"** 뿐이었다. 그래서 축을 열어줘도 **시도하지 않는다** —
    열렸다는 사실을 알 방법이 없기 때문이다(툴 설명은 "ALLOW_*=1 이 필요하다"까지만 말한다).

    ⇒ 게이트 상태를 **config 에서 계산해서** 프롬프트에 싣는다. 사람이 시드에 손으로
      적는 방식은 틀린다 — 시드는 낡고 게이트는 env 로 바뀐다.
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
        print(f"\033[91m[!] 대상 로드 실패: {e}\033[0m")
        return
    guid = ""
    if T.TARGET.get("_pe"):
        guid = T.TARGET["_pe"].codeview()[0] or ""
    loaded = ledger.attach(binary or corpus, guid)
    # ★ 2026-09-04: 운영자 목표를 **attach 뒤에** 심는다. 환경변수로 받는 이유가 있다.
    #   nightrun 은 목표를 state JSON 에 써 넣는데,
    #     ① 첫 접촉 표적은 그 파일이 **아직 없어서** json.load 가 터지고 (조용히 삼켜졌다),
    #     ② 파일이 있어도 nightrun 기본값 `FRESH=1` 이면 attach() 가 통째로 버린다.
    #   즉 목표는 `FRESH=0` 회차에서만 살아 있었다. 종료 게이트가 목표를 못 보면
    #   "표 정리"가 종료로 가는 최단 경로가 된다 — 09-02 에 그렇게 19분에 끝난 회차가 있다.
    _og = (os.environ.get("OPERATOR_GOAL") or "").strip()
    if _og:
        _ok = (os.environ.get("OPERATOR_GOAL_KIND") or "judge").strip()
        # ★ `by` 는 **정책**이다. operator 목표만 `set_goal` 이 잠근다(ledger.py 참조).
        #   여기서 "operator" 로 굳히면 지휘자 *제안*이 잠긴 목표로 승격된다.
        _oby = (os.environ.get("OPERATOR_GOAL_BY") or "operator").strip()
        # ★ 2026-09-05 — 예전엔 이 블록이 `seed_goal` 의 **본문을 복사**하고 있었다.
        #   그래서 `seed_goal` 이 하는 검사(집행가능성 C-024 · 결론 처방 C-030)가 실제
        #   회차에서는 **한 번도 돌지 않았다** — `seed_goal` 은 테스트에서만 불렸다.
        #   `built-but-never-wired` 그대로다. 이제 한 곳으로 모은다.
        _gres = ledger.seed_goal(_og, _ok, by=_oby)
        print(f"\033[96m[goal] 목표 설치 by={_oby} (kind={_ok}, FRESH 무관): {_og[:80]}\033[0m")
        if isinstance(_gres, dict) and _gres.get("_warn"):
            print("\033[93m%s\033[0m" % _gres["_warn"])
            runlog.bump("goal_warned")
    # ★ 크로스 이미지 등록. `IMAGES=nt=/mnt/c/.../ntoskrnl.exe,apphelp=/mnt/c/.../apphelp.dll`
    #   표적 이미지 하나만 보면 `nt!` 계약에 바닥이 닿는 주장이 전부 BLOCKED 로 죽는다.
    #   ntoskrnl 은 공개 PDB 심볼이 있어 익스포트 이름으로 바로 건너갈 수 있다.
    for _spec in [x.strip() for x in os.environ.get("IMAGES", "").split(",") if x.strip()]:
        if "=" not in _spec:
            print(f"\033[91m[images] 형식은 name=path 다: {_spec!r}\033[0m"); continue
        _n, _p = _spec.split("=", 1)
        try:
            _m = T.add_image(_n.strip(), _p.strip())
            ledger.record_image(_m)
            print(f"\033[96m[images] {_m['name']} ← {os.path.basename(_m['path'])} "
                  f"(base={_m['base']} guid={_m['guid'][:16]} 익스포트 {_m['exports']}개) "
                  f"— 인용은 `{_m['name']}!0xVA` 로 태그하라\033[0m")
        except Exception as _e:
            print(f"\033[91m[images] {_n} 등록 실패: {type(_e).__name__}: {_e}\033[0m")
    if loaded:
        pct, done, tot = ledger.coverage()
        print(f"\033[92m[ledger] 이전 원장 복원 — 전수 표 {tot}개, 커버리지 {pct*100:.0f}%, "
              f"묘지 {len(ledger.STATE['graveyard'])}건 "
              f"(FRESH={os.environ.get('FRESH','')!r} — **누적 모드**다)\033[0m")
    runlog.start(binary or corpus, config.RUN_TAG)
    runlog.mark_baseline(ledger.STATE)   # ★ 반려는 원장 누적 — 이번 회차분 기준선

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
        print(f"[brief] {brief} 적용")
        task.append("\n=== BRIEF (BRIEF.md from the target folder) ===\n" + open(brief).read().strip())
    if loaded and ledger.STATE["graveyard"]:
        # ★ 2026-09-04: 옛 코드는 `[-12:]` 최근 12건에 전부 "do not resurrect" 를 붙였다.
        #   실측으로 묘지 394건 중 **반박자 킬은 24건(6%)** 이고 370건은 분석가 자신의 기각이다.
        #   자기 판정이 적대자 판정과 같은 언어로 되돌아와 재심을 막는 프라이밍이 됐다.
        #   `graveyard_priming()` 이 출처별로 문구를 가르고 klass 층화로 뽑는다.
        _gp = ledger.graveyard_priming(12)
        if _gp:
            task.append("\n" + _gp)

    async with ClaudeSDKClient(options=opts) as client:
        await client.query("\n".join(task))
        final = None
        async for msg in client.receive_response():
            if isinstance(msg, AssistantMessage):
                # ★ 2026-09-07 — 타임아웃(SIGKILL)이면 ResultMessage 가 안 온다.
                #   토큰은 여기서 누적해 두어야 부분 스냅샷이 비용 칸을 채운다.
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
          "env  : ALT=<코퍼스와 같은 빌드의 PE>  SEED=<변종 사냥 씨앗 파일|문자열>\n"
          "       IMAGES=nt=/mnt/c/Windows/System32/ntoskrnl.exe[,name=path...]\n"
          "       FRESH=1 원장 초기화 · GATE_REFUTE=0 반박자 끄기 · REFUTER_MODEL=<모델>")


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
        print("\033[93m[!] ANTHROPIC_API_KEY 를 제거했다 (있으면 구독이 아니라 API 과금).\033[0m")
    asyncio.run(run(b, c, os.environ.get("ALT") or None, seed or None))
