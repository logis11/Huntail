#!/usr/bin/env python3
# dblfetch.py — **is the same user pointer read twice?** It is a whole bug class
# in WDM drivers and nothing in this harness was looking at it.
#
# Why it became urgent once `cfg.py` grew taint-lite: a double fetch is now
# **rejected more quietly, not less** — the first fetched value does flow to the
# sink, so the site earns a `flows` verdict and passes R3. The gate that was just
# built buries this bug class.
#
# The pattern:
#   p    = IoStackLocation->Type3InputBuffer  (METHOD_NEITHER, +0x20)
#        | Irp->UserBuffer (+0x70)
#   len  = [p+off]       <- first fetch: used for validation
#   if (len > MAX) fail
#   len2 = [p+off]       <- second fetch: used for the operation
#                           ** another thread changes it in between **
#
# This is a **candidate generator.** It emits any (pointer lineage, offset) read
# two or more times. A re-read is not itself a defect — it is dangerous only when
# the first read feeds a comparison and the second feeds a sink, and that is
# flagged separately.
#
# ── Why it is a dataflow analysis and not a scan ─────────────────────────────
# The first implementation walked a function **in address order** and so ignored
# control flow: one branch's register state leaked into another. Measured:
#     0x...59B  mov rbx, rdx              ; rbx = IRP
#     0x...6D9  mov rbx, [rsp+0x90]       ; **another branch's** epilogue restore
#                                         ;   (7 push + sub rsp,0x50 -> the same
#                                         ;    slot as [rsp+8] at entry = the
#                                         ;    caller's rbx)
#     0x...77C  mov rcx, [rbx+0xB8]       ; rbx must still be the IRP here, but
#                                         ;   the lineage is broken
# It could not catch its own positive control, so its zero findings meant
# **the detector is broken**, not "no double fetches". A linear scan cannot work
# in principle; this version builds the basic-block graph with `cfg.build` and
# joins at merge points.
import capstone
from capstone import x86 as X

import cfg as CFG
import config
import verifier_guard as VG

IRP_CURRENT_STACK = 0xB8
IRP_USERBUFFER = 0x70
SP_TYPE3 = 0x20
SP_INLEN = 0x10
SP_IOCTL = 0x18
USER_PTR_SRC = (SP_TYPE3, IRP_USERBUFFER)


def _md():
    m = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    m.detail = True
    return m


def _reg(md, r):
    n = md.reg_name(r) or ""
    W = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx", "esi": "rsi", "edi": "rdi",
         "ebp": "rbp", "esp": "rsp", "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11",
         "r12d": "r12", "r13d": "r13", "r14d": "r14", "r15d": "r15"}
    return W.get(n, n)


def _defs(md, ins):
    """The registers this instruction **defines** (what taint gets killed)."""
    out = set()
    if ins.mnemonic in ("cmp", "test", "push", "ret", "jmp") or ins.mnemonic.startswith("j"):
        return out
    ops = ins.operands
    if ops and ops[0].type == X.X86_OP_REG:
        out.add(_reg(md, ops[0].reg))
    if ins.mnemonic == "call":
        out |= {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}   # volatile
    return out


def _transfer(md, block, state):
    """Push one block through, updating taint and collecting user-memory reads.

    **The taint has two stages.** The first version seeded on "disp is 0x20 or
    0x70, therefore a user pointer", but `+0x20` is a common struct offset, so it
    emitted unrelated slots like `[rbp+0x8]` as candidates. (The same shape of
    over-detection had already happened once in `cfg._double_fetch`.) Lineage is
    now required:
        irp  : rdx at entry (the WDM `Xxx(DeviceObject, Irp)` convention)
        sp   : mov A, [irp + 0xB8]        <- CurrentStackLocation
        user : mov C, [sp  + 0x20]        <- Type3InputBuffer
             | mov C, [irp + 0x70]        <- Irp->UserBuffer
    """
    irp, sp, t = set(state["irp"]), set(state["sp"]), set(state["user"])
    devctl = bool(state.get("devctl"))
    reads = []
    for i in block:
        ops = i.operands
        if i.mnemonic == "mov" and len(ops) == 2 and ops[0].type == X.X86_OP_REG \
                and ops[1].type == X.X86_OP_MEM and ops[1].mem.base and not ops[1].mem.index:
            dst, b, d = _reg(md, ops[0].reg), _reg(md, ops[1].mem.base), ops[1].mem.disp
            if d == IRP_CURRENT_STACK and b in irp:
                sp.add(dst)
                irp.discard(dst)
                t.discard(dst)
                continue
            if (d == SP_TYPE3 and b in sp and state.get("devctl")) \
                    or (d == IRP_USERBUFFER and b in irp):
                t.add(dst)
                irp.discard(dst)
                sp.discard(dst)
                continue
        # `IO_STACK_LOCATION.Parameters` is a **union** — `+0x20` is
        #   Type3InputBuffer **only for DEVICE_CONTROL/FSCTL**; under any other
        #   major function it is just the fourth parameter slot. Without this
        #   gate, the detector reported kernel struct bookkeeping
        #   (`and qword ptr [rbx+0x28], 0`) as a user-buffer double fetch.
        #   => treat `+0x20` as Type3InputBuffer only if the same function also
        #      touched `sp+0x10` (InputBufferLength) or `sp+0x18` (IoControlCode).
        for op in ops:
            if op.type == X.X86_OP_MEM and op.mem.base and not op.mem.index \
                    and _reg(md, op.mem.base) in sp and op.mem.disp in (SP_INLEN, SP_IOCTL):
                devctl = True
        # (2) record user-memory **reads** (before the kill)
        for k, op in enumerate(ops):
            if op.type != X.X86_OP_MEM or not op.mem.base or op.mem.index:
                continue
            b = _reg(md, op.mem.base)
            if b in t and not (k == 0 and i.mnemonic == "mov"):    # a write is not a fetch
                reads.append({"va": i.address, "base": b, "disp": op.mem.disp,
                              "insn": "%s %s" % (i.mnemonic, i.op_str),
                              "is_cmp": i.mnemonic in ("cmp", "test", "sub")})
        # (3) copy propagation
        if i.mnemonic == "mov" and len(ops) == 2 and ops[0].type == X.X86_OP_REG \
                and ops[1].type == X.X86_OP_REG and _reg(md, ops[1].reg) in t:
            t.add(_reg(md, ops[0].reg))
            continue
        # (4) kill
        k = _defs(md, i)
        t -= k
        irp -= k
        sp -= k
    return {"irp": irp, "sp": sp, "user": t, "devctl": devctl}, reads


def scan_function(pe, va):
    """Double-fetch candidates in one function. A worklist that **joins by union
    at merge points.**"""
    g = CFG.build(pe, va)
    if not g:
        return []
    md = _md()
    # (1) `devctl` is a **function-level fact**. Left as a flow-sensitive flag it
    #     never gets seeded in a function where the `sp+0x10` / `sp+0x18`
    #     reference comes **after** the `+0x20` read, so it is established over
    #     the whole function first.
    #     This has to be **two passes.** A flow-insensitive pre-scan gets it
    #     wrong: after `mov rbx,[rbx+0x30]` makes rbx a FileObject, the following
    #     `[rbx+0x18]` is misread as IoControlCode. Pass 1 only **discovers**
    #     devctl flow-sensitively; pass 2 uses that fact as the function-level
    #     initial value, which removes the ordering problem.
    devctl_fn = False

    def _empty():
        return {"irp": set(), "sp": set(), "user": set(), "devctl": devctl_fn}

    IN = {a: _empty() for a in g["leaders"]}
    OUT = {}
    IN[g["leaders"][0]]["irp"].add("rdx")      # rdx at entry = IRP (WDM dispatch convention)
    work = list(g["leaders"])
    allreads = {}
    guard = 0
    passes = 0
    while work and guard < 4000:
        guard += 1
        a = work.pop(0)
        out, reads = _transfer(md, g["blocks"].get(a, []), IN[a])
        allreads[a] = reads
        OUT[a] = out                      # The union has to be taken over **OUT**,
                                          # not IN — the seed is created by passing
                                          # through the block.
        for s_ in g["succ"].get(a, ()):
            grew = False
            for k in ("irp", "sp", "user"):
                if not out[k] <= IN[s_][k]:
                    IN[s_][k] |= out[k]        # join = union (a may-analysis)
                    grew = True
            if out["devctl"] and not IN[s_]["devctl"]:
                IN[s_]["devctl"] = True
                grew = True
            if grew:
                work.append(s_)
        if out["devctl"] and not devctl_fn:
            devctl_fn = True               # found in pass 1 -> initial value in pass 2
        if not work and passes == 0 and devctl_fn:
            passes = 1
            for a2 in g["leaders"]:
                IN[a2] = {"irp": set(), "sp": set(), "user": set(), "devctl": True}
            IN[g["leaders"][0]]["irp"].add("rdx")
            work = list(g["leaders"])
    # (2) **Jump-table compensation.** With an indirect branch the `succ` edges
    #     are cut, most of the function becomes unreachable in the CFG, taint
    #     never arrives, and the result is a **false negative** (eight injected
    #     double fetches were all missed this way). Since this is a candidate
    #     generator, unreachable blocks are given **the union of every OUT** and
    #     run once more as an over-approximation. Anything that comes out of that
    #     is marked `approx` — so the branch confusion the header warns about
    #     does not come back in disguise.
    reach = set()
    stack = [g["leaders"][0]]
    while stack:
        a = stack.pop()
        if a in reach:
            continue
        reach.add(a)
        stack += list(g["succ"].get(a, ()))
    orphan = [a for a in g["leaders"] if a not in reach]
    if orphan:
        allsp, alluser, allirp = set(), set(), set()
        for a in g["leaders"]:
            o_ = OUT.get(a) or IN[a]
            allsp |= o_["sp"]
            alluser |= o_["user"]
            allirp |= o_["irp"]
        for a in orphan:
            st = {"irp": set(allirp) | {"rdx"}, "sp": set(allsp), "user": set(alluser),
                  "devctl": devctl_fn}
            _o, rd = _transfer(md, g["blocks"].get(a, []), st)
            allreads[a] = [dict(r, approx=True) for r in rd]

    slots = {}
    for a, reads in allreads.items():
        for r in reads:
            slots.setdefault((r["base"], r["disp"]), []).append(dict(r, block=a))
    out = []
    for (b, d), rs in slots.items():
        uniq = {r["va"]: r for r in rs}
        if len(uniq) < 2:
            continue
        rs2 = sorted(uniq.values(), key=lambda x: x["va"])
        out.append({"func": g["beg"], "slot": "[%s+0x%X]" % (b, d), "reads": rs2,
                    "validated": any(r["is_cmp"] for r in rs2),
                    "used": any(not r["is_cmp"] for r in rs2),
                    "approx": any(r.get("approx") for r in rs2)})
    return out


def scan(pe, limit=None):
    """`limit` defaults to **none**. The first version had `limit=400`, which
    **silently cut 64%** of a 1102-function image — and a truncated result looks
    exactly like "zero candidates". That is the same shape as a failure returning
    a value. If you want truncation, ask for it, and the result says it was
    truncated."""
    fns = pe.merged_functions()
    out = []
    if limit and len(fns) > limit:
        out.append({"func": None, "slot": "(TRUNCATED)", "reads": [],
                    "validated": False, "used": False,
                    "note": "only the first %d of %d functions were walked — this result is "
                            "not exhaustive." % (limit, len(fns))})
        fns = fns[:limit]
    for b, _e in fns:
        try:
            out += scan_function(pe, b)
        except Exception:
            continue
    # Dangerous shape first: one read feeds a check, another feeds a use.
    out.sort(key=lambda r: (not (r["validated"] and r["used"]), -len(r["reads"])))
    return out


# ── Controls ────────────────────────────────────────────────────────────────
def _synth(user_off):
    md = _md()
    code = (b"\x48\x8b\x82\xb8\x00\x00\x00"      # mov rax,[rdx+0xb8]
            + b"\x48\x8b\x70" + bytes([user_off])    # mov rsi,[rax+off]
            + b"\x8b\x4e\x10"                        # mov ecx,[rsi+0x10]   1st
            + b"\x83\xf9\x08"                        # cmp ecx,8
            + b"\x72\x05"                            # jb +5
            + b"\x8b\x56\x10"                        # mov edx,[rsi+0x10]   2nd
            + b"\xe8\x00\x00\x00\x00")               # call
    ins = list(md.disasm(code, 0x1000))
    return {"beg": 0x1000, "end": 0x1000 + len(code), "leaders": [0x1000],
            "blocks": {0x1000: ins}, "succ": {0x1000: set()}, "indirect": set(),
            "ins": {i.address: i for i in ins}}


def _probe(label):
    md = _md()
    if label == "no_lineage_ignored":
        # Skip the rdx -> [+0xB8] step and read [rbx+0x20] directly = no lineage
        code = (b"\x48\x8b\x73\x20" + b"\x8b\x4e\x10" + b"\x83\xf9\x08"
                + b"\x72\x05" + b"\x8b\x56\x10" + b"\xe8\x00\x00\x00\x00")
        ins = list(md.disasm(code, 0x1000))
        _t, reads = _transfer(md, ins, {"irp": {"rdx"}, "sp": set(), "user": set(),
                                        "devctl": True})
        sl = {}
        for r in reads:
            sl.setdefault((r["base"], r["disp"]), set()).add(r["va"])
        return sum(1 for v in sl.values() if len(v) >= 2)
    g = _synth(0x20 if label == "user_slot_refetch" else 0x40)
    _t, reads = _transfer(md, g["blocks"][0x1000], {"irp": {"rdx"}, "sp": set(),
                                                    "user": set(), "devctl": True})
    slots = {}
    for r in reads:
        slots.setdefault((r["base"], r["disp"]), set()).add(r["va"])
    return sum(1 for v in slots.values() if len(v) >= 2)


# ** This detector has no independent real-image positive control. Zero findings
#    on a real image is UNMEASURED, not clean. **
#
#   At one point "at least one hit on a particular network driver" was pinned as
#   the positive control. That was **circular** — the output was read first and
#   the control was fitted to it, which is not an oracle that knows the answer
#   independently. Worse, checking by hand showed both of those hits were
#   **false positives**: the lineage matched in shape (`rdx -> [+0xB8] -> [+0x20]`),
#   but `IO_STACK_LOCATION.Parameters` is a **union**, so `+0x20` is
#   Type3InputBuffer only under DEVICE_CONTROL/FSCTL, and that function was
#   doing kernel struct bookkeeping (`and qword ptr [rbx+0x28], 0`, which makes
#   no sense for a user buffer).
#   => the control was **pinning a false positive in place.** That is worse than
#      circular.
#
#   What is wired now: one synthetic positive plus three negatives, one of which
#   is a **hand-verified real-image false positive**, so it is not circular.
#   The route to a real positive control is to add a **double-fetch mutation** to
#   the bug injector and measure the detection rate. Until then, real-image
#   results are reported as UNMEASURED.
#
#   Ported note: the real-image negative control used to be a hard-coded host
#   path. It now comes from `config.DBLFETCH_FP_CONTROL`. When that is unset or
#   missing the control **does not run** — and a control that did not run is not
#   a control that passed, so `control_status()` says which ones actually ran.
#   Callers must print it: zero candidates with that control missing is the one
#   case where the omission matters most.
def _fp_control(label):
    """A non-circular **negative** control: an image where this detector was
    hand-verified to produce a false positive. Its answer is pinned to zero."""
    import os

    import pe as PEmod
    path = config.DBLFETCH_FP_CONTROL
    if not path or not os.path.exists(path):
        raise RuntimeError("control image not available: %r" % path)
    return len([r for r in scan(PEmod.PE(path)) if "rbx" in r["slot"]])


def _fp_control_available():
    import os
    return bool(config.DBLFETCH_FP_CONTROL and os.path.exists(config.DBLFETCH_FP_CONTROL))


_CONTROLS = {"user_slot_refetch": 1,      # positive (synthetic): a user-pointer slot read twice is caught
             "kernel_slot_ignored": 0,    # negative: not a user pointer, not counted
             "no_lineage_ignored": 0}     # negative: never seed [X+0x20] with no lineage
_FP_CONTROL = {"real_union_misread": 0}   # negative (real image, hand-verified)


def _controls():
    c = dict(_CONTROLS)
    if _fp_control_available():
        c.update(_FP_CONTROL)
    return c


def control_status():
    """Which controls actually ran. Print this next to any result — including a
    zero result, which is exactly when a missing control matters most."""
    if _fp_control_available():
        return ("controls: 1 synthetic positive + 2 synthetic negatives + 1 hand-verified "
                "real-image negative (%s) — all passed."
                % config.DBLFETCH_FP_CONTROL)
    return ("controls: 1 synthetic positive + 2 synthetic negatives passed, but the "
            "**real-image false-positive control DID NOT RUN** (config.DBLFETCH_FP_CONTROL "
            "is unset or missing). Results are UNMEASURED against the "
            "IO_STACK_LOCATION union misread that control exists to catch — a zero result "
            "here is not clean.")


def detect(pe, limit=None):
    """No result comes out until the controls check out. The row shape is
    deliberately identical to `scan()`; control status is reported separately by
    `control_status()` so it can never be mistaken for a candidate."""
    @VG.guarded("dblfetch", _controls(),
                probe=lambda k: (_fp_control(k) if k in _FP_CONTROL else _probe(k)),
                expect=lambda want, got: (got >= want) if want else (got == 0))
    def _run():
        return scan(pe, limit)

    return _run()


if __name__ == "__main__":
    import sys

    import pe as PEmod
    p = PEmod.PE(sys.argv[1])
    rs = detect(p)
    hot = [r for r in rs if r["validated"] and r["used"]]
    print("%d double-fetch candidate(s), %d of them both **checked and used**"
          % (len(rs), len(hot)))
    for r in hot[:15]:
        print("\n  fn 0x%X  slot %s" % (r["func"], r["slot"]))
        for x in r["reads"]:
            print("     0x%X  %-34s %s"
                  % (x["va"], x["insn"], "check" if x["is_cmp"] else "use"))
