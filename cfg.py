#!/usr/bin/env python3
# cfg.py — compute, on the control-flow graph, whether a guard **dominates** a sink.
#
# Why this exists: in one measured run, essentially all 18 rejections were
# `guarded` ("there is a guard"). The anchors were 98/98 real. But **"a guard
# exists" and "a guard blocks every path" are different claims**, and the second
# one is computable with certainty — so it is not a job to hand to a model.
#
# Three verdicts:
#   gated         — the sink is reachable from **only one successor** of the guard
#                   branch. That is a real guard.
#   both_edges    — the sink is reachable from both successors. **The branch does
#                   not separate the sink out** = not a guard.
#   not_dominated — the guard block does not dominate the sink block. **There is
#                   a path that bypasses the guard.**
# Everything else (cross_function / no_branch / unbounded) comes back as
# undecidable, which means unanalysed — not clean.
import capstone
from capstone import x86 as X

_MD = None
_TERM = {"jmp", "ret", "retn", "iret", "int3", "ud2"}
_COND = {"je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle",
         "js", "jns", "jo", "jno", "jp", "jnp", "jc", "jnc", "jecxz", "jrcxz"}


def _md():
    global _MD
    if _MD is None:
        _MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        _MD.detail = True
    return _MD


def build(pe, va, max_span=0x20000, merged=True):
    """Build a basic-block graph, only inside the `.pdata` bounds. Bounds are
    never guessed.

    `merged=True` (the default): use bounds that **coalesce adjacent
      RUNTIME_FUNCTION chunks.** MSVC splits a large function across several
      `.pdata` chunks (chained unwind). Cutting at a chunk boundary **breaks the
      graph in the middle of a function** — two measured casualties:
        · Eight injected double fetches were all missed. The bounds spanned 0x59
          bytes and every injected site was outside them.
        · An owner check at one address and its consumer 13 bytes later came back
          as `no_branch`, because `.pdata` had split the shrink-wrap continuation
          out as a separate function.
      `merged=False` restores the old behaviour (raw chunk bounds).
    """
    b, e = (pe.func_bounds_merged(va) if merged and hasattr(pe, "func_bounds_merged")
            else pe.func_bounds(va))
    if b is None:
        b, e = pe.func_bounds(va)
    if b is None or e <= b or e - b > max_span:
        return None
    o = pe.va2off(b)
    if o is None:
        return None
    ins = list(_md().disasm(pe.d[o:o + (e - b)], b))
    if not ins:
        return None
    addrs = {i.address: i for i in ins}
    leaders = {b}
    for k, i in enumerate(ins):
        m = i.mnemonic
        if m in _COND or m == "jmp":
            try:
                t = int(i.op_str, 0)
            except ValueError:
                t = None                       # indirect branch — target unknown
            if t is not None and b <= t < e:
                leaders.add(t)
            if k + 1 < len(ins):
                leaders.add(ins[k + 1].address)
        elif m in ("ret", "retn") and k + 1 < len(ins):
            leaders.add(ins[k + 1].address)
    leaders = sorted(x for x in leaders if x in addrs)
    idx = {a: n for n, a in enumerate(leaders)}
    blocks, succ = {}, {a: set() for a in leaders}
    indirect = set()
    for n, a in enumerate(leaders):
        end = leaders[n + 1] if n + 1 < len(leaders) else e
        body = [i for i in ins if a <= i.address < end]
        blocks[a] = body
        if not body:
            continue
        last = body[-1]
        m = last.mnemonic
        nxt = leaders[n + 1] if n + 1 < len(leaders) else None
        if m in _COND:
            try:
                t = int(last.op_str, 0)
                if t in idx:
                    succ[a].add(t)
                else:
                    indirect.add(a)
            except ValueError:
                indirect.add(a)
            if nxt is not None:
                succ[a].add(nxt)
        elif m == "jmp":
            try:
                t = int(last.op_str, 0)
                if t in idx:
                    succ[a].add(t)
                else:
                    indirect.add(a)
            except ValueError:
                indirect.add(a)
        elif m in ("ret", "retn", "int3", "ud2"):
            pass
        else:
            if nxt is not None:
                succ[a].add(nxt)
    return {"beg": b, "end": e, "leaders": leaders, "blocks": blocks,
            "succ": succ, "indirect": indirect, "ins": addrs}


def _block_of(g, va):
    hit = None
    for a in g["leaders"]:
        if a <= va:
            hit = a
        else:
            break
    if hit is None:
        return None
    end = g["leaders"][g["leaders"].index(hit) + 1] if hit != g["leaders"][-1] else g["end"]
    return hit if va < end else None


def _reach(g, start, stop_at=None):
    seen, stack = set(), [start]
    while stack:
        x = stack.pop()
        if x in seen or x is None:
            continue
        seen.add(x)
        if stop_at is not None and x == stop_at:
            continue
        stack.extend(g["succ"].get(x, ()))
    return seen


def _doms(g):
    """Iterative dominator computation. Blocks unreachable from the entry are
    excluded."""
    entry = g["leaders"][0]
    live = _reach(g, entry)
    pred = {a: set() for a in live}
    for a in live:
        for s in g["succ"].get(a, ()):
            if s in live:
                pred[s].add(a)
    dom = {a: set(live) for a in live}
    dom[entry] = {entry}
    changed = True
    while changed:
        changed = False
        for a in live:
            if a == entry:
                continue
            ps = pred[a]
            new = set(live) if not ps else set.intersection(*[dom[p] for p in ps])
            new = new | {a}
            if new != dom[a]:
                dom[a] = new
                changed = True
    return dom, live


def _taint_lite(pe, g, gb, guard_va, sink_va):
    """taint-lite: **does the value the guard read reach a sink operand without
    being redefined?**

    Why this is needed — measured with a mutation experiment:
      at 30 sites where `cfg.gates` answered `gated`, the bound constant was
      widened (dominance and CFG unchanged, only the constraint removed) and
      **30/30 still came back `gated`.** Dominance proves *the guard executes*,
      not *the guard constrains*. If the value the guard checked and the value
      that flows to the sink differ, the site satisfies dominance and is still
      vulnerable.

    Limits (always report these alongside): forward tracking at register
    granularity only. It cannot see flow through memory, signed comparisons, or
    **double fetches**. Those are separate classes.
    """
    md = _md()
    gi = [i for i in g["blocks"].get(gb, []) if i.address <= guard_va]
    cmpi = None
    for i in reversed(gi):
        if i.mnemonic in ("cmp", "test", "sub"):
            cmpi = i
            break
    if cmpi is None:
        return {"taint": "no_cmp", "why": "no comparison instruction found in the guard block"}
    watched = set()
    for op in cmpi.operands:
        if op.type == X.X86_OP_REG:
            watched.add(_reg(md, op.reg))
        elif op.type == X.X86_OP_MEM and op.mem.base:
            watched.add(("mem", _reg(md, op.mem.base), op.mem.disp))
    if not watched:
        return {"taint": "no_operand", "why": "could not pin down the comparison operands"}
    # Walk the instructions on the guard -> sink path in address order, looking
    # for redefinition and for arrival at the sink.
    seq = []
    for a in g["leaders"]:
        for i in g["blocks"][a]:
            if guard_va < i.address <= sink_va:
                seq.append(i)
    seq.sort(key=lambda x: x.address)
    redefined = []
    for i in seq:
        if i.address == sink_va:
            break
        # If a watched value is **copied** to another register or to the stack,
        # propagate it. That is not a redefinition.
        if i.mnemonic in ("mov", "movzx", "movsx", "movsxd", "lea") and len(i.operands) == 2:
            src, dst = i.operands[1], i.operands[0]
            if src.type == X.X86_OP_REG and _reg(md, src.reg) in watched:
                if dst.type == X.X86_OP_REG:
                    watched.add(_reg(md, dst.reg))
                    continue
                if dst.type == X.X86_OP_MEM and dst.mem.base and \
                        _reg(md, dst.mem.base) == "rsp":
                    watched.add("__stack")
                    continue
        if i.operands and i.operands[0].type == X.X86_OP_REG and \
                i.mnemonic not in ("cmp", "test", "push"):
            r = _reg(md, i.operands[0].reg)
            if r in watched:
                watched.discard(r)
                redefined.append("0x%X %s %s" % (i.address, i.mnemonic, i.op_str))
    sink = None
    for i in seq:
        if i.address == sink_va:
            sink = i
    if sink is None:
        return {"taint": "no_sink_insn", "why": "the sink instruction is not on the path"}
    # If the sink is a call, its operand is the **call target**, not the
    #   arguments. The first version read the IAT slot of `call [rip+X]` as the
    #   operand and so dropped every such site to no_flow. A regression over a
    #   known-gated site caught it.
    reach = set()
    if sink.mnemonic in ("call", "jmp"):
        reach |= {"rcx", "rdx", "r8", "r9"}          # the four x64 integer args
        reach |= {"xmm0", "xmm1", "xmm2", "xmm3"}
        reach.add("__stack")                          # [rsp+0x20..] stack args
    else:
        for op in sink.operands:
            if op.type == X.X86_OP_REG:
                reach.add(_reg(md, op.reg))
            elif op.type == X.X86_OP_MEM:
                if op.mem.base:
                    reach.add(_reg(md, op.mem.base))
                if op.mem.index:
                    reach.add(_reg(md, op.mem.index))
    hit = watched & reach
    return {"taint": "flows" if hit else "no_flow",
            "watched_left": sorted(x for x in watched if isinstance(x, str)),
            "sink_operands": sorted(reach), "redefined": redefined[:6],
            "why": ("the value the guard read (%s) reaches the sink operand unchanged"
                    % sorted(hit))
                   if hit else
                   ("the value the guard read **does not reach** the sink operand — it "
                    "dominates but does not constrain. Redefined at: %s"
                    % ("; ".join(redefined[:3]) or "nowhere (a different value from the start)"))}


def _reg(md, r):
    n = md.reg_name(r) or ""
    for b, al in (("rax", "eax ax al ah"), ("rbx", "ebx bx bl bh"), ("rcx", "ecx cx cl ch"),
                  ("rdx", "edx dx dl dh"), ("rsi", "esi si sil"), ("rdi", "edi di dil"),
                  ("rbp", "ebp bp bpl"), ("rsp", "esp sp spl")):
        if n == b or n in al.split():
            return b
    for b in "r8 r9 r10 r11 r12 r13 r14 r15".split():
        if n.startswith(b) and (len(n) == len(b) or n[len(b):] in ("d", "w", "b")):
            return b
    return n


# Measured with the bug-injection bench: on these classes R3 misses **100%** of
#   the injected bugs. Dominance plus taint proves "the value flows"; it cannot
#   prove "the bound is right" or "the direction is right".
#   **Allowing a rejection while knowing that is policy, not an accident.** So the
#   authority is withdrawn instead.
_SIGNED_JCC = {"jl", "jle", "jg", "jge", "jns", "js"}


# ── R7 material: is the declared sink **actually a dangerous operation**? ─────
#   Found on a UMDF reflector driver: the claim was "it dereferences a user
#   pointer without probing", but the pair the machine verified was
#     guard = `cmp r13d, 8`      (a register length check)
#     sink  = `mov rdx, r13`     (a register move — **not a dangerous operation**)
#   The real counter-evidence (a probe helper, a user-probe import) was free text
#   that no gate ever looked at, and the gate handed out `gated` for an
#   **unrelated pair**.
#   ⇒ R3 verifies the pair the analyst chose. Nobody was checking that the pair
#     is the pair the claim is about.
SINK_CLASSES = ("call", "mem_write", "mem_read", "string_op", "reg_only", "control_flow")


def sink_class(pe, sink_va):
    """What class of operation is the instruction at the sink VA? If it is
    `reg_only` it cannot be used as a sink."""
    md = _md()
    fs, fe = pe.func_bounds(sink_va)
    if fs is None:
        return {"class": "unknown", "why": "no function in .pdata — cannot decode"}
    d = pe.read(sink_va, 16)
    if not d:
        return {"class": "unknown", "why": "outside the mapping"}
    ins = next(iter(md.disasm(bytes(d), sink_va)), None)
    if ins is None:
        return {"class": "unknown", "why": "decode failed"}
    m, txt = ins.mnemonic, "%s %s" % (ins.mnemonic, ins.op_str)
    if m.startswith("rep") or m.startswith("movs") or m.startswith("stos"):
        return {"class": "string_op", "insn": txt}
    if m == "call" or m == "jmp":
        return {"class": "call" if m == "call" else "control_flow", "insn": txt}
    mem_dst = mem_src = False
    for k, op in enumerate(ins.operands):
        if op.type == X.X86_OP_MEM and op.mem.base:
            base = _reg(md, op.mem.base)
            if base in ("rsp", "rbp"):      # a stack local is not a sink
                continue
            if k == 0:
                mem_dst = True
            else:
                mem_src = True
    if mem_dst:
        return {"class": "mem_write", "insn": txt}
    if mem_src:
        return {"class": "mem_read", "insn": txt}
    return {"class": "reg_only", "insn": txt,
            "why": "this is a register/immediate operation — **not a dangerous operation, so "
                   "it cannot be declared as the sink.** Give the VA of the operation the "
                   "claim is actually about (dereference / call / write)."}


# ── R3 authority withdrawal: double fetch ────────────────────────────────────
#   The `_taint_lite` docstring already wrote down the limit — "cannot see flow
#   through memory, signed comparisons, or double fetches". The double-fetch
#   detector says the same thing from the other side: **the first fetched value
#   flows to the sink, so the site earns a `flows` verdict and passes R3. The
#   gate buries this bug class.**
#   That was written down and not enforced. It is enforced here.
#
# Where a user-controlled pointer comes from. These offsets are the IRP /
# IO_STACK_LOCATION slots a user-mode caller controls directly; they are the same
# constants the double-fetch detector declares.
SP_TYPE3_INPUT = 0x20        # IO_STACK_LOCATION->Parameters.DeviceIoControl.Type3InputBuffer
IRP_USERBUFFER = 0x70        # Irp->UserBuffer
USER_PTR_SRC = (SP_TYPE3_INPUT, IRP_USERBUFFER)


def _base_is_user_ptr(md, g, base, before_va):
    """Did the `base` register come from a **user pointer**?

    Why this narrowing is mandatory (a regression caught it): before the
      narrowing, the detector reported a re-read of `[rsi+0x38]` as a double
      fetch. But kernel code re-reads struct fields constantly — leave it like
      that and R3's authority is withdrawn at nearly every site, which makes the
      gate useless and the ladder unusable. **A double fetch only holds when the
      slot is user-controlled.**
    """
    for a in g["leaders"]:
        for i in g["blocks"][a]:
            if i.address >= before_va:
                continue
            if i.mnemonic != "mov" or len(i.operands) != 2:
                continue
            dst, src = i.operands[0], i.operands[1]
            if dst.type != X.X86_OP_REG or _reg(md, dst.reg) != base:
                continue
            if src.type == X.X86_OP_MEM and src.mem.base and src.mem.disp in USER_PTR_SRC:
                return (True, "0x%X %s %s" % (i.address, i.mnemonic, i.op_str))
    return (False, None)


def _double_fetch(pe, g, gb, guard_va, sink_va):
    """Is the **memory slot** the guard read re-read between the guard and the sink?

    A re-read is not itself a defect — so this does not claim a defect, it only
    **withdraws the rejection authority**, and only when a user-pointer
    provenance is confirmed. With no provenance it withdraws nothing and just
    records the observation (`base["refetch"]`): leaving a candidate standing
    beats silently defeating the gate.
    Stack-based slots (rsp/rbp) are excluded: reloading a local spill is not a
    double fetch.
    """
    md = _md()
    body = g["blocks"].get(gb, [])
    gi = [i for i in body if i.address <= guard_va]
    cmpi = None
    for i in reversed(gi):
        if i.mnemonic in ("cmp", "test", "sub"):
            cmpi = i
            break
    if cmpi is None:
        return None
    slots = set()

    def _slot(op):
        if op.type == X.X86_OP_MEM and op.mem.base:
            b = _reg(md, op.mem.base)
            if b not in ("rsp", "rbp") and not op.mem.index:
                return (b, op.mem.disp)
        return None

    for op in cmpi.operands:
        s_ = _slot(op)
        if s_:
            slots.add(s_)
    # The common shape is `mov ecx, [rax+0x10]` then `cmp rcx, 1`. Pick up the
    # **load source** of the compared register.
    cmp_regs = {_reg(md, op.reg) for op in cmpi.operands if op.type == X.X86_OP_REG}
    for i in reversed(gi[:-1] if gi else []):
        if i.mnemonic in ("mov", "movzx", "movsx", "movsxd") and len(i.operands) == 2:
            dst, src = i.operands[0], i.operands[1]
            if dst.type == X.X86_OP_REG and _reg(md, dst.reg) in cmp_regs:
                s_ = _slot(src)
                if s_:
                    slots.add(s_)
                break
    if not slots:
        return None
    seq = []
    for a in g["leaders"]:
        for i in g["blocks"][a]:
            if guard_va < i.address <= sink_va:
                seq.append(i)
    seq.sort(key=lambda x: x.address)
    for i in seq:
        for op in i.operands:
            s_ = _slot(op)
            if not (s_ and s_ in slots):
                continue
            user, prov = _base_is_user_ptr(md, g, s_[0], i.address)
            info = {"slot": "[%s%+d]" % s_, "at": i.address,
                    "insn": "%s %s" % (i.mnemonic, i.op_str),
                    "user_ptr": user, "provenance": prov}
            if not user:
                return {"refetch": info}      # recorded only, no withdrawal
            return ("double_fetch",
                    "the memory slot the guard read (%s) is **read again** at 0x%X `%s`, and "
                    "its base came from a user pointer (%s). If the second value is the one "
                    "that reaches the sink, the first check does not constrain it — another "
                    "thread changes it in between. Dominance and flow analysis cannot see "
                    "this class."
                    % (info["slot"], info["at"], info["insn"], prov))
    return None


def _reject_authority(pe, g, gb, guard_va, sink_va):
    """May R3 **allow a rejection** at this site? If not, return the reason."""
    md = _md()
    body = g["blocks"].get(gb, [])
    jcc = body[-1] if body else None
    cmpi = None
    for i in reversed([x for x in body if x.address <= guard_va]):
        if i.mnemonic in ("cmp", "sub", "test"):
            cmpi = i
            break
    df = _double_fetch(pe, g, gb, guard_va, sink_va)
    if isinstance(df, dict):
        _reject_authority.last_refetch = df["refetch"]      # recorded only
    elif df:
        return df
    if jcc is not None and jcc.mnemonic in _SIGNED_JCC:
        return ("signed_compare",
                "this is a signed comparison (%s). A negative input passes the bound — "
                "dominance analysis cannot see this class (injection bench: 100%% missed)."
                % jcc.mnemonic)
    if cmpi is not None and len(cmpi.operands) == 2 and \
            cmpi.operands[1].type == X.X86_OP_IMM and cmpi.mnemonic == "cmp":
        return ("bound_compare",
                "this is a bound-constant comparison (%s %s). Dominance cannot tell you "
                "whether the constant is right — inject a mutation that widens the constant "
                "and R3 misses 100%% of them (measured)."
                % (cmpi.mnemonic, cmpi.op_str))
    return None


def gates(pe, guard_va, sink_va):
    """Does the guard branch actually block the sink? Undecidable comes back as
    undecidable."""
    gb_f = pe.func_bounds(guard_va)
    sb_f = pe.func_bounds(sink_va)
    if gb_f[0] is None or sb_f[0] is None:
        return {"verdict": "no_pdata",
                "why": "no function in .pdata — bounds are never guessed"}
    if gb_f[0] != sb_f[0]:
        return {"verdict": "cross_function",
                "why": "guard 0x%X and sink 0x%X are in different functions (0x%X vs 0x%X). "
                       "This tool does not adjudicate inter-procedural dominance — take it "
                       "to the call graph instead"
                       % (guard_va, sink_va, gb_f[0], sb_f[0])}
    g = build(pe, guard_va)
    if g is None:
        return {"verdict": "unbounded", "why": "CFG construction failed"}
    gb, sb = _block_of(g, guard_va), _block_of(g, sink_va)
    if gb is None or sb is None:
        return {"verdict": "unbounded", "why": "block assignment failed"}
    dom, live = _doms(g)
    if sb not in live:
        return {"verdict": "sink_unreachable",
                "why": "sink block 0x%X is unreachable from the function entry — either dead "
                       "code or an incomplete CFG" % sb}
    if gb not in dom.get(sb, set()):
        return {"verdict": "not_dominated", "guard_block": gb, "sink_block": sb,
                "why": "guard block 0x%X **does not dominate** sink block 0x%X — there is a "
                       "path that reaches the sink without passing the guard. This rejection "
                       "does not stand." % (gb, sb)}
    # Does the guard block end in a conditional branch?
    body = g["blocks"][gb]
    last = body[-1] if body else None
    if last is None or last.mnemonic not in _COND:
        return {"verdict": "no_branch", "guard_block": gb,
                "why": "guard block 0x%X does not end in a conditional branch (%s) — nothing "
                       "separates anything out"
                       % (gb, last.mnemonic if last else "?")}
    ss = sorted(g["succ"].get(gb, ()))
    if len(ss) != 2:
        return {"verdict": "no_branch", "guard_block": gb,
                "why": "the guard block does not have 2 successors (%d) — it may be an "
                       "indirect branch" % len(ss)}
    r0, r1 = _reach(g, ss[0]), _reach(g, ss[1])
    a0, a1 = sb in r0, sb in r1
    base = {"guard_block": gb, "sink_block": sb, "succ": [hex(x) for x in ss],
            "branch": "%s %s" % (last.mnemonic, last.op_str), "branch_va": last.address}
    if a0 and a1:
        base.update({"verdict": "both_edges",
                     "why": "the sink 0x%X is reachable from **both** branch successors "
                            "(0x%X, 0x%X) — this branch does not separate the sink out. "
                            "'There is a guard' is not grounds for a rejection."
                            % (sink_va, ss[0], ss[1])})
    elif a0 or a1:
        safe = ss[1] if a0 else ss[0]
        t = _taint_lite(pe, g, gb, guard_va, sink_va)
        base["taint"] = t
        if t["taint"] == "no_flow":
            base.update({"verdict": "dominates_only",
                         "why": "the branch does separate, but %s" % t["why"]})
            return base
        auth = _reject_authority(pe, g, gb, guard_va, sink_va)
        if auth:
            base.update({"verdict": "gated_no_authority", "class": auth[0],
                         "why": "the branch separates and the value does flow. **But R3 has "
                                "no rejection authority for this class** — %s" % auth[1]})
            return base
        # Soundness marker. An indirect branch has no successor edges, so
        #   `not_dominated` / `both_edges` (verdicts that **do not assert**
        #   reachability) stay sound, but `gated` ("this guard dominates the
        #   sink") **is not sound** — an edge we never saw can bypass it. This
        #   does not change the verdict; that is the adversaries' job. It only
        #   makes the difference visible in the ledger.
        _ind = len(g.get("indirect") or ())
        base.update({"verdict": "gated",
                     "unsound_indirect": _ind,
                     "why": "the sink is reachable only from successor 0x%X and cannot be "
                            "reached via 0x%X. %s%s"
                            % (ss[0] if a0 else ss[1], safe, t["why"],
                               ("  WARNING: this function has %d indirect branch(es) — they "
                                "have no successor edges, so this `gated` is not sound (a "
                                "bypass edge may be unseen). Resolve those %d before using "
                                "it as a dominance claim." % (_ind, _ind))
                               if _ind else "")})
    else:
        base.update({"verdict": "unbounded",
                     "why": "the sink is unreachable from either successor — the CFG is "
                            "incomplete (%d indirect branches)" % len(g["indirect"])})
    return base


def _reach_excluding(g, start, banned):
    """The set reachable from `start` in the graph with `banned` blocks deleted."""
    seen, stack = set(), [start]
    while stack:
        x = stack.pop()
        if x is None or x in seen or x in banned:
            continue
        seen.add(x)
        stack.extend(g["succ"].get(x, ()))
    return seen


def gates_cut(pe, guard_vas, sink_va):
    """Does a **set** of guards block the sink — the generalisation of `gates()`
    (single-block dominance).

    Why: in real code an invariant is often established by **several blocks
      together.** One measured case: two separate comparison chains each narrow a
      version field to four values, and the invariant holds at the join. **Neither
      one alone dominates the sink** (the other chain is the bypass). The same
      shape was reported 14 times before this existed.

    A plain cut is not enough — declare enough blocks and anything becomes a
      cut. **All four** conditions are required:
        (1) cut       — deleting **every** declared block makes the sink
                        unreachable from the entry. At n=1 this is exactly
                        dominance, so `gates()` and this agree down to the order
                        of the checks.
        (2) escape    — there must be an edge out of the guard set that misses
                        the sink. With only the cut condition, a useless "it
                        dominates but both edges reach the sink" set passes.
        (3) minimality— removing one member should break the cut. If it does not,
                        that member is **padding**. This is the clause that stops
                        "cut it with anything".
        (4) flow      — the value each guard read must reach a sink operand
                        (`_taint_lite`).
      And the R3 authority withdrawal (`_reject_authority`) applies in full if
      **any** member trips it.

    **At n=1 this is equivalent to `gates()`.** (1) is the both_edges check, (2)
    is dominance, (3) is trivial, (4) is identical. A regression pins that
    equivalence against the full set of existing verdicts.
    """
    vas = sorted({int(v) for v in guard_vas})
    if not vas:
        return {"verdict": "no_guard", "why": "not a single guard VA was declared"}
    sb_f = pe.func_bounds(sink_va)
    if sb_f[0] is None:
        return {"verdict": "no_pdata",
                "why": "the sink's function is not in .pdata — bounds are never guessed"}
    for v in vas:
        f = pe.func_bounds(v)
        if f[0] is None:
            return {"verdict": "no_pdata",
                    "why": "could not establish function bounds for guard 0x%X" % v}
        if f[0] != sb_f[0]:
            return {"verdict": "cross_function",
                    "why": "guard 0x%X is in a different function from the sink (0x%X vs "
                           "0x%X). Inter-procedural goes to the call graph"
                           % (v, f[0], sb_f[0])}
    g = build(pe, sink_va)
    if g is None:
        return {"verdict": "unbounded", "why": "CFG construction failed"}
    sb = _block_of(g, sink_va)
    if sb is None:
        return {"verdict": "unbounded", "why": "sink block assignment failed"}
    entry = g["leaders"][0]
    if sb not in _reach(g, entry):
        return {"verdict": "sink_unreachable",
                "why": "sink block 0x%X is unreachable from the entry — either dead code or "
                       "an incomplete CFG" % sb}
    gbs, seen = [], {}
    for v in vas:
        b = _block_of(g, v)
        if b is None:
            return {"verdict": "unbounded", "why": "block assignment failed for guard 0x%X" % v}
        if b in seen:
            return {"verdict": "padded_cut",
                    "why": "0x%X and 0x%X are in the **same block 0x%X** — that is the same "
                           "check counted twice. Declare only distinct checks."
                           % (seen[b], v, b)}
        seen[b] = v
        gbs.append(b)
    base = {"guards": [hex(v) for v in vas], "guard_blocks": [hex(b) for b in gbs],
            "sink_block": hex(sb), "n": len(gbs)}

    # (1) cut — is the sink unreachable once all of them are removed? At n=1 this
    #     is dominance, in the same order as `gates()`.
    if sb in _reach_excluding(g, entry, set(gbs)):
        # At n=1 this condition is exactly "does not dominate". **Match the
        #   label to `gates()`** — otherwise re-running an old verdict produces a
        #   different verdict string in the verification record.
        base.update({"verdict": "not_dominated" if len(gbs) == 1 else "not_a_cut",
                     "why": "**removing all %d declared guards** still leaves a path from "
                            "the entry to the sink 0x%X — there is a route that passes none "
                            "of them. This rejection does not stand." % (len(gbs), sink_va)})
        return base

    # (2) escape — is there actually an exit out of the guard set that misses the sink?
    #   The first version asked "each member must separate the sink on its own".
    #     **That was wrong.** In a chain (`cmp v,A / je` -> `cmp v,B / je` -> ...)
    #     **only the last comparison** separates. An earlier comparison's
    #     fall-through merely goes to the next comparison, so both of its edges
    #     reach the sink — ask per member and every legitimate chain dies as
    #     `both_edges` (confirmed on a real chain).
    #   The right generalisation is a question about the set: **does an escape
    #     exist?** If no edge leaving a guard block misses the sink then the set
    #     is a cut that filters nothing — which is what `both_edges` is at n=1,
    #     and this is its natural extension.
    escapes = []
    for v, b in zip(vas, gbs):
        body = g["blocks"][b]
        last = body[-1] if body else None
        if last is None or last.mnemonic not in _COND:
            base.update({"verdict": "no_branch",
                         "why": "guard 0x%X's block 0x%X does not end in a conditional branch "
                                "(%s) — nothing separates anything out"
                                % (v, b, last.mnemonic if last else "?")})
            return base
        ss = sorted(g["succ"].get(b, ()))
        if len(ss) != 2:
            base.update({"verdict": "no_branch",
                         "why": "guard 0x%X's block does not have 2 successors (%d) — it may "
                                "be an indirect branch" % (v, len(ss))})
            return base
        for e in ss:
            if sb not in _reach(g, e):
                escapes.append((v, e))
    if not escapes:
        # At n=1 this is exactly both_edges — match the label too.
        base.update({"verdict": "both_edges" if len(gbs) == 1 else "no_escape",
                     "why": ("guard 0x%X reaches the sink from both branch edges — this "
                             "branch does not separate the sink out. 'There is a guard' is "
                             "not grounds for a rejection." % vas[0])
                            if len(gbs) == 1 else
                            ("not one edge of the %d guards **escapes past the sink** — it "
                             "is a cut, but it filters nothing. Point at where the failure "
                             "path (drop / return / assert) actually is." % len(gbs))})
        return base
    base["escapes"] = ["0x%X→0x%X" % (v, e) for v, e in escapes[:8]]

    # (3) minimal core vs added members — **a classification, not a rejection**
    #   The first version said "remove a member; if the cut survives it is
    #     padding, so reject". That was wrong too. In the measured chain case the
    #     minimal cut is just the **two chain heads** — the comparisons that
    #     follow sit behind the heads and can be removed without breaking the
    #     cut. Yet what **confines the value to four possibilities is all eight
    #     comparisons.** So minimality forces an answer that is graph-correct and
    #     semantically wrong.
    #   ⇒ Minimality is **demoted from a hard rejection to a signal.** Return the
    #     core and the extras separately; whether an extra is a chain narrowing
    #     the same value or unrelated padding is a **semantic** judgement that
    #     requires reading the disassembly, so it is handed up to the judge.
    #     At n=1 the extras are empty by definition, so behaviour is identical.
    core, extra = list(gbs), []
    if len(gbs) > 1:
        # Greedily find the minimal cut core: if it is still a cut without a
        # block, drop that block.
        for b in sorted(gbs):
            trial = [x for x in core if x != b]
            if trial and sb not in _reach_excluding(g, entry, set(trial)):
                core = trial
                extra.append(b)
    base["cut_core"] = [hex(x) for x in sorted(core)]
    base["cut_extra"] = [hex(x) for x in sorted(extra)]

    # (4) flow — does each guard's value reach the sink?
    taints = []
    for v, b in zip(vas, gbs):
        t = _taint_lite(pe, g, b, v, sink_va)
        taints.append({"guard": hex(v), **t})
        if t["taint"] == "no_flow":
            base.update({"verdict": "dominates_only", "taint": taints,
                         "why": "guard 0x%X does separate, but %s" % (v, t["why"])})
            return base
    base["taint"] = taints

    # R3 authority — if any single member is in a withdrawal class, withdraw.
    for v, b in zip(vas, gbs):
        auth = _reject_authority(pe, g, b, v, sink_va)
        if auth:
            base.update({"verdict": "gated_no_authority", "class": auth[0],
                         "why": "the guard set forms a cut, but **R3 has no rejection "
                                "authority for this class** (0x%X) — %s" % (v, auth[1])})
            return base

    if extra:
        # The graph stops here. Whether an added member is a chain narrowing the
        # same value takes reading the comparison instructions, so the judgement
        # goes up (`needs_judgement`).
        base.update({"verdict": "cut_needs_judgement",
                     "why": "the %d guards do **cut** the sink 0x%X (no bypass, an escape "
                            "exists, and the value flows). But the graph-minimal core is "
                            "**%s** and the other %d sit behind that core — they may be a "
                            "chain narrowing the same value, or unrelated padding. Telling "
                            "those apart requires **reading** the comparison instructions, "
                            "so the machine does not adjudicate it."
                            % (len(gbs), sink_va, ", ".join(base["cut_core"]), len(extra))})
        return base
    base.update({"verdict": "gated_cut",
                 "why": "the %d guards form a **minimal cut** over the sink 0x%X: %s. All of "
                        "them must be removed before a bypass appears, there is an escape "
                        "edge that misses the sink, and the value flows to it. No added "
                        "members."
                        % (len(gbs), sink_va, ", ".join(hex(v) for v in vas))})
    return base


def sink_gates(pe, sink_va, max_span=0x20000):
    """Enumerate every cmp/test/call that **dominates** the sink. This asks the
    opposite question from `gates()`.

    Why it is needed (two measured failures):
      · A length underflow was real, but ahead of the store there was a
        `cmp [rbp-0x11],0` (destination-buffer NULL check) and a reallocating
        string call. The allocation cannot succeed with the underflowed size.
        The claim **never mentioned either gate.**
      · Reporting 8 bytes while writing only 4 was accurate, but the caller in
        the kernel enforces a per-class minimum length from a table, and that
        gate killed the overflow variant.

    `gates()` asks "does the guard the agent pointed at dominate the sink?".
    This asks "**what else** dominates the sink?". Every confirmation gate was on
    the anchor and refutation axes, so nobody was looking at this one.

    Returns {"gates": [(addr, mnemonic, op_str, kind)], "calls": n, "cmps": n}
    or None.
    """
    g = build(pe, sink_va, max_span)
    if not g:
        return None
    sb = _block_of(g, sink_va)
    if sb is None:
        return None
    dom, live = _doms(g)
    if sb not in dom:
        return None
    out = []
    # Decode the whole function and walk **only the dominating block ranges**
    # (the bounds come from .pdata).
    b, e = pe.func_bounds(sink_va)
    o = pe.va2off(b)
    ins = list(_md().disasm(pe.d[o:o + (e - b)], b))
    leaders = list(g["leaders"])
    for blk in sorted(dom[sb]):
        try:
            nxt = leaders[leaders.index(blk) + 1]
        except (ValueError, IndexError):
            nxt = g["end"]
        for i in ins:
            if not (blk <= i.address < nxt):
                continue
            if i.address >= sink_va and blk == sb:
                break                       # past the sink is not a gate
            if i.mnemonic == "call":
                out.append((i.address, i.mnemonic, i.op_str, "call"))
            elif i.mnemonic in ("cmp", "test"):
                out.append((i.address, i.mnemonic, i.op_str, "check"))
    # Dominance alone **misses the check in the immediately preceding block.**
    #   That is what one of the measured failures was: the `cmp [rbp-0x11],0`
    #   wrapping the store, and the allocation call before it, were not in the
    #   dominator set (a loop structure meant the block was not the unique
    #   predecessor). Missing those defeats the purpose of this tool, so the
    #   sink block's **immediate predecessors** are reported separately,
    #   regardless of dominance.
    pred = {}
    for a in live:
        for t in g["succ"].get(a, ()):
            pred.setdefault(t, set()).add(a)
    # Predecessors up to 2 hops. One hop misses it — in the measured case the
    # buffer NULL check was in the **predecessor of the predecessor** of the
    # sink block.
    front, seen_b = {sb}, set()
    for _ in range(2):
        nxt_set = set()
        for x in front:
            nxt_set |= pred.get(x, set())
        seen_b |= front
        front = nxt_set - seen_b
    seen_b |= front
    near = []
    for blk in sorted(seen_b):
        if blk in dom[sb]:
            continue
        try:
            nxt = leaders[leaders.index(blk) + 1]
        except (ValueError, IndexError):
            nxt = g["end"]
        for i in ins:
            if not (blk <= i.address < nxt) or i.address >= sink_va:
                continue
            if i.mnemonic == "call":
                near.append((i.address, i.mnemonic, i.op_str, "call"))
            elif i.mnemonic in ("cmp", "test"):
                near.append((i.address, i.mnemonic, i.op_str, "check"))
    return {"gates": out, "nearby": near,
            "calls": sum(1 for x in out + near if x[3] == "call"),
            "cmps": sum(1 for x in out + near if x[3] == "check"),
            "blocks": len(dom[sb])}


def render_sink_gates(r, limit=14):
    if not r:
        return ("sink-gate analysis not possible (no .pdata bounds / span exceeded) — that is "
                "**unanalysed**, not 'no gates'.")
    if not r["gates"] and not r.get("nearby"):
        return "nothing that dominates the sink is a cmp/test/call. The path is unconditional."
    L = ["What **dominates** this sink — the claim has to get past all of it "
         "(%d dominating blocks, %d call, %d check):" % (r["blocks"], r["calls"], r["cmps"])]
    for a, m, o, k in r["gates"][:limit]:
        L.append("   0x%X  %-5s %s%s"
                 % (a, m, o[:56], "   <- may consume the value" if k == "call" else ""))
    if len(r["gates"]) > limit:
        L.append("   ... and %d more" % (len(r["gates"]) - limit))
    if r.get("nearby"):
        L.append("Immediately preceding blocks (not dominating, but directly ahead on the "
                 "path) — **this is where the real misses were**:")
        for a, m, o, k in r["nearby"][:limit]:
            L.append("   0x%X  %-5s %s%s"
                     % (a, m, o[:56], "   <- may consume the value" if k == "call" else ""))
    L.append("Both failures happened here: before the defective value reached the sink it had "
             "to be **used as an allocation argument** or the destination pointer had to pass "
             "a **NULL check**, and the claim did not mention either.")
    return "\n".join(L)


if __name__ == "__main__":
    import sys
    from pe import PE
    p = PE(sys.argv[1])
    r = gates(p, int(sys.argv[2], 16), int(sys.argv[3], 16))
    print("verdict: %s" % r["verdict"])
    for k, v in r.items():
        if k != "verdict":
            print("   %-12s %s" % (k, v))
