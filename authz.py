#!/usr/bin/env python3
# authz.py — two things off the call graph: (1) reachability of authorization
# APIs, and (2) **inter-procedural** guard dominance.
#
# They are the same problem. `cfg.py` computes dominance **inside** one function
# only, and in one measured audit four rejections came back `cross_function`,
# undecidable. All four had the same shape:
#   **the guard is in the dispatcher, the sink is in the handler.**
# That is the *checked once at the door* pattern the doctrine calls the most
# common real defect.
#
# (1) is a per-target reachability script lifted into the harness, with its
#     target-specific dispatch-table probing stripped out. Handler VAs come from
#     the attack-surface recovery module.
#
# **A negative from this tool ("zero authorization APIs") is not ground without
# a positive control.** So `audit()` refuses to call a negative confirmed unless
# `controls=` is given.
import collections

import capstone
from capstone import x86 as X

import xref

AUTHZ = xref.AUTHZ
IDENTITY = xref.IDENTITY


def _md():
    m = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    m.detail = True
    return m


def callgraph(pe, max_fn=20000):
    """**Direct call** edges over every `.pdata` function, across every
    executable section.

    Limits (always report them alongside):
      - indirect calls, vtables and DPC callbacks are not tracked
      - **reachable is not executed.** Once the BFS leaks into a shared helper it
        picks up APIs that have nothing to do with the request under analysis. In
        one measured case `IoGetRequestorProcess` was reached from a client
        request, and its consumer was `ObOpenObjectByPointer` — shared code on
        the device-open path. Reaching an identity API is **a signal to go read**,
        not proof that a gate exists.
    """
    md = _md()
    try:
        fns = pe.runtime_functions()
    except Exception:
        fns = []
    bounds = []
    for f in fns[:max_fn]:
        b, e = (f[0], f[1]) if isinstance(f, (tuple, list)) else (f["begin"], f["end"])
        if e > b and e - b < 0x20000:
            bounds.append((b, e))
    bounds.sort()
    names = xref.iat(pe)
    out = {b: {"calls": set(), "imports": set(), "callsites": []} for b, _ in bounds}
    for b, e in bounds:
        o = pe.va2off(b)
        if o is None:
            continue
        for i in md.disasm(pe.d[o:o + (e - b)], b):
            if i.mnemonic != "call":
                continue
            try:
                t = int(i.op_str, 0)
                out[b]["calls"].add(t)
                out[b]["callsites"].append((i.address, t, None))
                continue
            except ValueError:
                pass
            for op in i.operands:
                if op.type == X.X86_OP_MEM and op.mem.base == X.X86_REG_RIP:
                    t = i.address + i.size + op.mem.disp
                    if t in names:
                        out[b]["imports"].add(names[t])
                        out[b]["callsites"].append((i.address, None, names[t]))
    return out, bounds


def func_of(bounds, va):
    lo, hi = 0, len(bounds) - 1
    while lo <= hi:
        m = (lo + hi) // 2
        b, e = bounds[m]
        if va < b:
            hi = m - 1
        elif va >= e:
            lo = m + 1
        else:
            return b
    return None


def reach_apis(pe, start, apis=AUTHZ, depth=6, cg=None):
    """Authorization APIs reachable from `start` by a direct-call BFS, with the
    path to each one."""
    if cg is None:
        cg = callgraph(pe)
    g, bounds = cg
    st = func_of(bounds, start) or start
    if st not in g:
        return {"error": "start 0x%X is not a .pdata function" % start}
    seen, q, found, nvis = {st: None}, collections.deque([(st, 0)]), {}, 0
    apis_l = {a.lower() for a in apis}
    while q:
        f, d = q.popleft()
        nvis += 1
        for nm in g[f]["imports"]:
            if any(a in nm.lower() for a in apis_l) or nm.lower() in apis_l:
                if nm not in found:
                    path, x = [], f
                    while x is not None:
                        path.append(x)
                        x = seen[x]
                    found[nm] = list(reversed(path))
        if d >= depth:
            continue
        for t in g[f]["calls"]:
            tf = func_of(bounds, t)
            if tf is not None and tf not in seen:
                seen[tf] = f
                q.append((tf, d + 1))
    return {"start": st, "visited": nvis, "found": found, "depth": depth}


def identity_compares(pe, func, depth=0):
    """After a `call PsGetCurrentProcess`-style site, is the return value
    **compared against a stored value**?

    One measured driver had exactly that shape: `PsGetCurrentProcess()` compared
    against `SiloContext->[0]`, locking the object to one process per silo. With
    no `Se*` call anywhere, an import-based authorization scan cannot see it.
    This reports **only that a comparison exists** — whether it is the real gate
    takes a human reading it.
    """
    md = _md()
    names = xref.iat(pe)
    b, e = pe.func_bounds(func)
    if b is None:
        return []
    o = pe.va2off(b)
    if o is None:
        return []
    ins = list(md.disasm(pe.d[o:o + (e - b)], b))
    out = []
    for k, i in enumerate(ins):
        if i.mnemonic != "call":
            continue
        nm = None
        for op in i.operands:
            if op.type == X.X86_OP_MEM and op.mem.base == X.X86_REG_RIP:
                nm = names.get(i.address + i.size + op.mem.disp)
        if not nm or not any(x.lower() in nm.lower() for x in IDENTITY):
            continue
        # Is the return value (rax) compared against memory, or stored into it?
        for j in range(k + 1, min(k + 14, len(ins))):
            m = ins[j]
            if m.mnemonic in ("cmp", "sub") and "rax" in m.op_str and "ptr" in m.op_str:
                out.append({"api": nm, "call_va": i.address, "kind": "compare",
                            "insn": "%s %s" % (m.mnemonic, m.op_str), "va": m.address})
                break
            if m.mnemonic == "mov" and m.op_str.endswith(", rax") and "ptr" in m.op_str:
                out.append({"api": nm, "call_va": i.address, "kind": "store",
                            "insn": "%s %s" % (m.mnemonic, m.op_str), "va": m.address})
                break
            if m.mnemonic == "call":
                break
    return out


def audit(pe, targets, controls=None, apis=AUTHZ, depth=6):
    """Authorization reachability for the target handlers. **Without `controls`
    a negative is never reported as confirmed.**

    `controls` = VAs of handlers known to carry authorization. Zero hits there
    means the analyser is broken, not that the targets are unguarded.
    """
    cg = callgraph(pe)
    res = {"targets": {}, "controls": {}, "valid": None, "note": ""}
    for t in targets:
        r = reach_apis(pe, t, apis, depth, cg)
        # Zero authorization APIs plus a reachable **identity gate** is still not
        # grounds for "there is no authorization".
        ident = reach_apis(pe, t, IDENTITY, depth, cg)
        r["identity"] = ident.get("found", {})
        if not r.get("found") and r["identity"]:
            cmps = []
            for nm, path in list(r["identity"].items())[:6]:
                cmps += identity_compares(pe, path[-1])
            r["identity_compares"] = cmps[:8]
        res["targets"]["0x%X" % t] = r
    for c in (controls or []):
        res["controls"]["0x%X" % c] = reach_apis(pe, c, apis, depth, cg)
    if not controls:
        res["valid"] = None
        res["note"] = ("No positive control. Do not use 'zero authorization APIs' as "
                       "ground — a broken analyser and an unguarded target produce "
                       "the same output. Put handlers known to carry authorization "
                       "in controls=.")
    else:
        ok = any(r.get("found") for r in res["controls"].values())
        res["valid"] = ok
        res["note"] = ("positive control passed — this analyser does detect "
                       "authorization where it is present."
                       if ok else
                       "positive control **FAILED**. The control handlers report zero "
                       "authorization APIs too — **the analyser is broken.** Every "
                       "negative from this run is void.")
    return res


# ── (2) inter-procedural guard dominance (extends cfg.py's cross_function) ──
def gates_inter(pe, guard_va, sink_va, depth=6):
    """Does the guard (inside F) dominate the sink (inside G)? Decided by
    **call-site dominance plus sole caller.**

    Both conditions are required:
      (a) every call to G is **inside F** — a call from elsewhere is a path that
          never passes the guard
      (b) the guard dominates every G call site inside F
    If either breaks, the answer is "does not dominate". If it cannot be decided,
    it is not decided.
    """
    import cfg
    g, bounds = callgraph(pe)
    F = func_of(bounds, guard_va)
    G = func_of(bounds, sink_va)
    if F is None or G is None:
        return {"verdict": "no_pdata", "why": "the guard or the sink is outside any .pdata function"}
    if F == G:
        return cfg.gates(pe, guard_va, sink_va)
    # (a) every caller of G
    callers = {f for f, v in g.items() if G in v["calls"]}
    if not callers:
        return {"verdict": "indirect_only", "F": F, "G": G,
                "why": "**nothing directly calls** the sink function 0x%X — it is reached "
                       "through a function pointer or a callback. The call graph cannot "
                       "adjudicate that (a measured case was a DPC callback)." % G}
    outside = callers - {F}
    if outside:
        return {"verdict": "other_callers", "F": F, "G": G,
                "callers": ["0x%X" % x for x in sorted(callers)],
                "why": "the sink function 0x%X is **also called from outside the guard "
                       "function** (%s) — that path does not pass the guard 0x%X. This "
                       "rejection does not stand."
                       % (G, ", ".join("0x%X" % x for x in sorted(outside)), guard_va)}
    # (b) does the guard dominate every G call site inside F?
    sites = [a for a, t, _n in g[F]["callsites"] if t == G]
    if not sites:
        return {"verdict": "unbounded", "why": "no call site found"}
    bad = []
    for a in sites:
        r = cfg.gates(pe, guard_va, a)
        if r["verdict"] != "gated":
            bad.append((a, r["verdict"], r.get("why", "")))
    if bad:
        return {"verdict": "not_dominated", "F": F, "G": G,
                "sites": ["0x%X" % a for a in sites],
                "why": "the guard does not dominate %d of the %d G call sites inside F 0x%X: %s"
                       % (F, len(sites), len(bad),
                          "; ".join("0x%X(%s)" % (a, v) for a, v, _w in bad))}
    return {"verdict": "gated_inter", "F": F, "G": G,
            "sites": ["0x%X" % a for a in sites],
            "why": "the sink function 0x%X is called only from 0x%X, and the guard 0x%X "
                   "dominates all %d of those call sites." % (G, F, guard_va, len(sites))}


def render(res):
    L = [res["note"], ""]
    for k, r in res["controls"].items():
        L.append("  [control] %s -> %s" % (k, ", ".join(r.get("found", {})) or "zero"))
    for k, r in res["targets"].items():
        f = r.get("found", {})
        L.append("  %s  %d functions visited -> %s" % (k, r.get("visited", 0),
                                             ", ".join(f) if f else "**zero authorization APIs**"))
        for nm, path in list(f.items())[:3]:
            L.append("      %s  path: %s" % (nm, " -> ".join("0x%X" % x for x in path)))
        ident = r.get("identity") or {}
        if not f and ident:
            L.append("      but it **does reach an identity API**: %s" % ", ".join(ident))
            for c in (r.get("identity_compares") or []):
                L.append("         %s @0x%X → %s @0x%X  [%s]"
                         % (c["api"], c["call_va"], c["insn"], c["va"], c["kind"]))
            L.append("      => **do not claim 'no authorization'.** It may be done with a "
                     "**pointer comparison** such as `PsGetCurrentProcess() == <stored>` "
                     "rather than an Se* API. One measured driver had exactly that shape "
                     "(one process per silo), and missing it produced a confirmation.")
    return "\n".join(L)


if __name__ == "__main__":
    import sys
    from pe import PE
    p = PE(sys.argv[1])
    tg = [int(x, 0) for x in sys.argv[2].split(",")] if len(sys.argv) > 2 else []
    ct = [int(x, 0) for x in sys.argv[3].split(",")] if len(sys.argv) > 3 else []
    print(render(audit(p, tg, ct)))
