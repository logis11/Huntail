#!/usr/bin/env python3
# xref.py — import xrefs over **every executable section.** The habit of looking
# only at `.text` is removed at the tool level rather than by reminder.
#
# Why: in one run the agent wrote "SeSinglePrivilegeCheck is not among the 23
# import calls in .text" and failed to close its kill condition. **The call was
# in `PAGE`.** A driver scatters code across `.text` / `PAGE` / `INIT` / `fothk`
# — initialisation code and pageable code go to different sections — so looking
# at `.text` alone misses the authorization check entirely.
#
# This tool **always reports which sections it swept.** An absence claim can only
# rest on coverage that was stated.
import struct

import capstone
from capstone import x86 as X

# Authorization / privilege APIs — the set that has to be enumerated
# exhaustively before anyone claims "there is no check".
AUTHZ = ("SeSinglePrivilegeCheck", "SePrivilegeCheck", "SeAccessCheck", "SeAccessCheckFromState",
         "SeSinglePrivilegeCheckEx", "SeCaptureSecurityDescriptor", "SeCaptureSubjectContext",
         "SeCreateAccessState", "SeCreateAccessStateEx", "SeQueryInformationToken",
         "SeTokenIsAdmin", "SeTokenIsRestricted", "PsReferencePrimaryToken",
         "PsReferenceImpersonationToken", "PsIsSystemThread", "ZwOpenProcessToken",
         "ZwOpenThreadToken", "ZwQueryInformationToken", "ObSetSecurityObjectByPointer",
         "ZwSetSecurityObject", "RtlValidSid", "RtlEqualSid", "SeImpersonateClient")
# **Identity gates** — the assumption that authorization is only ever done
# through `Se*` APIs is wrong. In one measured driver the real gate was
# `PsGetCurrentProcess() == SiloContext->[0]`, i.e. **a plain pointer
# comparison**, with no `Se*` call anywhere. An authorization scan keyed on
# import names misses that completely. (The agent confirmed "no re-authorization"
# while the object was in fact locked to one process per silo.)
# => if anything on this list hits, **find the comparison against a stored value
# before claiming there is no authorization.**
IDENTITY = ("PsGetCurrentProcess", "PsGetCurrentProcessId", "PsGetCurrentThread",
            "PsGetCurrentThreadId", "PsGetProcessId", "PsGetThreadId",
            "IoGetRequestorProcess", "IoGetRequestorProcessId", "IoGetRequestorSessionId",
            "PsGetCurrentServerSilo", "PsGetPermanentSiloContext", "PsGetSiloContext",
            "PsGetJobSilo", "PsGetCurrentSilo", "ObGetObjectSecurity",
            "PsGetProcessSessionId", "PsGetCurrentProcessSessionId")

# User-pointer validation.
PROBE = ("ProbeForRead", "ProbeForWrite", "MmProbeAndLockPages", "MmUserProbeAddress")


def iat(pe):
    """IAT VA -> import name. Works without `pefile`."""
    out = {}
    try:
        rva, _ = struct.unpack_from("<II", pe.d, pe.dd + 8)
        o = pe.rva2off(rva)
    except Exception:
        return out
    if o is None:
        return out
    for i in range(512):
        e = o + 20 * i
        if e + 20 > len(pe.d):
            break
        oft, _t, _f, _nm, ft = struct.unpack_from("<IIIII", pe.d, e)
        if not (oft or ft):
            break
        lo = pe.rva2off(oft or ft)
        if lo is None:
            continue
        j = 0
        while True:
            v = struct.unpack_from("<Q", pe.d, lo + 8 * j)[0]
            if not v:
                break
            if not (v >> 63):
                no = pe.rva2off(v)
                if no is not None:
                    z = pe.d.index(b"\0", no + 2)
                    out[pe.base + ft + 8 * j] = pe.d[no + 2:z].decode("latin-1")
            j += 1
    return out


def code_sections(pe):
    return [s for s in pe.secs if s["chars"] & 0x20000000]


def sweep(pe, want=None, kinds=("call", "jmp", "lea", "mov")):
    """Linearly disassemble every executable section and collect IAT references.

    A linear sweep can desync and invent a reference that is not there. So every
    hit also reports **whether its address falls inside a `.pdata` function** —
    a hit outside one is a signal to distrust it.
    """
    names = iat(pe)
    if want is not None:
        w = tuple(want) if not isinstance(want, str) else (want,)
        names = {va: n for va, n in names.items()
                 if any(x.lower() in n.lower() for x in w)}
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    hits, cov = [], []
    for s in code_sections(pe):
        beg = pe.base + s["va"]
        o = s["raw"]
        n = min(s["rsize"], max(0, len(pe.d) - o))
        cov.append({"name": s["name"], "va": beg, "size": n})
        if n <= 0:
            continue
        for i in md.disasm(pe.d[o:o + n], beg):
            if kinds and i.mnemonic not in kinds:
                continue
            for op in i.operands:
                if op.type == X.X86_OP_MEM and op.mem.base == X.X86_REG_RIP:
                    t = i.address + i.size + op.mem.disp
                    if t in names:
                        fb, _fe = pe.func_bounds(i.address)
                        hits.append({"section": s["name"], "va": i.address,
                                     "mnem": i.mnemonic, "name": names[t],
                                     "func": fb, "in_pdata": fb is not None})
    return hits, cov, names


def render(hits, cov, names, want_desc=""):
    L = []
    L.append("executable sections swept: " + ", ".join("%s(0x%X, %d bytes)" % (c["name"], c["va"], c["size"])
                                            for c in cov))
    L.append("%d import(s) in scope%s" % (len(names), (" — " + want_desc) if want_desc else ""))
    if not names:
        L.append("There is **no import by that name.** An absent import is stronger "
                 "ground than an absent call — but dynamic resolution and forwarded "
                 "imports do not show up here.")
        return "\n".join(L)
    if not hits:
        L.append("Zero references — across every section listed above. 'It is not "
                 "called' can now be used as ground. (Indirect calls and function "
                 "pointers are still invisible.)")
        return "\n".join(L)
    L.append("%d reference(s):" % len(hits))
    byname = {}
    for h in hits:
        byname.setdefault(h["name"], []).append(h)
    for nm, hs in sorted(byname.items()):
        L.append("  %s — %d" % (nm, len(hs)))
        for h in hs[:12]:
            mark = "" if h["in_pdata"] else "   WARNING: outside any .pdata function (suspect a linear-sweep desync)"
            L.append("     [%-6s] 0x%X  %s  (function 0x%X)%s"
                     % (h["section"], h["va"], h["mnem"], h["func"] or 0, mark))
        if len(hs) > 12:
            L.append("     ... and %d more" % (len(hs) - 12))
    miss = sorted(set(names.values()) - set(byname))
    if miss:
        L.append("imports with zero references: " + ", ".join(miss))
    return "\n".join(L)


if __name__ == "__main__":
    import sys
    from pe import PE
    p = PE(sys.argv[1])
    w = sys.argv[2].split(",") if len(sys.argv) > 2 else AUTHZ
    h, c, n = sweep(p, w)
    print(render(h, c, n, "filter=%s" % (sys.argv[2] if len(sys.argv) > 2 else "AUTHZ preset")))
