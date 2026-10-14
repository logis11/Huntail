#!/usr/bin/env python3
# guards.py — find, deterministically, where a guard is **under-applied.** Not
# absent: bypassed.
#
# Three grounding cases:
#  (1) CVE-2026-40369 (ntoskrnl!ExpGetProcessInformation) — ProbeForWrite **is
#      there**, and is skipped entirely on the length==0 path. Then, even after
#      deciding "the buffer is too small", it increments three DWORDs before
#      returning -> a 12-byte arbitrary increment -> SYSTEM.
#  (2) Project Zero GPHFH — open the object as **KernelMode** and the access
#      check is skipped wholesale.
#  (3) METHOD_NEITHER with no Probe* anywhere in the handler (the classic driver
#      bug).
#
# All of these are candidate generators. **None of them is an adjudicator.**
#
# Ported note: upstream this read the IAT through a security-descriptor scanner's
# private helper. `xref.iat` is the same routine and is already here, so that
# dependency is gone — the two were verified to return identical maps.
import struct
import sys

import capstone
from capstone import x86 as X

import xref
from pe import PE

PROBE = ("ProbeForRead", "ProbeForWrite")
PROBE_GLOB = "MmUserProbeAddress"
IRP_REQUESTORMODE = 0x40   # _IRP.RequestorMode (x64)
# Where the AccessMode argument lives (x64). KernelMode=0 skips the access check.
#   ObReferenceObjectByHandle(Handle, Access, Type, AccessMode=r9, ...)
#   ObOpenObjectByPointer(Obj, Attr, State, Access, Type=[rsp+28], AccessMode=[rsp+30], Handle)
ACCESSMODE_ARG = {"ObReferenceObjectByHandle": ("reg", "r9"),
                  "ObOpenObjectByPointer": ("stack", 0x30),
                  "ObOpenObjectByPointerWithTag": ("stack", 0x30),
                  "ZwOpenProcess": None}

_R = {}


def canon(md, r):
    if r in _R:
        return _R[r]
    n = md.reg_name(r) or ""
    for b, al in (("rax", "eax ax al ah"), ("rbx", "ebx bx bl bh"), ("rcx", "ecx cx cl ch"),
                  ("rdx", "edx dx dl dh"), ("rsi", "esi si sil"), ("rdi", "edi di dil"),
                  ("rbp", "ebp bp bpl"), ("rsp", "esp sp spl")):
        if n == b or n in al.split():
            _R[r] = b
            return b
    for b in "r8 r9 r10 r11 r12 r13 r14 r15".split():
        if n.startswith(b) and (len(n) == len(b) or n[len(b):] in ("d", "w", "b")):
            _R[r] = b
            return b
    _R[r] = n
    return n


def funcs(pe):
    out = []
    try:
        for f in pe.runtime_functions():
            b, e = (f[0], f[1]) if isinstance(f, (tuple, list)) else (f["begin"], f["end"])
            if e > b and e - b < 0x20000:
                out.append((b, e))
    except Exception:
        pass
    return out


def scan(path):
    pe = PE(path)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    iat = xref.iat(pe)
    probe_va = {va for va, n in iat.items() if n in PROBE}
    obj_va = {va: n for va, n in iat.items() if n in ACCESSMODE_ARG and ACCESSMODE_ARG[n]}
    hits = {"probe_skip": [], "kernelmode": [], "probe_none": [], "write_before_fail": []}
    nprobe = 0
    for beg, end in funcs(pe):
        o = pe.va2off(beg)
        if o is None:
            continue
        ins = list(md.disasm(pe.d[o:o + (end - beg)], beg))
        # Indices of the Probe* calls inside this function
        probe_idx = []
        for k, i in enumerate(ins):
            for op in i.operands:
                if op.type == X.X86_OP_MEM and op.mem.base == X.X86_REG_RIP and i.mnemonic == "call":
                    t = i.address + i.size + op.mem.disp
                    if t in probe_va:
                        probe_idx.append((k, iat[t]))
                        nprobe += 1
                    elif t in obj_va:
                        # ── (2) is AccessMode == KernelMode? ──
                        kind, where = ACCESSMODE_ARG[obj_va[t]]
                        km = None
                        for j in range(max(0, k - 12), k):
                            m = ins[j]
                            if kind == "reg" and m.op_str.startswith(where + ","):
                                if m.mnemonic == "xor" and m.op_str.split(",")[1].strip().startswith(where[:2]):
                                    km = "xor %s" % where
                                elif m.mnemonic == "mov":
                                    try:
                                        km = "KernelMode" if int(m.op_str.split(",")[1], 0) == 0 else None
                                    except ValueError:
                                        km = None
                            elif kind == "stack" and m.mnemonic in ("mov", "and") and \
                                    m.op_str.startswith(("dword ptr [rsp + 0x%x]" % where,
                                                         "qword ptr [rsp + 0x%x]" % where)):
                                tail = m.op_str.split(",")[1].strip()
                                if tail in ("0", "0x0") or (m.mnemonic == "and" and tail == "0"):
                                    km = "stack[+0x%x]=0" % where
                        if km:
                            hits["kernelmode"].append(
                                {"func": beg, "va": i.address, "api": obj_va[t], "how": km})
        # ── (1) a branch that skips the Probe ──
        for k, name in probe_idx:
            for j in range(max(0, k - 10), k):
                m = ins[j]
                if m.mnemonic not in ("test", "cmp"):
                    continue
                z = None
                if m.mnemonic == "test" and len(m.operands) == 2 and \
                        m.operands[0].type == m.operands[1].type == X.X86_OP_REG and \
                        canon(md, m.operands[0].reg) == canon(md, m.operands[1].reg):
                    z = canon(md, m.operands[0].reg)
                elif m.mnemonic == "cmp" and len(m.operands) == 2 and \
                        m.operands[1].type == X.X86_OP_IMM and m.operands[1].imm == 0:
                    z = (canon(md, m.operands[0].reg)
                         if m.operands[0].type == X.X86_OP_REG else "mem")
                if z is None:
                    continue
                # Strip a whole layer of false positives: `cmp byte ptr [reg+0x40], 0`
                #   is _IRP.RequestorMode, and
                #     `if (Irp->RequestorMode != KernelMode) Probe...`
                #   is **the correct idiom**. A real candidate branches on a
                #   length or a pointer, not on RequestorMode (CVE-2026-40369 is
                #   length==0). On the first run, all 17 hits in one driver were
                #   exactly this.
                if m.operands[0].type == X.X86_OP_MEM and m.operands[0].mem.disp == IRP_REQUESTORMODE:
                    continue
                if m.mnemonic == "test" and m.operands[0].type == X.X86_OP_REG and \
                        (md.reg_name(m.operands[0].reg) or "").endswith(("b", "l")) and \
                        m.op_str.count(",") == 1 and \
                        m.op_str.split(",")[0].strip() == m.op_str.split(",")[1].strip():
                    # An 8-bit self-test is usually a BOOLEAN flag (including a
                    # copy of RequestorMode). Do not drop it; only downgrade it.
                    weak = True
                else:
                    weak = False
                # Does the conditional branch right after it jump **past** the
                # Probe call?
                for jj in range(j + 1, min(j + 4, k)):
                    b2 = ins[jj]
                    if b2.mnemonic in ("je", "jz", "jbe", "jb", "jae", "jne", "jnz"):
                        try:
                            tgt = int(b2.op_str, 0)
                        except ValueError:
                            continue
                        if tgt > ins[k].address:
                            hits["probe_skip"].append(
                                {"weak": weak, "func": beg, "probe": name, "probe_va": ins[k].address,
                                 "test_va": m.address, "test": "%s %s" % (m.mnemonic, m.op_str),
                                 "jmp": "%s %s" % (b2.mnemonic, b2.op_str), "reg": z})
                        break
    return pe, hits, nprobe


def render(name, hits, nprobe, neither_no_probe=None):
    L = []
    n = sum(len(v) for v in hits.values())
    L.append("%-26s %2d Probe call(s) - %d candidate(s)" % (name, nprobe, n))
    strong = [h for h in hits["probe_skip"] if not h.get("weak")]
    weakn = len(hits["probe_skip"]) - len(strong)
    for h in strong[:8]:
        L.append("   [PROBE-SKIP!] func 0x%X  %s @0x%X  <- %s @0x%X / %s"
                 % (h["func"], h["probe"], h["probe_va"], h["test"], h["test_va"], h["jmp"]))
    if weakn:
        L.append("   (%d 8-bit flag branch(es) downgraded to weak candidates — they may be a "
                 "RequestorMode copy)" % weakn)
    for h in hits["kernelmode"][:6]:
        L.append("   [KERNELMODE ] func 0x%X  %s @0x%X  (%s)  => the access check is skipped"
                 % (h["func"], h["api"], h["va"], h["how"]))
    if neither_no_probe:
        L.append("   [NEITHER    ] %d METHOD_NEITHER IOCTL(s) and zero Probe* in the handler"
                 % neither_no_probe)
    return "\n".join(L)


if __name__ == "__main__":
    for p in sys.argv[1:]:
        try:
            pe, h, n = scan(p)
            print(render(p.rsplit("/", 1)[-1], h, n))
        except Exception as e:
            print("%-26s ERR %s" % (p.rsplit("/", 1)[-1], e))
