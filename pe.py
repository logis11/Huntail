# pe.py — the PE layer. The model used to rewrite this from scratch with
# `run_python` on every single run.
#
# From the first run's transcript, these are the things the model reimplemented
# by hand each time:
#   (1) PE section / ImageBase parsing   (2) VA -> file offset
#   (3) capstone disassembly             (4) byte comparison between two builds
#                                            with rip-relative normalisation
#                                            (did the anchor survive?)
# All four are deterministic and give the same answer every time, so they belong
# in the tool layer, not in the model.
# (Rationale: a classification whose precision matters is made by a
#  deterministic node, not by an LLM.)
import struct
from functools import lru_cache

try:
    import capstone
    _CS = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    _CS.detail = True
except Exception:                                       # pragma: no cover
    capstone = None
    _CS = None


class NotPE(Exception):
    pass


class PE:
    """Read-only PE. Works without `pefile`, so the harness does not require it."""

    def __init__(self, path):
        with open(path, "rb") as f:
            d = f.read()
        if len(d) < 0x40 or d[:2] != b"MZ":
            raise NotPE(f"no MZ signature: {path} "
                        "(did you hand over an IDA database (.id0/.i64) instead of the PE?)")
        po = struct.unpack_from("<I", d, 0x3C)[0]
        if po + 24 > len(d) or d[po:po + 4] != b"PE\0\0":
            raise NotPE(f"no PE header: {path}")
        self.path, self.d, self.po = path, d, po
        nsec = struct.unpack_from("<H", d, po + 6)[0]
        optsz = struct.unpack_from("<H", d, po + 20)[0]
        opt = po + 24
        self.magic = struct.unpack_from("<H", d, opt)[0]
        if self.magic != 0x20B:
            raise NotPE(f"not PE32+ (magic=0x{self.magic:X}) — this harness is x64 only")
        self.base = struct.unpack_from("<Q", d, opt + 24)[0]
        self.sa = struct.unpack_from("<I", d, opt + 32)[0]
        self.fa = struct.unpack_from("<I", d, opt + 36)[0]
        self.dllchar = struct.unpack_from("<H", d, opt + 70)[0]
        self.timestamp = struct.unpack_from("<I", d, po + 8)[0]
        self.dd = opt + 112
        so = opt + optsz
        self.secs = []
        for i in range(nsec):
            o = so + 40 * i
            vs, va, rs, pr = struct.unpack_from("<IIII", d, o + 8)
            self.secs.append({"name": d[o:o + 8].rstrip(b"\0").decode("latin-1"),
                              "va": va, "vsize": vs, "raw": pr, "rsize": rs,
                              "chars": struct.unpack_from("<I", d, o + 36)[0]})

    # ── export table ────────────────────────────────────────────
    def exports(self):
        """{name: VA}. **The only entrance to cross-image wiring.**

        On the importing side all you can see is a name (`call [rip+X]` -> IAT
        slot -> name). The BODY behind that name lives in a different file, and
        crossing over to it requires that file's export table. Forwarders
        (string entries that hand off to another DLL) are not code, so they get
        `None` instead of a VA and keep only the name — **"absent" and
        "forwarded elsewhere" must stay distinguishable.**
        """
        if getattr(self, "_exp", None) is not None:
            return self._exp
        out = {}
        try:
            rva, size = struct.unpack_from("<II", self.d, self.dd)   # dir[0] = EXPORT
            if rva:
                off = self.rva2off(rva)
                if off is not None:
                    nfun, nnam = struct.unpack_from("<II", self.d, off + 20)
                    afun, anam, aord = struct.unpack_from("<III", self.d, off + 28)
                    ofun, onam, oord = (self.rva2off(afun), self.rva2off(anam),
                                        self.rva2off(aord))
                    if None not in (ofun, onam, oord):
                        for i in range(nnam):
                            nrva = struct.unpack_from("<I", self.d, onam + 4 * i)[0]
                            no = self.rva2off(nrva)
                            if no is None:
                                continue
                            end = self.d.find(b"\0", no)
                            nm = self.d[no:end].decode("latin-1", "replace")
                            idx = struct.unpack_from("<H", self.d, oord + 2 * i)[0]
                            if idx >= nfun:
                                continue
                            frva = struct.unpack_from("<I", self.d, ofun + 4 * idx)[0]
                            # inside the directory range => forwarder string, not code
                            fwd = rva <= frva < rva + size
                            out[nm] = None if fwd else self.base + frva
        except Exception:
            pass
        self._exp = out
        return out

    def export_va(self, name):
        """name -> VA, with a case-insensitive fallback. Forwarder/absent -> None."""
        e = self.exports()
        if name in e:
            return e[name]
        low = name.lower()
        for k, v in e.items():
            if k.lower() == low:
                return v
        return None

    # ── address translation ─────────────────────────────────────
    def rva2off(self, rva):
        for s in self.secs:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rsize"]):
                off = s["raw"] + (rva - s["va"])
                return off if off < len(self.d) else None
        return None

    def va2off(self, va):
        return self.rva2off(va - self.base)

    def sec_of(self, va):
        rva = va - self.base
        for s in self.secs:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rsize"]):
                return s
        return None

    def read(self, va, n):
        o = self.va2off(va)
        return self.d[o:o + n] if o is not None else None

    def text(self):
        for s in self.secs:
            if s["name"] == ".text":
                return s
        return self.secs[0]

    # ── CodeView ───────────────────────────────────────────────
    def codeview(self):
        rva, sz = struct.unpack_from("<II", self.d, self.dd + 6 * 8)
        o = self.rva2off(rva)
        if o is None:
            return None, None, None
        for i in range(sz // 28):
            e = o + i * 28
            if struct.unpack_from("<I", self.d, e + 12)[0] != 2:
                continue
            szd, _ad, pd = struct.unpack_from("<III", self.d, e + 16)
            cv = self.d[pd:pd + szd]
            if cv[:4] != b"RSDS":
                continue
            g = cv[4:20]
            guid = "%08X%04X%04X%s" % (struct.unpack_from("<IHH", g, 0) +
                                       (g[8:16].hex().upper(),))
            return guid, struct.unpack_from("<I", cv, 20)[0], \
                cv[24:].split(b"\0")[0].decode("latin-1")
        return None, None, None

    def mitigations(self):
        return [n for b, n in ((0x20, "HIGH_ENTROPY_VA"), (0x40, "DYNAMIC_BASE"),
                               (0x100, "NX"), (0x400, "NO_SEH"),
                               (0x4000, "GUARD_CF")) if self.dllchar & b]

    # ── function bounds (.pdata) ────────────────────────────────
    # An x64 PE already carries RUNTIME_FUNCTION{Begin,End,Unwind} for every
    # function in the exception directory. There is **no reason to guess** where
    # a function ends by looking for int3 padding — it is written down.
    # (Blindly sweeping 0x6000 bytes from a handler's entry once scraped a
    #  neighbouring function's code and misread an NTSTATUS as a control code.
    #  Ignoring the bounds is exactly how that contamination happens.)
    def runtime_functions(self):
        if getattr(self, "_rf", None) is not None:
            return self._rf
        rf = []
        try:
            rva, sz = struct.unpack_from("<II", self.d, self.dd + 3 * 8)
            o = self.rva2off(rva)
            if o is not None:
                for i in range(sz // 12):
                    b, e, _u = struct.unpack_from("<III", self.d, o + i * 12)
                    if b and e > b:
                        rf.append((self.base + b, self.base + e))
        except struct.error:
            pass
        rf.sort()
        self._rf = rf
        return rf

    def func_bounds(self, va):
        """(start, end) of the function containing `va`; (None, None) if unknown."""
        rf = self.runtime_functions()
        lo, hi = 0, len(rf) - 1
        best = None
        while lo <= hi:
            m = (lo + hi) // 2
            if rf[m][0] <= va:
                best = rf[m]; lo = m + 1
            else:
                hi = m - 1
        if best and best[0] <= va < best[1]:
            return best
        return (None, None)

    # ── disassembly ────────────────────────────────────────────

    def merged_functions(self):
        """**Merge adjacent RUNTIME_FUNCTION chunks into one function.**

        Why: MSVC splits a large function into several `.pdata` chunks (chained
        unwind). Sweeping per chunk **separates the chunk holding the prologue
        from the chunk holding the body**, which cuts argument tracking in half.

        Measured on one driver: a WDF device-control handler was split into four
        chunks — [...,+0x27) holding the prologue, [...,+0x6fa) holding the
        control-code comparisons — and the handler-shape reader **saw 16 codes
        as 0**. On that same image 71 of 941 pairs (7.5%) were adjacent chunks,
        which is not a ratio you can wave away.

        Only merge when end == next start. Detached cold blocks are left alone
        (over-merging is its own failure).
        """
        rf = sorted(self.runtime_functions())
        out = []
        for b, e in rf:
            if out and out[-1][1] == b:
                out[-1] = (out[-1][0], e)
            else:
                out.append((b, e))
        return [tuple(x) for x in out]

    def func_bounds_merged(self, va):
        """Bounds per merged_functions — **function** bounds, not chunk bounds."""
        for b, e in self.merged_functions():
            if b <= va < e:
                return b, e
        return None, None

    def disasm(self, va, count=64, max_bytes=None):
        """[(va, bytes, mnem, ops)] — always relative to this PE file. No IDA needed."""
        if _CS is None:
            raise RuntimeError("capstone is not installed")
        n = max_bytes or count * 15
        b = self.read(va, n)
        if b is None:
            return []
        out = []
        for ins in _CS.disasm(b, va):
            out.append((ins.address, ins.bytes, ins.mnemonic, ins.op_str))
            if len(out) >= count:
                break
        return out


# ── cross-build anchors ─────────────────────────────────────────
# rip-relative displacements and call/jmp rel32 all change if a section shifts
# by a single page. On the first run this is where the model reported
# "3796 of 3884 functions differ" and nearly drew the wrong conclusion.
# Masking those two to zero leaves only the question that matters:
# **did the code actually change?**
def normalize_ex(code, va):
    """(normalised bytes, length that decoded cleanly).

    The second value is the important one. If the end of the window cuts an
    instruction in half, those trailing bytes are never normalised — and if a
    rip displacement lives in them, **identical code reads as different.** One
    real VA reported "the code changed" at window 0x30 and `same` at 0x20 /
    0x40 / 0x60. So a comparison always stops at the last complete instruction.
    """
    if _CS is None:
        return code, len(code)
    out = bytearray(code)
    dec = 0
    for ins in _CS.disasm(bytes(code), va):
        off = ins.address - va
        # rel8/rel32 branches and calls
        if capstone.x86.X86_GRP_JUMP in ins.groups or capstone.x86.X86_GRP_CALL in ins.groups:
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_IMM:
                    for k in range(max(0, ins.size - 4), ins.size):
                        out[off + k] = 0
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                d = ins.disp_offset
                if d:
                    for k in range(d, min(d + ins.disp_size, ins.size)):
                        out[off + k] = 0
        dec = off + ins.size
    return bytes(out), dec


def normalize(code, va):
    return normalize_ex(code, va)[0]


def code_equal(a_pe, b_pe, va, n=0x40):
    """Is the code at the same VA identical after normalisation?
    Returns (equal, first_diff_offset). The compared span stops at the length
    **both sides decoded cleanly**."""
    a, b = a_pe.read(va, n), b_pe.read(va, n)
    if a is None or b is None:
        return None, None
    a, da = normalize_ex(a, va)
    b, db = normalize_ex(b, va)
    L = min(da, db)
    if L == 0:
        return None, None
    a, b = a[:L], b[:L]
    if a == b:
        return True, None
    k = next((i for i in range(min(len(a), len(b))) if a[i] != b[i]), None)
    return False, k


@lru_cache(maxsize=8)
def _text_blob(pe):
    s = pe.text()
    return pe.d[s["raw"]:s["raw"] + s["rsize"]], pe.base + s["va"]


def relocate(old_pe, new_pe, va, n=0x30):
    """Where did the code at `va` in the old build move to in the new build?
    Normalised signature search.

    Returns (new_va, how) or (None, reason). how in {'same','moved','ambiguous'}

    How the search works: normalisation only zeroes the rip-disp / rel32 slots,
    so **bytes outside the masked slots are identical to the original.** Search
    raw for the longest unmasked run to cut the candidate set down, then
    normalise only those candidates to confirm. (Normalising everything takes
    ~10 s on a 1.5 MB .text.)
    """
    sig_raw = old_pe.read(va, n)
    if sig_raw is None:
        return None, "not mapped in the old build"
    same, _ = code_equal(old_pe, new_pe, va, n)
    if same:
        return va, "same"
    sig, dec = normalize_ex(sig_raw, va)
    if dec < 8:
        return None, "the cleanly decoded span is too short"
    sig, sig_raw, n = sig[:dec], sig_raw[:dec], dec      # stop at the last whole instruction
    mask = bytes(0 if c == 0 else 0xFF for c in sig)
    # longest contiguous unmasked run
    best_s = best_l = cur_s = cur_l = 0
    for i, m in enumerate(mask):
        if m:
            if cur_l == 0:
                cur_s = i
            cur_l += 1
            if cur_l > best_l:
                best_s, best_l = cur_s, cur_l
        else:
            cur_l = 0
    if best_l < 4:
        return None, "signature is almost entirely relocatable — cannot search"
    needle = sig_raw[best_s:best_s + best_l]
    blob, blob_va = _text_blob(new_pe)
    hits, i = [], 0
    while True:
        i = blob.find(needle, i)
        if i < 0:
            break
        start = i - best_s
        if start >= 0 and start + n <= len(blob):
            cand, cdec = normalize_ex(blob[start:start + n], blob_va + start)
            if cdec >= n and all((cand[k] & mask[k]) == sig[k] for k in range(n)):
                hits.append(blob_va + start)
                if len(hits) > 2:
                    break
        i += 1
    if not hits:
        return None, "signature not found in the new build — the code really did change"
    if len(hits) == 1:
        return hits[0], "moved"
    return None, f"ambiguous({len(hits)}+)"


def relocate_escalating(old_pe, new_pe, va, windows=(0x30, 0x60, 0xC0, 0x180)):
    """A function prologue is compiler boilerplate, so a short window is not
    unique. A 0x30 window really did relocate one function **onto a different
    function**. Grow the window until the match is unique; if it never becomes
    unique, return None rather than quietly hand back a wrong address."""
    last = "not attempted"
    for n in windows:
        va2, how = relocate(old_pe, new_pe, va, n)
        if va2 is not None:
            return va2, (how if n == windows[0] else f"{how}@0x{n:x}")
        last = how
        if how.startswith("signature not found"):
            break
    return None, last


def relocate_function(old_pe, new_pe, va, extent=0x400, probes=5):
    """Function-level relocation — the answer is the **consensus** of the deltas
    measured at several points inside the function.

    Looking only at the prologue either is not unique (compiler boilerplate) or
    fails wholesale when only the prologue changed. That really happened: one
    function failed at every window size because of its prologue while the
    sentinel guard inside it was alive and well in the live build.

    So probe several instruction boundaries and only answer when at least two
    of them agree on the delta — self-consistency *is* the verification.

    Returns (new_va, how). how in {'same','consensus(k)','single','none'}
    """
    same, _ = code_equal(old_pe, new_pe, va, 0x40)
    if same:
        return va, "same"
    # pick probe points on instruction boundaries
    pts, want = [], [0]
    step = max(0x20, extent // (probes + 1))
    want += [step * i for i in range(1, probes + 1)]
    cur = 0
    for a, b, _m, _o in old_pe.disasm(va, 4096, max_bytes=extent):
        off = a - va
        while want and off >= want[0]:
            want.pop(0)
            pts.append(a)
        if off > extent:
            break
    if va not in pts:
        pts.insert(0, va)
    deltas = {}
    for p in pts[:probes + 1]:
        nv, _how = relocate_escalating(old_pe, new_pe, p)
        if nv is not None:
            deltas.setdefault(nv - p, []).append(p)
    if not deltas:
        return None, "none"
    d, hits = max(deltas.items(), key=lambda kv: len(kv[1]))
    if len(hits) >= 2:
        return va + d, f"consensus({len(hits)}/{len(pts[:probes+1])})"
    return va + d, "single"
