#!/usr/bin/env python3
# xref.py — **전 실행섹션** 임포트 xref. `.text` 만 보는 습관을 도구 차원에서 없앤다.
#
# 왜: ipt.sys 실행에서 에이전트가 "SeSinglePrivilegeCheck 는 23개 .text 임포트 호출 중에
# 없다"고 적고 킬 조건을 닫지 못했다. **호출은 `PAGE` 에 있었다** (0x14000CC59).
# 드라이버는 `.text` / `PAGE` / `INIT` / `fothk` 로 코드가 흩어진다 — 초기화 코드와
# 페이징 가능 코드가 각각 다른 섹션에 간다. `.text` 만 보면 인가 검사를 통째로 놓친다.
#
# 이 도구는 **어느 섹션을 훑었는지 항상 같이 보고한다.** 부재 주장의 근거가 되려면
# 커버리지가 명시돼야 하기 때문이다.
import struct

import capstone
from capstone import x86 as X

# 인가/권한 관련 — "검사가 없다"를 주장하기 전에 반드시 전수해야 할 것
AUTHZ = ("SeSinglePrivilegeCheck", "SePrivilegeCheck", "SeAccessCheck", "SeAccessCheckFromState",
         "SeSinglePrivilegeCheckEx", "SeCaptureSecurityDescriptor", "SeCaptureSubjectContext",
         "SeCreateAccessState", "SeCreateAccessStateEx", "SeQueryInformationToken",
         "SeTokenIsAdmin", "SeTokenIsRestricted", "PsReferencePrimaryToken",
         "PsReferenceImpersonationToken", "PsIsSystemThread", "ZwOpenProcessToken",
         "ZwOpenThreadToken", "ZwQueryInformationToken", "ObSetSecurityObjectByPointer",
         "ZwSetSecurityObject", "RtlValidSid", "RtlEqualSid", "SeImpersonateClient")
# ★ **정체성 게이트** — 인가가 `Se*` API 로만 이뤄진다는 가정이 틀렸다.
# ksecdd.sys 의 실제 게이트는 `PsGetCurrentProcess() == SiloContext->[0]` 즉 **평범한
# 포인터 비교**다. Se* 가 하나도 안 나온다. 임포트 이름 기반 인가 스캔은 이걸 통째로 놓친다.
# (에이전트가 "재인가 없음"으로 확정을 냈고, 실제로는 실로당 1프로세스로 잠겨 있었다.)
# ⇒ 이 목록이 걸리면 **"인가 없음"을 주장하기 전에 저장값과의 비교를 찾아야 한다.**
IDENTITY = ("PsGetCurrentProcess", "PsGetCurrentProcessId", "PsGetCurrentThread",
            "PsGetCurrentThreadId", "PsGetProcessId", "PsGetThreadId",
            "IoGetRequestorProcess", "IoGetRequestorProcessId", "IoGetRequestorSessionId",
            "PsGetCurrentServerSilo", "PsGetPermanentSiloContext", "PsGetSiloContext",
            "PsGetJobSilo", "PsGetCurrentSilo", "ObGetObjectSecurity",
            "PsGetProcessSessionId", "PsGetCurrentProcessSessionId")

# 유저 포인터 검증
PROBE = ("ProbeForRead", "ProbeForWrite", "MmProbeAndLockPages", "MmUserProbeAddress")


def iat(pe):
    """IAT VA → 임포트 이름. pefile 없이."""
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
    """전 실행섹션을 선형 디스어셈블해 IAT 참조를 모은다.

    선형 스윕은 디싱크로 없는 참조를 만들 수 있다. 그래서 결과마다 **그 주소가
    .pdata 함수 안에 드는지**를 같이 보고한다 — 함수 밖 히트는 의심하라는 신호다.
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
    L.append("훑은 실행섹션: " + ", ".join("%s(0x%X, %d bytes)" % (c["name"], c["va"], c["size"])
                                            for c in cov))
    L.append("대상 임포트 %d개%s" % (len(names), (" — " + want_desc) if want_desc else ""))
    if not names:
        L.append("★ 그 이름의 임포트가 **없다**. 임포트 부재는 호출 부재보다 강한 근거다 "
                 "(단 동적 해결·순방향 임포트는 여기 안 잡힌다).")
        return "\n".join(L)
    if not hits:
        L.append("★ 참조 0건 — 위 섹션 전부에서. 이제 '호출되지 않는다'를 근거로 쓸 수 있다. "
                 "(간접호출·함수포인터 경유는 여전히 안 보인다)")
        return "\n".join(L)
    L.append("참조 %d건:" % len(hits))
    byname = {}
    for h in hits:
        byname.setdefault(h["name"], []).append(h)
    for nm, hs in sorted(byname.items()):
        L.append("  %s — %d건" % (nm, len(hs)))
        for h in hs[:12]:
            mark = "" if h["in_pdata"] else "   ⚠ .pdata 함수 밖 (선형스윕 디싱크 의심)"
            L.append("     [%-6s] 0x%X  %s  (함수 0x%X)%s"
                     % (h["section"], h["va"], h["mnem"], h["func"] or 0, mark))
        if len(hs) > 12:
            L.append("     … 외 %d건" % (len(hs) - 12))
    miss = sorted(set(names.values()) - set(byname))
    if miss:
        L.append("참조 0건인 임포트: " + ", ".join(miss))
    return "\n".join(L)


if __name__ == "__main__":
    import sys
    from pe import PE
    p = PE(sys.argv[1])
    w = sys.argv[2].split(",") if len(sys.argv) > 2 else AUTHZ
    h, c, n = sweep(p, w)
    print(render(h, c, n, "필터=%s" % (sys.argv[2] if len(sys.argv) > 2 else "AUTHZ 프리셋")))
