#!/usr/bin/env python3
# authz.py — 호출그래프 기반 두 가지: ① 인가 API 도달성 ② **함수 간** 가드 지배.
#
# 둘은 같은 문제다. `cfg.py` 는 함수 **안**에서만 지배를 계산했고, pcw.sys 감사에서
# 4건이 `cross_function` 으로 판정 불가였다. 그 4건의 모양은 전부 같다:
#   **가드는 디스패처에, 싱크는 핸들러에.**
# 그게 교리가 "가장 흔한 진짜 결함"이라 부르는 *문에서 한 번만 검사* 패턴이다.
#
# ① 은 window_kernel/tools/authz_reach.py (A-13 에서 쓴 것)를 하네스로 옮기고
#    http.sys 전용 디스패치표 탐침을 걷어낸 것이다. 핸들러 VA 는 driver.py 가 준다.
#
# ★ 이 도구의 음성("인가 API 0건")은 **양성 대조 없이는 근거가 아니다.**
#   그래서 audit() 는 controls= 없이는 음성을 확정으로 내놓지 않는다.
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
    """.pdata 함수 전체에 대해 **직접 call** 간선. 전 실행섹션을 포함한다.

    한계(항상 같이 보고할 것):
      - 간접호출·vtable·DPC 콜백 미추적
      - ★ **도달 ≠ 실행**. BFS 가 공유 헬퍼로 새어 들어가면 그 IOCTL 과 무관한 API 가
        잡힌다. http.sys 클라이언트 IOCTL 48 에서 `IoGetRequestorProcess` 가 잡혔는데
        그 소비처는 `ObOpenObjectByPointer`(디바이스 open 경로의 공유 코드)였다.
        정체성 API 도달은 **"읽어보라"는 신호**이지 게이트의 존재 증명이 아니다.
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
    """start 함수에서 직접호출 BFS 로 도달하는 인가 API. 경로도 돌려준다."""
    if cg is None:
        cg = callgraph(pe)
    g, bounds = cg
    st = func_of(bounds, start) or start
    if st not in g:
        return {"error": "start 0x%X 가 .pdata 함수가 아니다" % start}
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
    """`call PsGetCurrentProcess` 류 직후 그 반환값이 **저장된 값과 비교되는가**.

    ksecdd.sys 가 그 모양이다: PsGetCurrentProcess() 를 SiloContext->[0] 와 비교해
    실로당 1프로세스로 잠근다. Se* 가 없으니 임포트 기반 인가 스캔에는 안 잡힌다.
    여기서는 **비교의 존재만** 보고한다 — 그게 진짜 게이트인지는 사람이 읽어야 한다.
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
        # 반환값(rax)이 메모리와 비교되는가 / 메모리에 저장되는가
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
    """대상 핸들러들의 인가 도달성. **controls 없이는 음성을 확정으로 내지 않는다.**

    controls = 인가가 있는 것이 알려진 핸들러 VA 목록. 거기서도 0건이면 분석기 고장이다.
    """
    cg = callgraph(pe)
    res = {"targets": {}, "controls": {}, "valid": None, "note": ""}
    for t in targets:
        r = reach_apis(pe, t, apis, depth, cg)
        # ★ 인가 API 0건이어도 **정체성 게이트**가 있으면 '인가 없음'을 주장하면 안 된다.
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
        res["note"] = ("★ 양성 대조 없음. '인가 API 0건'을 근거로 쓰지 마라 — "
                       "분석기 고장과 인가 부재는 결과가 같다. "
                       "controls= 에 인가가 있는 것이 알려진 핸들러를 넣어라.")
    else:
        ok = any(r.get("found") for r in res["controls"].values())
        res["valid"] = ok
        res["note"] = ("양성 대조 통과 — 이 분석기는 인가가 있는 곳에서 실제로 검출한다."
                       if ok else
                       "★ 양성 대조 **실패**. 대조 핸들러에서도 인가 API 가 0건이다 — "
                       "**분석기가 고장났다.** 이 실행의 음성 결과는 전부 무효다.")
    return res


# ── ② 함수 간 가드 지배 (cfg.py 의 cross_function 확장) ──────
def gates_inter(pe, guard_va, sink_va, depth=6):
    """가드(F 안)가 싱크(G 안)를 지배하는가 — **호출지점 지배 + 유일 호출자**로 판정.

    성립 조건 둘 다 필요하다:
      (a) G 를 부르는 곳이 **F 안에만** 있다 (밖에서 부르면 그 경로는 가드를 안 지난다)
      (b) F 안의 모든 G 호출지점을 가드가 지배한다
    하나라도 깨지면 '지배 안 함'이다. 판정 못 하면 판정 안 한다.
    """
    import cfg
    g, bounds = callgraph(pe)
    F = func_of(bounds, guard_va)
    G = func_of(bounds, sink_va)
    if F is None or G is None:
        return {"verdict": "no_pdata", "why": "가드/싱크가 .pdata 함수 밖이다"}
    if F == G:
        return cfg.gates(pe, guard_va, sink_va)
    # (a) G 의 호출자 전수
    callers = {f for f, v in g.items() if G in v["calls"]}
    if not callers:
        return {"verdict": "indirect_only", "F": F, "G": G,
                "why": "싱크 함수 0x%X 를 **직접 호출하는 곳이 없다** — 함수포인터/콜백 경유다. "
                       "호출그래프로는 판정할 수 없다 (ipt.sys 의 wrmsr DPC 콜백이 그 경우였다)." % G}
    outside = callers - {F}
    if outside:
        return {"verdict": "other_callers", "F": F, "G": G,
                "callers": ["0x%X" % x for x in sorted(callers)],
                "why": "★ 싱크 함수 0x%X 를 **가드 함수 밖에서도 부른다** (%s) — "
                       "그 경로는 가드 0x%X 를 지나지 않는다. 이 기각은 성립하지 않는다."
                       % (G, ", ".join("0x%X" % x for x in sorted(outside)), guard_va)}
    # (b) F 안의 모든 G 호출지점을 가드가 지배하는가
    sites = [a for a, t, _n in g[F]["callsites"] if t == G]
    if not sites:
        return {"verdict": "unbounded", "why": "호출지점을 못 찾았다"}
    bad = []
    for a in sites:
        r = cfg.gates(pe, guard_va, a)
        if r["verdict"] != "gated":
            bad.append((a, r["verdict"], r.get("why", "")))
    if bad:
        return {"verdict": "not_dominated", "F": F, "G": G,
                "sites": ["0x%X" % a for a in sites],
                "why": "★ F 0x%X 안의 G 호출지점 %d개 중 %d개를 가드가 지배하지 않는다: %s"
                       % (F, len(sites), len(bad),
                          "; ".join("0x%X(%s)" % (a, v) for a, v, _w in bad))}
    return {"verdict": "gated_inter", "F": F, "G": G,
            "sites": ["0x%X" % a for a in sites],
            "why": "싱크 함수 0x%X 는 오직 0x%X 에서만 호출되고, 그 호출지점 %d개 전부를 "
                   "가드 0x%X 가 지배한다." % (G, F, len(sites), guard_va)}


def render(res):
    L = [res["note"], ""]
    for k, r in res["controls"].items():
        L.append("  [대조] %s → %s" % (k, ", ".join(r.get("found", {})) or "0건"))
    for k, r in res["targets"].items():
        f = r.get("found", {})
        L.append("  %s  탐색 %d함수 → %s" % (k, r.get("visited", 0),
                                             ", ".join(f) if f else "**인가 API 0건**"))
        for nm, path in list(f.items())[:3]:
            L.append("      %s  경로: %s" % (nm, " → ".join("0x%X" % x for x in path)))
        ident = r.get("identity") or {}
        if not f and ident:
            L.append("      ★ 그런데 **정체성 API 에는 도달한다**: %s" % ", ".join(ident))
            for c in (r.get("identity_compares") or []):
                L.append("         %s @0x%X → %s @0x%X  [%s]"
                         % (c["api"], c["call_va"], c["insn"], c["va"], c["kind"]))
            L.append("      ⇒ **'인가 없음'을 주장하지 마라.** 인가가 Se* API 가 아니라 "
                     "`PsGetCurrentProcess() == 저장된값` 같은 **포인터 비교**로 되어 있을 수 있다. "
                     "ksecdd.sys 가 정확히 그 모양이고(실로당 1프로세스), 그걸 놓쳐 확정을 냈다.")
    return "\n".join(L)


if __name__ == "__main__":
    import sys
    from pe import PE
    p = PE(sys.argv[1])
    tg = [int(x, 0) for x in sys.argv[2].split(",")] if len(sys.argv) > 2 else []
    ct = [int(x, 0) for x in sys.argv[3].split(",")] if len(sys.argv) > 3 else []
    print(render(audit(p, tg, ct)))
