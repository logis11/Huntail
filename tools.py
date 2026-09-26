# tools.py — 분석 툴 구현.
#
# 설계 원칙 두 개:
#  ① **모델이 매번 다시 짜는 것은 툴로 내린다.** 첫 실행 기록을 보면 모델이 PE 파싱·VA 변환·
#     capstone·크로스빌드 diff 를 run_python 으로 손수 재구현했다. 전부 결정론이다.
#     (정밀도가 중요한 분류는 LLM 이 아니라 결정론 노드가 해야 한다 — ARG 패턴.)
#  ② **항해가 병목이다.** COTS 바이너리 에이전트 연구에서 툴셋을 붙이는 것만으로
#     Claude Code 의 F1 이 +0.214 올랐다. 3884 함수를 이름 grep 하나로 다닐 수는 없다.
import hashlib
import json, os, re, struct, subprocess, sys, tempfile, time

import config, ledger, nav, evidence, xref, authz
import pe as PEmod

TARGET = {"binary": None, "alt": None, "corpus": None,
          "_pe": None, "_alt": None, "_ix": None,
          # ★ 크로스 이미지. 표적 하나만 보면 주장이 이미지 경계에서 끊긴다 —
          #   `nt!MmCreateSection` 이 핸들을 어느 모드로 참조하는가 같은 질문은
          #   우리 드라이버를 100% 읽어도 답이 안 나온다. 그 벽을 여는 자리다.
          "_images": {}, "_imeta": {}}

_BANNER = nav.BANNER


def set_target(binary=None, corpus=None, alt=None):
    TARGET.update({"binary": os.path.abspath(binary) if binary else None,
                   "alt": os.path.abspath(alt) if alt else None,
                   "corpus": os.path.abspath(corpus) if corpus else None,
                   "_pe": None, "_alt": None, "_ix": None})
    if TARGET["binary"]:
        TARGET["_pe"] = PEmod.PE(TARGET["binary"])       # NotPE 는 호출자가 잡는다
    if TARGET["alt"]:
        TARGET["_alt"] = PEmod.PE(TARGET["alt"])
    if TARGET["corpus"]:
        TARGET["_ix"] = nav.Index(TARGET["corpus"], cache_dir=config.WORK_DIR)
    TARGET["_iix"] = None          # IDA 인덱스 캐시 리셋
    TARGET["_images"] = {}         # 표적이 바뀌면 보조 이미지도 전부 내린다
    TARGET["_imeta"] = {}


def _ix():
    """코퍼스 인덱스가 있으면 그걸, 없으면 **IDA 인덱스**를 준다.
    ★ 예전엔 코퍼스가 없으면 그냥 None 이었고, 항해 툴 6종이 통째로 죽었다."""
    if TARGET["_ix"] is not None:
        return TARGET["_ix"]
    return _ida_index()


def _pe():
    return TARGET["_pe"]


MAIN_ALIASES = ("", "main", "target", "self", "none")


def add_image(name, path):
    """보조 이미지를 등록한다. 이름은 인용 태그가 된다 (`nt!0x14098f670 mov ...`).

    ★ 빌드 동일성을 **같이** 기록한다. 다른 빌드의 ntoskrnl 로 검증한 앵커는
      검증이 아니라 우연이다 — 그걸 구분 못 하면 크로스 이미지는 환각을 한 홉 옮긴 것뿐이다.
    """
    nm = str(name).strip().lower()
    if nm in MAIN_ALIASES:
        raise ValueError("보조 이미지 이름으로 %r 는 못 쓴다 (main 예약어)" % name)
    if not re.fullmatch(r'[a-z_][a-z0-9_]{0,15}', nm):
        raise ValueError("이미지 이름은 [a-z_][a-z0-9_]{0,15} 여야 한다: %r" % name)
    ap = os.path.abspath(os.path.expanduser(path))
    img = PEmod.PE(ap)                       # NotPE 는 호출자가 잡는다
    guid = age = pdb = ""
    try:
        guid, age, pdb = img.codeview()          # (guid, age, pdb) 튜플이다
    except Exception:
        pass
    TARGET["_images"][nm] = img
    TARGET["_imeta"][nm] = {
        "name": nm, "path": ap, "size": os.path.getsize(ap),
        "base": "0x%x" % img.base, "timestamp": "0x%x" % img.timestamp,
        "guid": guid or "", "age": age or "", "pdb": os.path.basename(pdb or ""),
        "exports": len(img.exports()),
    }
    return TARGET["_imeta"][nm]


def image_of(name):
    """이름 → PE. main/빈값이면 측정 대상. 모르는 이름이면 None."""
    nm = str(name or "").strip().lower()
    if nm in MAIN_ALIASES:
        return _pe()
    return TARGET["_images"].get(nm)


def images_all():
    """{이름: PE} — main 포함. evidence 의 이미지별 앵커 검증이 이걸 받는다."""
    d = {"main": _pe()} if _pe() is not None else {}
    d.update(TARGET["_images"])
    return d


def _img_resolve(img, target):
    """보조 이미지에서 `0xVA` 또는 **익스포트 이름** 을 VA 로. (va, note)"""
    t = str(target).strip()
    if re.fullmatch(r'0x[0-9a-fA-F]+', t):
        return int(t, 16), ""
    va = img.export_va(t)
    if va:
        return va, "익스포트 %s → 0x%x" % (t, va)
    if t in img.exports():
        return None, ("`%s` 은 이 이미지의 **포워더** 다 — 몸통이 다른 파일에 있다. "
                      "그 파일을 이미지로 등록해야 따라갈 수 있다." % t)
    near = [k for k in img.exports() if t.lower() in k.lower()][:8]
    return None, ("보조 이미지에서는 **익스포트 이름이나 0xVA 만** 해결된다 "
                  "(코퍼스 심볼은 측정 대상 것이다). `%s` 는 익스포트에 없다.%s"
                  % (t, ("  비슷한 이름: " + ", ".join(near)) if near else ""))


def _cap(s, n=None):
    n = n or config.TOOL_OUT_CAP
    s = s if isinstance(s, str) else str(s)
    if len(s) <= n:
        return s
    return s[: n // 2] + f"\n... [{len(s)-n} chars elided] ...\n" + s[-n // 2:]


# ── 주소 해결: 이름/0xVA → (코퍼스VA, 측정빌드VA, 메모) ──────────
def resolve(target, from_corpus=False):
    """코퍼스 빌드와 측정 빌드가 다를 수 있다. **항상** 둘을 분리해서 돌려준다.

    규칙 (헷갈리면 여기가 기준):
      · **심볼 이름** 은 코퍼스에서만 나온다 ⇒ 코퍼스 좌표 → 측정 빌드로 재도출한다.
      · **주소** 는 측정 빌드 좌표로 본다 ⇒ 그대로 쓴다.
        find_bytes/disassemble 가 방금 준 주소를 또 옮기면 안 되기 때문이다.
        구빌드 주소를 옮기고 싶으면 from_corpus=1 또는 anchor(relocate=...) 를 써라.
    """
    ix, p, a = _ix(), _pe(), TARGET["_alt"]
    cva = lva = None
    name = None
    if isinstance(target, str) and target.lower().startswith("0x"):
        va = int(target, 16)
        if not from_corpus:
            return (ix.func_at(va) if ix else None), None, va, ""
        cva = va
        name = ix.func_at(cva) if ix else None
    elif ix:
        name = ix.resolve(target)
        if name:
            cva = ix.fn[name][0]
    if cva is None:
        return None, None, None, f"'{target}' 를 코퍼스/주소로 해결할 수 없다"
    if a is None or p is None:
        return name, cva, cva, ""
    ext = 0x400
    if ix:
        nxt = [v for v, _ in ix.byva if v > cva]
        ext = min(nxt[0] - cva, 0x800) if nxt else 0x400
    nva, how = PEmod.relocate_function(a, p, cva, ext)
    if nva is None:
        return name, cva, None, (
            f"⚠ 코퍼스 빌드 VA 0x{cva:x} 를 측정 빌드에서 못 찾았다 — {how}.\n"
            "★ 이것이 곧 '패치됐다' 는 뜻은 아니다. 재컴파일만으로도(레지스터 할당·스택 슬롯 변경) "
            "바이트는 전부 달라진다. 다음 수는 **변하지 않는 상수로 다시 찾기** 다: "
            "find_bytes(hex='<구조체오프셋+즉치>') — 예를 들어 cmp [r+0x2d4], 0x0FFFFFFF 는 "
            "'d4020000ffffff0f'. 찾고 나서 그 주소로 disassemble 하라.")
    note = "" if how == "same" else \
        f"★ 앵커 이동: 코퍼스 0x{cva:x} → 측정빌드 0x{nva:x} ({how}). 인용은 측정빌드 주소로 하라."
    return name, cva, nva, note


# ── binary_info ──────────────────────────────────────────────
def _t_binary_info(_):
    p = _pe()
    if not p:
        return "binary 미지정 (corpus 전용 모드). 판정 근거를 디스어셈블로 세울 수 없다."
    guid, age, pdb = p.codeview()
    L = [f"path      : {p.path}", f"size      : {len(p.d)}",
         f"ImageBase : 0x{p.base:X}   TimeStamp: 0x{p.timestamp:X}",
         f"CodeView  : GUID={guid} age={age} pdb={pdb}",
         f"완화       : {', '.join(p.mitigations()) or '없음'}", "",
         "sections (name / RVA / VSize / RawPtr / RawSize / X):"]
    for s in p.secs:
        L.append(f"  {s['name']:<10} 0x{s['va']:08X} 0x{s['vsize']:08X} "
                 f"0x{s['raw']:08X} 0x{s['rsize']:08X} {'X' if s['chars'] & 0x20000000 else '-'}")
    L += ["", f"FileAlignment=0x{p.fa:X} SectionAlignment=0x{p.sa:X}" +
          ("  → file offset == RVA" if p.fa == p.sa else
           "  → file offset ≠ RVA. base+fileoff 로 VA 를 추정하지 마라")]
    a = TARGET["_alt"]
    if a:
        g2 = a.codeview()[0]
        L += ["", f"대조 빌드   : {os.path.basename(a.path)}  GUID={g2}",
              ("  ⇒ GUID 동일 — 코퍼스 앵커를 그대로 써도 된다." if g2 == guid else
               "  ⇒ **GUID 다름.** 코퍼스는 대조 빌드에서 뜬 것이다. 모든 주소는 resolve/anchor 가 "
               "자동 재도출한다. 인용은 반드시 측정 빌드 주소로 하라.")]
    elif TARGET["corpus"]:
        L += ["", "⚠ 대조 빌드 미지정. 코퍼스가 어느 빌드에서 나왔는지 하네스가 모른다 — "
                  "앵커 재도출을 자동으로 못 한다. ALT=<코퍼스와 같은 빌드의 PE> 로 주면 된다."]
    if _ix():
        L += ["", f"코퍼스     : {len(_ix().fn)} 함수, 콜그래프 간선 "
                  f"{sum(len(v) for v in _ix().out.values())}개"]
    return "\n".join(L)



def _noix(extra=""):
    """항해 인덱스가 없을 때의 **진단 가능한** 메시지.
    ★ 예전엔 그냥 "corpus 미지정." 이었다. IDA 브리지가 고장나 있어도 같은 문구라
      원인이 안 보였다 (실제로 WSLENV 누락으로 항상 죽어 있었다)."""
    why = []
    if not TARGET["corpus"]:
        why.append("코퍼스 미지정")
    if not TARGET["binary"]:
        why.append("바이너리 미지정")
    elif not config.USE_IDA:
        why.append("USE_IDA=0")
    elif not os.path.exists(config.IDAT):
        why.append("IDAT 없음(%s)" % config.IDAT)
    else:
        why.append("IDA 인덱스 구축 실패 — `python3 -c \"import tools;tools.set_target(binary=...);print(tools._ida_index())\"` 로 직접 재현하라")
    return "항해 인덱스 없음: " + " / ".join(why) + (("  (%s)" % extra) if extra else "")


# ── 항해 ─────────────────────────────────────────────────────
def _t_find_funcs(a):
    ix = _ix()
    if not ix:
        return _noix()
    hits, tot = ix.search(a["pattern"], int(a.get("limit") or 60))
    body = "\n".join(f"  {n:<58} 0x{va:x}" for n, va in hits)
    return f"'{a['pattern']}' 이름 매치 {tot}개 (표시 {len(hits)})\n{body}"


def _t_func_at(a):
    """VA 를 감싸는 함수 + **경계**.

    경계를 같이 주는 이유: 고정 창(0x1200 등)으로 훑다가 **남의 함수를 긁는** 사고가
    이 프로젝트에서 이미 두 번 났다(초기 스캐너 0x6000 고정 스팬, 그리고 최근 즉치 스윕).
    `.pdata` RUNTIME_FUNCTION 이 정답을 갖고 있으니 추측할 이유가 없다.
    ⇒ 이 함수를 훑을 때는 반드시 이 범위 안에서만."""
    va = int(a["va"], 16) if isinstance(a["va"], str) else int(a["va"])
    p = _pe()
    lo = hi = None
    if p is not None:
        try:
            lo, hi = p.func_bounds(va)
        except Exception:
            lo = hi = None
    ix = _ix()
    n = ix.func_at(va) if ix else None
    if not n and lo is None:
        return _noix() if not ix else f"0x{va:x} 를 감싸는 함수 없음"
    L = []
    if n:
        fva = ix.fn[n][0]
        L.append(f"0x{va:x} \u2208 {n} @ 0x{fva:x}  (+0x{va-fva:x})")
    if lo is not None and hi is not None:
        L.append(f"경계(.pdata): [0x{lo:x}, 0x{hi:x})  크기 0x{hi-lo:x}")
        L.append("\u2605 훑을 때는 **이 범위 안에서만** 해라. 고정 창은 남의 함수를 긁는다.")
    else:
        L.append("경계(.pdata): 없음 — **미분석**이지 '함수가 아님'이 아니다")
    return "\n".join(L)


def _t_callers(a):
    ix = _ix()
    if not ix:
        return _noix()
    n, cs = ix.callers(a["target"])
    if not n:
        return f"'{a['target']}' 미해결"
    return (f"{n} 의 호출자 {len(cs)}개:\n" + "\n".join(f"  {c}" for c in cs) +
            "\n\n★ 이 그래프는 디컴파일 본문의 **직접 호출**만 본다. 함수 포인터·vtable·"
            "디스패치 표 경유는 안 보인다 — 부재를 주장하기 전에 dispatch_table 과 "
            "corpus_grep 으로 간접 경로를 따로 확인하라.")


def _t_callees(a):
    ix = _ix()
    if not ix:
        return _noix()
    n, cs = ix.callees(a["target"])
    if not n:
        return f"'{a['target']}' 미해결"
    # ★ 2026-09-11 — **이 목록의 부재는 증거가 아니다.** `callers` 는 이미 이 경고를
    #   달고 있었는데 `callees` 만 안 달고 있었다(비대칭). 그 밤에 바로 대가를 치렀다:
    #   bfs.sys 케이스 1 이 *"MEASURED FROM callees(): BfsPreCreateOperation does NOT call
    #   ExAcquireRundownProtection"* 을 UAF 리드의 **하중 지지 근거**로 썼다. 케이스 2 가
    #   바이트로 반증했고 운영자가 IAT 슬롯까지 풀어 확인했다:
    #     0x14000390e lea rcx,[rip+0x1aa7b]     ; gBfsRundownProtection 0x14001E390
    #     0x140003915 call qword ptr [rip+0x1cd24]  ; IAT 0x140020640 = ExAcquireRundownProtection
    #   즉 **임포트 간접호출은 이 그래프에 안 들어온다.** 리드 하나가 그 부재 위에 섰다가 죽었다.
    return (f"{n} 이 부르는 것 {len(cs)}개:\n" + "\n".join(f"  {c}" for c in cs) +
            "\n\n★ **이 목록에 없다고 '안 부른다'로 쓰지 마라.** 임포트 간접호출"
            "(`call qword ptr [rip+…]` → IAT)·디스패치 표·함수포인터는 여기 안 잡힌다. "
            "실측(2026-09-11 bfs.sys): 이 목록에 `ExAcquireRundownProtection` 이 없었는데 "
            "`0x140003915` 에서 IAT 로 부르고 있었고, 그 부재를 근거로 세운 UAF 리드가 다음 "
            "회차에 반증됐다. 부재를 주장하려면 `disassemble` 로 그 함수 전 구간의 "
            "`call qword ptr [rip+…]` 슬롯을 풀거나 `import_xref` 로 확인하라.")


def _t_callpath(a):
    ix = _ix()
    if not ix:
        return _noix()
    p, how = ix.callpath(a["src"], a["dst"], int(a.get("maxdepth") or 8))
    if not p:
        return (f"{a['src']} → {a['dst']}: 경로 없음 ({how}).\n"
                "★ 이것만으로 '도달 불가' 를 확정하지 마라 — 간접 호출은 이 그래프에 없다. "
                "도달 불가는 기각 사유 1위이므로 근거가 약하면 blocked 로 남겨라.")
    return (f"{a['src']} → {a['dst']}  ({len(p)-1} 홉)\n" +
            "\n".join(f"  {i}. {n}" for i, n in enumerate(p)))


def _t_census(a):
    ix = _ix()
    if not ix:
        return _noix()
    ment = set()
    for k, v in ledger.STATE["surface"].items():
        ment.add(k)
    rows = ix.census(ment)
    L = ["패밀리      전체   미등재   미감사율", "-" * 40]
    for k, tot, un, r in rows[:24]:
        L.append(f"  {k:<8} {tot:>5} {un:>7}   {r*100:>3.0f}%")
    L.append("\n★ '전수 표에 없음 = 확실히 미감사'. 언급됐다고 감사한 것은 아니다.")
    return "\n".join(L)


# ── 코드 ─────────────────────────────────────────────────────
def _t_decompile(a):
    ix = _ix()
    if ix:
        hit = ix.body(a["target"])
        if hit:
            n, va, body = hit
            _nm, _c, lva, note = resolve(n)
            return (f"[corpus] {n} @ 0x{va:x}" + (f"\n{note}" if note else "") + "\n" +
                    _cap(body) + "\n\n⚠ 디컴파일 출력이다. 판정을 바꿀 코드는 disassemble 로 확인하라 — "
                    "디컴파일러는 검사를 누락하기도 하고 없는 결함을 만들어내기도 한다.")
    r = _ida_call("decompile", a["target"])
    if r and not r.get("error"):
        return _cap(r.get("code") or str(r)) + "\n\n⚠ 디컴파일 출력이다."
    return f"decompile 실패: corpus 에 {a['target']} 없음, IDA 도 불가. ({r})"


def _t_disassemble(a):
    """이름이든 주소든 받는다. **측정 빌드**를 디코드하고, 앵커가 이동했으면 그렇게 말한다.

    `image='nt'` 를 주면 **보조 이미지**를 디코드한다(크로스 이미지). 그때 인용은
    반드시 `nt!0xVA mnem ops` 형태로 써라 — 태그 없는 인용은 측정 대상에 대고 검증되고,
    그러면 다른 파일의 주소가 통과하거나(우연) 실패한다(정상). 태그가 곧 검증 대상이다.
    """
    t = a["target"]
    cnt = int(a.get("count") or 80)
    imgname = str(a.get("image") or "").strip().lower()
    if imgname not in MAIN_ALIASES:
        img = image_of(imgname)
        if img is None:
            return ("보조 이미지 %r 가 등록돼 있지 않다. `images(action='list')` 로 확인하고, "
                    "필요하면 `images(action='add', name=..., path=...)` 로 등록하라." % imgname)
        va, note = _img_resolve(img, t)
        if va is None:
            return note
        ins = img.disasm(va, cnt)
        if not ins:
            return "0x%x 디코드 실패 — 이미지 %s 에 매핑 안 됨?" % (va, imgname)
        meta = TARGET["_imeta"].get(imgname, {})
        head = ("[%s / image=%s] @ 0x%x  (%d insn)\n빌드: %s ts=%s"
                % (os.path.basename(img.path), imgname, va, len(ins),
                   meta.get("guid", "?")[:16] or "?", meta.get("timestamp", "?")))
        if note:
            head += "\n" + note
        ledger.note_disasm("%s!%s" % (imgname, t))
        body = "\n".join("0x%x  %-20s %s %s" % (v, b.hex(), m, o) for v, b, m, o in ins)
        return _cap(head + "\n" + body +
                    "\n\n★ 이 이미지의 인용은 **`%s!0x…`** 로 태그하라. 태그 없으면 "
                    "측정 대상에 대고 검증되어 실패한다." % imgname)
    p = _pe()
    name, cva, lva, note = resolve(t, from_corpus=bool(a.get("from_corpus")))
    if p is None:
        return "binary 미지정 — 판정 근거(디스어셈블)를 만들 수 없다. corpus 모드에서는 확정 불가."
    if lva is None:
        # 재도출 실패. 코퍼스 좌표를 측정 빌드에 그대로 대고 디코드하면 **쓰레기**가 나온다.
        # 조용히 쓰레기를 주느니 여기서 멈춘다.
        return (note or f"'{t}' 해결 실패") + (
            "\n\n(이 주소로 그냥 디코드하지 않는다 — 좌표가 다른 빌드의 것이라 "
            "나오는 명령은 의미가 없다. find_bytes 로 먼저 이 빌드의 주소를 찾아라.)")
    ins = p.disasm(lva, cnt)
    if not ins:
        return f"0x{lva:x} 디코드 실패 (매핑 안 됨?)"
    head = f"[{os.path.basename(p.path)}] {name or ''} @ 0x{lva:x}  ({len(ins)} insn)"
    if note:
        head += "\n" + note
    ledger.note_disasm(name or t)
    ledger.note_disasm(f"0x{lva:x}")
    body = "\n".join("0x%x  %-20s %s %s" % (v, b.hex(), m, o) for v, b, m, o in ins)
    return _cap(head + "\n" + body +
                "\n\n★ 인용은 위 주소 그대로 하라. verdict 의 evidence 는 기계 검증된다.")


def _t_grep(a):
    # ★ _t_grep 는 디컴파일 본문(.c) 을 정규식으로 훑는다. IDA 인덱스에는 본문이 없다
    #   (`_IdaIndex.text == ""`). `_ix()` 를 그대로 쓰면 **빈 문자열을 훑어 항상 0건**을
    #   돌려준다 — globmerger 회차에서 실제로 그랬다(바이너리에 18건 있는 DbgPrintEx 가 0건).
    #   에이전트가 양성 대조로 잡아서 결과를 안 썼지만, 그건 운이었다. 여기서 막는다.
    ix = TARGET["_ix"]
    if ix is None or not getattr(ix, "text", ""):
        return _noix("corpus_grep 은 **디컴파일 본문(.c)** 이 있어야 한다. "
                     "IDA 인덱스에는 본문이 없다 — 0건을 부재의 근거로 쓰지 마라. "
                     "바이너리 문자열/상수는 find_bytes 로, 호출관계는 callers/callees 로 봐라")
    try:
        rx = re.compile(a["pattern"], re.M)
    except re.error as e:
        return f"정규식 오류: {e}"
    txt = ix.text
    out, seen = [], 0
    lim = int(a.get("limit") or 60)
    for m in rx.finditer(txt):
        seen += 1
        if len(out) >= lim:
            continue
        fn = ix.func_at_offset(m.start()) if hasattr(ix, "func_at_offset") else None
        if fn is None:
            fn = "?"
            for va, n in ix.byva:
                if ix.fn[n][1] <= m.start():
                    fn = n
                else:
                    break
        line = txt[txt.rfind("\n", 0, m.start()) + 1: txt.find("\n", m.end())]
        out.append(f"  {fn}: {line.strip()[:150]}")
    grouped = {}
    for o in out:
        k = o.split(":")[0].strip()
        grouped[k] = grouped.get(k, 0) + 1
    return (f"'{a['pattern']}' 매치 {seen}건 (표시 {len(out)}, 함수 {len(grouped)}개)\n" +
            "\n".join(out) +
            ("\n\n★ 0건이면 '없다' 가 아니라 '이 표현으로는 안 잡힌다' 다. 동작 기반으로 다시 물어라."
             if seen == 0 else ""))


# ── 디스패치 표 (IOCTL census 기법) ──────────────────────────
_METHOD = {0: "BUFFERED", 1: "IN_DIRECT", 2: "OUT_DIRECT", 3: "NEITHER"}
_ACCESS = {0: "ANY", 1: "READ", 2: "WRITE", 3: "READ|WRITE"}


def _locate_table(p, probe_code, stride, code_off):
    """알려진 IOCTL 코드 하나를 앵커로 디스패치 표의 시작을 찾는다.

    판정 기준(전부 결정론):
      ① 그 4바이트가 데이터/읽기전용 섹션에 있다
      ② 앞뒤로 stride 간격의 이웃도 **CTL_CODE 형태**다 (driver.plausible_ctl)
      ③ 그런 이웃이 3개 이상 연속
    한 조건이라도 못 채우면 후보로 내놓지 않는다 — 추측하느니 답을 안 주는 게 낫다.
    """
    import driver as DRV
    need = struct.pack("<I", probe_code & 0xFFFFFFFF)
    out = []
    for s_ in p.secs:
        beg, o = p.base + s_["va"], s_["raw"]
        n = min(s_["rsize"], max(0, len(p.d) - o))
        start = 0
        while True:
            j = p.d.find(need, o + start, o + n)
            if j < 0:
                break
            start = (j - o) + 1
            hit_va = beg + (j - o) - code_off
            # 이웃 검사
            run, first = 0, hit_va
            for k in range(1, 40):
                d = p.read(hit_va - k * stride + code_off, 4)
                if not d:
                    break
                v = int.from_bytes(d, "little")
                if not DRV.plausible_ctl(v):
                    break
                run += 1
                first = hit_va - k * stride
            fwd = 0
            for k in range(1, 256):
                d = p.read(hit_va + k * stride + code_off, 4)
                if not d:
                    break
                v = int.from_bytes(d, "little")
                if not DRV.plausible_ctl(v):
                    break
                fwd += 1
            if run + fwd >= 3:
                out.append((first, "[%s] 앵커 0x%X → 표 시작 0x%X (뒤로 %d, 앞으로 %d 엔트리 연속)"
                            % (s_["name"], hit_va, first, run, fwd)))
    out.sort(key=lambda t: -len(t[1]))
    return out


def _t_dispatch_table(a):
    """디스패치 표를 결정론으로 해독한다. CTL_CODE 필드 분해는 정의상 정확하다 —
    LLM 이 손으로 셀 일이 아니다. (Windows IOCTL 인구조사가 27k 드라이버에 이 방식을 썼고
    독립 디스어셈블 대조 272/272 정확했다.)"""
    p = _pe()
    ix = _ix()
    if not p:
        return "binary 미지정."
    stride = int(a.get("stride") or 24)
    # ★ probe= : 알려진 IOCTL 코드 하나로 표를 **찾아준다**. 지금까지는 표 VA 를 손으로
    # 받아야 했고(driver.py 주석에 그 한계가 적혀 있다), A-13 에서는 authz_reach.py 가
    # 따로 이 일을 했다. 결정론이므로 하네스가 해야 한다.
    if a.get("va") in (None, "", 0) and a.get("probe") not in (None, ""):
        pr = a["probe"]
        pr = int(pr, 16) if isinstance(pr, str) and not pr.startswith("0x") else int(str(pr), 0)
        found = _locate_table(p, pr, stride, int(a.get("code_off") or 0))
        if not found:
            return ("probe=0x%X 로 stride=%d 짜리 표를 못 찾았다. stride 를 바꿔보거나 "
                    "code_off 를 주어라. (표는 code 필드가 stride 간격으로 반복되고 "
                    "이웃도 CTL_CODE 형태여야 한다)" % (pr, stride))
        va, why = found[0]
        if len(found) > 1:
            why += "  ⚠ 후보 %d개 중 첫째 — 나머지: %s" % (
                len(found), ", ".join("0x%X" % v for v, _w in found[1:4]))
        a = dict(a); a["va"] = va
    va = int(a["va"], 16) if isinstance(a["va"], str) else int(a["va"])
    count = int(a.get("count") or 64)
    code_off = int(a.get("code_off") or 0)
    hoffs = a.get("handler_offs") or [8, 16]
    if isinstance(hoffs, str):
        hoffs = [int(x, 0) for x in re.split(r'[,\s]+', hoffs) if x]
    name_of = {}
    if ix:
        # 측정 빌드 VA → 이름. 코퍼스 빌드가 다르면 역방향 재배치가 필요하다.
        for cva, n in ix.byva:
            name_of[cva] = n
    def nm(x):
        if not x:
            return "-"
        if x in name_of:
            return name_of[x]
        if TARGET["_alt"] is not None:
            back, how = PEmod.relocate_escalating(p, TARGET["_alt"], x)
            if back in name_of:
                return name_of[back] + ("" if how == "same" else f" (←0x{back:x})")
        return "0x%x" % x
    L = [f"dispatch table @ 0x{va:x}  stride={stride} count={count}",
         "idx  code        devtype func  method     access  " + "  ".join(f"h@+{h}" for h in hoffs),
         "-" * 130]
    live = 0
    for i in range(count):
        d = p.read(va + i * stride, stride)
        if d is None or len(d) < stride:
            L.append(f"{i:<4} (매핑 밖)"); continue
        code = int.from_bytes(d[code_off:code_off + 4], "little")
        hs = [int.from_bytes(d[h:h + 8], "little") for h in hoffs]
        if not code and not any(hs):
            L.append(f"{i:<4} (empty)"); continue
        live += 1
        L.append("%-4d 0x%08X  0x%04X  %-5d %-10s %-7s %s" %
                 (i, code, (code >> 16) & 0xFFFF, (code >> 2) & 0xFFF,
                  _METHOD.get(code & 3, "?"), _ACCESS.get((code >> 14) & 3, "?"),
                  "  ".join(nm(h) for h in hs)))
    L += ["-" * 130, f"live {live} / {count}",
          "★ 이 표가 곧 전수 표다. surface(action='add') 로 그대로 등재하라 — "
          "분석 못 한 항목은 미분석으로 남기고 빼지 마라."]
    return _cap("\n".join(L))



# ── 전 실행섹션 임포트 xref ──────────────────────────────────
def _t_import_xref(a):
    """**전 실행섹션**에서 임포트 참조를 전수한다. `.text` 만 보는 습관을 도구가 없앤다.

    실제 실패: ipt.sys 에서 모델이 "SeSinglePrivilegeCheck 는 23개 .text 임포트 호출 중에
    없다"고 적고 킬 조건을 닫지 못했다. **호출은 PAGE 에 있었다** (0x14000CC59).
    그 이미지는 .text 12KB / PAGE 32KB 이고 **인가 호출 5건이 전부 PAGE 에 있다** —
    .text 만 보면 인가가 0으로 보인다.
    """
    p = _pe()
    if not p:
        return "binary 미지정."
    want = a.get("names")
    if want in (None, "", "authz"):
        want, desc = xref.AUTHZ, "AUTHZ 프리셋(권한·토큰·SD 관련)"
    elif want == "probe":
        want, desc = xref.PROBE, "PROBE 프리셋(유저 포인터 검증)"
    elif want == "all":
        want, desc = None, "전체 임포트"
    else:
        want = [x.strip() for x in str(want).split(",") if x.strip()]
        desc = "필터=" + ",".join(want)
    try:
        hits, cov, names = xref.sweep(p, want)
    except Exception as e:
        return "xref 실패: %s" % e
    ledger.record_xref(desc, [c["name"] for c in cov], sorted(set(names.values())), len(hits))
    return xref.render(hits, cov, names, desc) + (
        "\n\n★ 이 결과는 **직접 참조만** 본다. 함수포인터·vtable·DPC 콜백 경유는 안 보인다 — "
        "부재를 확정하기 전에 그 이미지의 `lea reg, [rip+X]` 로 함수 주소를 잡는 곳도 확인하라.")


def _t_authz_reach(a):
    """핸들러에서 **인가 API 에 도달하는가** — 호출그래프 BFS. 전 실행섹션.

    A-13(http.sys ClientSession)의 핵심 측정이 이것이었다: 클라이언트 IOCTL 20개 전부
    인가 API 0건, 서버측 대조군에서는 검출. 그 도구가 window_kernel 전용 스크립트로만
    있었다 — 하네스로 옮겨 일반화했다.

    ★ controls= 없이 나온 '0건'은 근거가 아니다. 인가가 있는 것이 알려진 핸들러를
    같이 넣어라. 대조군에서도 0건이면 분석기가 고장난 것이다.
    """
    p = _pe()
    if not p:
        return "binary 미지정."
    def _vas(x):
        if not x:
            return []
        return [int(v, 0) for v in re.split(r'[,\s]+', str(x)) if v]
    tg, ct = _vas(a.get("targets") or a.get("va")), _vas(a.get("controls"))
    if not tg:
        return "targets= 에 핸들러 VA 를 (쉼표로) 주어라. dispatch_table 이 그 목록을 준다."
    apis = a.get("apis")
    apis = tuple(x.strip() for x in str(apis).split(",")) if apis else authz.AUTHZ
    try:
        res = authz.audit(p, tg, ct, apis=apis, depth=int(a.get("depth") or 6))
    except Exception as e:
        return "authz 실패: %s" % e
    if res.get("valid"):
        ledger.record_xref("authz_reach 양성대조 통과", ["<callgraph>"], list(apis)[:20],
                           sum(len(v.get("found", {})) for v in res["targets"].values()))
    return authz.render(res) + (
        "\n\n한계: **직접 call 만** 추적한다(간접·vtable·DPC 콜백 미추적). 깊이 %d. "
        "import 이름 기반. 이 세 가지를 리포트에 같이 적어라." % int(a.get("depth") or 6))


# ── 바이트/명령 검색 ─────────────────────────────────────────
def _t_find_bytes(a):
    """측정 빌드의 .text 에서 바이트 패턴을 찾는다. `??` 는 와일드카드.

    **재배치가 실패했을 때의 정답 경로다.** 코드 시그니처 재배치는 재컴파일을 따라가지 못한다 —
    레지스터 할당과 스택 슬롯만 바뀌어도 바이트가 전부 달라진다 (실제로 8875→라이브에서
    UlPrepareParsedHeaderRangeResponse 가 그랬다: 명령 순서는 같은데 r13→rax, [rbp-0x21]→[rbp-0x31]).
    그럴 때 사람이 하는 일은 **변하지 않는 상수**로 다시 찾는 것이다 —
    구조체 오프셋 + 즉치 쌍은 재컴파일을 넘어 살아남는다.
    예: cmp dword [r+0x2d4], 0x0FFFFFFF → hex='d4020000ffffff0f'
    """
    _imgn = str(a.get("image") or "").strip().lower()
    if _imgn not in MAIN_ALIASES:
        p = image_of(_imgn)
        if p is None:
            return "보조 이미지 %r 미등록. images(action='list')." % _imgn
    else:
        p = _pe()
    if not p:
        return "binary 미지정."
    pat = re.sub(r'[\s_]', '', a.get("hex", ""))
    if not pat or len(pat) % 2 or not re.fullmatch(r'[0-9a-fA-F?]+', pat):
        return "hex= 에 바이트 패턴을 주어라 (짝수 길이, `??` 는 와일드카드)."
    pairs = [pat[i:i + 2] for i in range(0, len(pat), 2)]
    fixed = [(i, int(b, 16)) for i, b in enumerate(pairs) if b != "??"]
    if not fixed:
        return "전부 와일드카드다."
    secs = [s for s in p.secs if s["chars"] & 0x20000000] if a.get("code_only", 1) else p.secs
    out, total = [], 0
    lim = int(a.get("limit") or 40)
    ix = _ix()
    for s in secs:
        blob = p.d[s["raw"]:s["raw"] + s["rsize"]]
        base = p.base + s["va"]
        anchor_i, anchor_b = fixed[0]
        needle = bytes(b for _i, b in fixed[:1])
        i = 0
        while True:
            i = blob.find(needle, i)
            if i < 0:
                break
            st = i - anchor_i
            if st >= 0 and all(st + k < len(blob) and blob[st + k] == v for k, v in fixed):
                total += 1
                if len(out) < lim:
                    va = base + st
                    # 매치는 보통 명령 **중간**(변위/즉치)에 걸린다. 그 바이트를 포함하는
                    # 명령의 시작을 찾아 올라간다 — 안 그러면 늘 "디코드 실패" 가 뜬다.
                    mlen = len(pairs)
                    ins, iva = p.disasm(va, 1), va
                    best = None
                    for back in range(0, 16):
                        cand = p.disasm(va - back, 1)
                        if not cand:
                            continue
                        s0, e0 = cand[0][0], cand[0][0] + len(cand[0][1])
                        if s0 <= va and e0 >= va + mlen:      # 매치 전체를 덮는 명령
                            best = (cand, va - back)
                            break
                    if best:
                        ins, iva = best
                    fn = ""
                    if ix and TARGET["_alt"] is not None:
                        b2, _ = PEmod.relocate_escalating(p, TARGET["_alt"], iva)
                        if b2:
                            fn = ix.func_at(b2) or ""
                    elif ix:
                        fn = ix.func_at(iva) or ""
                    out.append("  0x%x%s  %-40s %s" % (
                        iva, ("(+%d)" % (va - iva)) if iva != va else "    ",
                        (ins[0][2] + " " + ins[0][3])[:39] if ins else "(디코드 실패)", fn))
            i += 1
    return (f"'{pat}' {total}건 (표시 {len(out)}, 섹션 {[s['name'] for s in secs]})\n" +
            "\n".join(out) +
            ("\n\n★ 0건이면 이 빌드에 그 형태가 없다는 뜻이다. 상수를 줄여 다시 찾아라 "
             "(구조체 오프셋만, 또는 즉치만)." if total == 0 else
             "\n\n★ 함수명은 대조 빌드로 역추적한 것이라 재컴파일된 함수에서는 빌 수 있다."))


# ── 앵커 ─────────────────────────────────────────────────────
def _t_anchor(a):
    p = _pe()
    if not p:
        return "binary 미지정 — 앵커 검증 불가."
    txt = a.get("cites") or ""
    if a.get("relocate"):
        alt = TARGET["_alt"]
        if not alt:
            return "relocate 하려면 대조 빌드(ALT)가 필요하다."
        out = []
        for m in re.finditer(r'0x[0-9a-fA-F]{6,16}', a["relocate"]):
            v = int(m.group(0), 16)
            nv, how = PEmod.relocate_escalating(alt, p, v)
            out.append(f"  0x{v:x} → " + (f"0x{nv:x} ({how})" if nv else f"미발견 ({how})"))
        return "대조 빌드 → 측정 빌드 재배치:\n" + "\n".join(out)
    res, summ = evidence.check(p, txt, alt=TARGET["_alt"], images=images_all())
    return evidence.render(res, summ)


# ── 노트 (컨텍스트 밖 체크포인트) ────────────────────────────
def _t_priorart(a):
    """선행연구 조사 결과를 원장에 남긴다. 확정 게이트가 이 기록을 요구한다.

    이 하네스는 네트워크가 없다 — 검색은 **네가 가진 지식과 사용자가 준 자료**로 하고,
    무엇을 근거로 '새롭다/알려졌다'고 판단했는지 여기에 적어라. 모르면 모른다고 적어라.
    '조사 안 함'과 '조사했는데 없음'은 완전히 다른 값이다.
    """
    what = a.get("what") or ""
    if not what:
        return ("what= 에 **무엇을 조사했는지** 적어라 (디바이스 이름 / IOCTL 코드 / 핸들러명). "
                "where= 는 어디서 찾았는지, result= 는 무엇이 나왔는지.\n"
                "axis= 는 셋 중 하나다: device | ioctl | symbol. "
                "축이 없는 기록은 확정 게이트가 세지 않는다.")
    return ledger.record_priorart(what, a.get("where") or "(미기재)",
                                  a.get("result") or "(결과 미기재 — 이건 조사한 게 아니다)",
                                  axis=a.get("axis") or "")


# ★ 2026-09-05 — **노트는 `work/notes/` 에만 있었고, 그 디렉터리는 "지워도 되는 곳"이다**
#   (`runlog.py` 첫 주석: *"work/ 는 … 지우고 싶으면 `rm -rf work/*`"*).
#   실측 아침: 노트 **562개 · 3.1MB**. 그 안에 트랙 노트가 "full detail in note X" 로 가리키는
#   근거가 전부 들어 있고, `reports/reopen-shortlist.md` 도 그걸 참조한다.
#   ⇒ 안내대로 지우면 **추림 문서가 통째로 죽은 포인터가 된다.**
#   transcript 에 이미 같은 처리를 했다(`runlog.ARCHIVE_DIR`). 노트도 같이 보존한다.
NOTES_ARCHIVE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports", "notes")


def _note_archive(key, body):
    """`reports/notes/` 에 사본을 남긴다. 실패해도 원래 쓰기를 막지 않는다."""
    try:
        os.makedirs(NOTES_ARCHIVE, exist_ok=True)
        with open(os.path.join(NOTES_ARCHIVE, key + ".md"), "w", encoding="utf-8") as f:
            f.write(body)
    except OSError:
        pass


# ★ 2026-09-25 — **산문 인계가 적대자를 덮는 구멍을 막는다.**
#   실제 사건(S166-HANDOFF): 인터로게이터가 TDIDRAIN 기각 4건을 전부 깨고(broke:true)
#   07:06 에 "라벨을 다섯 번째로 고쳐쓰지 마라 — 빠진 건 관측이다, needs-measurement 로
#   봉하라"고 에스컬레이트했다. 그런데 07:08 손글씨 인계 노트가 "THE TDIDRAIN FAMILY IS
#   CLOSED. Do NOT reopen." 로 그 판정을 정면으로 뒤집었고, 다음 세션이 그 산문을 믿어
#   "음성"으로 보고했다. 게이트는 판정만 검사하지 산문 노트는 아무도 검사하지 않는다
#   (memory: prose-cannot-carry-a-predicate · gates-audit-verdicts-not-reasoning ·
#    broke-rejections-are-open-not-negative). 노트는 GOAL 과 같은 계열 — 적대자가 안 보는 표면.
#   ⇒ 막지 않고(헛돌기 금지, predicate-cannot-ask) **살아있는 배너**를 붙인다. 접지는
#     graveyard_trust() 를 매 호출 재도출 — 낡지 않고(raw-material-goes-stale), 이미 쓰인
#     노트도 잡고, 원문은 손대지 않는다.
_CLOSURE_RX = re.compile(
    r'\bCLOSED\b|do\s*not\s*re\s*open|is\s+closed|clean\s+negative'
    r'|no\s+(surviving\s+)?variant|닫혔|닫힘|재개\s*금지|서지\s*않|진짜\s*음성|clean\b.*negative',
    re.I)


def _broke_doubt_banner(text):
    """노트 본문이 '서지 않는 음성'(broke/reopened)을 CLOSED 로 주장하면 경고 배너를 만든다.
    두 조건이 모두 참일 때만: (1) 종결-어법이 있고 (2) 그 broke/reopened 기각을 id 토큰이나
    앵커 VA 로 참조한다. 접지는 ledger.graveyard_trust() — 매 호출 현재 상태에서 재도출한다."""
    if not text or not _CLOSURE_RX.search(text):
        return ""
    try:
        _, rows, _ = ledger.graveyard_trust(limit=10 ** 6)   # broke + reopened 행만 반환
    except Exception:
        return ""
    # 잘리지 않은 전체 묘지 엔트리(target/claim/reason)에서 앵커를 뽑는다 — 행의 target[:90] 은
    # 앵커를 잃는다. 그리고 가족 접두사(id 의 첫 토큰)로도 매칭한다 — 인계 산문은 개별 id 대신
    # "TDIDRAIN FAMILY IS CLOSED" 처럼 가족을 부른다.
    try:
        _gy = {str(g.get("id")): g for g in (ledger.STATE.get("graveyard") or [])}
    except Exception:
        _gy = {}
    low = text.lower()
    hits = []
    for r in rows or []:
        gid = str(r.get("id") or "")
        if not gid:
            continue
        g = _gy.get(gid) or {}
        blob = " ".join(str(g.get(k) or "") for k in ("target", "claim", "reason")) or str(r.get("target") or "")
        anchors = set(re.findall(r'0x[0-9a-fA-F]{6,16}', blob.lower()))
        fam = re.split(r'[-_]', gid)[0]                       # 가족 접두사
        ref = (gid.lower() in low
               or (len(fam) >= 4 and not fam.isdigit() and fam.lower() in low)
               or any(a in low for a in anchors))
        if ref:
            hits.append((gid, r.get("grade"), r.get("klass")))
    if not hits:
        return ""
    L = ["⚠️ HARNESS — 이 노트의 CLOSED/음성 주장은 서지 않는다 (매 읽기 재도출):"]
    for gid, grade, klass in hits[:8]:
        tag = "심문자가 깼다(broke)" if grade == "broke" else "재개됨(reopened) — 철회된 음성"
        L.append("   · %s [%s] %s — needs-measurement/재심 대상이지 '닫힘'이 아니다."
                 % (gid, klass or "?", tag))
    L.append("   broke:true 기각은 적대자가 이미 반박했다. verdict(action='lead'|'reaudit') 로 "
             "처리하고, 측정으로 해소하기 전엔 인계에서 CLOSED 로 쓰지 마라.")
    L.append("   (memory: broke-rejections-are-open-not-negative)")
    return "\n".join(L) + "\n\n"


def _t_note(a):
    """컨텍스트가 압축돼도 살아남는 기록. 긴 세션에서 findings 가 조용히 사라지는 것을 막는다."""
    d = os.path.join(config.WORK_DIR, "notes")
    os.makedirs(d, exist_ok=True)
    key = re.sub(r'[^A-Za-z0-9._-]', '_', a.get("key", "misc"))[:60]
    p = os.path.join(d, key + ".md")
    if a.get("action") == "read":
        if not os.path.exists(p):
            avail = sorted(x[:-3] for x in os.listdir(d)) if os.path.isdir(d) else []
            return f"'{key}' 없음. 있는 것: {', '.join(avail) or '(없음)'}"
        _body = open(p, encoding="utf-8").read()
        return _cap(_broke_doubt_banner(_body) + _body)      # 배너가 잘리지 않게 맨 앞
    with open(p, "a", encoding="utf-8") as f:
        f.write(a.get("text", "") + "\n")
    # ★ 보존 사본 — work/ 는 지워도 되는 곳이다 (위 NOTES_ARCHIVE 주석 참조)
    try:
        _note_archive(key, open(p, encoding="utf-8").read())
    except OSError:
        pass
    _warn = _broke_doubt_banner(a.get("text", ""))            # 저자에게 즉시 경고 (막지는 않음)
    tail = ("\n\n" + _warn) if _warn else ""
    return f"note[{key}] 에 {len(a.get('text',''))} 자 추가. 컨텍스트 밖에 남는다." + tail


# ── IDA (있으면) ─────────────────────────────────────────────
def _winpath(p):
    if p.startswith("/mnt/"):
        return p[5].upper() + ":" + p[6:].replace("/", "\\")
    try:
        return subprocess.run(["wslpath", "-w", p], capture_output=True,
                              text=True, timeout=10).stdout.strip() or p
    except Exception:
        return p


def _ida_call(op, target):
    if not (config.USE_IDA and TARGET["binary"] and os.path.exists(config.IDAT)):
        return None
    with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as f:
        outp = f.name
    env = dict(os.environ, IDA_CMD=json.dumps({"op": op, "args": {"target": target}}),
               IDA_OUT=_winpath(outp))
    # ★ WSL → Windows 프로세스로 환경변수는 **자동으로 안 넘어간다.** WSLENV 에 이름을
    #   올린 것만 건너간다. 이게 없으면 ida_worker 가 IDA_CMD 를 못 받아 overview 로
    #   폴백하다 os.environ["IDA_OUT"] 에서 KeyError 로 죽고, 출력 파일이 안 생겨
    #   `_ida_call` 이 "IDA 실패: Expecting value" 를 돌려준다 —
    #   즉 **IDA 가 설치돼 있어도 항상 '불가'로 보이는 조용한 음성**이었다.
    #   (경로는 _winpath 로 이미 Windows 형식이므로 /p 플래그를 붙이면 안 된다.)
    env["WSLENV"] = ":".join(x for x in (env.get("WSLENV", ""), "IDA_CMD", "IDA_OUT") if x)
    cmd = ([config.WINE] if config.WINE else []) + [
        config.IDAT, "-A", "-S" + _winpath(config.IDA_WORKER), _winpath(TARGET["binary"])]
    # ★ 낡은 unpacked DB 가 남아 있으면 IDA 는 rc=4 로 즉시 죽고 출력이 안 나온다.
    #   예전엔 그걸 "IDA 실패: Expecting value" 로만 보고해서 원인이 안 보였다.
    #   한 번은 정리하고 재시도한다 — 재시도도 실패하면 rc 를 그대로 보고한다.
    # ★ 기동을 **보이게** 한다. 첫 분석은 수십 초~IDA_TIMEOUT(기본 900s)이 걸리는데
    #   지금까지 그동안 stdout/stderr 이 완전 무음이라, 멎은 건지 도는 건지 구분이 안 됐다.
    #   (bench 가 코퍼스 없이 http.sys 를 물었을 때 실제로 이렇게 멎었다.)
    #   같은 실패 클래스가 §0-septies 에도 있었다 — 침묵이 원인을 덮는 것.
    def _run():
        sys.stderr.write("[ida] %s ← %s (최대 %ds)\n"
                         % (op, os.path.basename(TARGET["binary"]), config.IDA_TIMEOUT))
        sys.stderr.flush()
        t0 = time.time()
        pr = subprocess.run(cmd, capture_output=True, timeout=config.IDA_TIMEOUT, env=env)
        sys.stderr.write("[ida] %s rc=%d %.1fs\n" % (op, pr.returncode, time.time() - t0))
        sys.stderr.flush()
        try:
            with open(outp, encoding="utf-8", errors="replace") as f:
                return pr.returncode, json.load(f)
        except Exception as e:
            return pr.returncode, None if pr.returncode == 0 else e

    try:
        rc, res = _run()
        if isinstance(res, dict):
            return res
        stale = [TARGET["binary"] + e for e in (".id0", ".id1", ".id2", ".nam", ".til")
                 if os.path.exists(TARGET["binary"] + e)]
        if stale:
            for f in stale:
                try:
                    os.unlink(f)
                except OSError:
                    pass
            rc, res = _run()
            if isinstance(res, dict):
                return res
        return {"error": "IDA rc=%d, 출력 없음 (%s). 낡은 DB 정리 후에도 실패했다면 "
                         "`%s -A -S%s %s` 를 직접 돌려 원인을 봐라."
                         % (rc, res, config.IDAT, config.IDA_WORKER, TARGET["binary"])}
    except Exception as e:
        return {"error": f"IDA 실패: {e}"}
    finally:
        try:
            os.unlink(outp)
        except OSError:
            pass


# ── IDA 인덱스: 코퍼스(.c) 가 없을 때 항해 툴을 살린다 ────────────
# 왜 필요한가: 코퍼스 없이 돌면 find_funcs/func_at/callers/callees/callpath/census 가
# 전부 "corpus 미지정" 으로 죽었다. 그게 nightrun 의 기본 경로다 — 에이전트가 주소만
# 들고 더듬고 있었다. ida_worker 의 `index` op 한 번(≈30s, 이후 IDB 재사용 ≈3s)이면
# 함수표 + 직접호출 그래프가 다 나온다. 이름은 PDB 가 붙으면 실명으로 나온다.
class _IdaIndex(nav.Index):
    """nav.Index 와 **같은 인터페이스**. 메서드는 전부 물려받고 자료만 IDA 로 채운다.
    ⇒ 툴 함수들을 하나도 안 고쳐도 그대로 동작한다."""

    def __init__(self, data):
        # nav.Index.__init__ 는 .c 파일을 파싱한다. 여기선 부르지 않는다.
        self.path = "(IDA)"
        self.text = ""
        self.fn, self.byva = {}, []
        for f in data.get("functions") or []:
            n = f["name"]
            va = int(f["start"], 16)
            if n in self.fn:                      # 동명이인은 VA 로 구분 (nav 와 같은 규칙)
                n = "%s@%x" % (n, va)
            self.fn[n] = (va, 0, 0)               # body 오프셋은 안 쓴다 (body() 가 None)
            self.byva.append((va, n))
        self.byva.sort()
        _byva = {va: n for va, n in self.byva}
        self.out, self.inn = {}, {}
        for sva, dsts in (data.get("calls") or {}).items():
            a = _byva.get(int(sva, 16))
            if not a:
                continue
            for d in dsts:
                b = _byva.get(int(d, 16))
                if not b:
                    continue
                self.out.setdefault(a, []).append(b)
                self.inn.setdefault(b, []).append(a)

    def body(self, name):
        # 디컴파일 본문은 캐시가 없다 — _t_decompile 이 _ida_call('decompile') 로 간다.
        return None


def _ida_index():
    """IDA 함수표+호출그래프. 프로세스 안에서 1회, 디스크에도 캐시한다."""
    if TARGET.get("_iix") is not None:
        return TARGET["_iix"] or None
    b = TARGET["binary"]
    if not (b and config.USE_IDA and os.path.exists(config.IDAT)):
        TARGET["_iix"] = False
        return None
    try:
        st = os.stat(b)
        key = hashlib.sha1(("%s|%d|%d" % (b, st.st_size, int(st.st_mtime))).encode()).hexdigest()[:16]
        cp = os.path.join(config.WORK_DIR, "idaidx-%s.json" % key)
    except OSError:
        cp = None
    data = None
    if cp and os.path.exists(cp):
        try:
            data = json.load(open(cp, encoding="utf-8"))
        except Exception:
            data = None
    if data is None:
        r = _ida_call("index", None)
        if not r or r.get("error") or not r.get("functions"):
            TARGET["_iix"] = False
            return None
        data = r
        if cp:
            try:
                json.dump(data, open(cp, "w", encoding="utf-8"))
            except OSError:
                pass
    try:
        TARGET["_iix"] = _IdaIndex(data)
    except Exception:
        TARGET["_iix"] = False
        return None
    return TARGET["_iix"]



# ── 나머지 ───────────────────────────────────────────────────
def _t_surface(a):
    act = a.get("action")
    if act == "add":
        return ledger.surface_add(a.get("items") or [], a.get("kind", "ingress"),
                                  a.get("reach", "unknown"))
    if act == "incidental":
        # ★ **A 를 보다 B 를 발견**했을 때. 넓히기(무작정 등재)와 구분하기 위한 채널이다.
        #   이 세션 최고의 결함이 정확히 그렇게 나왔는데, 시드가 "새 표면 늘리지 마라"로
        #   그 경로를 벌주고 있었다. 표시해두면 분모 부풀리기 경고에서 빠지고 worklist 가 올린다.
        nm, fw = a.get("name"), a.get("found_while") or a.get("why") or ""
        if not nm:
            return "incidental 에는 name= 이 필요하다 (이미 add 로 등재한 표면 이름)."
        if len(fw) < 10:
            return ("`found_while=` 에 **무엇을 하다 발견했는지** 한 줄 적어라. "
                    "그게 이 표시의 근거다 — 그냥 등재한 것과 파다가 걸린 것을 가르는 것이 그 문장이다.")
        r = ledger.mark_incidental(nm, fw)
        if r is None:
            return "그런 표면이 없다: %r — surface(action='add') 로 먼저 등재하라." % nm
        return ("`%s` 를 **부수 발견**으로 표시했다 (하다가: %s)\n"
                "★ 이건 분모 부풀리기가 아니다. 실제 작업의 산물이므로 worklist 가 위로 올린다."
                % (nm, fw[:120]))
    if act == "race":
        return ledger.race_add(a.get("a", ""), a.get("b", ""), a.get("shared", ""),
                               a.get("why", ""), a.get("reach", "user-triggerable-async"))
    if act == "async":
        # 비동기 진입점 전수 — 경합 상대 풀. 여기 없는 것을 '없다'로 읽지 마라(후보 생성기).
        try:
            import async_entry as AE
            p_ = _pe()
            if p_ is None:
                return "binary 미지정."
            rs = AE.enumerate_async(p_)
            got = [r for r in rs if r.get("callback")]
            ix = _ix()
            nm = {cva: n for cva, n in ix.byva} if ix else {}
            L = ["등록 호출부 %d건 / 콜백 회수 %d건 (미회수는 레지스터·전역 경유일 수 있다)"
                 % (len(rs), len(got)), "이들은 reach='user-triggerable-async' 다 — "
                 "사용자가 **유발**하는 비동기 상대다(kernel-only 로 버리지 마라)."]
            seen = set()
            for r in got:
                if r["callback"] in seen:
                    continue
                seen.add(r["callback"])
                L.append("  0x%X  %-46s ← %s" % (r["callback"],
                         nm.get(r["callback"], "(무명)")[:46], r["registrar"]))
            return _cap("\n".join(L))
        except Exception as e:
            return "async 열거 실패: %s" % e
    if act == "reach":
        # ★ 2026-09-05: name 없이 부르면 **아직 안 정한 행을 열거한다.**
        #   완료 게이트가 unknown 행을 요구하는데 그걸 지목할 길이 없어
        #   두 회차가 약 150회 이름 탐침을 했다(S42 16 · S45 ~140).
        _nm = (a.get("name") or "").strip()
        if not _nm or _nm == "?":
            _rows, _n = ledger.reach_unknown(40)
            if not _n:
                return "reach='unknown' 인 행이 없다. 완료 게이트의 이 항목은 이미 만족됐다."
            return ("reach 를 아직 안 정한 행 %d개 (최대 40개 표시) — **이름을 그대로 복사해 써라**:\n"
                    % _n + "\n".join("  · " + r for r in _rows)
                    + "\n\nsurface(action='reach', name='<위 이름 그대로>', reach=..., why=...)")
        _r = ledger.surface_reach(_nm, a.get("reach", "unknown"), a.get("why", ""))
        if isinstance(_r, str) and "전수 표에 없다" in _r:
            _rows, _n = ledger.reach_unknown(20)
            if _n:
                _r += ("\n\n아직 안 정한 행 %d개는 이것들이다 (이름 추측하지 마라 — 복사해라):\n"
                       % _n + "\n".join("  · " + x for x in _rows))
        return _r
    if act == "set":
        return ledger.surface_set(a.get("name", "?"), a.get("status", "감사중"), a.get("why", ""))
    return ledger.status_block(None, None)


def _t_sink_gates(a):
    """싱크를 **지배하는** cmp/test/call 을 전수한다 — ASK(`dominates_only`) 의 **한 홉**.
    방향이 `dispatch`/`gates` 와 반대다: '내가 지목한 가드가 막는가'가 아니라
    '이 싱크를 막는 것이 **무엇이 더 있는가**'."""
    p = _pe()
    if p is None:
        return "binary 미지정."
    import cfg as CFG
    # ★ 2026-09-02 확정 버그: 예전엔 `a.get("target") or a.get("sink")` 였다.
    #   즉 target 이 있으면 **sink 를 통째로 버렸다.** 에이전트의 표준 호출은
    #     sink_gates(target='WcFsctlSetLayerRoot', sink='0x14002f31b')
    #   인데, 도구는 함수 **진입점**(0x14002F1D8)을 분석하고 그 답을 돌려줬다.
    #   실측: target+sink 호출의 답 == target 만 준 호출의 답 (sink 무시), 그리고
    #        sink 만 준 답과는 **다르다**. 함수 진입점을 지배하는 cmp 는 당연히 없으므로
    #        결과는 언제나 "가드 없음"이었다 — 즉 **조용히 다른 질문에 답했다.**
    #   ⇒ sink 를 **우선**한다. 둘이 다르면 어느 쪽을 썼는지 출력에 박는다.
    _sk = (str(a.get("sink") or "")).strip()
    _tg = (str(a.get("target") or "")).strip()
    name, cva, lva, note = resolve(_sk or _tg)
    if lva is None:
        return note or "싱크 주소를 해결하지 못했다."
    _amb = ""
    if _sk and _tg:
        _n2, _c2, _l2, _ = resolve(_tg)
        if _l2 is not None and _l2 != lva:
            _amb = ("\n\n※ `target=%s`(→0x%X) 와 `sink=%s`(→0x%X) 가 다르다. "
                    "**sink 를 썼다.** target 은 담는 함수를 가리키는 이름으로만 읽는다 — "
                    "명령어 단위 지배를 물으려면 sink= 가 맞는 인자다."
                    % (_tg, _l2, _sk, lva))
    try:
        r = CFG.sink_gates(p, lva, int(a.get("max_span") or 0x20000))
    except Exception as e:
        return "sink_gates 실패: %s" % e
    if not r:
        return ("싱크 0x%X 를 지배하는 cmp/test/call 을 못 찾았다. **이건 '가드 없음'이 아니다** — "
                "함수 밖(호출자)에서 검증할 수 있다. callers() 로 한 홉 더 올라가라." % lva) + _amb
    return _cap("\n".join(str(x) for x in (r if isinstance(r, list) else [r]))) + _amb


# ★ 하네스가 직접 관측한 마지막 프로브 결과. `_t_measure` 가 이걸 정본으로 쓴다.
_LAST_PROBE = {}
# ★ 2026-09-13 — kd 출력 보관함. `_LAST_PROBE` 와 같은 이유로 존재한다: 채점기가
#   **에이전트가 옮겨 적은 값**이 아니라 **하니스가 직접 본 출력**에서 채점할 수 있게.
#   `measure(action='before_after')` 가 여기서 전/후 값의 출처를 대조한다 —
#   찾으면 kd 접지(D형), 못 찾으면 `declared`(B형). 세탁을 막는 것이 요점이다.
_LAST_KD = {"v": []}
_LAST_KD_MAX = 8


_IL_SID = {
    "S-1-16-4096":  "Low",
    "S-1-16-8192":  "Medium",
    "S-1-16-12288": "High",
    "S-1-16-16384": "System",
}


def _principal_lines(r):
    """이 측정을 낸 **자격**을 결과에 적는다. 없으면 없다고 적는다.

    ★ 2026-09-06. 왜: 게스트 ioctl 채널은 vmrun 토큰(High+Administrators)으로 돈다.
      그 사실이 결과 어디에도 없어서, "저권한 principal 이 이 싱크에 도달한다"가
      **측정으로 뒷받침되지 않는데도** 쓰였고, 지휘자가 같은 항목을 22·19·15회째
      하니스 문제로 다시 신고하고 있었다. 기억에 맡기지 않는다 — 측정이 자기 자격을 들고 온다.
    ★ 결론을 처방하지 않는다. **이 결과가 무엇을 말할 수 있고 무엇을 못 말하는지**만 적는다.
    """
    pc = (r or {}).get("principal") or {}
    if pc.get("err"):
        return ["  ⚠ principal 읽기 실패: %s — 이 측정의 자격을 모른다. "
                "권한경계 주장에는 쓰지 마라." % str(pc["err"])[:120]]
    if not pc:
        return ["  ⚠ principal 칸이 없다 (옛 프로브). 이 측정이 어느 토큰에서 났는지 "
                "모른다 — 권한경계 주장에는 쓰지 마라."]
    sid = str(pc.get("il_sid") or "")
    out = ["  principal: %s · IL=%s · elevated=%s"
           % (pc.get("user"), _IL_SID.get(sid, sid or "unknown"), pc.get("elevated"))]
    if pc.get("elevated") or sid in ("S-1-16-12288", "S-1-16-16384"):
        out.append("  ★ **이 측정은 승격된 토큰에서 났다.** 도달성 자체는 이 결과로 말할 수 "
                   "있지만 **권한 경계는 말할 수 없다** — '저권한 principal 이 도달한다'는 "
                   "주장에는 비승격 컨텍스트가 따로 필요하다"
                   "(`schtasks /ru \"NT AUTHORITY\\LOCAL SERVICE\"`).")
    return out


def _t_ioctl(a):
    """**IOCTL 을 실제로 보낸다.** 하니스에 없던 조각 — `measure` 는 채점기지 실행기가 아니다.

    두 번(기본 0xCC / 0x55) 다른 채움값으로 보내 `measure(action='classify')` 가 요구하는
    모양을 그대로 낸다. 매 실행 **대조 3항**(NUL 열림 / PhysicalDrive0 err=5 / 없는장치 err=2)을
    같이 내고, 하나라도 어긋나면 **결과를 주지 않는다** — 고장난 프로브와 막힌 드라이버는
    결과가 같기 때문이다.

    ★ `where=` (2026-09-05 배선)
      `host`(기본) — 이 분석자 머신에 쏜다. **BSOD 나면 하니스·원장이 같이 죽는다.**
      `guest`      — 격리된 VMware 게스트에 쏜다(`vmprobe.py`). 터져도 스냅샷으로 복구된다.
                     같은 코드·같은 대조3항이 게스트 안에서 돈다 — 전송 수단만 다르다.
      **터질 수 있는 것을 시험할 때는 `guest` 를 써라.** 호스트에서 주저하다 실측을 안 하면
      정적 추정이 실측 없이 결론으로 굳는다.
    """
    _where = str(a.get("where") or "host").lower()
    _prin = str(a.get("principal") or "default").lower()
    if _prin not in ("default", "low"):
        return "principal 은 default | low 중 하나다 (받은 값: %r)" % _prin
    if _prin == "low" and _where not in ("guest", "vm"):
        return ("principal='low' 는 게스트에서만 된다 — 호스트 프로브에는 비승격 전송 수단이 "
                "없다. where='guest' 로 같이 지정하라.")
    if _where in ("guest", "vm"):
        import vmprobe as P
        _st = P.status()
        if _st != "ok":
            return ("게스트 실측 불가: %s\n"
                    "**이건 '결함 없음'이 아니라 미측정이다.** VM 전원/Tools/자격을 먼저 세워라."
                    % _st)
    else:
        import probe as P
    try:
        _kw = {"principal": _prin} if _where in ("guest", "vm") else {}
        # ★ 2026-09-08 — **`aux`/`fh` 를 넘긴다.** `probe.ioctl` 은 09-05 부터 둘 다 받고
        #   PowerShell 도 실제로 버퍼를 잡아 주소를 박는데, **이 전달부와 툴 스키마에만
        #   없어서** 분석가가 쓸 수 없었다. 그 결과 트랙 3개가 며칠째
        #   "the harness cannot place an interior pointer in the 0x188 request" 로 서 있었다
        #   (`S25-AXIS-mutation-authz-asymmetry` 0/5 · `class1-mask-delta` 2→3 보류 ·
        #    `per-class-authz`). 세 층이 되는데 위 두 층이 없던 전형적 미배선이다.
        _aux, _fh = a.get("aux") or None, a.get("fh") or None
        for _nm, _v, _req in (("aux", _aux, ("at", "hex")), ("fh", _fh, ("at", "path"))):
            if _v is None:
                continue
            if not isinstance(_v, (list, tuple)):
                return "%s 는 리스트여야 한다 (받은 값: %r)" % (_nm, type(_v).__name__)
            for _e in _v:
                if not isinstance(_e, dict) or any(k not in _e for k in _req):
                    return ("%s 의 각 항목은 %s 키를 가진 dict 여야 한다. 받은 것: %r\n"
                            "  aux=[{'at': <입력버퍼 내 포인터를 박을 오프셋>, "
                            "'hex': '<그 버퍼의 내용>', 'lenat': <선택: UNICODE_STRING "
                            "Length/MaximumLength 를 쓸 오프셋>}]\n"
                            "  fh =[{'at': <핸들을 박을 오프셋>, 'path': '<열 파일>', "
                            "'acc': <DesiredAccess>}]" % (_nm, "/".join(_req), _e))
        if _aux:
            _kw["aux"] = _aux
        if _fh:
            _kw["fh"] = _fh
        r = P.ioctl(a.get("device", ""), int(str(a.get("code")), 0),
                    a.get("input", ""), **_kw,
                    inlen=int(str(a["inlen"]), 0) if a.get("inlen") else None,
                    outlen=int(str(a.get("outlen") or 0), 0),
                    access=int(str(a.get("access") or 0xC0000000), 0),
                    fills=tuple(int(x) for x in (a.get("fills") or (0xCC, 0x55))))
    except P.ProbeRefused as e:
        return "프로브 거부: %s" % e
    except Exception as e:
        return "프로브 실패: %s: %s" % (type(e).__name__, e)
    L = ["[%s 에서 실행] 대조 3항 통과. open_err=%s" % (_where, r.get("open_err"))]
    L += _principal_lines(r)
    for run in r.get("runs") or []:
        if run.get("exc"):
            L.append("  fill=0x%02X  예외: %s" % (run.get("fill", 0), run["exc"]))
            continue
        L.append("  fill=0x%02X  ok=%s err=%s info=%s outhex=%s"
                 % (run.get("fill", 0), run.get("ok"), run.get("err"), run.get("info"),
                    (run.get("outhex") or "")[:160]))
    # ★ 2026-09-05: 하네스가 **직접 쏜 값**을 보관한다. 지금까지 `measure` 는 에이전트가
    #   옮겨 적은 hex 를 받았다(B형 = 에이전트 주장). 하네스는 쏘는데 채점기는 전언을 받는
    #   구조였고, 그래서 실측 등급이 접지되지 않았다. 보관해두고 `_t_measure` 가 대조한다.
    try:
        _runs = [x for x in (r.get("runs") or []) if not x.get("exc")]
        if len(_runs) >= 2:
            _LAST_PROBE["v"] = {
                "a": _runs[0].get("outhex") or "", "b": _runs[1].get("outhex") or "",
                "status": _runs[0].get("err"), "info": _runs[0].get("info"),
                "device": a.get("device"), "code": str(a.get("code")),
                # ★ 보관함이 principal 을 같이 나른다. 안 나르면 `measure(action=
                #   'classify')` 가 **하네스가 쏜 바이트를 채점하면서도** 자격을
                #   'unknown' 으로 적는다 — 있는 사실을 버리는 것이다.
                "principal": r.get("principal"), "principal_req": _prin,
                "t": __import__("time").strftime("%m-%d %H:%M")}
            # ★ 쏜 자리에서 바로 채점한다 — 관측이 채점 없이 버려지지 않게.
            try:
                import measure as M, ledger as _L
                _ha = bytes.fromhex((_runs[0].get("outhex") or "").replace(" ", ""))
                _hb = bytes.fromhex((_runs[1].get("outhex") or "").replace(" ", ""))
                _df = M.DualFill(_ha, _hb, status=_runs[0].get("err") or 0,
                                 info=_runs[0].get("info") or 0)
                _kh = M.kernel_ptrs(_ha)
                # ★ 이 경로는 `DeviceIoControl` 의 **Win32 GetLastError** 를 넘긴다.
                #   추론에 맡기지 말고 선언한다 — 5(ACCESS_DENIED)가 NTSTATUS 표의
                #   0xC0000022 에 안 걸려 인가층 거부가 `unmeasured` 로 새고 있었다.
                _g, _w = M.classify(_df, kernel_hits=_kh, space="win32",
                                    neither=(int(str(a.get("code")), 0) & 3) == 3)
                # ★ 2026-09-10 — **자격을 같이 싣는다.** `r["principal"]` 은 게스트
                #   토큰을 실제로 읽은 값이고 `principal='low'` 였다면
                #   `vmprobe.assert_low_principal()` 이 이미 검증했다(D형). 여기서
                #   안 넘기면 그 사실이 원장 경계에서 사라진다.
                _L.measure_record(a.get("target") or a.get("device") or "?", _g, _w,
                                  principal=_L.normalize_principal(
                                      r.get("principal"), req=_prin, src="probe"))
                L.append("\n★ 하네스가 **직접 채점했다**: 등급=%s — %s" % (_g, _w))
                L.append("   이 등급은 네가 옮겨 적은 값이 아니라 하네스가 관측한 바이트에서 나왔다. "
                         "원장에 실측으로 기록됐으니 basis='measured' 로 인용할 수 있다.")
            except Exception as _me:
                L.append("\n[자동 채점 실패: %s: %s] — 실패는 clean 이 아니다." 
                         % (type(_me).__name__, _me))
            L.append("\n[하네스가 관측한 값을 보관했다] measure(action='classify') 를 인자 없이 부르면 "
                     "그 값으로 채점한다. 직접 a=/b= 를 넣으면 보관값과 **대조**해서 어긋나면 알려준다.")
        else:
            # ★ 2026-09-08 — 채움이 하나뿐이라 **채점이 안 걸린 경우에도** 실행 사실은 남긴다.
            #   전에는 여기서 원장에 아무것도 안 남아, 실제로 쏜 회차가 "실측 0" 으로 보였다
            #   (09-08 런: 로그 `ioctl 0회`, transcript 에는 ioctl 4회).
            #   ★ 등급이 아니라 `trace` 다 — 단일 채움 판정은 여전히 금지다.
            import ledger as _Li
            _blob2 = "%s %s %s" % (a.get("target") or "", a.get("device") or "",
                                   a.get("code") or "")
            _Li.measure_record(a.get("target") or a.get("device") or "?", "trace",
                               "ioctl %s %s (단일 실행 — 채점 안 됨)"
                               % (a.get("device"), a.get("code")),
                               kind="trace", vas=_Li.measure_vas(_blob2),
                               principal=_Li.normalize_principal(
                                   r.get("principal"), req=_prin, src="probe"))
    except Exception:
        pass
    L.append("\n두 채움의 outhex 를 measure(action='classify', a=..., b=..., status=, info=) 에 넣어라. "
             "**단일 채움 판정은 금지다** — 커널이 그 채움값과 같은 바이트를 쓰면 미기록으로 오판한다.")
    return _cap("\n".join(L))


def _t_kd(a):
    """**게스트 커널을 심볼과 함께 세우고 묻는다** (KDNET / WinDbg kd).

    `ioctl` 은 쏘고 **결과**를 본다. 이건 **왜 그 결과가 나왔는가**를 묻는다 —
    `x nt!<sym>` / `dt` / `!object` / `bp` 로 커널 안을 직접 본다. debugStub(gdb) 축은
    심볼이 없어 페이지 스캔으로 베이스를 유도해야 했다. 여기서는 이름이 그대로 나온다.

    ★ 매 실행 **대조 2항**을 같이 낸다 — 있는 심볼(`nt!NtCreateFile`)은 반드시 해석되고
      없는 심볼은 반드시 해석되면 안 된다. 어긋나면 **결과를 주지 않는다**: 고장난 디버거와
      "그런 것 없음"은 결과가 같기 때문이다.
    ★ 끝나고 게스트가 **실제로 재개됐는지** 확인한다(`qd` 를 넣었다고 재개된 게 아니다).
    """
    import kdnet as K
    st = K.status()
    if not st.startswith("ok"):
        return ("KDNET 실측 불가: %s\n"
                "**이건 '결함 없음'이 아니라 미측정이다.**" % st)
    try:
        r = K.run(a.get("cmds", ""), timeout=(int(str(a["timeout"]), 0)
                                              if a.get("timeout") else None),
                  target=a.get("target"))
    except K.ProbeRefused as e:
        return "KDNET 거부: %s" % e
    except Exception as e:
        return "KDNET 실패: %s: %s" % (type(e).__name__, e)
    # ★ 2026-09-08 — **원장에 묶는다.** 이 툴의 설명은 `target=` 을 "so the ledger can
    #   bind it" 이라고 약속하는데 **배선이 없었다**(`built-but-never-wired`). 실측:
    #   09-08 런에서 분석가가 kd 로 기준선→처치→사후 3단을 대조군 3/3 으로 돌리고
    #   `basis=measured` 로 냈다가 "measurement record 없음"으로 거부당했고, 그 회차의
    #   유일한 등재 판정이 `basis=disassemble` 로 내려앉았다.
    #   ★ 등급은 매기지 않는다 — kd 는 이중채움 채점기가 아니다. `kind='trace'` 로 남긴다:
    #     "하네스가 이걸 실제로 실행했다"는 사실만이 이 기록의 내용이다.
    try:
        import ledger as _Lk
        _blob = "%s %s" % (a.get("cmds", ""), a.get("target") or "")
        _Lk.measure_record(a.get("target") or _Lk.STATE.get("target") or "?",
                           "trace", "kd: %s" % str(a.get("cmds", ""))[:200],
                           kind="trace", vas=_Lk.measure_vas(_blob),
                           # ★ kd 는 사용자 토큰이 아니라 커널 디버거다. 관측이긴 하지만
                           #   "어느 principal 이 도달한다"는 주장에는 쓸 수 없다.
                           principal="kd")
    except Exception:
        pass                       # 기록 실패가 관측 결과를 못 돌려주게 하면 안 된다
    # ★ 하니스가 **직접 본 출력**을 보관한다. `measure(action='before_after')` 가
    #   전/후 값의 출처를 여기에 대조해 D형/B형을 가른다.
    try:
        _LAST_KD["v"].append({"cmds": str(a.get("cmds", ""))[:400],
                              "output": str(r.get("output") or ""),
                              "target": a.get("target") or "",
                              "t": __import__("time").strftime("%m-%d %H:%M")})
        del _LAST_KD["v"][:-_LAST_KD_MAX]
    except Exception:
        pass
    # ★ 2026-09-13 — **채점으로 가는 길을 여기서 말한다.** 09-13 야간런 케이스 2 의
    #   분석가는 *"이걸 graded before/after 로 바꾸겠다"* 라고 적고도 그렇게 하지 못했다:
    #   `measure` 툴을 **ToolSearch 로 한 번도 불러오지 않아** 스키마가 없었던 것이다
    #   (그 회차 ToolSearch 목록에 measure 0회). 채점기를 만들어도 가는 길이 없으면
    #   관측은 `trace` 로만 남고, 그건 이 표적이 3개월간 `measures=0` 이던 이유와 같다.
    #   프롬프트는 회차 시작 1회뿐이라 늦다 — **툴 응답은 반드시 읽힌다.**
    _grade_hint = (
        "\n★ 이 관측을 **등급**으로 만들어라. 지금 이대로면 원장에 `trace`(실행 사실)로만 "
        "남고 어떤 판정도 뒷받침하지 못한다.\n"
        "   처치 **전/후**로 같은 자리를 읽었다면:\n"
        "     ToolSearch(query='select:mcp__vuln__measure')  ← 먼저 스키마를 불러와야 부를 수 있다\n"
        "     measure(action='before_after', target=…, before=…, after=…,\n"
        "             control_before=…, control_after=…)\n"
        "   **대조군(처치를 안 한 팔)이 없으면 등급은 `uncontrolled`** 다 — 값이 스스로 "
        "표류하는지 처치가 바꿨는지 구분되지 않기 때문이다. 값은 하니스가 자기 kd 출력과 "
        "대조해 출처를 판정한다(옮겨 적으면 `declared`).")
    return _cap("[게스트 커널에서 실행] 대조 2항 통과 · kernel_base=%s · 재개확인=%s\n%s%s"
                % (r.get("kernel_base"), r.get("resumed"),
                   r.get("output") or "(출력 없음)", _grade_hint))



def _t_kdscan(a):
    """**조건에 걸리는 표본 하나를 찾을 때까지 브레이크포인트를 살려 둔다.**

    `kd` 는 한 번 세우고 묻고 나온다. 이건 bp 를 걸고 **게스트를 다시 달리게 한 뒤**
    조건이 걸리는 순간을 기다린다. "이 언더플로우가 실제로 일어나는가" 처럼
    **분포를 묻는 질문**은 이 모양이 아니면 답이 안 나온다.

    ★ 2026-09-13 — `kd(cmds="bp …; g")` 로는 **절대 안 된다.** `kd` 는 뒤에 `qd` 를 붙이므로
      재개 즉시 detach 돼 bp 가 사라진다. 오류도 출력도 없는 **완전한 침묵**이라
      "측정했는데 0건"으로 보인다. 그날 ~10분짜리 회차 3개가 그렇게 사라졌다.
      그래서 `kd` 는 이제 최상위 `g` 를 **거부**하고 여기로 보낸다.

    ★★ 반환의 `verdict` 를 그대로 판정에 쓰지 마라 — 셋 중 하나다:
        hit         조건 표본을 찾았다 (덤프 인용 가능)
        no-match    조건 밖 표본을 봤는데 조건은 안 걸렸다 → **이것만이 음성이다**
        UNMEASURED  조건 밖 표본조차 0건 → 자극이 그 코드를 안 탔다. 음성이 아니다.
    """
    import kdbp as B
    import kdnet as K
    st = K.status()
    if not st.startswith("ok"):
        return ("KDNET 실측 불가: %s\n**이건 '결함 없음'이 아니라 미측정이다.**" % st)
    bp = (a.get("bp") or "").strip()
    dump = _kdq(a.get("dump"))
    if not bp or not dump:
        return "bp= 와 dump= 가 둘 다 필요하다. dump 는 조건에 걸렸을 때 찍을 kd 명령이다."

    act = None
    stim = (a.get("stim_ps1") or "").strip()
    if stim:
        def act():
            _kdscan_stim(stim, int(str(a.get("stim_timeout") or "240"), 0))

    try:
        r = B.scan(bp, dump, cond=(a.get("cond") or None), action=act,
                   ctrl_dump=(_kdq(a.get("ctrl_dump")) or None),
                   ctrl_n=int(str(a.get("ctrl_n") or "6"), 0),
                   wait_s=int(str(a.get("wait_s") or "240"), 0),
                   target=a.get("target"))
    except B.ProbeRefused as e:
        return "kdscan 거부: %s" % e
    except Exception as e:
        return "kdscan 실패: %s: %s" % (type(e).__name__, e)

    try:
        import ledger as _Lk
        _Lk.measure_record(a.get("target") or _Lk.STATE.get("target") or "?",
                           "trace", "kdscan[%s]: %s" % (r.get("verdict"), bp[:160]),
                           kind="trace", vas=_Lk.measure_vas("%s %s" % (bp, dump)),
                           principal="kd")
    except Exception:
        pass

    v = r.get("verdict")
    head = {"hit": "★ 조건 표본을 찾았다 — 덤프를 그대로 인용하라.",
            "no-match": "조건 밖 표본은 봤고 조건은 안 걸렸다. **이건 음성이다.**",
            "UNMEASURED": "★★ **미측정이다. 음성으로 쓰지 마라.**"}.get(v, v)
    return _cap(
        "[kdscan] verdict=%s  armed=%s  hit=%s  대조표본=%d  trigger=%s  정리=%s\n%s\n%s\n"
        "--- 조건 표본 ---\n%s\n--- 대조 표본(조건 밖) ---\n%s\n"
        "★ 대조 표본이 **판별식이 걸린 필드**에서 비자명한 값을 가졌는지 눈으로 확인하라. "
        "전부 자명한 값(0 등)이면 표적이 표본 공간에 없었던 것이고 그건 미측정이다."
        % (v, r.get("armed"), r.get("hit"), r.get("controls"), r.get("trigger_used"),
           r.get("clear_why") or r.get("cleared"), head, r.get("why") or "",
           r.get("hit_text") or "(없음)", r.get("control_text") or "(없음)"))



def _kdq(cmds):
    """kd bp 명령 **안에 들어가는** 문자열의 따옴표를 이스케이프한다.

    ★ 2026-09-14 — 이걸 안 해서 내가 만든 `kdscan` 이 첫 실사용에서 죽었다.
      `bp ADDR "…dump…"` 형태라 dump 안의 `"` 는 반드시 `\"` 여야 하는데,
      호출자가 `.printf "X=%x\n", …` 를 그대로 넘기면 kd 가
      `Malformed string in '.reload; x nt'` 로 **체인 전체를 버린다.**
      그러면 bp 도 안 걸리고 `qd` 도 안 돌아 **게스트가 정지한 채 남는다**(실제로 그랬다).
    ★ 인코딩·개행과 같은 원칙: **따옴표는 하니스가 책임진다.** 분석가 머리에 맡기면
      멀쩡한 회차가 조용히 사라진다.
    이미 `\"` 로 이스케이프된 것은 건드리지 않는다(이중 이스케이프 방지).
    """
    t = (cmds or "").strip()
    if not t:
        return t
    out, i = [], 0
    while i < len(t):
        c = t[i]
        if c == "\\" and i + 1 < len(t) and t[i + 1] == '"':
            out.append('\\"'); i += 2; continue
        if c == '"':
            out.append('\\"'); i += 1; continue
        out.append(c); i += 1
    return "".join(out)

def _kdscan_stim(ps1_body, timeout):
    """자극 스크립트를 게스트에 **ASCII+CRLF 로** 배달하고 `-File` 로 실행한다.

    ★ 인코딩·개행·전송 방식은 하니스가 책임진다. 09-13 에 이걸 분석가 머리에 맡겼더니
      UTF-8 BOM·LF·`-Command` 문자열 이스케이프로 세 번 조용히 죽었다.
    """
    import config as C
    import vmprobe as V
    body = ps1_body.replace("\r\n", "\n").replace("\n", "\r\n")
    body.encode("ascii")                       # ASCII 아니면 여기서 크게 터진다
    host = os.path.join(C.PROBE_DIR, "kdscan_stim.ps1")
    with open(host, "wb") as f:
        f.write(body.encode("ascii"))
    g = C.VM_PROBE_DIR_GUEST
    V._vmrun("createDirectoryInGuest", g, guest=True, timeout=60)
    rc, out = V._vmrun("CopyFileFromHostToGuest", C.PROBE_DIR_WIN + r"\kdscan_stim.ps1",
                       g + r"\kdscan_stim.ps1", guest=True, timeout=120)
    if rc != 0:
        raise RuntimeError("자극 배달 실패: %s" % str(out)[:160])
    V._vmrun("runProgramInGuest",
             r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
             g + r"\kdscan_stim.ps1", guest=True, timeout=timeout)


def _t_record(a):
    """**판정이 아닌 것을 원장에 담는다.** 09-14 에 다섯 건이 `reports/unrecordable/` 로 샜다.

    `kind='population'` — 집합 A / 집합 B / **교집합은 하니스가 센다** / 멤버별 상태.
        이 방법론이 말하는 「덜 적용됨」의 정확한 모양이고, 지금까지 담을 칸이 없었다.
        ★ 멤버 기본값은 `미분석` 이고 렌더링이 **항상 미분석 수를 같이 낸다** —
          부분 전수가 완전 전수로 읽히는 게 가장 비싼 거짓말이기 때문이다.
    `kind='posture'`    — 결함 주장 없이 **측정된 속성** (인가 상수, 전송 방식, 플래그).
        `body_read=0` 을 보존한다: "쟀지만 본문은 안 읽었다"가 이 기록의 내용이다.
    `kind='os_fact'`    — **표적 이미지에 안 묶이는** OS 경로 사실. 공유 파일에 간다.

    ★ 셋 다 **확정/기각을 담지 못한다.** 승격은 여전히 `verdict()` 를 거치고 거기 붙은
      게이트(basis·대조군·부채상한)를 그대로 받는다. 뒷문이 아니라 **재료 보존**이다.
    """
    import ledger as L
    k = (a.get("kind") or "").strip().lower()

    def _list(v):
        if v is None:
            return None
        if isinstance(v, (list, tuple)):
            return [str(x) for x in v]
        return [x.strip() for x in str(v).replace(",", " ").split() if x.strip()]

    if k == "population":
        nm = (a.get("name") or "").strip()
        if not nm:
            return "name= 이 필요하다. 이 인구가 어느 질문의 분모인지 이름으로 남겨라."
        ms = a.get("member_state")
        if isinstance(ms, str) and ms.strip():
            d = {}
            for tok in ms.replace(",", " ").split():
                if "=" in tok:
                    kk, vv = tok.split("=", 1); d[kk.strip()] = vv.strip()
            ms = d
        r = L.population(nm, query_a=a.get("query_a"), set_a=_list(a.get("set_a")),
                         query_b=a.get("query_b"), set_b=_list(a.get("set_b")),
                         differentiator=a.get("differentiator"), note=a.get("note") or "",
                         member_state=ms if isinstance(ms, dict) else None,
                         target=a.get("target"), invariant=a.get("invariant"))
        bad = r.get("_rejected")
        todo = sum(1 for v in r["members"].values() if v == "미분석")
        return _cap(
            "[인구 기록] `%s`\n%s\n%s"
            "\n★ 교집합은 **하니스가 셌다**(%d). 네가 선언한 값이 아니다.\n"
            "★ 미분석 %d건이 남아 있다. 그게 0 이 되기 전에는 이 전수를 「닫혔다」고 쓰지 마라.\n"
            "★ 멤버를 판정으로 올리려면 `verdict()` 를 따로 불러라 — 이 기록은 판정이 아니다."
            % (nm, L.population_render(nm),
               ("★ 어휘 밖 상태라 거부됨: %s (허용: %s)" % (", ".join(bad), "/".join(L.POP_MEMBER_STATES)))
               if bad else "",
               len(r["inter"]), todo))

    if k == "posture":
        if not a.get("subject") or not a.get("prop"):
            return "subject= 와 prop= 이 필요하다 (무엇의 어떤 속성을 쟀는가)."
        r = L.posture(a.get("subject"), a.get("prop"), a.get("value") or "",
                      a.get("derivation") or "", body_read=str(a.get("body_read") or "0") in ("1", "true", "True"),
                      anchors=_list(a.get("anchors")), note=a.get("note") or "",
                      target=a.get("target"))
        return _cap("[속성 기록] %s · %s = %s  (본문읽음=%s)\n출처: %s\n"
                    "★ 이건 판정이 아니다. 도달성/영향 주장으로 올리려면 `verdict()` 를 거쳐라 — "
                    "그때 `body_read=%s` 가 근거의 한계로 같이 읽힌다."
                    % (r["subject"], r["prop"], r["value"], r["body_read"], r["derivation"], r["body_read"]))

    if k == "os_fact":
        if not a.get("routine"):
            facts = L.os_fact()
            return _cap("[OS 경로 사실 %d건]\n%s" % (len(facts), L.osfact_render(n=12)))
        L.os_fact(routine=a.get("routine"), arm=a.get("arm"), validated=a.get("validated"),
                  omitted=a.get("omitted"), anchors=_list(a.get("anchors")),
                  applies_to=a.get("applies_to"), image=a.get("image") or "",
                  build=a.get("build") or "", note=a.get("note") or "")
        return _cap("[OS 경로 사실 등재]\n%s\n"
                    "★ 이건 **공유 파일**에 갔다 — 어느 표적에서 attach 하든 보인다. "
                    "다음 표적에서 재도출하지 마라." % L.osfact_render(n=6))

    return ("kind= 가 필요하다: 'population' | 'posture' | 'os_fact'.\n"
            "이 셋은 **판정이 아닌 것**을 담는 칸이다 — 판정은 `verdict()` 로 간다.")

def _t_measure(a):
    """실측 4게이트. **결과를 넣으면 등급이 나온다** — clean 은 조건을 다 만족해야만 나온다.

    ★ `measure.py` 는 2026-08-26 에 만들어졌는데 루프에 **한 번도 연결되지 않았다.**
      '실측했어?' 라는 질문에 답할 도구가 선반에 있었다.
    """
    import measure as M
    act = (a.get("action") or "classify").lower()
    # ★ D형 접지 (2026-09-05): 인자를 안 주면 **하네스가 직접 관측한 값**으로 채점한다.
    #   지금까지 `measure` 는 에이전트가 옮겨 적은 hex 를 받았다(B형 = 에이전트 주장).
    #   하네스는 `ioctl` 로 직접 쏘는데 채점기는 전언을 받는 구조였다.
    #   인자를 주면 **금지가 아니라 대조**한다 — 어긋나면 그 사실을 알린다.
    _obs = _LAST_PROBE.get("v")
    _mismatch = ""
    # ★ 2026-09-10 — 이 채점이 **하네스가 쏜 바이트**에서 났는지 **에이전트가 옮겨 적은
    #   hex**에서 났는지가 principal 의 접지를 가른다(D형 vs B형). 그 사실을 여기서 정한다.
    _from_probe = False
    if act == "classify" and _obs:
        if not a.get("a") and not a.get("b"):
            a = dict(a, a=_obs["a"], b=_obs["b"],
                     status=a.get("status") if a.get("status") is not None else _obs.get("status"),
                     info=a.get("info") if a.get("info") is not None else _obs.get("info"))
            _mismatch = "\n[하네스가 직접 관측한 값으로 채점했다 — 전언이 아니다]"
            _from_probe = True
        else:
            _same = all(re.sub(r"\s+", "", str(a.get(_k) or "")).lower()
                        == re.sub(r"\s+", "", str(_obs.get(_k) or "")).lower()
                        for _k in ("a", "b"))
            _from_probe = bool(_same and a.get("a") and a.get("b"))
            for _k in ("a", "b"):
                _typed = re.sub(r"\s+", "", str(a.get(_k) or "")).lower()
                _seen = re.sub(r"\s+", "", str(_obs.get(_k) or "")).lower()
                if _typed and _seen and _typed != _seen:
                    _mismatch += ("\n⚠ 네가 적은 %s 가 하네스 관측값과 다르다 "
                                  "(관측 %d바이트 / 입력 %d바이트). **관측값이 정본이다.**"
                                  % (_k, len(_seen)//2, len(_typed)//2))
    if act == "kernel_ptrs":
        try:
            buf = bytes.fromhex((a.get("buf") or "").replace(" ", ""))
        except ValueError:
            return "buf 는 hex 문자열이어야 한다."
        hits = M.kernel_ptrs(buf)
        return "커널 포인터 후보 %d개: %s" % (len(hits), [hex(x) for x in hits][:12])
    if act == "armed":
        # ★ 2026-09-06 수정. 이전 코드는 `str(M.armed(...))` 로 **데코레이터 객체의 repr**
        #   을 돌려줬다 — 원장에 아무것도 안 남고 성공처럼 보이는 무동작이었다(S47부터).
        #   `M.armed` 는 데코레이터 팩토리라 문자열 경계를 넘어올 수 없다. 여기서는
        #   **자기신고를 기록**하는 것까지만 한다. 평가는 하지 않는다 — 하는 척도 안 한다.
        nm = str(a.get("name") or "").strip()
        pc = str(a.get("precondition") or "").strip()
        wy = str(a.get("why") or "").strip()
        if not nm or not pc:
            return ("armed 는 name= 과 precondition= 이 **둘 다** 필요하다.\n"
                    "  name=        무엇을 재려는가 (classify 의 target= 과 같은 문자열을 써라)\n"
                    "  precondition= 그 가드가 **평가되려면** 참이어야 하는 조건\n"
                    "  why=         그 조건을 네가 **어떻게 성립시켰는지**")
        ledger.arm_record(nm, pc, wy)
        return ("무장 신고 기록: %s\n  전제: %s\n  성립근거: %s\n"
                "★ 이건 **자기신고이지 검증이 아니다** — 하네스는 이 전제를 평가하지 않는다"
                "(문자열은 술어를 못 나른다). classify(target='%s') 가 이 기록의 유무를 "
                "판정문에 붙인다." % (nm, pc, wy or "(안 적음)", nm))
    if act == "before_after":
        # ★ 세 번째 증거 모형: **통제된 전/후 관측**. 09-12 에 실제로 결함을 깬 모양인데
        #   채점될 수 없어서 아무도 하도록 밀리지 않았다(원장 measures 0건).
        _bef, _aft = a.get("before"), a.get("after")
        if not _bef or not _aft:
            return ("before_after 는 before= 과 after= 가 **둘 다** 필요하다.\n"
                    "  before=/after=         처치 전후로 **같은 관측점**을 읽은 값\n"
                    "  control_before=/_after= 처치를 **안 한** 채 같은 간격으로 읽은 값\n"
                    "★ 대조군이 없으면 등급은 `uncontrolled` 로 나간다 — 값이 스스로 "
                    "표류하는지 처치가 바꿨는지 구분되지 않기 때문이다.")
        grade, why = M.before_after(_bef, _aft, a.get("control_before"),
                                    a.get("control_after"))
        # ★ 출처를 **하니스가 단언한다**. 에이전트가 적은 문자열이 kd 출력 안에 실제로
        #   있었는지 대조한다. 있으면 kd 접지, 없으면 declared — 섞으면 B형이 D형으로
        #   세탁된다(grounding-decides-gate).
        _blob = "\n".join(x.get("output") or "" for x in _LAST_KD.get("v") or [])
        _flat = re.sub(r"\s+", "", _blob).lower()
        def _seen(v):
            v = re.sub(r"\s+", "", str(v or "")).lower()
            return bool(v) and v in _flat
        _grounded = _seen(_bef) and _seen(_aft)
        _tgt = a.get("target", "?")
        ledger.measure_record(_tgt, grade, why, kind="before_after",
                              vas=ledger.measure_vas("%s %s" % (_tgt, a.get("why") or "")),
                              principal=("kd" if _grounded else "declared"))
        _src = ("[출처: 하니스가 본 kd 출력에서 전/후 값을 **둘 다 찾았다** — 접지됨]"
                if _grounded else
                "[출처: **네가 옮겨 적은 값**이다. 보관된 kd 출력에서 못 찾았다 — "
                "`declared` 로 기록했다. 접지하려면 같은 세션에서 `kd(cmds=...)` 로 "
                "읽고 그 출력의 값을 그대로 넣어라.]")
        _ctl = ("" if (a.get("control_before") and a.get("control_after")) else
                "\n★ **음성 대조가 없다.** 처치를 안 한 팔에서 같은 간격으로 같은 관측점을 "
                "읽어 control_before=/control_after= 로 넣어라. 그전에는 이 델타로 "
                "'처치가 바꿨다'를 주장하지 마라.")
        return ("전/후 관측 등급: **%s**\n  %s\n%s%s" % (grade, why, _src, _ctl))
    if act == "classify":
        try:
            A_ = bytes.fromhex((a.get("a") or "").replace(" ", ""))
            B_ = bytes.fromhex((a.get("b") or "").replace(" ", ""))
        except ValueError:
            return "a=/b= 는 **서로 다른 채움값**으로 두 번 돌린 출력 버퍼의 hex 여야 한다."
        if not A_ or not B_:
            return ("a=/b= 둘 다 필요하다. **단일 채움 판정은 금지다** — 커널이 그 채움값과 "
                    "같은 바이트를 쓰면 '미기록'으로 오판한다(실제로 0xCC 로 그런 위양성이 났다).")
        df = M.DualFill(A_, B_, status=int(str(a.get("status") or 0), 0),
                        info=int(str(a.get("info") or 0), 0))
        kh = M.kernel_ptrs(A_)
        grade, why = M.classify(df, kernel_hits=kh, neither=bool(a.get("neither")))
        _tgt = a.get("target", "?")
        # ★ 하네스가 쏜 바이트면 보관함의 검증된 자격을 싣고, 에이전트가 옮겨 적은
        #   hex 면 `declared` 다 — **verified 가 아니다**. 둘을 섞으면 B형이 D형으로
        #   세탁된다(grounding-decides-gate).
        _pr = (ledger.normalize_principal(_obs.get("principal"),
                                          req=(_obs or {}).get("principal_req"), src="probe")
               if (_from_probe and _obs) else ledger.normalize_principal("declared"))
        ledger.measure_record(_tgt, grade, why, principal=_pr)
        _prline = ("\nprincipal: %s (%s)" % (ledger.principal_grade(_pr), _pr.get("src"))
                   + ("" if _pr.get("verified") else
                      " — **검증 안 됨**. 이 측정으로 '어느 principal 이 도달한다'를 "
                      "주장할 수 없다. ioctl(where='guest', principal='low') 로 쏘면 "
                      "하네스가 토큰을 읽어 검증한다."))
        _arm = ledger.armings(_tgt)
        _armline = ("\n무장 신고: 있음 — 전제 «%s»" % _arm[-1]["precondition"][:140]) if _arm else (
            "\n무장 신고: **없음** — 이 측정이 그 경로를 실제로 탔다고 아무도 신고하지 않았다. "
            "가드를 재는 측정이면 `measure(action='armed', name='%s', precondition=…, why=…)` "
            "를 먼저 적어라." % _tgt)
        return _mismatch + ("등급=%s\n%s\n기록 %d바이트 / 보고 %d / 비결정 %d / 커널포인터 %d%s%s\n%s"
                % (grade, why, len(df.written), df.info, len(df.nondet), len(kh),
                   _prline, _armline,
                   "★ UNMEASURED 는 clean 이 아니다 — 핸들러가 실행조차 안 됐다."
                   if grade == M.UNMEASURED else ""))
    return "action 은 classify | kernel_ptrs | armed 중 하나."


def _t_images(a):
    """보조 이미지 등록/조회. **크로스 이미지 배선의 관리 창구.**

    action='list'  — 등록된 이미지와 **빌드 동일성**을 보여준다
    action='add'   — name=, path= 로 등록 (읽기 전용 오픈)
    """
    act = (a.get("action") or "list").lower()
    if act == "add":
        nm, path = a.get("name"), a.get("path")
        if not nm or not path:
            return "images(action='add') 에는 name= 과 path= 가 필요하다."
        if not os.path.exists(os.path.expanduser(str(path))):
            return "그 경로에 파일이 없다: %s" % path
        try:
            meta = add_image(nm, path)
        except Exception as e:
            return "등록 실패: %s: %s" % (type(e).__name__, e)
        ledger.record_image(meta)
        return ("이미지 등록: %s ← %s\n  base=%s ts=%s guid=%s 익스포트=%d\n"
                "★ 이 이미지에서 인용할 때는 **`%s!0xVA mnem ops`** 로 태그하라."
                % (meta["name"], meta["path"], meta["base"], meta["timestamp"],
                   (meta["guid"] or "?")[:16], meta["exports"], meta["name"]))
    L = ["등록된 이미지:"]
    pm = _pe()
    if pm is not None:
        L.append("  main  %-42s base=0x%x  (태그 없이 인용)" % (os.path.basename(pm.path), pm.base))
    if not TARGET["_imeta"]:
        L.append("  (보조 이미지 없음 — 주장이 nt! 계약에 바닥이 닿으면 여기서 막힌다.")
        L.append("   IMAGES=nt=/mnt/c/Windows/System32/ntoskrnl.exe 로 시작하거나 action='add')")
    for m in TARGET["_imeta"].values():
        L.append("  %-5s %-42s base=%s ts=%s guid=%s 익스포트=%d"
                 % (m["name"], os.path.basename(m["path"]), m["base"], m["timestamp"],
                    (m["guid"] or "?")[:16], m["exports"]))
    return "\n".join(L)


def _t_crossref(a):
    """**이미지 경계를 건넌다.** 측정 대상이 부르는 임포트 이름 → 그 함수의 몸통.

    지금까지 막혀 있던 모양이 이것이다:
      `0x140001bb6 call qword ptr [rip+0x2058b]`  ← 우리가 보는 것 (IAT 슬롯, 이름만)
      그 함수가 인자를 어떻게 쓰는가                ← 답이 다른 파일에 있다
    name= 을 주면 등록된 보조 이미지들에서 익스포트를 찾아 **거기서 디스어셈블**해 준다.
    """
    name = (a.get("name") or "").strip()
    if not name:
        return "crossref 에는 name=<임포트/익스포트 이름> 이 필요하다. 예: name='MmCreateSection'"
    cnt = int(a.get("count") or 60)
    want = str(a.get("image") or "").strip().lower()
    cands = [(k, v) for k, v in TARGET["_images"].items() if not want or k == want]
    if not cands:
        return ("보조 이미지가 없다%s. `images(action='add', name='nt', "
                "path='/mnt/c/Windows/System32/ntoskrnl.exe')` 부터."
                % (" (image=%r 로 걸렀다)" % want if want else ""))
    hits, fwd = [], []
    for nm, img in cands:
        va = img.export_va(name)
        if va:
            hits.append((nm, img, va))
        elif name in img.exports():
            fwd.append(nm)
    if not hits:
        if fwd:
            return ("`%s` 은 %s 에서 **포워더** 다 — 몸통이 또 다른 파일에 있다. "
                    "그 파일을 등록해야 따라갈 수 있다." % (name, ", ".join(fwd)))
        return ("등록된 이미지 %s 어디에도 `%s` 익스포트가 없다. 이름을 확인하거나 "
                "그 함수를 담은 이미지를 등록하라." % (", ".join(k for k, _ in cands), name))
    if len(hits) > 1:
        return ("`%s` 이 여러 이미지에 있다: %s. image= 로 하나를 지정하라 — "
                "**어느 이미지의 계약인지가 주장의 일부다.**"
                % (name, ", ".join("%s(0x%x)" % (n, v) for n, _, v in hits)))
    nm, img, va = hits[0]
    ins = img.disasm(va, cnt)
    if not ins:
        return "0x%x 디코드 실패 (%s)" % (va, nm)
    meta = TARGET["_imeta"].get(nm, {})
    ledger.note_disasm("%s!%s" % (nm, name))
    head = ("[%s / image=%s] %s @ 0x%x  (%d insn)\n빌드: guid=%s ts=%s"
            % (os.path.basename(img.path), nm, name, va, len(ins),
               (meta.get("guid") or "?")[:16], meta.get("timestamp", "?")))
    body = "\n".join("0x%x  %-20s %s %s" % (v, b.hex(), m, o) for v, b, m, o in ins)
    return _cap(head + "\n" + body +
                "\n\n★ 인용은 **`%s!0x…`** 로 태그하라(태그 없으면 측정 대상에 대고 검증된다).\n"
                "★ 그리고 이 함수의 **계약**을 주장할 거면 인자 레지스터가 어디서 오는지까지 "
                "타이핑하라 — 익스포트 진입점만 보고 계약을 단정하지 마라." % nm)


def _t_verdict(a):
    return ledger.verdict(a)


def _t_control(a):
    return ledger.control(a.get("kind", ""), a.get("what", ""), a.get("result", ""))


def _scratch_dir():
    """표적별 스크래치 디렉터리. **병렬 실행에서 유일한 정확도 위험이었다.**

    ★ 2026-09-02: 예전엔 두 에이전트가 `work/` 를 **그대로 공유**했고 파일명은
      에이전트가 정했다(기본값 `m.py` 로 **둘 다 같았다**). 순서가 겹치면
      A가 쓴 파일을 B가 덮어쓰고 **A가 B의 코드를 실행해 그 출력을 자기 실측으로 받는다**
      — 표적이 뒤바뀐 측정이고, 어느 로그에도 흔적이 안 남는다.
      그날 밤은 우연히 안 겹쳤다(ahcache `s27_*` 7개 / wcifs `s28_*` 11개, 교집합 0).
      다만 R1 에선 **둘 다 자기를 'S26'이라 불렀고** run_python 을 쓴 쪽이 하나뿐이었을 뿐이다.
      `chk_cs.py` / `r8_defs.py` 같은 표적 무관 이름도 실제로 쓰였다.
    ⇒ 표적 키로 가른다. 같은 표적의 다음 회차는 앞 회차 파일을 그대로 본다(연속성 유지).

    ★ **cwd 는 `work/` 그대로 둔다.** 격리하는 것은 *파일 위치*지 작업 디렉터리가 아니다.
      옛 스크래치 중엔 cwd 상대경로로 여는 것들이 있어(`ahc_bytes2.py`, `an3.py` …)
      cwd 까지 옮기면 그 관용구가 조용히 다른 파일을 읽는다 — 고치려던 실패와 같은 형태다.
    """
    b = TARGET.get("binary")
    key = re.sub(r'[^A-Za-z0-9._-]', '_', os.path.basename(str(b)))[:50] if b else "_no_target"
    d = os.path.join(config.WORK_DIR, "scratch", key)
    os.makedirs(d, exist_ok=True)
    return d


def _t_run_python(a):
    code = a.get("code", "")
    fn = a.get("filename") or "m.py"
    # ★ 경로 이탈 금지 — fn 은 에이전트가 정한다. 예전엔 `../` 로 아무 데나 쓸 수 있었다.
    fn = os.path.basename(str(fn)).strip() or "m.py"
    if not fn.endswith(".py"):
        fn += ".py"
    d = _scratch_dir()
    p = os.path.join(d, fn)
    with open(p, "w", encoding="utf-8") as f:
        f.write(code)
    try:
        r = subprocess.run(["python3", "-u", p], cwd=config.WORK_DIR,
                           capture_output=True, text=True,
                           timeout=int(a.get("timeout") or 180))
        # 경로를 돌려준다 — 다음 회차가 이어받을 때 어디를 볼지 알아야 한다.
        _rel = os.path.relpath(p, config.WORK_DIR)
        return _cap(f"[{_rel}] exit={r.returncode}\n"
                    f"--- stdout ---\n{r.stdout}\n--- stderr ---\n{r.stderr}")
    except subprocess.TimeoutExpired:
        return "timeout — 종료 코드도 못 받았다. 음성 결과로 읽지 마라."


def _t_double_fetch(a):
    """이중 페치(TOCTOU) 후보 — CFG 데이터플로. **대조를 통과해야 결과가 나온다.**

    ★ **한계를 먼저 읽어라.** 계보를 `진입 rdx = IRP`(WDM 디스패치 관례)에서 시작한다.
      그래서 **fast-io 경로는 구조적으로 못 본다** — `FastIoDeviceControl` 은 IRP 가 없고
      유저 버퍼가 직접 인자로 온다. fast-io/METHOD_NEITHER 표적에서 나온 0건은
      **'이중 페치 없음'이 아니라 '이 도구의 사정거리 밖'** 이다. 그때는 손으로
      인자 레지스터를 따라가라 (`disassemble` 로 핸들러 진입부터).
    """
    p = _pe()
    if not p:
        return "binary 미지정."
    try:
        import dblfetch as DF
        lim = a.get("limit")
        rs = DF.detect(p, int(lim) if lim else None)
    except Exception as e:
        return ("dblfetch 실패: %s: %s\n**실패는 0건이 아니다.**" % (type(e).__name__, e))
    hot = [r for r in rs if r.get("validated") and r.get("used")]
    trunc = [r for r in rs if r.get("slot") == "(TRUNCATED)"]
    out = ["이중 페치 후보 %d건 (그중 **검사에 한 번·사용에 한 번** 둘 다인 것 %d건)"
           % (len(rs) - len(trunc), len(hot))]
    if trunc:
        out.append("⚠ " + trunc[0].get("note", ""))
    for r in hot[:12]:
        out.append("\n  fn 0x%X  slot %s" % (r["func"], r["slot"]))
        for x in r["reads"][:8]:
            out.append("     0x%X  %-34s %s" % (x["va"], x["insn"],
                                                "검사" if x["is_cmp"] else "사용"))
    out.append("\n대조(양성 합성 1 / 음성 3, 실물 afd 포함) 통과 상태에서만 이 결과가 나온다.")
    out.append("한계: 진입 rdx=IRP 시드 — **fast-io 는 사정거리 밖이다.**")
    return "\n".join(out)


def _t_guards(a):
    """가드가 **"덜 적용됨"** 인 자리를 결정론으로 스캔한다 (`guards.py`).

    ★ 2026-09-04 배선. 그 전까지 이 모듈은 4주 동안 **호출자가 0** 이었다 —
      SYSTEM 이 가장 세게 박는 독트린("결함은 부재가 아니라 덜 적용됨")을
      결정론으로 판정할 도구가 에이전트에게 없었다. `test_wiring.py` 가 잡았다.

    후보 생성기다. **판정기가 아니다.** 나온 자리는 disassemble 로 앵커를 걸어라.
    """
    p = _pe()
    if p is None or not TARGET.get("binary"):
        return "binary 미지정."
    import guards as G
    try:
        _pe2, hits, nprobe = G.scan(TARGET["binary"])
    except Exception as e:
        return "guards 실패: %s: %s" % (type(e).__name__, e)
    name = os.path.basename(TARGET["binary"])
    body = G.render(name, hits, nprobe)
    n = sum(len(v) for v in hits.values())

    # ★ 음성 결과에는 대조가 붙어야 한다. Probe 호출이 0이면 "가드가 덜 적용됐다"가
    #   아니라 **이 축이 이 드라이버에 없다**는 뜻이다. 둘을 섞으면 0건이 clean 으로 읽힌다.
    if nprobe == 0 and n == 0:
        return (body + "\n\n★ Probe* 호출이 **0회**다. 이건 '가드가 다 걸려 있다'가 아니라 "
                "**이 축이 이 이미지에 적용되지 않는다**는 뜻이다 (사용자 버퍼를 Probe 로 "
                "받는 드라이버가 아니거나, 검증이 다른 형태로 되어 있다). "
                "0건을 clean 으로 쓰지 마라 — 이 이미지의 실제 신뢰 경계를 먼저 세워라.")
    if n == 0:
        return (body + "\n\n★ Probe* %d회는 잡았고 **비대칭 후보는 0건**이다. "
                "스캐너는 돌았다(양성 대조 성립) — 이 축에서는 clean 이라고 쓸 수 있다. "
                "단 이 스캐너가 보는 것은 probe-skip / KernelMode / METHOD_NEITHER-no-probe "
                "네 형태뿐이다. 다른 형태의 '덜 적용됨'은 여전히 수동이다." % nprobe)
    return (body + "\n\n★ 전부 **후보**다. 각 자리를 disassemble 로 확인하고 "
            "가드가 지배하는지는 `sink_gates` 로 물어라. 여기 나왔다는 사실 자체는 근거가 아니다.")


TOOLS = {
    "binary_info": _t_binary_info, "surface": _t_surface,
    "decompile": _t_decompile, "disassemble": _t_disassemble,
    "sink_gates": _t_sink_gates, "measure": _t_measure, "ioctl": _t_ioctl,
    "find_funcs": _t_find_funcs, "func_at": _t_func_at,
    "callers": _t_callers, "callees": _t_callees, "callpath": _t_callpath,
    "census": _t_census, "corpus_grep": _t_grep,
    "dispatch_table": _t_dispatch_table, "anchor": _t_anchor,
    "find_bytes": _t_find_bytes, "note": _t_note, "priorart": _t_priorart, "import_xref": _t_import_xref, "authz_reach": _t_authz_reach,
    "verdict": _t_verdict, "control": _t_control, "run_python": _t_run_python,
    "images": _t_images, "crossref": _t_crossref,
    "double_fetch": _t_double_fetch, "guards": _t_guards,
    "kd": _t_kd, "kdscan": _t_kdscan, "record": _t_record,
}

READONLY = ("binary_info", "decompile", "disassemble", "sink_gates", "find_funcs", "func_at",
            "callers", "callees", "callpath", "census", "corpus_grep",
            "dispatch_table", "anchor", "find_bytes", "import_xref", "authz_reach",
            "double_fetch", "images", "crossref", "guards")


# ── 마무리 구간 ────────────────────────────────────────────────────────────
# ★ 2026-09-11 — 케이스 타임아웃은 **SIGKILL** 이다(`subprocess.run(timeout=…)`).
#   그래서 `finish()` 가 못 돌고 **종료 시점 산출물이 통째로 사라진다**. 실측(bfs 야간런):
#   11회차 중 8회가 타임아웃, 그 8회 전부 `total_cost_usd=None`, 그리고 종료 시점에만 도는
#   정리가 한 번도 안 돌아 묘지에 깨진 기각 20건이 그대로 남았다.
#   ⇒ 하드 킬 전에 **에이전트에게 직접** 알린다. 툴 결과는 반드시 읽히므로 여기가 유일하게
#     확실한 채널이다(프롬프트는 회차 시작에 한 번뿐이라 늦다).
#   ★ 한 번만 크게 말하고 그 뒤로는 한 줄로 센다 — 같은 문단을 반복하면 읽히지 않는다.
_WD_FIRED = [False]


def _winddown(now=None):
    """남은 시간이 마무리 구간에 들어갔으면 붙일 문구. 아니면 ''."""
    ts = os.environ.get("CASE_DEADLINE_TS")
    if not ts:
        return ""                      # 데드라인을 모르면 아무 말도 안 한다
    try:
        left = float(ts) - (now if now is not None else time.time())
    except ValueError:
        return ""
    cap = getattr(config, "WINDDOWN_SEC", 300)
    if left > cap:
        return ""
    mins = max(0, int(left // 60))
    if _WD_FIRED[0]:
        return "\n\n[마무리 구간 · 남은 ~%d분]" % mins
    _WD_FIRED[0] = True
    return (
        "\n\n" + "=" * 66 +
        "\n★★ **마무리 구간에 들어왔다 — 남은 ~%d분 뒤 이 회차는 예고 없이 죽는다(SIGKILL).**\n"
        "그때 `finish()` 는 안 돌고 **지금 원장에 없는 것은 전부 사라진다.** 지금부터는 새 분석을\n"
        "시작하지 말고 **가진 것을 등재하라.** 순서대로:\n"
        "  1. 서는 것을 판정으로 낸다. 불완전하면 **불완전하다고 적어서** 낸다\n"
        "     (`verdict(action='reject'|'confirm', …)`; 인구를 못 닫았으면\n"
        "      `action='blocked', next='<다음 한 걸음 + 앵커>'`).\n"
        "  2. `verdict(action='reaudit')` — 심문자가 깬 기각이 묘지에 남아 있으면 치운다.\n"
        "     **이게 타임아웃마다 잃어온 바로 그 산출물이다.**\n"
        "  3. 트랙 단계는 **근거가 있을 때만** 움직여라. 마감이 가깝다고 올리지 마라 —\n"
        "     부풀린 단계는 다음 회차가 두 칸을 건너뛰게 만든다.\n"
        "  4. 인계 노트 한 건(`note`) — 다음 회차가 **이어받을 한 걸음**과 앵커.\n"
        % mins + "=" * 66)


def execute_tool(name, ti):
    fn = TOOLS.get(name)
    if not fn:
        out = f"unknown tool {name}"
    else:
        try:
            out = fn(ti or {})
        except Exception as e:
            out = f"{name} 예외: {type(e).__name__}: {e}"
    # ★ 마무리 배너는 **모든 반환 경로**에 붙는다. 조기 반환 하나만 빠져도 그 호출은
    #   마감을 모르고 지나간다 — 회귀가 정확히 그걸 잡았다(unknown tool 경로).
    try:
        return (out or "") + _winddown()
    except Exception:
        return out                     # 마무리 배너가 툴을 죽이면 안 된다
