# ledger.py — 판정 원장 + 커버리지 + 지속성.
#
# 바뀐 것 (근거와 함께):
#  1) **디스크에 산다.** 예전 원장은 프로세스 메모리였다 — RESUME 로 세션을 이어도 원장은 0에서
#     시작해 커버리지가 거짓이 됐다. 긴 세션에서 컨텍스트가 압축되면 findings 가 사라진다는 것은
#     실제로 보고된 실패다 (Slyp 은 pre-compaction 체크포인팅으로 대응했고, 장기 과제에서
#     컨텍스트 길이만으로 정확도가 13.9~85% 떨어진다는 측정이 있다). 원장은 컨텍스트 밖에 둔다.
#  2) **후보 생애주기** — proposed → refuted / promoted. 반박당한 주장은 사유(klass)와 함께 남고
#     상태 블록에 계속 뜬다. 이 프로젝트는 실제로 죽은 후보(A-12)를 두 번 되살렸다.
#  3) **시나리오 중복 제거** — (함수, 가설) 쌍으로. 소스 타깃은 ±20줄로 잡지만 여기서는 ±0x40 VA.
#  4) **앵커 기록** — 확정마다 기계 검증된 인용을 같이 저장한다. 리포트가 그대로 쓸 수 있다.
import atexit, hashlib, json, os, re, sys, tempfile, time, uuid

import config

STATE = {
    "target": "", "guid": "", "started": "",
    "surface":   {},   # name -> {status, kind, why}
    "verdicts":  [],   # 확정/기각 기록
    "candidates": [],  # {id,target,claim,state,klass,reason,anchors}
    "disasm":    set(),
    "controls":  {},
    "graveyard": [],
    "hedges":    0,
    "refutes":   {"run": 0, "killed": 0, "survived": 0, "failed": 0},
    # 기각 측 압력. broke = 기각이 무너져 ASK 로 되돌아간 건수.
    "interrogs": {"run": 0, "broke": 0, "sustained": 0, "failed": 0, "skipped": 0},
}

STATUS = ("미분석", "감사중", "확정", "기각", "반박됨", "경계보류")
# 경계보류 = **결함은 섰는데 경계가 범위 밖**(현재는 admin→kernel).
#   확정이 아니다(등급을 못 준다). 기각도 아니다(코드의 결함은 실재한다).
#   ★ 남은 질문이 딱 하나로 좁혀진 상태다: **"이 싱크에 닿는 더 낮은 권한이 있는가."**
#   그래서 이 행은 승격자에게 간다. 묘지에 가지 않는다.
# ★ disassemble 과 measured 를 같은 3으로 두면 **정적 판독 clean 이 실측 clean 과 같은 칸에 들어간다.**
# afd.sys 세션의 반증 3건(전부 disassemble 판정이 measured 에 의해 뒤집히거나 무효화됨):
#   · TDI 전송명 검증: "레벨2=미등록 거부" -> 실측은 존재하지 않는 이름까지 전부 SUCCESS
#   · free-후-미NULL 스캐너: 후보 86 -> 실측 표본 9/9 오탐
#   · AfdGetConnectData: 정적 clean -> 실측 8케이스 전부 조기반환, 한 번도 실행 안 됨
BASIS_RANK = {"decompile": 1, "doc": 2, "disassemble": 3, "measured": 4}

# ★ 2026-09-07 — **`basis` 가 자유 문자열이라 어휘가 붕괴하고 게이트가 우회됐다.**
#   실측(원장 전수): ahcache 기각 157건의 basis 가 `disassemble` 83 · `disassembly` 30 ·
#   `static` 22 · `disasm` 3 — **같은 것에 이름 4개**. 30자를 넘는 basis 가 50건,
#   최대 **3,116자**(논증 전문이 basis 칸에 들어가 있었다).
#   그래서 `BASIS_RANK` 는 대부분 0 으로 떨어지고, 무엇보다
#   `GATE_CONTROL_BEFORE_REJECT` 가 `basis == "measured"` **정확일치**로만 걸려서
#   `"measured on the live kernel, not inferred…"` 로 시작하는 실측 기각이
#   **양성 대조 검사를 통째로 건너뛰었다**(verifier_guard 사건이 만든 바로 그 게이트다).
#   ⇒ **선두 토큰**으로 정본화한다. 산문은 버리지 않고 `basis_note` 로 옮긴다.
#     ("disassembly of the measured build" 는 선두가 disassemble 계열이므로 정적이다 —
#      부분문자열 매칭이었다면 이 5건이 거짓으로 실측 취급됐을 것이다.)
_BASIS_ALIAS = {
    "measured": "measured", "measure": "measured", "measurement": "measured",
    "live": "measured", "kd": "measured", "ioctl": "measured", "runtime": "measured",
    "disassemble": "disassemble", "disassembly": "disassemble", "disasm": "disassemble",
    "disassembled": "disassemble", "static": "disassemble", "bytes": "disassemble",
    "decompile": "decompile", "decompiler": "decompile", "decompiled": "decompile",
    "hexrays": "decompile", "hex-rays": "decompile",
    "doc": "doc", "docs": "doc", "documentation": "doc", "msdn": "doc",
}


def normalize_basis(b):
    """`basis` 의 **선두 토큰**을 정본 어휘로 접는다. 반환: (정본 또는 None, 원문).

    None 이면 등록되지 않은 어휘다 — 호출자가 반려한다. 접히면 `BASIS_RANK` 가 살아난다.
    """
    raw = str(b or "").strip()
    if not raw:
        return None, raw
    tok = re.split(r'[^A-Za-z-]+', raw.lower(), 1)[0]
    return _BASIS_ALIAS.get(tok), raw
_PATH = [None]

# PreToolUse 게이트가 계산한 것을 verdict 툴로 넘기는 인계함.
# hook 에서 tool_input 을 고쳐도 툴에는 전달되지 않는다 (실측).
PENDING = {"anchors": None, "refute": None, "key": None}
# ★ `basis=measured` 를 무엇이 뒷받침했는지 판정 레코드까지 나르는 한 칸.
#   `classify`(채점됨) 와 `trace`(실행됨, 미채점)는 증거 무게가 달라 소비부가 구분해야 한다.
_pending_meas = [None]


def stage(target, claim, anchors, refute=None):
    PENDING.update({"anchors": anchors, "refute": refute,
                    "key": (str(target), (claim or "")[:120])})


def _take(target, claim):
    if PENDING["key"] == (str(target), (claim or "")[:120]):
        a, r = PENDING["anchors"], PENDING["refute"]
        PENDING.update({"anchors": None, "refute": None, "key": None})
        return a or [], r
    return [], None


# ── 지속성 ────────────────────────────────────────────────────
def _key(target):
    return re.sub(r'[^A-Za-z0-9._-]', '_', os.path.basename(target or "corpus"))[:60]


# ★ test/prod 경계. 벤치가 프로덕션 원장에 섞여 `pcw.sys` 를 오염시켰다(2026-08-24).
#   지우는 것으로 끝내면 같은 사고가 또 난다 — 원장에 출처를 박고 네임스페이스를 가른다.
PROVENANCE = os.environ.get("LEDGER_NS", "prod")     # prod | bench | scratch


def _ns_dir():
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "state")
    if PROVENANCE != "prod":
        d = os.path.join(d, "_" + PROVENANCE)
    os.makedirs(d, exist_ok=True)
    return d


# 표적을 바꿀 때 되돌릴 기본 골격. `attach` 가 **비우고** 채우기 위해 필요하다.
_SKELETON = {k: (v.copy() if hasattr(v, "copy") else v) for k, v in STATE.items()}


# 회차(프로세스) 스코프 카운터 — 원장에 저장하지 않는다. 회차마다 0에서 시작한다.
_RUN = {"adds": 0, "verdicts0": 0}

# 등재 예산: 기본 12개 + 이번 회차에 낸 **판정 1건당 8개**.
#   "더 등재하고 싶으면 먼저 판정하라." 완전성을 막는 게 아니라 **순서**를 강제한다.
SURFACE_BASE = int(os.environ.get("SURFACE_BASE", "12"))
SURFACE_PER_VERDICT = int(os.environ.get("SURFACE_PER_VERDICT", "8"))


def surface_budget():
    """(남은 등재 수, 예산, 이번 회차 판정 수)."""
    made = max(0, len(STATE.get("verdicts") or []) - int(_RUN.get("verdicts0") or 0))
    cap = SURFACE_BASE + SURFACE_PER_VERDICT * made
    return cap - int(_RUN.get("adds") or 0), cap, made


# ── 원장 키 락 ────────────────────────────────────────────────
# ★ 왜: 같은 표적을 두 프로세스가 열면 `save()` 가 last-writer-wins 로 판정을 통째로
#   지운다. 로그에 흔적이 없다 — 이 저장소가 반복해서 잃은 바로 그 모양이다.
#   `nightrun.acquire_lock()` 이 같은 일을 하는데 **거기에만 있었다.** `agent_sdk.py` 를
#   직접 부르거나 스크립트가 attach 하면 무방비였다. 락이 지키는 것은 원장이므로
#   진입점이 아니라 **원장 옆**에 둔다 — 어느 경로로 들어와도 같은 규칙이 걸린다.
#   (표적을 안 겹치게 여러 터미널을 띄우는 것은 그대로 된다. 키가 다르면 락도 다르다.)
_LOCK = {"path": None}
_LOCK_HOOKED = [False]


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True                      # 살아 있는데 남의 것
    except OSError:
        return False
    return True


def _lock_release():
    p = _LOCK.get("path")
    if not p:
        return
    try:
        if open(p).read().strip() == str(os.getpid()):
            os.unlink(p)
    except OSError:
        pass
    _LOCK["path"] = None


def detach():
    """원장을 놓는다. 락을 풀고 `save()` 를 무장해제한다(미부착 예외로 되돌린다)."""
    _lock_release()
    _PATH[0] = ""


def _lock_acquire(path):
    if os.environ.get("LEDGER_NOLOCK", "") in ("1", "true", "yes"):
        return
    lp = os.path.join(os.path.dirname(path), "." + os.path.basename(path) + ".lock")
    if _LOCK.get("path") == lp:
        return                           # 같은 프로세스가 같은 원장에 다시 붙는다
    _lock_release()                      # 표적을 바꾼다 — 앞 락을 놓는다
    if os.path.exists(lp):
        try:
            old = int(open(lp).read().strip())
        except (ValueError, OSError):
            old = None
        if old is not None and old != os.getpid() and _pid_alive(old):
            raise RuntimeError(
                "이 원장은 이미 다른 프로세스가 쓰고 있다: %s (pid %d).\n"
                "  같은 표적을 두 곳에서 열면 save() 가 서로를 덮어써 판정이 조용히 사라진다.\n"
                "  · 표적이 다른 병렬 실행은 막지 않는다 — 다른 표적으로 띄워라\n"
                "  · 그 프로세스가 죽은 것 같으면:  kill %d ; rm %s\n"
                "  · 읽기만 할 거면:  LEDGER_NOLOCK=1 (쓰지 마라)"
                % (os.path.basename(path), old, old, lp))
        if old is not None and old != os.getpid():
            sys.stderr.write("\033[93m[ledger] 낡은 락 제거 (죽은 pid %s)\033[0m\n" % old)
    try:
        with open(lp, "w") as f:
            f.write(str(os.getpid()))
    except OSError as e:
        sys.stderr.write("\033[93m[ledger] 락 파일을 만들지 못했다: %s\033[0m\n" % e)
        return
    _LOCK["path"] = lp
    if not _LOCK_HOOKED[0]:
        atexit.register(_lock_release)
        _LOCK_HOOKED[0] = True


def attach(target, guid=""):
    d = _ns_dir()
    _p = os.path.join(d, _key(target) + ".json")
    # ★ 락을 **STATE 를 건드리기 전에** 잡는다. 실패해도 지금 들고 있는 원장은 멀쩡하다.
    _lock_acquire(_p)
    _PATH[0] = _p
    # ★ 2026-09-02 버그: 예전엔 `STATE.update(d)` 만 했다. 그러면 **앞 표적의 키가 남는다** —
    #   한 프로세스에서 두 표적을 붙이자 ahcache 의 `tracks` 가 wcifs 원장에 그대로 새어
    #   저장됐다(트랙 초기화 스크립트가 그걸 드러냈다). 원장을 섞는 것은 조용한 오염이고,
    #   판정 계보를 근본에서 망가뜨린다. 붙일 때마다 **비우고** 채운다.
    STATE.clear()
    STATE.update({k: (v.copy() if hasattr(v, "copy") else v) for k, v in _SKELETON.items()})
    if os.path.exists(_PATH[0]) and os.environ.get("FRESH", "") not in ("1", "true"):
        try:
            with open(_PATH[0], encoding="utf-8") as f:
                d = json.load(f)
            d["disasm"] = set(d.get("disasm", []))
            STATE.update(d)
            loaded = True
        except Exception:
            loaded = False
    else:
        loaded = False
    STATE["target"], STATE["guid"] = target or "", guid or STATE.get("guid", "")
    # ★ 2026-09-08 — **옛 질문에 `kind`/`by` 를 붙이는 소급을 붙일 때 돌린다.**
    #   둘 다 이미 있는 칸에서 유도한다(파생 필드, 멱등). 새 행만 고치면 옛 356행이
    #   영원히 랭킹 축 없이 남는다 — 그러면 단일 큐가 정렬되지 않는다.
    if loaded:
        try:
            backfill_ask_fields()
        except Exception:
            pass                     # 소급 실패가 붙기 자체를 막으면 안 된다
        # ★ 2026-09-08 자기 정정 — 저항 질문을 **원장에 물질화**한다.
        #   전에는 `resisted_to_asks` 를 시드 렌더(파일 사본, save_now=False)에서만 불러서
        #   XQ 질문이 **SEED 에는 있고 원장에는 없었다**. 분석가가 시드에서 본 id 를
        #   `verdict(action='asks')` 로 못 찾는다(09-08 런에서는 리드가 상위를 다 차지해
        #   안 물렸을 뿐, 잠복한 결함이었다).
        #   ★ 멱등이다: id 는 표적에서 결정적으로 나오고, 재생성은 저항이 실제로 늘었을 때만
        #     `attempts` 를 올린다. 안 그러면 랭킹 2순위 축이 "몇 번 돌았나"가 된다.
        try:
            resisted_to_asks(STATE.get("target"))
        except Exception:
            pass
    # ★ 회차 예산의 기준선. 표면 등재는 싸고 판정은 비싸다 — 그대로 두면 분모만 큰다.
    #   실측(2026-09-02 3시간): 표면 +69 / 판정 +4, blocked 476/518(92%).
    #   ahcache R3 은 툴 108회 중 25회를 등재에 썼다.
    _RUN["adds"] = 0
    _RUN["verdicts0"] = len(STATE.get("verdicts") or [])
    # ★ 인수인계 게이트의 기준선. 물려받은 손잡이를 이번 회차 것으로 세면 게이트가 죽는다 —
    #   실측: 누적 원장의 BLOCKED 행 450개가 앵커를 거의 다 덮어서 armA 가 그냥 통과했다.
    _RUN["asks0"] = {str(a.get("id")) for a in (STATE.get("asks") or [])}
    _RUN["surface0"] = set(STATE.get("surface") or {})
    # ★ 2026-09-07 — **부채 상한(WIP cap)의 기준선.** 재고가 아니라 **흐름**을 잰다.
    #   재고로 걸면 누적 blocked 546 · 열린 ASK 160 때문에 첫 턴부터 잠긴다.
    #   흐름으로 걸면 "이번 회차가 연 것 − 닫은 것"만 보므로, 09-06 의 순증 +90 /
    #   09-07 의 +34 같은 일만 정확히 불가능해진다.
    try:
        _RUN["leads0"] = {str(x.get("id")) for x in open_leads(STATE.get("target"))}
    except Exception:
        _RUN["leads0"] = set()
    _RUN["blocked0"] = _blocked_rows()
    STATE["provenance"] = PROVENANCE
    if PROVENANCE != "prod":
        STATE.setdefault("_warn", "This ledger is in the %s namespace. Do NOT use its verdicts as "
                                  "evidence."
                         % PROVENANCE)
    STATE.setdefault("started", time.strftime("%Y-%m-%d %H:%M"))
    status_reset("attach")       # 표적이 바뀌면 델타를 믿을 수 없다 — 다음 블록은 전문
    save()
    return loaded


def save():
    if not _PATH[0]:
        raise RuntimeError(
            "ledger.save(): attach() was never called. This record was about to be discarded "
            "silently. Call ledger.attach(target) first.")
    # ★ 원자적 쓰기. 예전엔 `open(path,"w")` 가 파일을 **먼저 0바이트로 자르고** 그 위에 썼다.
    #   쓰는 도중에 죽거나 두 프로세스가 겹치면 **잘린 JSON** 이 남고, 다음 `attach()` 는
    #   그걸 `except Exception: loaded=False` 로 삼켜 원장을 0에서 다시 시작한다.
    #   판정이 통째로 사라져도 로그에 흔적이 없다. tmp 에 쓰고 `os.replace` 로 갈아끼우면
    #   그 창이 없어진다 — 같은 디렉터리라 같은 파일시스템이고, replace 는 원자적이다.
    d = dict(STATE)
    d["disasm"] = sorted(STATE["disasm"])
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(_PATH[0]) or ".",
                                   prefix=".ledger-", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, _PATH[0])
        tmp = None
    except OSError as e:
        # ★ 조용히 넘기지 않는다. 저장 실패는 판정 유실이고, 예전 `except OSError: pass` 는
        #   그것을 정상 종료와 구분 불가능하게 만들었다.
        sys.stderr.write("\033[91m[ledger] save 실패 — 이 회차의 기록이 디스크에 없다: "
                         "%s (%s)\033[0m\n" % (e, _PATH[0]))
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


# ── 1) 전수 표 ────────────────────────────────────────────────
# ★ 도달성은 **항목의 속성**이다. 예전엔 아니었고, 그래서 분모가 이질적이었다:
#   WUDFRd 회차에서 `RdFdoDevice` 의 **PnP/전원 핸들러 20개**가 `kind="ingress"` 로 등재돼
#   공격면 114개의 일부가 됐다. 비특권 프로세스는 `IRP_MJ_PNP` 를 보낼 수 없다.
#   에이전트는 정직하게 *"neither reachable nor unreachable"* 이라고 적었지만
#   그 문장을 담을 **필드가 없어서** `kind` 는 계속 `ingress` 였다.
#
# ★★ 그리고 `kernel-only` 를 그냥 버리면 안 된다 — SCPVBUS-01 UAF 의 살해자가
#    **PnP 스레드**였다. 사용자가 IOCTL 로 재열거를 유발하면 PnP 가 비동기로 REMOVE 를 친다.
#    그래서 3치가 아니라 **4치**다: 가운데 칸이 **경합 상대 풀**이다.
REACH = ("user-direct",            # DeviceIoControl 등으로 직접
         "user-triggerable-async",  # 사용자 요청이 간접 유발 (PnP·완료·취소·DPC·work item·타이머)
         "kernel-only",             # 진짜 사용자와 무관
         "unknown")                 # ★ 기본값. 모르는 것을 안다고 적지 않는다.
# ★ unknown 을 뺀 집합. `reach_unknown()` 이 "아직 안 정한 행"을 고르는 기준이다.
REACH_KNOWN = tuple(x for x in REACH if x != "unknown")


_CODE_RE = re.compile(r'0x8[0-9a-fA-F]{7}')


def _ctl_code(name):
    """표면 항목 이름에서 컨트롤 코드를 뽑는다. 없으면 None."""
    m = _CODE_RE.search(name or "")
    return m.group(0).lower() if m else None


def code_index():
    """컨트롤 코드 -> 등재된 이름들. 중복 등재 탐지용."""
    idx = {}
    for k in (STATE.get("surface") or {}):
        c = _ctl_code(k)
        if c:
            idx.setdefault(c, []).append(k)
    return idx


# ── 앵커 역색인 ──────────────────────────────────────────────────
# ★ 2026-09-03. 이 프로젝트에서 가장 비쌌던 손실의 직접 대응.
#   "이 기능 게이트의 기본값은 무엇인가"라는 질문이 **다섯 회차**에 걸쳐 다시 올라왔다.
#   답은 그동안 `verdicts[].evidence` 안에 산문으로 있었다 — 분석자 자신이 쓴 문장에
#   그 디스크립터 주소가 "ENABLED 로 평가된다"고 적혀 있었다.
#   원장은 판정을 **행 단위**로만 보고, 근거는 자유서술이라 아무도 조회하지 않았다.
#
#   그리고 저장소 여섯 개(verdicts/asks/graveyard/gate_blocks/candidates/surface)가
#   전부 **표현 기반 키**를 쓴다: 이름 문자열 · 주장 단어주머니 SHA1 · target 완전일치 · 키 없음.
#   문장을 바꾸면 뚫리고, 접두사 하나만 달라도 다른 시나리오가 된다.
#   ⇒ 표현을 바꿔도 안 변하는 것은 **앵커(VA)** 뿐이다. 그것을 1급 키로 쓴다.
# ★ 접두사 `0x` 를 요구하면 **정작 그 답을 놓친다.** 문제의 확정 행 근거에는
#   "descriptor VAs 14000f818, 14000f540, 14000f690" 처럼 **0x 없이** 적혀 있었다.
#   자유서술은 표기를 강제할 수 없으므로 둘 다 잡고 **정규화**한다.
#   맨 16진수는 커널 VA 모양(1 로 시작하는 9자리, 즉 0x1_0000_0000~0x1_FFFF_FFFF)만 본다 —
#   빌드 GUID 같은 긴 토큰은 단어 경계 때문에 조각으로 안 걸린다.
_ANCHOR_RE = re.compile(r'0x([0-9a-fA-F]{6,16})\b|\b(1[0-9a-fA-F]{8})\b')


def _vas(text):
    """표기 정규화된 앵커 집합. 0x14003625d · 14003625D · 0x014003625d 를 같은 것으로 본다."""
    out = set()
    for m in _ANCHOR_RE.finditer(str(text or "")):
        h = (m.group(1) or m.group(2)).lower().lstrip("0") or "0"
        out.add(h)
    return out


def anchor_index():
    """VA -> [(저장소, id, 한줄)] . 매번 새로 만든다(원장이 작고, 낡은 색인이 더 위험하다)."""
    idx = {}

    def add(blob, store, ident, brief):
        for va in _vas(blob):
            idx.setdefault(va, []).append((store, str(ident or "-"), str(brief)[:74]))

    for v in STATE.get("verdicts") or []:
        add(" ".join(str(v.get(k) or "") for k in ("claim", "evidence", "reason")),
            v.get("status") or "판정", v.get("id"), v.get("target"))
    for a in STATE.get("asks") or []:
        n = len(a.get("attempts") or [])
        add(" ".join(str(a.get(k) or "") for k in ("claim", "why", "guard", "sink", "method")),
            "질문%s" % ("·%d회" % n if n else ""), a.get("id"), a.get("target"))
    for g in STATE.get("graveyard") or []:
        add(" ".join(str(g.get(k) or "") for k in ("claim", "reason")),
            "묘지[%s]" % (g.get("klass") or "-"), g.get("id"), g.get("target"))
    for b in STATE.get("gate_blocks") or []:
        add(" ".join(str(b.get(k) or "") for k in ("why", "would_be", "evidence", "gate")),
            "칸없음", b.get("gate"), b.get("target"))
    for c in STATE.get("candidates") or []:
        add(" ".join(str(c.get(k) or "") for k in ("claim", "reason")),
            "후보[%s]" % (c.get("state") or "-"), c.get("id"), c.get("target"))
    for k, r in (STATE.get("surface") or {}).items():
        add("%s %s" % (k, r.get("why") or ""), "표면[%s]" % (r.get("status") or "-"), "", k)
    for n, t in (STATE.get("tracks") or {}).items():
        add(t.get("note") or "", "트랙·단계%s" % t.get("stage"), n, n)
    for m in (STATE.get("measures") or []):
        add(json.dumps(m, ensure_ascii=False), "실측", m.get("id") if isinstance(m, dict) else "", "")
    return idx


def anchor_hits(text, exclude_id=None, limit=10):
    """이 텍스트의 앵커가 원장 어디에 이미 있는가. 없으면 빈 문자열."""
    want = _vas(text)
    if not want:
        return ""
    idx = anchor_index()
    grouped = {}
    for va in want:
        for store, ident, brief in idx.get(va, []):
            if exclude_id and ident == str(exclude_id):
                continue
            grouped.setdefault((store, ident, brief), set()).add(va)
    if not grouped:
        return ""
    # 근거가 이미 있는 판정 → 질문 → 묘지 순으로 위험도가 높다
    def rank(k):
        st = k[0]
        return (0 if st.startswith(("확정", "기각")) else
                1 if st.startswith("질문") else
                2 if st.startswith("묘지") else 3, -len(grouped[k]))
    # 같은 저장소가 화면을 다 먹지 않게 종류별 상한을 둔다(표면은 중복 등재가 많다).
    per, rows = {}, []
    for k in sorted(grouped, key=rank):
        st = k[0].split("[")[0]
        per[st] = per.get(st, 0) + 1
        if per[st] > 3:
            continue
        rows.append(k)
        if len(rows) >= limit:
            break
    L = ["", "─" * 66,
         "THIS ANCHOR IS ALREADY IN THE LEDGER. Read it before re-deriving anything -",
         "   Re-deriving the same fact in different words has burned five sessions of "
         "this project.",
         "─" * 66]
    for (store, ident, brief) in rows:
        vs = ", ".join(sorted(grouped[(store, ident, brief)])[:4])
        L.append("   [%-14s %-16s] %s" % (store, ident[:16], vs))
        if brief:
            L.append("        %s" % brief)
    more = len(grouped) - len(rows)
    if more > 0:
        L.append("   … 외 %d건" % more)
    L.append("   => To read the full basis, open that row with note(action='read') or status().")
    L.append("─" * 66)
    return "\n".join(L)


def surface_add(items, kind="ingress", reach="unknown"):
    # ★ 2026-09-03: 등재에 상한이 없었다. 시드는 완전성을 요구하고(미분석을 빼지 마라),
    #   등재는 싸고, 등재된 행은 전부 판정을 요구한다 ⇒ 분모만 커지고 커버리지가 거짓으로
    #   나빠진다. 막는 게 아니라 **순서**를 강제한다: 판정을 내면 등재 예산이 늘어난다.
    left, cap, made = surface_budget()
    if left <= 0:
        return ("YOU HAVE SPENT THIS SESSION'S REGISTRATION BUDGET (%d/%d, %d verdicts this "
                "session).\nSurfaces are cheap and verdicts are expensive - the table is %d rows "
                "and %d of them are blocked.\nEACH VERDICT YOU FILE OPENS %d MORE REGISTRATIONS. "
                "Use worklist() and close the highest-scoring rows first.\nIf something really "
                "must be registered now, put it in note() and add it next session - written down "
                "is not lost." % (_RUN.get("adds"), cap, made, len(STATE.get("surface") or {}),
                   sum(1 for r in (STATE.get("surface") or {}).values() if r.get("blocked")),
                   SURFACE_PER_VERDICT))
    _asked = len(list(items))
    items = list(items)[:left]
    _clipped = _asked - len(items)
    n = 0
    dup = []
    idx = code_index()
    for it in items:
        name = it if isinstance(it, str) else it.get("name", "")
        if not name or name in STATE["surface"]:
            continue
        # ★ 같은 컨트롤 코드를 **다른 접두사로** 다시 등재하면 분모가 부풀고
        #   같은 코드를 두 번 판정하게 된다. WUDFRd 08-31 야간 실행에서 실제로 일어났다:
        #   USB 코드 20개가 `USB.*` / `CTRL.IRP.*` 로 이중 등재돼 표면 115 중 21개가 중복이었고,
        #   기각 22건 중 4건이 같은 코드의 재판정이었다.
        c = _ctl_code(name)
        if c and idx.get(c):
            dup.append((name, idx[c][0]))
            continue
        r = reach if isinstance(it, str) else (it.get("reach") or reach)
        if r not in REACH:
            return f"reach 는 {REACH} 중 하나. 모르면 'unknown' — 추측해서 적지 마라."
        # ★ 2026-09-05: `entry` 는 **읽기만 하고 아무도 안 썼다** — 실측 1144행 중 0행.
        #   그래서 `code_coverage()` 가 늘 `Dispatch|Callback|Unload` 이름 휴리스틱으로
        #   떨어졌고, 도달가능 집합이 진짜 인그레스가 아니라 이름이 그럴싸한 함수들에서
        #   출발했다. 그런데 **381행이 이름에 `@0xVA` 를 이미 달고 있다.**
        #   (에이전트가 게이트 신고로 정확히 이걸 지적했다 — 신고가 옳았다.)
        #   ⇒ 이름에 박힌 주소를 그대로 쓴다. 추측하지 않는다: 없으면 안 넣는다.
        _rec = {"status": "미분석", "kind": kind, "reach": r,
                "why": "" if isinstance(it, str) else it.get("why", "")}
        _ent = None if isinstance(it, str) else it.get("entry")
        if not _ent:
            # ★ 2026-09-07 — **`@` 를 요구하면 표적마다 무장 여부가 갈린다.**
            #   실측: wcifs 는 `WcProcessGetUnions@0x140020d48` 관례라 354/583 행이 entry 를
            #   갖는데, ahcache 는 `IOCTL f6 -> 0x140038850` 관례라 **0/620** 이었다.
            #   `code_coverage()` 의 씨앗이 이 칸이므로 ahcache 는 계속 이름 휴리스틱
            #   폴백으로 돌았다. 계기가 **에이전트의 작명 관례에 달려 있으면 안 된다.**
            #   ⇒ `@` 는 선택. 없으면 이름 안의 **첫 주소**를 쓴다(추측이 아니라 인용이다).
            _me = (re.search(r'@\s*(0x[0-9a-fA-F]{6,16})', name)
                   or re.search(r'(0x[0-9a-fA-F]{6,16})', name))
            if _me:
                _ent = _me.group(1)
        if _ent:
            try:
                _rec["entry"] = int(str(_ent), 16) if isinstance(_ent, str) else int(_ent)
            except (TypeError, ValueError):
                pass
        STATE["surface"][name] = _rec
        n += 1
    _RUN["adds"] = int(_RUN.get("adds") or 0) + n
    save()
    if dup:
        return ("DUPLICATE REGISTRATION BLOCKED - the same control code is already in the table "
                "under a different name:\n"
                + "\n".join("  · %s (already registered as %s)" % d for d in dup[:10])
                + (f"\n  … and {len(dup)-10} more" if len(dup) > 10 else "")
                + "\nKeeping the same code under two names INFLATES THE DENOMINATOR AND "
                  "ADJUDICATES THE SAME CODE TWICE. Adjudicate under the existing name, or - if "
                  "it really is a different surface - put the distinguishing axis (handler / "
                  "transfer method) in the name, not the code.")
    #   ★ kind / reach 를 반환에 남긴다 — 무엇으로 등재됐는지 모델이 확인할 수 있어야 한다.
    #     그리고 예산 때문에 **일부만** 들어간 경우를 조용히 넘기지 않는다.
    _clip = (" Registered only %d of the %d requested (registration budget)." %
             (n, _asked)) if _clipped else ""
    return ("Registered %d items (kind=%s, reach=%s).%s Total table: %d items. Nothing ever "
            "disappears from this table - if you cannot analyse it, file "
            "verdict(action='blocked').\n"
            "reach='unknown' MAKES THE DENOMINATOR FALSE. Settle reachability, or update it "
            "with surface(action='reach', name=..., reach=...)."
            % (n, kind, reach, _clip, len(STATE["surface"])))


def count_via(bucket, v):
    """적대자 판정이 **어느 매체로** 왔는지 센다: 툴 제출 / 텍스트 폴백 / 고장.

    ★ 2026-09-03. 제출 툴을 붙이고도 이걸 안 세면 **효과를 알 수 없다.** 이 저장소는
      만들고 배선 안 한 도구를 이미 여러 번 잃었다(measure·sink_gates·claimaudit).
      `via_text` 가 계속 올라간다면 모델이 툴을 안 부르고 있다는 뜻이고, 그때는
      프롬프트가 아니라 **툴 설명**을 고쳐야 한다.
    """
    if not isinstance(v, dict):
        return
    st = STATE.setdefault(bucket, {})
    key = "via_fault" if v.get("fault") else ("via_%s" % (v.get("via") or "text"))
    st[key] = st.get(key, 0) + 1
    save()


def measure_vas(text):
    """문자열에서 **실측이 건드린 주소**를 뽑는다. 절대 VA + `<mod>+0xOFF` 둘 다.

    ★ 왜 필요한가 (2026-09-08 실측): `measured()` 가 `m["target"] == target` **정확
      문자열 일치**였다. target 은 자유 산문이라(사이트 하나에 11행이 붙는 그 문제)
      `ioctl` 이 `device`(`\\.\ahcache`)로 기록한 실측을 판정의 target
      (`0x14004188c K2 call site in AhcQuirksInit …`)이 절대 못 만난다.
      09-06 에 `mark_interrogated` 를 target 문자열 → `vid=` 로 고친 그 병이 여기 남아 있었다.
    ★ `<mod>+0xOFF` 는 이 원장의 표적 모듈일 때만 **ImageBase 를 더해** 절대 VA 로 접는다.
      `nt!…` 같은 다른 모듈은 접지 않는다 — 베이스를 모르면서 접으면 가짜 일치가 난다.
    """
    t = str(text or "")
    out = {int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{6,16})', t)}
    try:
        _mod = os.path.basename(str(STATE.get("target") or "")).lower()
        _mod = re.sub(r'\.(sys|exe|dll)$', '', _mod)
        if _mod:
            _p = _img()
            _base = getattr(_p, "base", None) if _p is not None else None
            if _base:
                for off in re.findall(r'\b%s\s*\+\s*0x([0-9a-fA-F]{1,8})\b'
                                      % re.escape(_mod), t, re.I):
                    out.add(_base + int(off, 16))
    except Exception:
        pass
    return out


# ─── principal 정본화 (2026-09-10) ────────────────────────────────────────────
#   ★ 배선이 끊겨 있던 자리다. `probe.py` 는 결과에 `principal={user,il_sid,elevated}`
#     를 싣고 `vmprobe.assert_low_principal()` 이 토큰을 **실제로 읽어** 비승격이
#     아니면 던진다(D형 접지). 그런데 `measure_record()` 에 그 인자가 없어서
#     원장 경계에서 그 사실이 버려졌다 — 실측 212건 전부 principal 칸 없음.
#   ⇒ 원장만 읽는 다음 세션은 **"저권한에서 안 됐다"와 "저권한으로 재본 적이 없다"를
#     구분할 수 없다.** 그 구분이 권한경계 주장의 전부다.
#   관련: memory `vm-guest-channel-runs-elevated`(vmrun 토큰은 High+Administrators),
#         `controls-assume-a-context`(승격을 가르는 건 이제 principal 칸뿐이다),
#         `built-but-never-wired` · `prose-cannot-carry-a-predicate`.
PRINCIPAL_SRC = ("probe", "kd", "declared", "unknown")
# 비승격으로 인정하는 무결성 SID (Low / Medium). vmprobe._IL_OK 와 같은 집합이다.
_IL_LOW = ("S-1-16-4096", "S-1-16-8192")


def normalize_principal(p, req=None, src=None):
    """어떤 형태로 들어오든 **관측된 것만** 실은 정본 dict 로 접는다.

    반환 키:
      src      probe | kd | declared | unknown  — 이 사실이 어디서 왔나
      req      low | default | None             — 요청한 것 (probe 만)
      il_sid / elevated / user                  — **관측값**. 모르면 None (0/False 로 채우지 마라)
      verified True 일 때만 "이 측정은 이 principal 에서 났다"를 주장할 수 있다

    ★ `verified` 가 이 함수의 존재 이유다. 나머지는 참고값이고, 소비부는 이 한 칸만 본다.
      `src='declared'`(에이전트가 옮겨 적음)는 **절대 verified 가 아니다** — B형이다.
    """
    out = {"src": "unknown", "req": (req or None), "il_sid": None,
           "elevated": None, "user": None, "verified": False}
    if isinstance(p, dict):
        # 프로브 결과의 principal 칸. err 가 있으면 자격을 못 읽은 것이다 = 미검증.
        out["src"] = src or "probe"
        if not p.get("err"):
            out["il_sid"] = str(p.get("il_sid") or "") or None
            out["user"] = str(p.get("user") or "") or None
            if p.get("elevated") is not None:
                out["elevated"] = bool(p.get("elevated"))
            out["verified"] = bool(out["il_sid"])
    elif isinstance(p, str) and p.strip():
        tok = p.strip().lower()
        out["src"] = tok if tok in PRINCIPAL_SRC else (src or "declared")
        if out["src"] == "declared":
            out["user"] = p.strip()[:120]
        # kd 는 사용자 토큰이 아니라 커널 디버거다. 관측이긴 하나 principal 주장에는 못 쓴다.
    elif src:
        out["src"] = src if src in PRINCIPAL_SRC else "unknown"
    return out


def principal_grade(p):
    """정본 dict → 한 단어. 질의·집계용."""
    if not isinstance(p, dict):
        return "unknown"
    if p.get("src") == "kd":
        return "kernel-debugger"
    if not p.get("verified"):
        return "declared" if p.get("src") == "declared" else "unknown"
    sid = str(p.get("il_sid") or "")
    if p.get("elevated"):
        return "verified_elevated"
    return "verified_low" if sid in _IL_LOW else "verified_default"


def measure_record(target, grade, why="", kind="classify", vas=None, principal=None):
    """실측 기록. `verdict(basis='measured')` 는 이게 있어야 성립한다 —
    없으면 '실측했다'가 **자기 신고**로 남는다.

    ★ 2026-09-08 — `kind` 를 가른다. 둘은 증거 무게가 다르고, 섞으면 등급이 거짓이 된다:
        `classify` — 이중채움으로 **채점된** 관측 (measure.py 가 등급을 냈다)
        `trace`    — 하네스가 **실행한** 관측이지만 채점은 안 됐다 (kd 체인 등)
      trace 도 **자기 신고가 아니다** — 하네스가 쏜 기록이다.

    ★ 2026-09-10 — `principal` 을 받는다. **호출자가 관측한 것만 넘겨라.**
      프로브 경로는 `principal=r.get("principal")`(게스트 토큰을 실제로 읽은 dict),
      kd 경로는 `principal="kd"`, 에이전트가 옮겨 적은 hex 는 `principal="declared"`.
      안 넘기면 `unknown` 으로 남는다 — 그리고 **그게 정직한 값이다**. 기본값으로
      `default` 를 채우면 "승격에서 쟀다"가 사실로 둔갑한다(read-shaped-call-writes). 그래서 게이트를 통과시키되
      판정에 무엇이 뒷받침했는지 **도장을 찍는다**. 그리고 `basis=measured` 기각은
      `GATE_CONTROL_BEFORE_REJECT` 가 여전히 **양성 대조를 따로 요구**하므로,
      이걸 허용해도 "고장난 하네스와 결함 부재"를 못 가르는 구멍은 안 열린다.
    """
    _pr = principal if isinstance(principal, dict) and "verified" in principal \
        else normalize_principal(principal)
    STATE.setdefault("measures", []).append(
        {"target": target, "grade": str(grade), "why": why[:300], "kind": kind,
         "vas": sorted(vas)[:24] if vas else [],
         "principal": _pr, "principal_grade": principal_grade(_pr),
         "t": time.strftime("%m-%d %H:%M")})
    save()
    return True


def measured(target, state=None):
    """이 판정을 뒷받침하는 실측 기록. **정확일치 + 주소 겹침**.

    ★ 정확일치만 보던 것이 09-08 런에서 실제로 값나가는 판정을 떨어뜨렸다:
      분석가가 기준선→처치→사후 3단을 대조군 3/3 으로 돌리고 `basis=measured` 로 냈는데
      `measures` 에 그 target 문자열이 없어 거부됐고, 결국 `basis=disassemble` 로 내려앉았다.
    """
    _S = state if state is not None else STATE
    M = _S.get("measures") or []
    tgt = str(target or "")
    hit = [m for m in M if m.get("target") == target]
    _va = measure_vas(tgt)
    if _va:
        for m in M:
            if m in hit:
                continue
            mv = set(m.get("vas") or []) | measure_vas(m.get("target"))
            if mv & _va:
                hit.append(m)
    return hit


def measured_principal(target, state=None):
    """이 표적의 실측들이 **어느 principal 에서 났는가**. 반환: (최선 등급, 근거 레코드들).

    최선 = 권한경계 주장에 가장 강한 것. `verified_low` > `verified_default`
    > `verified_elevated` > `kernel-debugger` > `declared` > `unknown`.

    ★ 이 함수의 요점은 **`unknown` 을 `denied` 와 구분해서 돌려주는 것**이다.
      "저권한에서 안 됐다"(측정했고 거부됐다)와 "저권한으로 재본 적이 없다"(미측정)는
      권한경계 주장에서 정반대인데, principal 칸이 없던 동안 원장에서 같아 보였다.
    """
    _rank = {"verified_low": 5, "verified_default": 4, "verified_elevated": 3,
             "kernel-debugger": 2, "declared": 1, "unknown": 0}
    recs = measured(target, state=state)
    if not recs:
        return ("none", [])
    best, who = "unknown", []
    for m in recs:
        g = m.get("principal_grade") or principal_grade(m.get("principal"))
        if _rank.get(g, 0) > _rank.get(best, 0):
            best, who = g, [m]
        elif g == best:
            who.append(m)
    return (best, who)


def arm_record(name, precondition, why=""):
    """측정 **무장 자기신고**. `measure(action='armed')` 의 뒷단.

    ★ 이건 검증이 아니다. 문자열은 술어를 못 나른다 (memory
    `prose-cannot-carry-a-predicate`) — 하네스는 `precondition` 을 평가하지 않는다.
    그래도 기록해야 하는 이유: `classify` 가 이 기록의 **유무**를 판정문에 붙인다.
    없으면 "그 경로를 실제로 탔는지 아무도 신고하지 않았다"가 판정에 같이 남는다.

    실사례(원 docstring): `AfdRioInvalidateBuffer` 의 `id < table_count` 경계검사를
    재려고 극단 id 10종을 먹여 전부 SUCCESS 를 받았는데, 테이블이 비어 count=0 이라
    **경계검사 경로를 애초에 안 탔다.** "측정했다"는 착각이었다.
    """
    STATE.setdefault("armings", []).append(
        {"name": name, "precondition": str(precondition)[:300],
         "why": str(why)[:300], "t": time.strftime("%m-%d %H:%M")})
    save()
    return True


def armings(name):
    return [x for x in (STATE.get("armings") or []) if x["name"] == name]


def race_add(a, b, shared, why="", reach="user-triggerable-async"):
    """★ **2항 표면 항목.** 경합은 위치의 성질이 아니라 (T_A, T_B) + 공유객체의 성질이다.

    전 원장 표면 604개 중 경합 가설 형태는 **1개**였고, 이 프로젝트의 유일한 확정
    메모리 안전 버그(SCPVBUS-01 UAF)가 그 1개에서 나왔다. 담을 행이 없으면 등재가 안 되고
    등재가 안 되면 **미분석으로도 안 남는다** — 분모에서 통째로 빠진다.
    """
    if not (a and b and shared):
        return "race 는 a=, b=, shared=(공유 객체/필드) 셋이 다 필요하다."
    if reach not in REACH:
        return f"reach 는 {REACH} 중 하나."
    name = f"RACE({a} , {b} @ {shared})"
    STATE["surface"][name] = {"status": "미분석", "kind": "race", "reach": reach,
                              "pair": [a, b], "shared": shared, "why": why[:400]}
    save()
    return ("\nTo adjudicate you must show that BOTH sides touch the SAME SHARED STATE and that "
            "their order is not enforced.\nABSENCE OF A LOCK IS ONLY ONE FORM OF RACE. These hold "
            "even when locking is correct:\n  - double fetch - the value checked and the value "
            "used are DIFFERENT READS (user buffer / METHOD_NEITHER). Locks are irrelevant. With "
            "a kernel copy (METHOD_BUFFERED) this axis dies - state the transfer method first.\n  "
            "- state-transition window (dirty-COW shaped) - the premise validated changes between "
            "dropping and re-taking the lock. Look for RE-VALIDATION after re-acquisition; "
            "without it, a lock still leaves a window.\n  - handle / object reuse - the lock "
            "protects the slot while the IDENTITY inside the slot changes.\n  - refcount "
            "asymmetry - acquire and release sit under different locks.\n=> To reject, you must "
            "rule out EACH of those four. 'There is a common lock' alone does not sustain a "
            "rejection.")


def races():
    return {k: v for k, v in (STATE.get("surface") or {}).items()
            if v.get("kind") == "race"}


def surface_reach(name, reach, why=""):
    """도달성을 갱신한다. `kernel-only` 는 공격면 분모에서 빠지지만 **표에는 남는다** —
    경합 상대(`user-triggerable-async`) 후보이기 때문이다."""
    if reach not in REACH:
        return f"reach 는 {REACH} 중 하나."
    if name not in STATE["surface"]:
        return f"'{name}' 은 전수 표에 없다. surface(action='add') 가 먼저다."
    STATE["surface"][name]["reach"] = reach
    if why:
        STATE["surface"][name]["reach_why"] = why[:300]
    save()
    return f"{name} → reach={reach}"


def reach_unknown(limit=40):
    """★ `reach='unknown'` 인 행의 **이름을 돌려준다.**

    2026-09-05 사건: 완료 게이트가 `reach=unknown` 행이 남으면 막는데,
    **그 행을 이름으로 지목할 방법이 없었다.** 에이전트는 개수만 볼 수 있었다.
    S42 가 16행을 설정하고도 0에 못 닿아 gate_blocked 를 냈고, S45 는 **이름으로 약 140회**
    탐침하고도 못 찾아 gate_blocked 를 두 번 냈다. 두 회차 합쳐 150회 가까운 헛수고다.
    S45 의 노트 제목이 그대로 증거다: `STOP-PROBING-read-before-touching`.
    ⇒ 게이트가 요구하는 것을 **열거할 수 있게** 만든다. 이건 판단이 아니라 배선 문제였다.
    """
    out = [k for k, v in (STATE.get("surface") or {}).items()
           if isinstance(v, dict) and (v.get("reach") or "unknown") not in REACH_KNOWN]
    return out[:limit], len(out)


def dead_claim_open(limit=40, surface=None):
    """★ **주장은 죽었는데 표면이 안 닫힌 행**을 두 통으로 나눠 이름째 돌려준다.

    반환: (no_scope, open_cand, n_no_scope, n_open)
      · no_scope  — 분모가 선언된 적이 없다. `verdict(action='scope', target=, items=, method=)`
                    한 번이면 닫기 경로가 열린다.
      · open_cand — 분모는 있는데 후보가 남았다. 남은 후보를 판정하면 표면이 닫힌다.

    2026-09-06 실측: 표면 560행 중 **83행**이 이 상태다(`rejected_claims` 있는데 미분석).
    기각이 표면을 닫으려면 먼저 분모가 있어야 하고(`_settle_reject` 의 no_scope/open),
    안내문은 기각이 성공할 때마다 나간다 — **104번 나갔다**. 그런데 전 원장에서
    `closed_by_scope` 는 **1행**뿐이다. 안내를 못 봐서가 아니라 **적체가 안 보여서**다:
    그 행들을 이름으로 열거할 방법이 없었다.
    ⇒ `reach_unknown` 과 같은 처방이다. 게이트가 요구하는 것을 **열거 가능하게** 만든다.
      판단이 아니라 배선 문제다. 무엇을 먼저 할지는 처방하지 않는다.
    """
    # ★ `surface=` 로 **스냅샷**을 받을 수 있다. 2026-09-06 실측: `nightrun.build_carryover`
    #   는 `json.load(_state_path(name))` 파일 스냅샷으로 이어받기를 만들고 `ledger.STATE`
    #   를 쓰지 않는다. STATE 만 읽게 짰더니 부모 프로세스에서 **조용히 0건**이 나와
    #   블록이 통째로 안 실렸다(예외도 없어서 실패로도 안 보였다). 로직은 한 벌로 두고
    #   **데이터 출처만** 인자로 받는다 — 복제하면 한쪽만 고쳐진다.
    ns, oc = [], []
    _src = surface if surface is not None else (STATE.get("surface") or {})
    for k, v in _src.items():
        if not isinstance(v, dict) or v.get("status") != "미분석":
            continue
        if not (v.get("rejected_claims") or v.get("claims_rejected")):
            continue
        (oc if v.get("cand") else ns).append(k)
    return ns[:limit], oc[:limit], len(ns), len(oc)


def reach_breakdown():
    """(공격면 분모, kernel-only, unknown). 분모 = user-direct + user-triggerable-async."""
    c = {k: 0 for k in REACH}
    for v in (STATE.get("surface") or {}).values():
        c[v.get("reach", "unknown") if v.get("reach") in REACH else "unknown"] += 1
    return (c["user-direct"] + c["user-triggerable-async"], c["kernel-only"], c["unknown"], c)


def mark_incidental(name, found_while):
    """**A 를 보다 B 를 발견**한 것을 표시한다.

    ★ 왜 필요한가: 이 세션 최고의 결함(`S13-UAF-AVLNODE-V2`)이 정확히 그렇게 나왔다 —
      시드는 '정보 유출 게이트를 보라'였는데 AVL 노드 UAF 를 발견했다.
      그런데 그 뒤 시드마다 "새 표면을 늘리지 마라"를 박고 이어받기에 "분모만 키운 회차다"
      경고까지 자동으로 붙였다. **최고의 발견 경로에 벌을 주고 있었다.**
      넓히기(무작정 등재)와 파다가 걸린 것은 다르다 — 후자는 실제 작업의 산물이다.
    """
    r = STATE.get("surface", {}).get(name)
    if r is None:
        return None
    r["incidental"] = (found_while or "")[:160]
    r["t_found"] = time.strftime("%m-%d %H:%M")
    save()
    return r


def incidental_count():
    return sum(1 for v in (STATE.get("surface") or {}).values() if v.get("incidental"))


def surface_set(name, status, why=""):
    if status not in STATUS:
        return f"status 는 {STATUS} 중 하나."
    STATE["surface"].setdefault(name, {"status": "미분석", "kind": "ad-hoc",
                                      "reach": "unknown", "why": ""})
    STATE["surface"][name]["status"] = status
    if status != "미분석":
        STATE["surface"][name].pop("blocked", None)
        # 판정된 행의 '다음 걸음'은 무의미하다 — 남겨두면 다음 회차가 죽은 걸음을 집는다.
        STATE["surface"][name].pop("next", None)
    if why:
        STATE["surface"][name]["why"] = why
    save()
    return f"{name} → {status}"



def _settle(vid, tgt, status, why=""):
    """판정을 **전수 표에 올바른 키로** 반영한다.

    ★ 예전엔 `surface_set(tgt, ...)` 하나였다. 전수 표의 키는 에이전트가 등재한 **id**
      (예: `MJ_CREATE_0x18001b864`)인데 `tgt` 은 **주소**(`0x18001B864`)다.
      `surface_set` 이 setdefault 라 주소 키로 **새 행이 생기고** 원래 행은 영원히
      미분석으로 남았다 — 분모는 부풀고 분자는 안 오른다.
      cng.sys 회차가 25건을 판정하고도 커버리지 **13/42(31%)** 로 찍혔다 (실제 25/27).
      MIN_COVERAGE 를 켜면 만족 불가능한 게이트가 된다.

    규칙: id 가 표에 있으면 그것을, tgt 도 이미 표에 있으면 같이 표시한다.
          **판정이 전수 표에 새 행을 만들지 않는다.** 둘 다 없을 때만 하나 만든다
          (조용히 버리지 않기 위해서다).
    """
    keys = [k for k in (vid, tgt) if k and k in STATE["surface"]]
    if not keys:
        keys = [vid or tgt]
    for k in keys:
        surface_set(k, status, why)
    return keys


def _va(x):
    try:
        return int(str(x), 16) if str(x).lower().startswith("0x") else int(str(x))
    except Exception:
        return None


def _scope_of(k):
    return (STATE.get("surface", {}).get(k) or {}).get("cand")


def _scope_open(k):
    """아직 판정 안 된 후보를 돌려준다. 스코프 선언이 없으면 None (=선언부터 하라)."""
    sc = _scope_of(k)
    if not sc:
        return None
    return [it for it in sc["items"] if not it.get("done")]


def _scope_mark(k, item_label, sink_va, vid):
    """기각 하나가 후보 **하나**를 닫는다. 매칭은 명시(item=) 또는 sink VA 일치만 인정한다.

    ★ 문자열 유사도로 추측 매칭하지 않는다. 잘못 매칭하면 안 본 후보가 판정된 것으로
      둔갑하는데, 그건 이 하니스가 반복해서 밟은 바로 그 함정이다(조용한 오답).
    """
    sc = _scope_of(k)
    if not sc:
        return None
    want = (item_label or "").strip().lower()
    sv = _va(sink_va)
    for it in sc["items"]:
        if it.get("done"):
            continue
        if (want and want == it["label"].strip().lower()) or \
           (sv is not None and it.get("va") is not None and sv == it["va"]):
            it["done"] = vid
            return it
    return None


def _settle_reject(vid, tgt, claim, item_label, sink_va):
    """★ R-A: **기각은 표면 행을 닫지 않는다.**

    측정(2026-08-31): 기각된 표면 73건 중 **73건이 주장 1개로 닫혔다.** 경쟁 주장을 둘 이상
    세우고 닫힌 표면은 하나도 없었다. 실제 사례 `FDO.MAJOR.READ@0x14000d2d0` — 공유 분류기의
    싱크 **한 개**를 반박하고 major 핸들러 **전체**를 기각했는데, 같은 회차의 자기 노트에
    "CopyIoBuffer/MapIoBuffer/MakeSafeMdl 는 아직 안 봤다"고 적혀 있었다.

    그래서 표면이 `기각`이 되는 조건을 셋으로 못 박는다:
      ① `verdict(action='scope', ...)` 로 **후보 집합을 먼저 선언**했고
      ② 그 후보가 **전부** 판정됐거나
      ③ `action='exhaust'` (그건 기각이 아니라 방법 소진이다)
    조건이 안 차면 표면은 **미분석(blocked)** 으로 남는다 — 주장은 죽었지만 표면은 안 죽었다.
    """
    keys = [k for k in (vid, tgt) if k and k in STATE["surface"]] or [tgt or vid]
    out = []
    for k in keys:
        row = STATE["surface"].setdefault(
            k, {"status": "미분석", "kind": "ad-hoc", "reach": "unknown", "why": ""})
        row["claims_rejected"] = int(row.get("claims_rejected") or 0) + 1
        row.setdefault("rejected_claims", []).append({"vid": vid, "claim": (claim or "")[:120]})
        hit = _scope_mark(k, item_label, sink_va, vid)
        rest = _scope_open(k)
        if rest is None:
            row["status"] = "미분석"
            row["blocked"] = True
            row["why"] = ("%d claims were rejected but NO CANDIDATE SET WAS DECLARED - the "
                          "surface does not close. Declare this surface's denominator first with "
                          "verdict(action='scope', target=%r, items=[...], method=...)."
                          % (row["claims_rejected"], k))
            out.append((k, "no_scope", None))
        elif rest:
            row["status"] = "미분석"
            row["blocked"] = True
            row["why"] = ("주장 %d건 기각 · 후보 %d/%d 판정 — **남은 후보: %s**"
                          % (row["claims_rejected"],
                             len(_scope_of(k)["items"]) - len(rest),
                             len(_scope_of(k)["items"]),
                             ", ".join(it["label"] for it in rest[:6])))
            out.append((k, "partial", rest))
        else:
            surface_set(k, "기각", (claim or "")[:120])
            row["closed_by_scope"] = True
            out.append((k, "closed", hit))
    return out


def coverage():
    """**판정률** — 확정/기각/반박됨만 센다. blocked 는 성과가 아니므로 안 센다."""
    tot = len(STATE["surface"])
    if not tot:
        return 0.0, 0, 0
    done = sum(1 for v in STATE["surface"].values()
               if v["status"] in ("확정", "기각", "반박됨", "경계보류"))
    return done / tot, done, tot


def code_coverage():
    """★ **실제 코드 커버리지.** `coverage()` 와 재는 것이 다르다.

    `coverage()` = 판정/표면 인데, **표면은 에이전트가 스스로 채운다.**
    즉 자기가 고른 분모에 대한 비율이라 "얼마나 감사했나"가 아니라
    "적어둔 걸 정리했나"를 잰다. 진입점 16개를 적고 17건을 판정하면 57% 가 되지만,
    그 뒤에 도달 가능한 함수가 394개면 실제로 본 건 8% 다 (ahcache 실측).

    반환 (rate, 본 함수, 도달가능 함수). 인덱스가 없으면 (None,0,0).
    ※ 직접호출 그래프만 쓰므로 도달가능 수는 **하한**이다(점프표·guard_dispatch_icall 누락).
    """
    try:
        import tools as _T, pe as _PE
        ix = _T._ix()
        if not ix:
            return (None, 0, 0)
        nm = {cva: n for cva, n in ix.byva}
        # ★ 2026-09-05 — **키 공간이 섞여 있었다.** `ix.out` 과 아래 `touched` 는 **심볼 이름(str)**
        #   키인데, `surface[].entry` 는 **VA(int)** 다. 그대로 씨앗으로 넣으면
        #   `ix.out.get(<int>)` 이 항상 None 이라 폐포가 한 번도 안 커지고,
        #   마지막 교집합 `touched(이름들) & seen(정수들)` 이 **영원히 공집합**이다 ⇒ 늘 0%.
        #
        #   ★★ 이건 내가(관찰자) 만든 회귀다. 02:31 에 `entry` 를 채우는 배선을 넣으면서
        #   **소비자를 안 고쳤다.** 그전엔 `entry` 가 늘 비어 있어 아래 이름 휴리스틱 폴백이
        #   돌았고, 그래서 증상이 없었다. 즉 **필드를 올바르게 채우는 것이 게이트를 무장시켰다.**
        #   (msquic 회차가 `(0.0, 0, 20)` 을 그대로 재현해 진단했다. 그 진단이 맞다.)
        #   ⇒ 씨앗을 **그래프의 키 공간으로 정규화**한다. 함수 시작이 아니면 경계로 접는다.
        _t0 = STATE.get("target") or ""
        _pe0 = None
        if _t0 and os.path.exists(_t0):
            try:
                _pe0 = _PE.PE(_t0)
            except Exception:
                _pe0 = None
        ents, _unres = [], 0
        for v in (STATE.get("surface") or {}).values():
            if not isinstance(v, dict) or not v.get("entry"):
                continue
            try:
                _va = int(v["entry"], 16) if isinstance(v["entry"], str) else int(v["entry"])
            except (TypeError, ValueError):
                continue
            _n = nm.get(_va)
            if _n is None and _pe0 is not None:
                try:
                    _b, _ = _pe0.func_bounds_merged(_va)
                    _n = nm.get(_b)
                except Exception:
                    _n = None
            if _n is None:
                _unres += 1
            else:
                ents.append(_n)
        if not ents:
            ents = [n for n in nm.values()
                    if "Dispatch" in n or "Callback" in n or "Unload" in n]
        seen, stack = set(), list(ents)
        while stack:
            a = stack.pop()
            if a in seen:
                continue
            seen.add(a)
            stack += list(ix.out.get(a, ()) or ())
        t = STATE.get("target") or ""
        if not (t and os.path.exists(t)):
            return (None, 0, len(seen))
        p_ = _PE.PE(t)
        touched = set()
        for x in (STATE.get("disasm") or []):
            try:
                a = int(x, 16) if isinstance(x, str) else int(x)
                b, _e = p_.func_bounds_merged(a)
                if b in nm:
                    touched.add(nm[b])
            except Exception:
                pass
        hit = len(touched & seen)
        return ((hit / len(seen)) if seen else None, hit, len(seen))
    except Exception:
        return (None, 0, 0)


def mark_interrogated(tgt, v, broke=None, note="", vid=None):
    """기각 항목에 심문 결과를 박아둔다. **심문 안 받은 기각은 검증된 음성이 아니다** —
    표본율을 낮추는 것과 커버리지를 부풀리는 것은 다른 일이므로 per-항목으로 남긴다.

    ★ 2026-09-06 실측 — **이 함수가 target 문자열로 행을 찾아 남의 행을 덮고 있었다.**
      심문은 항상 기각이 기록되기 **전에** 도는 사전 게이트다. 그런데 아래 루프가
      "같은 target 의 기각"을 먼저 찾아 패치하므로, 후보 집합·형제 행처럼 **target 을
      공유하는 두 번째 기각부터는**
        ① 자기 표식을 못 받고(= 미심문으로 남고)
        ② 자기 심문 결과가 **앞선 행에 찍힌다**(= 조용한 오염).
      실측: target 을 공유하는 기각이 ahcache 18묶음 59행 · wcifs 12묶음 33행,
      심문기록을 가진 기각 중 42%(ahcache)가 뒤에 같은 target 기각이 또 온 행이었다.
      ⇒ **행 id 로 나른다.** id 를 받으면 그 행에만 박고, 없으면 id 키로 stash 한다.
      (memory `hook-local-dict-is-not-a-transport` 와 같은 계열 — 전달 수단이 행을 식별 못 했다.)
    """
    key = str(vid).strip() if vid else None
    for rec in reversed(STATE.get("verdicts") or []):
        # ★ id 를 받았으면 **그 행만** 고친다. 못 받았으면 아무 행도 고치지 않는다 —
        #   사전 게이트이므로 지금 맞는 행은 아직 존재하지 않는 것이 정상이다.
        if key and str(rec.get("id")) == key and rec.get("status") == "기각":
            rec["interrogated"] = bool(v)
            if v:
                rec["interrogation"] = {"klass": v.get("klass"),
                                        "reason": (v.get("reason") or "")[:400],
                                        # ★ 2026-09-05: `broke` 가 없으면 `session_products()`
                                        #   가 "깨진 기각"과 "심문 통과"를 구분 못 한다.
                                        "broke": bool(broke) if broke is not None
                                                 else (not v.get("sustained", True))}
            save()
            return True
    # ★ 심문은 **기각이 기록되기 전에** 도는 사전 게이트다 ⇒ 여기서 찾을 판정이 아직 없다.
    #   예전엔 bool 만 넣고 아무도 안 꺼내 써서 **심문 결과가 통째로 증발**했다:
    #   08-31 12:57 회차는 심문 2회를 돌고도 원장에 `rejects_interrogated=0` 으로 찍혔다.
    #   = "기각이 검증됐는지"를 계기판이 영원히 0으로 보고한다.
    STATE.setdefault("pending_interrog", {})[key or tgt] = {
        "ok": bool(v),
        # ★ 소비 측이 id 로 못 찾고 target 으로 폴백할 때, 그 결과가 정말 이 행 것인지
        #   판별할 수 있도록 출처를 같이 남긴다.
        "for_id": key,
        "for_target": str(tgt)[:160],
        # ★ 2026-09-05: `ok` 는 "심문이 돌았나"이지 "기각이 섰나"가 아니다.
        #   둘을 안 가르면 `session_products()` 가 **깨진 기각을 산출물로 센다.**
        "broke": (bool(broke) if broke is not None
                  else (bool(v) and not (v or {}).get("sustained", True))),
        "klass": (v or {}).get("klass"),
        "reason": ((v or {}).get("reason") or "")[:400],
        "note": (note or "")[:1200]}
    save()
    return False


def verified_negatives():
    """★ **검증된 음성률.** `coverage()` 는 기각을 전부 판정으로 세지만, 게이트가
    '판정 불가'로 통과시킨 기각은 음성이 아니라 미분석이다 (`ledger.py` 가 스스로
    "커버리지에서 이건 확정된 음성이 아니다"라고 적어두고도 세어 왔다).

    반환: (rate, verified, total_rejections). 표본 0이면 rate=None — 비율을 주장하지 않는다.
    """
    try:
        import rejaudit as RA
    except Exception:
        return (None, 0, 0)
    tot = ver = 0
    for v in STATE.get("verdicts") or []:
        if (v.get("status") or "") != "기각":
            continue
        tot += 1
        if RA.classify(v)[0] == "T0":
            ver += 1
    return ((ver / tot) if tot else None, ver, tot)


def settled():
    """**처리율** — 판정 + '사유가 붙은 blocked'. 종료 게이트는 이걸 본다.

    ★ 이걸 안 나눠서 게이트가 만족 불가능한 지시를 하고 있었다:
      can_finish() 는 "blocked 로 사유라도 붙여라"고 하는데 coverage() 는 blocked 를
      안 세므로, MIN_COVERAGE>0 을 켜면 그 지시를 따라도 영원히 못 끝낸다.
      MIN_COVERAGE 가 기본 0.0 이라 한 번도 안 켜져서 드러나지 않았다.
    사유가 붙은 미분석은 **정직한 미분석**이다 — 끝낼 수는 있게 하되, 성과로는 안 센다.
    """
    tot = len(STATE["surface"])
    if not tot:
        return 0.0, 0, 0
    # ★ R-A 마이그레이션이 되돌린 행은 **처리된 것이 아니다.** 그 행의 `why` 는 분석이 아니라
    #   마이그레이션 문구다. 이걸 세면 처리율이 시작부터 89%가 되어 종료 게이트가 즉시 만족된다
    #   — 08-31 15:50 회차가 실제로 그렇게 60분 cap 중 31분만에 스스로 끝났다(판정 0건).
    #   에이전트가 그 행에 **자기 사유**를 쓰면 `why` 가 덮이므로 이 배제는 자동으로 풀린다.
    def _migrated(v):
        return v.get("reopened_by") and str(v.get("why", "")).startswith("R-A 재개")
    n = sum(1 for v in STATE["surface"].values()
            if v["status"] in ("확정", "기각", "반박됨", "경계보류")
            or (v.get("blocked") and not _migrated(v)))
    return n / tot, n, tot


# ★ 2026-09-04 실측: 옛 구현은 `[:limit]` = **dict 삽입 순서 0~7** 이었다.
#   wcifs 미분석 560행 중 등재 순번 0~7 만 나오고 **552행은 한 번도 안 보였다**.
#   ahcache 도 같다 (fn0~fn7 고정) — 그런데 확정 3건은 전부 fn8·fn10 근처에서 나왔다.
#   이 목록은 `status_block` 에 실려 **툴 4회마다 + 모든 verdict 뒤**, 회차당 45회쯤 주입되고
#   회차를 넘어도 같은 8행이었다. 콜드스타트 편향의 극단형 — 새로 등재된 행은 **회수될
#   기회 자체가 없다**. (worklist 만 점수로 고르는데 그건 회차당 1회 실린다. 45:1 로 편향이 이긴다.)
#
# 대체안: ① 남은 것의 **구성**을 먼저 보여주고(8행보다 정보량이 크다)
#         ② 표본은 호출마다 **창을 밀어** 회차 안에서 전체를 훑는다.
#   점수축(worklist)을 쓰지 않는 이유 — 그건 "등급을 움직이는 행"을 고르는 축이고,
#   여기서 답할 질문은 "아직 안 본 것이 무엇인가"라 목적이 다르다. 우선순위를 두 번
#   겹치면 그 자체가 새 편향이 된다.
_UN_CURSOR = [0]


def unaudited(limit=8, rotate=True):
    rows = [k for k, v in STATE["surface"].items() if v["status"] == "미분석"]
    if not rows:
        return []
    if not rotate or len(rows) <= limit:
        return rows[:limit]
    i = _UN_CURSOR[0] % len(rows)
    _UN_CURSOR[0] = (i + limit) % len(rows)
    out = rows[i:i + limit]
    if len(out) < limit:                     # 끝을 넘으면 앞으로 감는다
        out += rows[:limit - len(out)]
    return out


def unaudited_shape():
    """남은 미분석의 **구성**. 이름 8개보다 이게 더 많은 것을 말해준다."""
    import collections as _c
    c = _c.Counter()
    for _k, v in STATE["surface"].items():
        if v.get("status") != "미분석":
            continue
        c[(v.get("reach") or "unknown")] += 1
    return c


# ── 2) 근거 ───────────────────────────────────────────────────
def note_disasm(target):
    STATE["disasm"].add(str(target))
    save()


def has_disasm(target):
    t = str(target)
    return any(t in d or d in t for d in STATE["disasm"])


# ── 3) 시나리오 중복 ──────────────────────────────────────────
def _scen(target, claim):
    """(위치, 가설) 쌍. 같은 함수에 같은 취지의 주장이 다시 오면 같은 시나리오다."""
    words = sorted(set(re.findall(r'[A-Za-z가-힣]{3,}', (claim or "").lower())))[:12]
    return hashlib.sha1((str(target) + "|" + " ".join(words)).encode()).hexdigest()[:12]


REOPEN_GROUND = {
    "new_evidence": "A NEW ANCHOR that breaks the refutation exists - the evidence must contain "
                    "a VA absent from the dead record",
    "category_error": "The rejection klass DOES NOT ADDRESS WHAT THE CLAIM IS ABOUT - write both "
                      "what the klass asserts and what the claim asserts",
    "precondition_resolved": "The precondition the rejection rested on HAS SINCE BEEN MEASURED - "
                             "give that measurement / question id",
}


def reopen(gid, ground, why, evidence=""):
    """묘지 재심. **되살리는 게 아니라 다시 다툴 자격을 준다.**

    ★ 2026-09-03 에 만든 이유. `S23-GATE3-DEFAULT-V2` 가 실제 사건이다:
      주장은 "이 기능 게이트는 기본 DISABLED 다"(값이 무엇인가), 기각 klass 는
      `not_controlled`("값이 상수다"). 상수라는 것은 그 주장을 **반박하는 게 아니라
      뒷받침한다.** 그런데 묘지에 들어가 '재개 금지'로 잠겼고, 그 위에 얹힌 OOB 신고가
      다섯 회차에 걸쳐 다시 올라왔다. 즉 **한 번의 관측이면 끝날 질문이 잠겨 있었다.**

    ★ 동시에 묘지가 **뚫려 있기도 했다**: `_scen` 이 단어주머니 해시라 표현만 바꾸면
      다른 시나리오가 된다. 실제로 에이전트가 "세 번째 표현"을 찾는 데 회차를 태웠다.
      ⇒ 정당한 재심은 열고, 바꿔쓰기는 막는다. 둘은 반대 방향의 결함이다.
    """
    gid = str(gid or "").strip()
    g = next((x for x in STATE.get("graveyard") or [] if str(x.get("id")) == gid), None)
    if g is None:
        ids = [str(x.get("id")) for x in (STATE.get("graveyard") or [])][-8:]
        return ("묘지에 id=%r 이 없다. 최근 id: %s\nstatus() 의 '묘지' 줄에서 골라라." % (gid, ids))
    ground = str(ground or "").strip().lower()
    if ground not in REOPEN_GROUND:
        return ("`reopen` requires ground=. It must be one of these three:\n"
                + "\n".join("  %-22s %s" % (k, v) for k, v in REOPEN_GROUND.items())
                + "\n\n'I WILL PHRASE IT DIFFERENTLY' IS NOT A GROUND. That is a move that "
                  "has already failed twice.")
    why = str(why or "").strip()
    if len(why) < 40:
        return ("why= must be AT LEAST 40 CHARACTERS. If you cannot write in one sentence what "
                "changed, it is not yet time to reopen.\nDead rejection: [%s] %s - %s"
                % (g.get("klass"), str(g.get("claim"))[:100], str(g.get("reason"))[:150]))

    if ground == "new_evidence":
        old = set(x.lower() for x in re.findall(r'0x[0-9a-fA-F]{6,16}',
                                                json.dumps(g, ensure_ascii=False)))
        new = set(x.lower() for x in re.findall(r'0x[0-9a-fA-F]{6,16}', str(evidence)))
        if not (new - old):
            return ("ground='new_evidence' but the evidence CONTAINS NO ANCHOR THAT THE DEAD "
                    "RECORD LACKED.\nAnchors in the dead record: %s\nRe-submitting the same "
                    "basis is not new evidence." % (", ".join(sorted(old)[:8]) or "(none)"))
    if ground == "category_error":
        kl = str(g.get("klass") or "")
        if kl and kl.lower() not in why.lower():
            return ("With ground='category_error' you must NAME THAT KLASS (%r) INSIDE why=, and "
                    "write side by side what that klass asserts and what the claim asserts. That "
                    "is the proof of a category error." % kl)

    g.setdefault("reopens", []).append(
        {"ground": ground, "why": why[:500], "t": time.strftime("%m-%d %H:%M"),
         "evidence": str(evidence)[:400]})
    g["reopened"] = True
    # ★ 2026-09-05 — **재개는 트랙의 "끝났다" 주장을 상하게 한다.** (memory `raw-material-goes-stale`)
    #   실측: `searchpath-head-injection` 트랙 노트가 *"S48 FINAL v4 — GOAL MET AND THE TRACK IS
    #   ANSWERED END TO END … closes NEGATIVE"* 인데, 그 축의 S46 이 범위 오류로 재개됐고
    #   ablation 팔이 같은 축에 열린 질문 3개를 새로 달았다. 그런데 노트는 여전히 모든 다음
    #   회차에게 "끝났고 음성"이라고 말한다. 지우지 않고 **표시만** 한다 — 판단은 사람·분석가 몫.
    _CLOSED = ("ANSWERED", "GOAL MET", "CLOSED AS", "closes NEGATIVE", "END TO END", "FINAL")
    for _tn, _t in (STATE.get("tracks") or {}).items():
        _note = str(_t.get("note") or "")
        if any(c in _note for c in _CLOSED):
            _t.setdefault("stale_closure", []).append(
                {"by": gid, "ground": ground, "t": time.strftime("%m-%d %H:%M")})
    save()
    n = len(g["reopens"])
    warn = ""
    if n >= 3:
        warn = ("\nTHIS IS REOPEN ATTEMPT %d. If three rounds of argument have not closed it, "
                "the problem is not the argument but the METHOD. Filing "
                "gate_blocked(kind='tool'/'taxonomy') is the better move." % n)
    return ("[REOPENED] %s - ground=%s (attempt %d)\nDead rejection: [%s] %s\n  its stated "
            "reason: %s\n\nYou may now attempt this scenario ONCE more. The refuter still "
            "runs.\nThe reopen is recorded on the graveyard entry - it is not erased.%s"
            % (gid, ground, n, g.get("klass"), str(g.get("claim"))[:120],
               str(g.get("reason"))[:200], warn))


def gy_origin(entry):
    """묘지 항목의 출처. 옛 항목은 `origin` 이 없으므로 후보 목록으로 **역추론**한다.

    ★ 둘은 증거 무게가 다르다:
      refuted — 킬 맨데이트를 가진 **독립 적대자**가 죽였다. 부활에 새 근거를 요구하는 게 맞다.
      self    — **분석가 자신의 기각**이다. 다음 회차가 다시 보는 것은 정상적인 재심이지
                "묘지에서의 부활"이 아니다.
    """
    o = entry.get("origin")
    if o:
        return o
    cid = str(entry.get("id"))
    for c in (STATE.get("candidates") or []):
        if str(c.get("id")) == cid and c.get("state") == "refuted":
            return "refuted"
    return "self"


def graveyard_priming(n=12):
    """★ 시작 프롬프트·상태블록에 실을 묘지 요약. 출처별로 **문구를 가른다.**

    옛 문구는 394건 전부에 "CLAIMS ALREADY KILLED (do not resurrect)" 를 붙였다.
    그중 94%가 분석가 자신의 기각이라, 자기 판정이 적대자 판정과 같은 언어로 되돌아왔다.

    선택도 `[-12:]`(최근성) 대신 **klass 층화** — "최근에 뭘 죽였나"가 아니라
    "어떤 사유로 죽는가"가 전달되어야 다음 회차가 그 사유를 미리 점검한다.
    """
    import collections as _c
    gy = STATE.get("graveyard") or []
    if not gy:
        return ""
    # ★ 2026-09-10 — **서지 않는 음성을 '죽은 주장' 칸에서 뺀다.**
    #   09-06 에 등급을 세고 이름까지 불러줬는데도 `reaudit` 호출은 09-07 의 3회가
    #   마지막이다(09-08·09·10 전 세션 0회). 그 사이 ahcache 의 `broke` 는 17 → 43.
    #   원인은 **같은 행이 두 칸에 동시에 실리기 때문**이다: 위의 "KILLED / YOUR OWN
    #   EARLIER REJECTIONS" 목록(길고 먼저 온다)과 아래의 "서 있지 않은 기각"(짧고 뒤에
    #   온다). 앞 칸이 이기고, 그 행은 닫힌 축으로 읽힌다.
    #   memory `graveyard-is-not-ground-truth` 의 규칙 그대로다 — *"기각됨"과 "적대자를
    #   통과한 기각"을 같은 칸에 두지 마라.* 이제 아래 재심 칸에만 실린다.
    try:
        _sc, _srows, _sn = graveyard_trust(limit=10 ** 6)
        _suspect = {str(r["id"]) for r in _srows}
    except Exception:
        _sc, _srows, _sn, _suspect = None, [], 0, set()
    ref = [g for g in gy if gy_origin(g) == "refuted" and str(g.get("id")) not in _suspect]
    own = [g for g in gy if gy_origin(g) != "refuted" and str(g.get("id")) not in _suspect]
    L = []
    if ref:
        L.append("=== KILLED BY AN INDEPENDENT REFUTER (%d) — do not resurrect without new "
                 "evidence that breaks the refutation ===" % len(ref))
        for g in ref[-min(n, 6):]:
            L.append("  [%s] %s — %s: %s" % (g.get("id"), str(g.get("target"))[:44],
                                             g.get("klass"), str(g.get("claim"))[:90]))
    if own:
        by = _c.Counter(g.get("klass") or "-" for g in own)
        L.append("")
        L.append("=== YOUR OWN EARLIER REJECTIONS (%d) — these are VERDICTS, NOT REFUTATIONS. "
                 "Re-examining one is normal re-audit, not resurrection. The interrogator breaks "
                 "%s of rejections it sees, so treat these as provisional ===" % (len(own), "67%"))
        L.append("  사유 분포: " + " · ".join("%s %d" % kv for kv in by.most_common(8)))
        # klass 층화 — 사유마다 하나씩
        seen = set()
        for g in reversed(own):
            k = g.get("klass") or "-"
            if k in seen:
                continue
            seen.add(k)
            L.append("  [%s] %s — %s: %s" % (g.get("id"), str(g.get("target"))[:44], k,
                                             str(g.get("claim"))[:80]))
            if len(seen) >= n - min(len(ref), 6):
                break
    # ★ 2026-09-06 — **묘지의 신뢰 등급을 같이 싣는다.**
    #   실측: 이 표의 `verified`(심문자가 못 깬 음성)는 ahcache 167행 중 54행(32%)뿐인데,
    #   위 문구는 등급을 구분하지 않고 나갔다. 특히 `broke`/`reopened` 행은
    #   **철회됐거나 서지 않는 음성**인데 다음 회차에는 닫힌 축으로 보였다 —
    #   09-06 런은 그렇게 `S77-REDIR-GUARD-ASYM`(심문자가 door_only 로 깨고 분석가가
    #   수용한 행)을 기각인 채로 남긴 채 예산 만료로 잘렸다. 이름으로 불러준다.
    _c2, _rows, _n = _sc, _srows, _sn      # ★ 위에서 이미 쟀다 — 두 번 세면 두 값이 갈린다
    if _c2:
        L.append("")
        L.append("=== 이 묘지의 신뢰 등급 — 검증된 음성 %d / 전체 %d ==="
                 % (_c2.get("verified", 0), sum(_c2.values())))
        L.append("  " + " · ".join("%s %d" % kv for kv in _c2.items() if kv[1]))
        L.append("  `verified` 만 적대자를 통과한 음성이다. `unexamined` 는 아무도 안 깨본 것이고,")
        L.append("  `broke`/`reopened` 는 **이미 무너졌는데 철회가 안 된 행**이다 — 재심 1순위다.")
    if _rows:
        L.append("")
        L.append("=== 서 있지 않은 기각 %d건 — 부활이 아니라 **정리**다 ===" % _n)
        L.append("  ★ 이 %d건은 **위의 '죽은 주장' 목록에서 빼 두었다.** 심문자가 깼거나"
                 "(broke) 저자가 철회한(reopened) 행이라 닫힌 축으로 읽으면 안 된다." % _n)
        for r in _rows[:6]:
            L.append("  [%s] %s (%s) %s — %s"
                     % (r["grade"], r["id"], r.get("klass"), r.get("target", "")[:40],
                        str(r.get("why") or "")[:90]))
    return "\n".join(L)


def seen_scenario(target, claim):
    s = _scen(target, claim)
    # ★ 재심이 열린 시나리오는 막지 않는다. 묘지 항목과 후보는 id 로 이어져 있다.
    reopened = {str(g.get("id")) for g in (STATE.get("graveyard") or [])
                if g.get("reopened") and not g.get("rekilled")}
    # ★ 2026-09-10 — **심문자가 깬 기각(broke)도 막지 않는다.**
    #   프라이밍은 이 행들을 "서지 않는 음성이니 정리하라"고 내보내는데, 정작 다시 열려고
    #   하면 이 게이트가 "이미 죽은 시나리오"로 거부했다. 길을 안 대는 거부는 헛돌기를
    #   만든다(memory `predicate-cannot-ask`). 등급은 `graveyard_trust` 하나에서만 온다 —
    #   같은 술어를 두 벌 쓰면 두 값이 갈린다.
    #   ★ 무제한 재제출이 아니다: 반복 미종결은 판결자(`ADJUDICATE_AFTER`)가 닫는다.
    try:
        _, _srows, _ = graveyard_trust(limit=10 ** 6)
        reopened |= {str(r["id"]) for r in _srows if r.get("grade") == "broke"}
    except Exception:
        pass
    for c in STATE["candidates"]:
        if c.get("scen") == s and c["state"] in ("refuted", "promoted"):
            if str(c.get("id")) in reopened:
                return None
            return c
    return None


# ── 4) 판정 ───────────────────────────────────────────────────
def open_candidate(target, claim, basis, evidence, anchors=None):
    cid = f"C{len(STATE['candidates']) + 1}"
    rec = {"id": cid, "target": target, "claim": claim, "basis": basis,
           "evidence": (evidence or "")[:4000], "anchors": anchors or [],
           "state": "proposed", "klass": None, "reason": "",
           "scen": _scen(target, claim), "t": time.strftime("%m-%d %H:%M")}
    STATE["candidates"].append(rec)
    save()
    return rec


def close_candidate(rec, state, klass=None, reason="", impact=None):
    """★ 2026-09-04 두 가지 추가:
      ① `impact` 보존 — 죽은 확정은 verdict 레코드가 안 생겨 임팩트 3항이 **통째로 사라졌다.**
         오늘 밤 `impact_unproven` 킬 2건을 사후 감사하려 했을 때 근거가 없었다.
      ② 묘지 레코드에 `t` — 없어서 날짜로 거르면 **전부 0건**이 나온다.
         실제로 내가 "오늘 밤 반박자 킬 0건"으로 오독했다(킬은 5건 있었다).
    """
    rec["state"] = state
    rec["klass"] = klass
    rec["reason"] = reason
    if impact:
        rec["impact"] = impact
    if state == "refuted":
        # ★ 재심으로 열렸던 항목이 다시 죽으면 **재심 표시를 닫는다**(rekilled).
        #   안 그러면 한 번의 재심이 영구 통행증이 된다.
        _prev = next((g for g in (STATE.get("graveyard") or [])
                      if str(g.get("id")) == str(rec.get("id"))), None)
        if _prev is not None and _prev.get("reopened"):
            _prev["rekilled"] = True
            _prev["rekill_reason"] = ("%s: %s" % (klass, reason))[:300]
        STATE["graveyard"].append({"id": rec["id"], "target": rec["target"],
                                   "claim": rec["claim"][:120], "klass": klass,
                                   "reason": reason[:300],
                                   "impact": rec.get("impact"),
                                   "origin": "refuted",     # 독립 적대자가 죽였다
                                   "t": time.strftime("%m-%d %H:%M")})
        _settle(rec.get("id"), rec["target"], "반박됨", f"{klass}: {reason[:70]}")
    save()




def _pe_for_gates():
    try:
        import tools as _T
        return _T.TARGET.get("_pe")
    except Exception:
        return None


def _sink_va(rec):
    """확정의 target/evidence 에서 싱크 VA 를 뽑는다. 없으면 None(=미분석)."""
    import re as _re
    for fld in (rec.get("target"), rec.get("evidence")):
        if not fld:
            continue
        m = _re.search(r"0x([0-9a-fA-F]{6,16})", str(fld))
        if m:
            return int(m.group(1), 16)
    return None


# ── ASK — 게이트가 못 정하면 **묻는다** ─────────────────────────
#   2026-08-29. 그 전까지 게이트는 술어였다: `(ok, note)`. 못 정하면 선택지가
#   **통과 아니면 거부** 둘뿐이고 둘 다 틀리므로, `⚠ 미검증 기각으로 기록한다` 라는
#   **경고 문구로 새어나갔다.** 그렇게 샌 것이 262건 중 186건이다.
#   세 번째 선택지가 필요하다 — **묻는다.** 술어는 못 묻는다. 그래서 반환에 질문을 싣는다.
#
#   게이트는 **왜** 못 정했는지 이미 안다 ⇒ 질문이 구체적이고, 다음 방법까지 붙는다.
#   (지금까지 경고 문구로 쓰던 문장이 그대로 질문이 된다.)
ASK_METHOD = {
    # ── 컷 일반화(2026-09-04)가 내는 판정들. 안내가 없으면 기본 문구로 떨어지고,
    #    에이전트는 "무슨 다음 수가 있는지"를 모른 채 같은 짝을 다시 낸다.
    "not_a_cut":
        "The declared guards are NOT a cut: removing all of them still leaves a path from the "
        "function entry to the sink, i.e. there is a way in that crosses none of your guards. "
        "Find that path (it is usually a SECOND ingress with its own check) and add its guard to "
        "`guards=`, or the rejection does not hold.",
    "no_escape":
        "Your guards form a cut, but NO edge out of any of them avoids the sink — so nothing is "
        "actually being filtered. Point at the failure path (the drop / return / assert arm). If "
        "there is none, the 'guard' does not guard anything.",
    "cut_needs_judgement":
        "Your guards cut the sink, but the graph's MINIMAL cut is a strict subset of what you "
        "declared. The extra members may be a refinement chain on the same value (legitimate) or "
        "padding (not). That distinction needs the comparison instructions read, so it is not "
        "decided mechanically - an adversary reviews it. Make sure `evidence=` contains the "
        "disassembly of EVERY declared guard, showing what each one compares.",
    "both_edges":
        "The branch you named reaches the sink on BOTH edges - it separates nothing. Either name "
        "the branch whose failure arm actually leaves (usually the LAST comparison of a chain), "
        "or declare the whole set with `guards=` if the invariant is established by several "
        "blocks together.",
    # ★ 2026-09-04, 원장 33건(answered) 을 읽고 고쳤다. 이 벽이 답해진 질문의 **85%** 다.
    #   그리고 결말이 **정반대 둘**로 갈린다 — 옛 문구는 그중 하나로 가는 길만 안내했다:
    #     (1)(2) 는 둘 다 "어딘가에 가드가 있다"를 전제한다. 그런데 실제로 답해진 것의
    #     절반 가까이는 **"가드가 없어서 결함"** 이었다(S11-P3b probe 범위 불일치,
    #     S15-AM1c AccessMode=KernelMode, S15-C2 RemoveEntryList 임의쓰기, S20 feature-off …).
    #   소진 기록이 그 대가를 보여준다: "게이트가 제시한 두 경로를 모두 시도했다 …
    #   이 싱크를 제약하는 분기는 하나뿐" — **없는 가드를 찾다 죽었다.**
    "dominates_only":
        "The value the guard reads never reaches the sink operand. The gate cannot tell WHICH "
        "of two opposite things this is, so answer that first:\n"
        "  (A) THE SINK OPERAND IS NOT ATTACKER-DERIVED at all -> no guard is needed and the "
        "rejection stands. Show it the way this ledger's own settled rows did: name every "
        "operand's origin (driver-planted constant, compile-time offset, read-only .rdata "
        "table decoded exhaustively, width fixed by the instruction pair itself).\n"
        "  (B) IT IS ATTACKER-DERIVED AND NOTHING CONSTRAINS IT -> then this is not a "
        "rejection, IT IS THE DEFECT. File it as a confirmation. Half of the answered "
        "questions on this exact wall ended here: a probe covering a shorter range than the "
        "sink reads, AccessMode=KernelMode skipping the access check, a length checked "
        "against one value and used against another, a feature gate that is OFF by default.\n"
        "  (C) only if neither holds: name the OTHER guard that constrains this sink, or show "
        "the path that value takes ONE MORE HOP (`sink_gates` enumerates the cmp/call that "
        "dominate the sink; give it `sink=`, not `target=`).\n"
        "KNOWN GATE LIMITS - if your guard has this shape, the gate is wrong and (A)/(B) is "
        "still the answer: the tracked value is a MEMORY operand (`cmp rax, [rbp-1]` - only "
        "the register term is followed), or it round-trips through another register "
        "(`mov rbx, rcx` ... `mov rcx, rbx` reads as a different value).",
    "no_branch":
        "The guard block does not have two successors — it is an indirect branch. DECODE THE "
        "DISPATCHER, recover the (code/major -> slot) mapping, and re-submit the pair that "
        "actually lies on that path. If it goes through guard-CF "
        "(`_guard_dispatch_icall`), the real target is one hop further.",
    "indirect_only":
        "Nothing calls the sink function directly (function pointer / vtable / callback). The "
        "call graph cannot settle this. What you CAN do: (1) recover the selector->handler "
        "mapping with `dispatch_table`; (2) use `find_bytes` to find where that function's "
        "address is referenced AS DATA (vtable / dispatch array) and trace that array's "
        "consumers back with `import_xref` / `callers`; (3) use `disassemble` to read the slot "
        "offset at the indirect call site and match it to the array index.",
    "sink_unreachable":
        "The sink block is not reachable from the guard block. The pair may lie on different "
        "paths — pick the entry point again and show that both points sit in the SAME "
        "execution.",
    "unbounded":
        "No successor reaches the sink — the CFG is incomplete (indirect branch). Recover the "
        "edges with `dispatch_table`; if it is a jump table, decode the table directly with "
        "`find_bytes`, enumerate the arms, and ask again. Do NOT do a cumulative subtraction "
        "ladder (`sub r,1`) in your head — expand it with `disassemble`.",
    "cross_function":
        "The pair crosses a function boundary. Compute dominance over the call graph with "
        "`authz.gates_inter` — the 'checked once at the door' shape lives here.",
    "no_pdata":
        "The function is not in .pdata. Do NOT guess the bounds — check whether adjacent "
        "chunks were merged via `pe.merged_functions` (chunk splitting trips here) and ask "
        "again.",
    "no_image":
        "The target image could not be opened. Settle the binary path and re-run — a verdict "
        "reached without the image is not a negative.",
    "double_fetch_unchecked":
        "This is a METHOD_NEITHER target and YOU HAVE NOT RULED OUT THE DOUBLE-FETCH AXIS. The "
        "user pointer arrives without a kernel copy, so 'guarded' only holds if you show the "
        "value CHECKED and the value USED come from the SAME READ. Either (1) cite the "
        "instruction that takes a kernel copy (ProbeForRead / capture), or (2) show that the "
        "check and the use come from the same register / stack slot. If there is a re-read, "
        "THAT is the defect.\n"
        "Tool: `double_fetch` (CFG dataflow, control-enforced). NOTE: that tool seeds its "
        "lineage from `entry rdx = IRP`, so FAST-IO IS OUT OF ITS RANGE — for a fast-io "
        "handler, follow the argument registers by hand from the entry with `disassemble`. "
        "A zero result from that tool must NOT be written down as clean.",

}


def asks(status="open"):
    """ASK 큐. `status=None` 이면 전부."""
    return [q for q in (STATE.get("asks") or [])
            if status is None or q.get("status") == status]


def _ask_open(tgt):
    for q in (STATE.get("asks") or []):
        if q.get("target") == tgt and q.get("status") == "open":
            return q
    return None


def _ask_close(tgt, vid, how="answered", note=""):
    """질문을 닫는다. **판정이 나면 자동으로 닫힌다** — 안 그러면 큐가 영원히 자란다."""
    n = 0
    for q in (STATE.get("asks") or []):
        if q.get("target") == tgt and q.get("status") == "open":
            q["status"] = how
            q["resolved_by"] = vid
            q["resolved_t"] = time.strftime("%m-%d %H:%M")
            if note:
                q["resolution"] = note[:300]
            n += 1
    return n


# ── 깨진 기각 기록부 (원장 **밖**) ────────────────────────────
# ★ 왜 원장 밖인가: 지휘자는 `state/*.json` 전체를 읽는다. 깨진 기각을 거기 넣으면
#   회차마다 수십 건씩 늘어 지휘자가 읽을 것이 폭증한다. 그런데 이 기록의 소비자는
#   지휘자가 아니라 **다음 회차의 분석가**다 — 그래서 매체를 가른다.
#
# ★ 왜 필요한가 (실측 2026-09-04): 심문자가 기각을 깬 것이 **213건**인데
#   원장에 사유가 남은 것은 11건이고 그마저 klass 가 비어 있다.
#   `mark_interrogated()` 가 **sustained 분기에서만** 불리기 때문이다 —
#   깨진 기각은 판정으로 기록되지 않으니 붙일 행이 없다.
#   사유는 `work/transcript.*.log` 로 갔는데 그 파일은 **회차마다 truncate** 된다.
#   ⇒ 213개의 "왜 이 기각이 안 서는가"가 흔적 없이 사라졌다. 그중에는 새 리드도 있었다
#     (살아남은 1줄에도 `AhcDispatch` 의 unprobed 0x1B8 memcpy 가 딸려 있었다).
def _break_dir():
    """★ 네임스페이스를 따른다. 안 따르면 **벤치·scratch 가 프로덕션 기록에서 학습**한다 —
    `_lesson_ledgers` 는 이미 그렇게 고쳤는데 여기만 빠져 있었다(T39 가 그걸로 터졌다).
    같은 사고가 08-24 에 벤치→pcw.sys 원장 오염으로 이미 났다."""
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports", "breaks")
    if PROVENANCE != "prod":
        d = os.path.join(d, "_" + PROVENANCE)
    return d


def _break_path(image=None):
    """★ 파일 키는 **이미지**다(표적 함수가 아니다). 함수로 가르면 표적마다 수백 개의
    한 줄짜리 파일이 생기고 누적이라는 목적 자체가 사라진다. 함수명은 행 안에 들어간다."""
    _d = _break_dir()
    os.makedirs(_d, exist_ok=True)
    return os.path.join(_d, _key(image or STATE.get("target") or "unknown") + ".jsonl")


# ★ 2026-09-07 — 리드 큐와 재제출 큐를 **갈라야 한다.**
#   실측(누적 71건): wrong_pair 28(39%) · other_constructor 11 · bound_wrong 11 ·
#   indirect_entry 7 · door_only 5 · window_too_short 5 · not_measured 4.
#   `break_digest` 자신이 적어둔 해석대로 `wrong_pair` 는 **분석가가 엉뚱한 짝을 냈다**는
#   서류 문제이지 리드가 아니다. 둘을 섞어 두니 실질 리드 20건이 71건처럼 보이고,
#   그러면 "큐 소진"이 불가능한 목표로 보여 아무도 손대지 않는다.
_REFILE_KLASS = {"wrong_pair"}


def break_kind(klass):
    """break 한 건이 **리드**인가 **재제출**인가. klass 하나로 갈린다."""
    return "refile" if (klass or "") in _REFILE_KLASS else "lead"


_BREAK_ESCALATE_AT = 3          # 같은 표적에서 이 횟수째 파손이면 승격한다


def _break_key(target, claim=""):
    """파손을 **표적 정체**로 묶는 키. 이름이 바뀌어도 같은 행으로 잡힌다.

    반환: {정규화한 함수명} | {문자열에서 뽑은 VA}. 교집합이 있으면 같은 행.
    """
    t = str(target or "").lower()
    out = set()
    for v in measure_vas(t + " " + str(claim or "")):
        out.add(("0x%x" % v) if isinstance(v, int) else str(v).lower())
    nm = re.sub(r'^[a-z0-9_]+!', '', t.split('@')[0].split('(')[0].strip())
    nm = re.sub(r'[^a-z0-9_]', '', nm)[:48]
    if len(nm) >= 6:
        out.add(nm)
    return out


def record_break(target, v, args=None, kind="interrogator"):
    """깨진 기각 하나를 append 한다. **STATE 를 건드리지 않는다** — 지휘자 부하 0.

    누적된다(회차마다 지워지지 않는다). 그게 이 파일의 존재 이유다.

    ★ 2026-09-07 — `id` 와 `status` 를 같이 박는다. 없으면 큐가 **줄지 않는다**:
      답한 것과 안 답한 것이 구분되지 않아 매 회차 같은 것을 다시 보여주거나,
      `B[-n:]` 에 밀려 영영 안 보이거나 둘 중 하나다(둘 다 실제로 일어났다).
    """
    a = args or {}
    bid = "%s-%s" % (time.strftime("%m%d%H%M%S"), uuid.uuid4().hex[:4])
    row = {"id": bid, "t": time.strftime("%Y-%m-%d %H:%M"), "kind": kind,
           "queue": break_kind((v or {}).get("klass")),
           "status": "open",
           "target": str(target)[:120],
           "klass": (v or {}).get("klass"),
           "reason": str((v or {}).get("reason") or "")[:1200],
           "next_method": str((v or {}).get("next_method") or "")[:800],
           "claim": str(a.get("claim") or "")[:300],
           "rejected_as": a.get("klass"),
           "vid": a.get("id"),
           "guard": a.get("guard"), "sink": a.get("sink")}
    # ★ 2026-09-23 — **표적 단위 반복 카운터.**
    #   ★ 처음엔 판정 id(vid)로 셌는데 **한 번도 안 걸린다**: 실제 루프는 id 를 바꿔가며
    #     돈다 — mrxsmb 09-22 밤의 그 행은 `QUIC-RECV-SEED-001 → -R2 → -R3 → -R4 → -R5`
    #     로 이름을 갈아입었다. 그래서 키를 **표적 정체**로 잡는다: 모듈 접두사와 주소를
    #     떼어낸 함수명 + 문자열에서 뽑은 VA 집합. 둘 중 하나라도 겹치면 같은 행으로 본다.
    #     (그 밤의 실측: 파손 20건 중 **10건이 한 함수** — 이름 4건은 VA 가 없었고
    #      6건은 `mrxsmb!SmbQuicReceiveEx@0x140052860` 이었다. 이름축이 없으면 4건을 놓친다.)
    #   ★ 큐 값은 {lead, refile} 그대로 둔다 — 새 큐 값을 만들면 `open_leads(queue="lead")`
    #     가 그 행들을 **어느 큐에서도 못 보게** 된다(큐가 두 종류를 섞는 그 병).
    #     대신 반복 행은 서류 큐에서 꺼내 **lead 로 되돌리고** 도장을 찍는다.
    _key = _break_key(target, a.get("claim"))
    _n = 0
    if _key:
        try:
            with open(_break_path(), encoding="utf-8") as _bf:
                for _l in _bf:
                    if not _l.strip():
                        continue
                    try:
                        _o = json.loads(_l)
                    except ValueError:
                        continue
                    if _break_key(_o.get("target"), _o.get("claim")) & _key:
                        _n += 1
        except OSError:
            _n = 0
    row["attempt"] = _n + 1
    if _n + 1 >= _BREAK_ESCALATE_AT:
        # ★ 2026-09-23 (2판) — **`queue` 를 변조하지 않는다.**
        #   첫 판은 refile→lead 로 덮었는데, `break_digest` 가 그 칸으로 "재제출 대기 N"
        #   을 세고 있어서 집계가 깨졌다(test_breaks 가 잡았다). 라벨을 덮는 대신
        #   **도장을 따로 찍고** `open_leads` 가 그 도장을 보게 한다 — 정보를 안 버린다.
        row["escalated"] = True
        row["escalate_hint"] = (
            "이 표적에서 %d번째 파손이다. 라벨을 다섯 번째로 고쳐 쓰지 마라 — "
            "빠진 것은 **관측**일 가능성이 높다. `verdict(action='gate_blocked', "
            "gate='needs-measurement', …)` 로 봉하고 그 관측을 요구하라." % (_n + 1))
    try:
        with open(_break_path(), "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    except OSError as e:
        sys.stderr.write("\033[93m[breaks] 기록 실패: %s\033[0m\n" % e)
        return None
    return row


# ★ 리드가 닫히는 길은 **셋뿐**이다. 여기에 `exhausted` 는 없다 —
#   ASK 가 정확히 그 출구로 샜다(생성 395 · 답함 41(10%) · **소진 194(49%)**,
#   09-04 하루에만 81건이 소진으로 닫혔고 그날 답한 것은 2건이다).
#   소진 압력을 걸면 답이 아니라 포기가 나온다는 것이 이 원장의 실측이다.
CLOSE_HOWS = {
    "refuted":        "반박자가 이 축의 확정을 죽였다 (적대자가 판단했다)",
    "measured":       "실측이 갈랐다 (대조 통과한 관측이 있다)",
    "reinterrogated": "다시 기각을 냈고 심문자가 이번엔 **못 깼다**",
}


def close_break(bid, how, why="", image=None):
    """리드 한 건을 닫는다. **append-only** — 닫힘도 한 줄로 쌓는다.

    ★ 파일을 다시 쓰지 않는 이유: 같은 이미지에 병렬 회차가 append 한다.
      재작성하면 그 사이의 append 를 통째로 날린다.
    """
    how = (how or "").strip().lower()
    if how not in CLOSE_HOWS:
        return ("[CLOSE REFUSED] how=%r 은 리드를 닫는 길이 아니다. 셋뿐이다:\n"
                % how + "\n".join("  · %s — %s" % kv for kv in CLOSE_HOWS.items())
                + "\n소진(exhausted)은 없다. 못 닫으면 열어 둔 채로 두는 것이 정직하다.")
    rec = {"op": "close", "ref": str(bid), "how": how,
           "why": str(why or "")[:600], "t": time.strftime("%Y-%m-%d %H:%M")}
    try:
        with open(_break_path(image), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as e:
        return "[CLOSE FAILED] %s" % e
    return "리드 %s 를 `%s` 로 닫았다 — %s" % (bid, how, CLOSE_HOWS[how])


# ── 질문 큐 — **수신자로 가른다** ─────────────────────────────
# ★ 2026-09-07 실측이 만든 것. 열린 질문 160건의 내역:
#     분석가가 낸 것 102 → 답함 34(33%) · 소진 64 · **열림 4**
#     지휘자가 낸 것 293 → 답함  7( 2%) · 소진 130 · **열림 156**
#   쌓인 160건 중 156건이 지휘자 것이다. 그리고 그중 최소 85건은 표적 분석이 아니라
#   원장·게이트 감사 질문이다(target 이 아예 `harness / …` 로 시작한다. CQ87 은 본문에
#   "행동하지 말고 수치로 보고하라"고 못 박혀 있다).
#   ⇒ 분석가에게 답할 수 없는 질문을 쌓아 놓고 답한 비율을 세고 있었다.
#     소진 130건의 상당수는 포기가 아니라 **오배송 반송**이다.
_ASK_OPERATOR = re.compile(r'^\s*[\[\(]?\s*harness\b', re.I)


# ★ 2026-09-08 — **질문의 출처는 라벨이 아니라 랭킹 축이다.**
#   실측(전 원장): `by=conductor` 질문은 ahcache **185건 중 answered 0건**, wcifs 87건 중 2건.
#   게이트·반박자 질문은 같은 원장에서 **32.6% / 18.4%** 가 답해졌다. 그런데 열린 질문의
#   113/115 가 지휘자 것이라, 회전 창이 돌아도 **보이는 것은 사실상 지휘자 질문뿐**이었다.
#   그리고 가장 값이 날 질문 — 심문자의 `next_method` — 은 `asks` 에 **한 건도 없다**
#   (73건이 `reports/breaks/` 에 있고 전부 next_method 를 갖고 있는데 닫힌 건 1건).
_ASK_BY = ("gate", "refuter", "interrogator", "resisted", "conductor")
_ASK_BY_ALIAS = {"gate": "gate", "r3": "gate", "reject_gate": "gate",
                 "refuter": "refuter", "refute": "refuter", "rq": "refuter",
                 "interrogator": "interrogator", "interrog": "interrogator",
                 "break": "interrogator", "lead": "interrogator",
                 "resisted": "resisted", "resist": "resisted", "xq": "resisted",
                 "conductor": "conductor", "cq": "conductor"}


def normalize_ask_by(b, aid=""):
    """질문 출처를 정본 어휘로. 비어 있으면 **id 접두로 역추론**한다(옛 행 소급용).

    ★ 지어내지 않는다 — 접두가 어휘에 없으면 `gate` 로 떨어진다. 그게 옛 기본값이다
      (게이트가 판정 불가일 때 만드는 것이 이 큐의 원래 유일한 생산자였다).
    """
    tok = str(b or "").strip().lower()
    if tok in _ASK_BY_ALIAS:
        return _ASK_BY_ALIAS[tok]
    pre = str(aid or "")[:2].lower()
    return _ASK_BY_ALIAS.get(pre, "gate")


def ask_yield(state=None):
    """출처별 **답해진 비율**. 랭킹 가중치를 상수로 박지 않고 원장에서 잰다.

    ★ 상수로 박으면 표적이 바뀔 때 낡는다. 그리고 이 수치 자체가 관측 대상이다 —
      지휘자 질문의 수율이 오르면 랭킹이 저절로 따라가야 한다.
    ★ 표본이 적으면(<8) `None` 을 돌려준다 — 0 과 미측정을 안 섞는다.
    """
    S = state if state is not None else STATE
    agg = {}
    for a in (S.get("asks") or []):
        o = normalize_ask_by(a.get("by"), a.get("id"))
        d = agg.setdefault(o, {"n": 0, "answered": 0, "closed": 0})
        d["n"] += 1
        if a.get("status") == "answered":
            d["answered"] += 1
            d["closed"] += 1
        elif a.get("status") == "exhausted":
            d["closed"] += 1
    out = {}
    for o, d in agg.items():
        # ★ 분모는 **닫힌 것**이지 전체가 아니다. 열린 질문은 아직 실패한 게 아니라
        #   답해지지 않았을 뿐이다. 전체를 분모로 쓰면 **한꺼번에 생성된 새 출처가
        #   기회를 갖기도 전에 0% 로 바닥에 깔린다** — 첫 판이 정확히 그랬다
        #   (`resisted` 가 26건을 한 번에 만들자 0/26 = 0.0 이 됐다).
        # ★ 표본이 적으면(<8) `None`. 0 과 미측정을 안 섞는다.
        out[o] = {"n": d["n"], "answered": d["answered"], "closed": d["closed"],
                  "rate": (d["answered"] / d["closed"]) if d["closed"] >= 8 else None}
    return out


def _ask_t_key(a):
    """정렬용 시각 키. **저장 값은 안 고친다** — 저장소가 둘이고 주인이 다르다.

    ★ 2026-09-08 실측: 리드 저장소는 `2026-09-04 23:11`(연도 있음), 원장 질문은
      `08-30 01:06`(연도 없음)을 쓴다. 문자열 비교라 `"2026-…"` 이 `"09-…"` 보다
      **항상 뒤로** 밀렸고, 그래서 동점 구간에서 **심문자 질문이 영구히 꼴찌**였다.
      가장 값이 날 질문이 형식 불일치 하나로 안 보이고 있었다.
    """
    t = str((a or {}).get("t") or "")
    m = re.match(r'^\d{4}-(\d{2}-\d{2}.*)$', t)
    return m.group(1) if m else t


def ask_rank_key(a, yields=None):
    """단일 큐의 정렬키. **수율 > 시도횟수 > 오래된 순**.

    ★ 시도횟수(`attempts`)가 2순위인 이유: 같은 행에 게이트가 반복해서 판정 불가였다는
      뜻이고, 그건 `resisted` 가 세는 것과 같은 신호다. 큐가 하나면 그 신호가 여기 산다.
    """
    o = normalize_ask_by(a.get("by"), a.get("id"))
    y = (yields or {}).get(o) or {}
    r = y.get("rate")
    # 수율 미측정(None)은 **중간**에 둔다 — 0 으로 취급하면 새 출처가 영원히 바닥에 깔린다.
    r = 0.5 if r is None else r
    return (-r, -len(a.get("attempts") or []), _ask_t_key(a))


def ask_audience(a):
    """질문 한 건의 **수신자**. 지휘자가 이미 `harness /` 접두어를 쓰고 있어 기계로 갈린다."""
    return "operator" if _ASK_OPERATOR.match(str((a or {}).get("target") or "")) else "analyst"


def open_asks(state=None, audience=None, rank=False, include_leads=False):
    """열린 질문 **하나의 큐**. 기본은 수율 랭킹, `rank=False` 면 옛 동작(오래된 순).

    ★ 2026-09-08 — 기본값은 **옛 계약 그대로**다(오래된 순 · 원장 질문만). 합류와 랭킹은
      **명시적 옵트인**이다: `ask_window` 는 회전과 건수를 세는 렌더러라 `_ask_close` 로
      닫을 수 없는 리드가 섞이면 계약이 깨진다(`test_askqueue` 가 그걸 잡았다).
      단일 큐를 보는 것은 `ask_queue()` 와 `verdict(action='asks')` 다.

    ★ 심문자 리드를 **합류시키되 저장소는 안 옮긴다**
      (`reports/breaks/` 를 원장 밖에 둔 이유가 유효하다 — 지휘자가 읽을 것이 폭증한다).
      **큐가 하나라는 것은 뷰가 하나라는 뜻이지 저장소가 하나라는 뜻이 아니다.**
      닫는 길이 다르므로 `_close_via` 를 실어 보낸다.
    """
    S = state if state is not None else STATE
    out = [a for a in (S.get("asks") or []) if (a.get("status") or "open") == "open"]
    if include_leads:
        # ★ 2026-09-11 — **표적이 안 잡히면 리드를 아예 싣지 않는다.**
        #   `breaks(None)` 은 "전 표적"이라는 뜻이다(운영자 큐에서는 옳다). 그런데 여기로
        #   `None` 이 흘러들면 **남의 표적 큐가 이 표적의 이어받기에 실린다.**
        #   실측(bfs.sys 첫 회차 00:18): 원장 0행짜리 새 표적의 SEED 에 열린 질문 **52건**이
        #   실렸고 전부 msquic·ahcache 것이었다. 첫 접촉 세션이 남의 질문부터 읽는다.
        #   ⇒ 부재를 "전체"로 해석하지 마라. 표적을 모르면 **0건이 정답**이다.
        #   ★ 그리고 원장의 `target` 은 **스테이징 전체 경로**다(`work/night/x.sys/x.sys`)
        #     반면 `reports/breaks/` 는 basename 으로 산다. 정규화 없이는 필터가
        #     조용히 0건을 내고(안전한 방향) 표적이 비면 전체를 낸다(위험한 방향).
        _tgt = os.path.basename(str(S.get("target") or "").strip()) or None
        try:
            for b in (breaks(_tgt, open_only=True, queue="lead") if _tgt else []):
                out.append({"id": b.get("id"), "target": b.get("target"),
                            "why": "심문자가 이 기각을 깼다 [%s] %s"
                                   % (b.get("klass") or "-", str(b.get("reason") or "")[:160]),
                            "method": b.get("next_method") or b.get("reason") or "",
                            "klass": b.get("klass"), "cfg": None, "status": "open",
                            "by": "interrogator", "kind": "need_observation",
                            "attempts": [], "t": b.get("t") or "",
                            "_close_via": "verdict(action='lead', id=%s, how=…, why=…)"
                                          % b.get("id")})
        except Exception:
            pass                        # 리드 저장소 실패가 원장 질문을 죽이면 안 된다
    if audience:
        out = [a for a in out if ask_audience(a) == audience]
    if not rank:
        return sorted(out, key=_ask_t_key)
    _y = ask_yield(S)
    return sorted(out, key=lambda a: ask_rank_key(a, _y))


def ask_window(state=None, n=6, audience="analyst"):
    """이어받기에 실을 **회전 창**. (창, 전체수, 시작오프셋)

    ★ 옛 동작은 `asks[:4]` — 오래된 순 **고정**이었다. 실측: ahcache 는 열린 질문이
      115건인데 매 회차 보이는 것은 항상 같은 4건(CQ65~68, 09-05 16:02 생성)이었고
      나머지 111건은 **한 번도 노출된 적이 없다**. 생성은 회차당 3~5건인데 노출이
      4건 고정이라 대역폭이 안 맞았다 — 답한 비율이 낮은 게 아니라 도달을 안 했다.
      그 증거: 09-07 에 지휘자가 CQ182 `harness / CQ66`, CQ184 `harness / CQ66 klass
      vocabulary` 를 새로 만들었다. 창에 갇힌 CQ66 을 두고 같은 주제를 재발행한 것이다.

    ★ 회전 키는 **회차 수**다. 새 상태를 안 만든다 — `shown` 카운터를 두면 이어받기가
      원장을 써야 하는데, 이어받기는 파일에서 읽은 사본으로 도는 렌더링이라 쓸 수 없다
      (임시 경로로 `save()` 를 무해화해 둔 자리다).
    """
    S = state if state is not None else STATE
    A = open_asks(S, audience=audience)
    if not A:
        return [], 0, 0
    r = len(S.get("rounds") or [])
    off = (r * n) % len(A)
    win = (A + A)[off:off + n] if len(A) > n else A
    return win, len(A), off


def backfill_graveyard_trust(state=None):
    """묘지 행에 **심문 결과를 되찍는다.** 멱등이고, 판정 쪽 기록만 옮긴다.

    ★ 왜 (2026-09-07 실측): 묘지 616행 중 `broke` 표식이 있는 것은 **12행**뿐이었다.
      표식을 박기 시작한 것이 09-06 이라 그 이전 행에는 필드 자체가 없다. 그런데
      `verdicts` 쪽에는 43건이 `interrogation.broke=True` 로 남아 있다 —
      **같은 사실이 한 저장소에만 있었다.** 묘지를 읽는 소비자(프라이밍·`lessons`·
      `_resolve_row` 폴백)에게는 그 행들이 전부 동등한 음성으로 보인다.

    ★ 새 사실을 만들지 않는다. `verdicts[i].interrogation` 을 같은 **id** 의 묘지 행에
      복사할 뿐이다. 충돌(두 저장소가 다른 값)이면 **건드리지 않고 센다** — 조용히 덮으면
      어느 쪽이 옳은지 영원히 못 가린다.
    """
    S = state if state is not None else STATE
    src = {}
    for v in (S.get("verdicts") or []):
        if v.get("status") != "기각" or v.get("id") is None:
            continue
        ig = v.get("interrogation") if isinstance(v.get("interrogation"), dict) else {}
        if ig.get("broke") is not None or v.get("interrogated") is not None:
            src[str(v.get("id"))] = (bool(ig.get("broke")), v.get("interrogated"),
                                     ig.get("klass"))
    stamped = same = conflict = 0
    for g in (S.get("graveyard") or []):
        r = src.get(str(g.get("id")))
        if not r:
            continue
        broke, interrogated, klass = r
        if g.get("broke") is None:
            g["broke"] = broke
            if g.get("interrogated") is None:
                g["interrogated"] = interrogated
            if broke and klass and not g.get("break_klass"):
                g["break_klass"] = klass
            stamped += 1
        elif bool(g.get("broke")) != broke:
            conflict += 1
        else:
            same += 1
    return {"stamped": stamped, "already": same, "conflict": conflict}


def breaks(target=None, limit=0, open_only=False, queue=None):
    """기록부를 읽고 **닫힘 레코드를 접는다.** target 이 없으면 전 표적.

    ★ 2026-09-07 — 옛 행에는 `id`/`status`/`queue` 가 없다(누적 71건 전부).
      읽을 때 백필한다: id 는 파일 안 **순번**으로 결정론적으로 만들고
      (닫힘 레코드는 순번에서 제외한다 — 안 그러면 닫을 때마다 id 가 밀린다),
      queue 는 klass 에서 유도한다.
    """
    import glob as _g
    _d = _break_dir()
    os.makedirs(_d, exist_ok=True)
    files = ([_break_path(target)] if target      # 여기서의 target 은 **이미지**다
             else sorted(_g.glob(os.path.join(_d, "*.jsonl"))))
    out = []
    for fp in files:
        rows, closes = [], {}
        key = os.path.basename(fp)[:-6]
        try:
            with open(fp, encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        r = json.loads(ln)
                    except ValueError:
                        continue
                    if r.get("op") == "close":
                        closes[str(r.get("ref"))] = r
                    else:
                        rows.append(r)
        except OSError:
            continue
        for i, r in enumerate(rows):
            r.setdefault("image", key)
            if not r.get("id"):
                r["id"] = "%s#%03d" % (key.split(".")[0][:12], i)
            if not r.get("queue"):
                r["queue"] = break_kind(r.get("klass"))
            c = closes.get(str(r["id"]))
            if c:
                r["status"], r["closed_how"] = "closed", c.get("how")
                r["closed_t"], r["closed_why"] = c.get("t"), c.get("why")
            else:
                r.setdefault("status", "open")
            out.append(r)
    if queue:
        out = [r for r in out if r.get("queue") == queue]
    if open_only:
        out = [r for r in out if r.get("status") != "closed"]
    return out[-limit:] if limit else out


def open_leads(target=None):
    """열린 **리드**만, 오래된 것부터. WIP cap 과 이어받기가 같은 함수를 본다.

    ★ 2026-09-23 — **승격된 재제출도 리드로 친다.** 같은 표적에서 %d회 깨진 행은
      서류 문제가 아니라 작업이다(mrxsmb 09-22: 한 함수에서 10회). 다만 `queue` 칸은
      건드리지 않는다 — `break_digest` 가 그 칸으로 재제출 건수를 센다.
    """ % _BREAK_ESCALATE_AT
    L = breaks(target, open_only=True, queue="lead")
    _esc = [r for r in breaks(target, open_only=True)
            if r.get("escalated") and r.get("queue") != "lead"]
    return sorted(L + _esc, key=lambda r: str(r.get("t") or ""))


def break_digest(target=None, n=None, width=260):
    """★ 다음 회차 분석가에게 줄 **리드 큐**. 요약이 아니라 작업 목록이다.

    ★ 2026-09-07 재설계 — 옛 동작은 `B[-n:]`, n=3 이었다. 즉 **최신 3건 LIFO**.
      누적 71건에 새 break 가 3건 생기면 그 전 것은 **영영 안 보인다** —
      큐를 만들어 놓고 큐의 앞쪽을 버리고 있었다. 이제 오래된 미해결부터 준다.

    ★ 두 큐를 가른다(`break_kind`): `wrong_pair` 는 짝을 다시 선언하면 되는
      **서류 문제**라 리드 큐에 있으면 실질 20건이 71건처럼 보인다. 건수만 알려준다.
    """
    n = int(n if n is not None else getattr(_cfgmod(), "LEAD_DIGEST_N", 8))
    B = breaks(target)
    if not B:
        return ""
    import collections as _c
    L = [x for x in B if x.get("queue") == "lead"]
    R = [x for x in B if x.get("queue") == "refile"]
    Lo = sorted([x for x in L if x.get("status") != "closed"],
                key=lambda r: str(r.get("t") or ""))
    Rc = sum(1 for x in R if x.get("status") != "closed")
    done = sum(1 for x in B if x.get("status") == "closed")
    c = _c.Counter(b.get("klass") or "(미기재)" for b in Lo)
    out = ["## ⟂ 리드 큐 — 심문자가 깬 기각 (reports/breaks/)", "",
           "  열린 리드 **%d** · 재제출 대기 %d · 닫힘 %d  (누적 %d)"
           % (len(Lo), Rc, done, len(B)), ""]
    if c:
        out += ["  " + " · ".join("%s %d" % kv for kv in c.most_common(8)), ""]
    _hint = {"wrong_pair": "네가 선언한 가드/싱크 짝이 주장과 다른 것을 가리키고 있다",
             "other_constructor": "같은 객체의 **다른 생성자**가 그 필드를 다르게 세운다 — 인구 절반이 면제다",
             "door_only": "검사가 open/create 에서 **한 번만** 돈다 — 연산마다 재적용되는지 봐라",
             "indirect_entry": "함수포인터·vtable·디스패치가 가드를 우회한다. `callers()` 는 직접호출만 본다",
             "bound_wrong": "지배는 증명됐지만 **경계 상수**가 틀렸다",
             "window_too_short": "고정 크기 창 안에서 '있다/없다'를 판단했다 — 한 홉 옆을 봐라",
             "not_measured": "정적 기각이다. 핸들러가 **실행되기는 하는가** — 실측 한 번이면 갈린다"}
    if c:
        top = c.most_common(1)[0][0]
        if top in _hint:
            out += ["★ 1위 `%s` — %s" % (top, _hint[top]), ""]
    if Rc:
        out += ["  (`wrong_pair` %d건은 **재제출 큐**다 — 결함이 아니라 짝 선언 문제이므로 "
                "리드로 세지 않는다)" % Rc, ""]
    out.append("**오래된 미해결부터 %d건.** 닫는 길은 셋뿐이다 — "
               "`verdict(action='lead', id=<리드id>, how=refuted|measured|reinterrogated, why=…)`"
               % min(n, len(Lo)))
    for b in Lo[:n]:
        out.append("- `%s` [%s] %s  (%s)"
                   % (b.get("id"), b.get("klass") or "-", str(b.get("target"))[:56],
                      str(b.get("t") or "")[:10]))
        nm = (b.get("next_method") or b.get("reason") or "").replace("\n", " ")
        if nm:
            out.append("    다음 수: %s" % nm[:width])
    if len(Lo) > n:
        out.append("  … 그리고 %d건 더 (전부 `verdict(action='leads')`)" % (len(Lo) - n))
    return "\n".join(out)


# ── L1 · 원재료 통합 ──────────────────────────────────────────
# ★ 세 곳에 흩어져 있던 실패/돌파 기록을 한 모양으로 읽는다.
#   answered  — 그 벽을 **실제로 뚫은** 기록. 가장 값지고, 지금까지 아무 데도 안 실렸다
#   exhausted — 뚫지 못하고 닫힌 기록. "이 방법은 이미 죽었다"
#   break     — 심문자가 기각을 깬 기록 (reports/breaks/, 2026-09-04 신설)
#
# ★ 원재료는 **상한다.** 실측: `sink_gates` 고장 불만이 소진 기록 3건에 남아 있는데
#   그 버그는 09-02 에 고쳐졌다(`tools.py` 의 사후 기록). 낡은 부정 지식을 그대로
#   먹이면 문헌이 말하는 "틀린 절차의 전파"가 **부정 방향으로** 일어난다.
#   ⇒ 날짜를 같이 싣고, 오래된 것은 그렇게 표시한다.
_LESSON_SKIP = ("dbg", "dbg2", "e2e", "demo", "rt", "bench", "bench_gate", "niede",
                "GOALTEST.sys", "GOALBY.sys", "XIMG.sys", "KslD.sys")


def _lesson_ledgers():
    # ★ 네임스페이스를 따른다. `state/` 를 하드코딩하면 **벤치가 프로덕션에서 학습**한다 —
    #   이 저장소는 이미 그 반대 방향으로 사고를 냈다(벤치가 pcw.sys 원장을 오염, 08-24).
    import glob as _g
    d = _ns_dir()
    out = []
    for fp in sorted(_g.glob(os.path.join(d, "*.json"))):
        nm = os.path.basename(fp)[:-5]
        if nm in _LESSON_SKIP or nm.startswith(("scratch", "_", "test")):
            continue
        out.append((nm, fp))
    return out


def lessons(cfg_verdict=None, srcs=("answered", "exhausted", "break", "graveyard"),
            min_len=60):
    """원재료를 한 모양으로. `cfg_verdict` 를 주면 그 벽의 것만.

    `min_len` — 짧은 것은 버린다. 테스트 원장의 `resolution` 이 "c" 같은 한 글자였다.
    """
    out = []
    for nm, fp in _lesson_ledgers():
        try:
            d = json.load(open(fp, encoding="utf-8"))
        except Exception:
            continue
        # ★ ① 그 표적이 결국 어떻게 끝났는가 — 같은 벽이 **정반대 두 결말**을 갖기 때문이다.
        #   dominates_only 돌파 25건을 읽어보면 절반은 "기각이 섰다"(오퍼랜드가 공격자 것이
        #   아니었다)이고 절반은 "그게 결함이었다"(제약이 아예 없었다). 한쪽만 보여주면
        #   편향이 아니라 **오답을 가르치는 것**이 된다.
        # ★ 링크는 **`resolved_by` → 판정 id** 로 잡는다. target 문자열로 맞추면 틀린다 —
        #   실측: `WcPortMessage@0x140035dd0` 하나에 판정이 2건 붙어 있어서, 스택릭 질문에
        #   **무관한 기각**의 상태가 라벨로 달렸다. 그건 편향이 아니라 오답이다.
        #   `_ask_close()` 가 남기는 `resolved_by` 는 정확한 링크다(answered 33/33 성립).
        _vst = {str(v.get("id")): v.get("status") for v in (d.get("verdicts") or [])}
        for q in (d.get("asks") or []):
            st = (q.get("status") or "").lower()
            if st not in srcs:
                continue
            if cfg_verdict and q.get("cfg") != cfg_verdict:
                continue
            txt = str(q.get("resolution") or "").strip()
            if len(txt) < min_len:
                continue
            out.append({"src": st, "image": nm, "cfg": q.get("cfg"), "klass": q.get("klass"),
                        "target": q.get("target"), "text": txt,
                        "outcome": {"기각": "clean", "확정": "defect",
                                    "경계보류": "defect"}.get(
                                        _vst.get(str(q.get("resolved_by") or ""))),
                        "t": q.get("resolved_t") or q.get("t") or "",
                        "attempts": len(q.get("attempts") or [])})
        # ★ ⑥ klass 축 — 묘지는 "이 사유로 죽은 선례"다. 반박자 킬(24) · 심문자 파기(213)
        #   경로는 cfg 가 아니라 klass 를 키로 쓰는데, 지금까지 그 축엔 회수가 없었다.
        if "graveyard" in srcs:
            for gy in (d.get("graveyard") or []):
                if cfg_verdict and gy.get("klass") != cfg_verdict:
                    continue
                txt = str(gy.get("reason") or "").strip()
                if len(txt) < min_len:
                    continue
                out.append({"src": "graveyard", "image": nm, "cfg": gy.get("klass"),
                            "klass": gy.get("klass"), "target": gy.get("target"),
                            "text": txt, "outcome": "killed", "t": "", "attempts": 0})
    if "break" in srcs:
        for b in breaks():
            if cfg_verdict and b.get("klass") != cfg_verdict:
                continue
            txt = str(b.get("next_method") or b.get("reason") or "").strip()
            if len(txt) < min_len:
                continue
            out.append({"src": "break", "image": "", "cfg": b.get("klass"),
                        "klass": b.get("rejected_as"), "target": b.get("target"),
                        "text": txt, "t": b.get("t") or "", "attempts": 0})
    return out


def rules_for(key, n=2, width=300, image=None):
    """★ 이 벽/이 사유에서 실제로 나온 선례를 회수한다.

    회수 시점은 **결정론 게이트가 실패의 종류를 확정하는 순간**이다. 문헌(ProactAgent)이
    "회수를 학습된 정책 행동으로"라고 하는데 우리는 그럴 필요가 없다 — `cfg`/`klass` 가
    이미 실패의 이름이라 정확 매칭이면 오회수가 0이다(오버헤드도 0).

    선택 규율 셋 (전부 실측이 만든 것):
      ① **결말 균형** — 같은 벽이 정반대 두 결말을 갖는다. 한쪽만 뽑으면 오답을 가르친다.
         `clean`(기각이 섰다) 1건 + `defect`(그게 결함이었다) 1건을 나란히 놓는다.
      ② **이미지 층화** — 실측: `won[-2:]` 가 둘 다 wcifs 였다. ahcache 를 감사해도
         ahcache 자체 돌파 11건은 하나도 안 보였다. 현재 표적 것을 먼저 집는다.
      ⑤ **끌 수 있어야 한다** — `GATE_LESSONS=0`. 안 재면 도움인지 소음인지 영영 모른다.
    """
    if not key:
        return ""
    try:
        import config as _cf
        if not getattr(_cf, "GATE_LESSONS", True):
            return ""
    except Exception:
        pass
    L = lessons(key)
    if not L:
        return ""
    img = _key(image or STATE.get("target") or "")
    won = [x for x in L if x["src"] == "answered"]
    dead = [x for x in L if x["src"] != "answered"]

    def _pick(pool):
        """② 현재 표적 것 우선 → 그다음 다른 이미지. 같은 이미지가 두 번 나오지 않게."""
        seen, out = set(), []
        for want_mine in (True, False):
            for x in sorted(pool, key=lambda y: y.get("t") or "", reverse=True):
                mine = x["image"] == img
                if mine != want_mine or x["image"] in seen:
                    continue
                seen.add(x["image"])
                out.append(x)
        return out

    # ① 결말 균형 — clean 1 + defect 1 을 먼저 채우고, 모자라면 나머지로 메운다
    chosen = []
    for oc in ("clean", "defect"):
        c = _pick([x for x in won if x.get("outcome") == oc])
        if c:
            chosen.append(c[0])
    if len(chosen) < n:
        for x in _pick(won):
            if x not in chosen:
                chosen.append(x)
            if len(chosen) >= n:
                break
    chosen = chosen[:n]

    _LBL = {"clean": "기각이 섰다", "defect": "★ 결함이었다", None: "결말 미상"}
    out = []
    if chosen:
        out.append("\n\n── 이 벽에서 실제로 결말이 난 기록 %d건 중 %d건 ──" % (len(won), len(chosen)))
        for x in chosen:
            out.append("  · [%s %s · %s] %s"
                       % (x["image"], x["t"][:11] or "-",
                          _LBL.get(x.get("outcome"), "결말 미상"), x["text"][:width]))
        if len({x.get("outcome") for x in chosen}) > 1:
            out.append("  ↑ **같은 벽이 정반대로 끝난 두 사례다.** 어느 쪽인지가 이 판정의 질문이다.")
    elif dead:
        # klass 축(묘지·파기)은 돌파 기록이 없다 — 주의 선례로만 쓴다
        d2 = _pick(dead)[:n]
        out.append("\n\n── 같은 사유로 죽은 선례 %d건 중 %d건 ──" % (len(dead), len(d2)))
        for x in d2:
            out.append("  · [%s] %s" % (x["image"] or "-", x["text"][:width]))
    if won and dead:
        out.append("  ⚠ 같은 벽에서 소진/파기된 것이 %d건 있다 — 같은 방법을 또 쓰지 마라." % len(dead))
    if not out:
        return ""
    out.append("  (선례는 그 시점의 것이다. 도구가 고쳐졌을 수 있으니 재확인하라 — "
               "실제로 `sink_gates` 고장 불만이 고쳐진 뒤에도 기록에 남아 있었다.)")
    return "\n".join(out)


def ask_refuted(target, claim, klass, reason, would_change):
    """★ **반박자가 죽인 확정을 열린 질문으로 되돌린다.**

    지금까지 `would_change_my_mind`("무엇이 있으면 살아남는가")는 에이전트 컨텍스트에 한 번 뜨고
    사라졌다. 그 결과 반박자에게 죽은 확정 **11건 중 재제출 시도가 0건** — 사실상 반박자가
    최종심이었다. 문헌([[refs/01]])의 stage-gated 설계에는 judge/adjudicator 가 있는데 우리에겐 없다.
    큐에 넣어 두면 최소한 **다음 회차가 그 조건을 보고 이어받을 수 있다.**
    """
    if not would_change and not reason:
        return None
    q = {"id": "RQ%d" % (len(STATE.get("asks") or []) + 1), "target": target,
         "why": "반박자가 죽인 확정 [%s] %s" % (klass or "-", (reason or "")[:200]),
         "method": (would_change or "(the refuter gave no revival condition - change the axis of "
                                    "your evidence)")[:300],
         "cfg": "refuted", "status": "open", "attempts": [],
         "kind": "need_observation", "by": "refuter",
         "claim": (claim or "")[:300], "t": time.strftime("%m-%d %H:%M")}
    STATE.setdefault("asks", []).append(q)
    save()
    return q


# ★ ASK 는 두 가지가 섞여 있었다. 그 둘은 **다음 수가 완전히 다르다.**
#   - need_observation : 관측이 모자란다 (이미지 없음, .pdata 없음, CFG 구성 실패).
#                        사람/도구가 하나 더 재 와야 한다. LLM 을 불러도 나올 게 없다.
#   - inexpressible    : **분석은 끝났는데 게이트의 모델이 그 모양을 표현 못 한다.**
#                        (가드가 clamp 라 분기가 아니다 / 값이 구문상 싱크 오퍼랜드에 안 닿는다 /
#                         불변식을 여러 블록이 함께 세운다)
#   2026-09-04 실측: 전 표적 열린 질문의 cfg 사유는 `dominates_only` 가 **62건**으로 압도적 1위다.
#   그리고 `_gate_verdict` 는 "ASK 는 아직 기각이 아니니 심문하지 않는다"며 **그 62건에서
#   심문자를 건너뛰었다.** 즉 표현 불가로 막힌 행을 **어떤 LLM 도 본 적이 없고**, 다음 회차의
#   분석가가 같은 규칙에 다시 부딪히는 루프가 된다. 지휘자가 이걸 09-02 부터 14회 보고했다.
#   ⇒ 종류를 갈라서 `inexpressible` 은 **적대층에 한 번 넘긴다**(새 역할을 만들지 않는다 —
#     심문자의 맨데이트가 이미 "애매하면 기각이 서지 않는다"라 방향이 맞다).
#   ★ `not_a_cut` / `no_escape` 는 여기 넣지 않는다. 그 둘은 **모델의 한계가 아니라
#     그래프의 확정 반증**이다 — "가드를 하나도 안 거치는 길이 실제로 있다",
#     "어느 간선도 싱크를 피하지 않는다". 적대층이 뒤집을 수 있게 두면 LLM 이 계산 가능한
#     사실을 이기게 된다. `both_edges`/`not_dominated` 와 같이 **하드 거부**로 간다.
_ASK_INEXPRESSIBLE = ("dominates_only", "cut_needs_judgement", "no_branch")


def history_for(target, ask=None):
    """★ 판결자에게 줄 **전체 이력**. 이 판에서 이걸 보는 것은 판결자뿐이다.

    반박자·심문자·승격자는 일부러 서로를 못 본다(담합 방지). 그 독립성이 값인데,
    대가로 **아무도 종합할 수 없다** — 그래서 같은 질문이 4~5회 돌았다.
    여기서 그 대가를 회수한다.
    """
    L = []
    tgt = str(target or "")
    a = ask or _ask_for(tgt)
    if a:
        L.append("## 열린 질문 [%s] — %d회 시도, 아직 미종결" % (a.get("id"), len(a.get("attempts") or [])))
        if a.get("why"):
            L.append("게이트 사유: %s" % str(a["why"])[:400])
        if a.get("method"):
            L.append("큐가 지시한 방법: %s" % str(a["method"])[:400])
        for i, at in enumerate(a.get("attempts") or [], 1):
            L.append("  시도 %d (%s): cfg=%s guard=%s sink=%s"
                     % (i, at.get("t"), at.get("cfg"), at.get("guard"), at.get("sink")))
    # 이 행에 붙은 판정 전부 — 기각/확정/반박됨
    # ★ 2026-09-04: 여기는 **자르면 안 된다.** 판결자의 존재 이유가 "이 판에서 유일하게
    #   전체 이력을 본다"인데 `[-6:]`/`[-4:]`/`[-3:]` 로 잘려 있었다. 같은 질문에 4~5회
    #   부딪힌 행을 종결하러 오는데 앞쪽 시도가 안 보이면 그 역할이 성립하지 않는다.
    #   길이는 **오래된 것을 한 줄로 접어서** 잡는다 — 빠뜨리지는 않는다.
    def _fold(items, keep, render, brief):
        old_n = max(0, len(items) - keep)
        if old_n:
            L.append("  (오래된 %d건은 한 줄로 접는다 — 빠뜨리지 않는다)" % old_n)
            for x in items[:old_n]:
                L.append("  · " + brief(x))
        for x in items[old_n:]:
            render(x)

    vs = [v for v in (STATE.get("verdicts") or []) if str(v.get("target")) == tgt]
    if vs:
        L.append("\n## 이 행에 기록된 판정 %d건 (전부)" % len(vs))
        for v in vs[:max(0, len(vs) - 6)]:
            L.append("  · [%s] %s — %s" % (v.get("status"), v.get("id"),
                                           str(v.get("claim"))[:110].replace("\n", " ")))
        for v in vs[max(0, len(vs) - 6):]:
            g = v.get("gate") if isinstance(v.get("gate"), dict) else {}
            L.append("- [%s] klass=%s cfg=%s (%s)"
                     % (v.get("status"), v.get("klass"), (g.get("cfg") or {}).get("verdict"),
                        v.get("t")))
            L.append("  주장/사유: %s" % str(v.get("reason") or v.get("claim"))[:400])
            it = v.get("interrogation")
            if isinstance(it, dict):
                L.append("  ↳ 심문자: sustained=%s klass=%s — %s"
                         % (it.get("sustained"), it.get("klass"), str(it.get("reason"))[:300]))
                if it.get("next_method"):
                    L.append("     심문자가 지목한 다음 관측: %s" % str(it["next_method"])[:250])
    # 반박자가 죽인 것 (묘지)
    gy = [x for x in (STATE.get("graveyard") or []) if str(x.get("target")) == tgt]
    if gy:
        L.append("\n## 반박자가 죽인 확정 %d건 (전부)" % len(gy))
        for x in gy[:max(0, len(gy) - 4)]:
            L.append("  · [%s] %s" % (x.get("klass"), str(x.get("reason"))[:110].replace("\n", " ")))
        for x in gy[max(0, len(gy) - 4):]:
            L.append("- [%s] %s" % (x.get("klass"), str(x.get("reason"))[:350]))
            if x.get("would_change_my_mind"):
                L.append("  ↳ 살아남는 조건: %s" % str(x["would_change_my_mind"])[:250])
    # 게이트가 표현 못 했다는 신고
    gb = [x for x in (STATE.get("gate_blocks") or []) if str(x.get("target")) == tgt]
    if gb:
        L.append("\n## 게이트가 막았다는 신고 %d건 (도구 한계이지 코드에 대한 증거가 아니다, 전부)"
                 % len(gb))
        for x in gb[:max(0, len(gb) - 3)]:
            L.append("  · %s — %s" % (x.get("gate"), str(x.get("why"))[:100].replace("\n", " ")))
        for x in gb[max(0, len(gb) - 3):]:
            L.append("- %s — %s" % (x.get("gate"), str(x.get("why"))[:300]))
    return "\n".join(L)


def record_adjudication(target, v, n_attempts, raw=""):
    """판결을 **따로** 남긴다. 판정 목록에만 넣으면 내일 채점에서 못 고른다."""
    rec = {"target": str(target)[:160], "verdict": v.get("verdict"),
           "reason": str(v.get("reason") or "")[:800],
           "decisive": str(v.get("decisive") or "")[:400],
           "residual_risk": str(v.get("residual_risk") or "")[:400],
           "downgraded_from": v.get("downgraded_from"),
           "fault": v.get("fault"), "via": v.get("via"),
           "attempts": n_attempts, "raw_tail": str(raw or "")[:600],
           "t": time.strftime("%m-%d %H:%M")}
    STATE.setdefault("adjudications", []).append(rec)
    save()
    return rec


def stash_adjudication(target, rec):
    """판결자는 판정이 **기록되기 전에** 도는 사전 게이트다 ⇒ 붙일 판정이 아직 없다.
    보관해 두고 `verdict()` 가 기록 시점에 박는다. (심문/승격과 같은 패턴 —
    훅에서 `inp` 를 고쳐도 툴까지 간다는 보장이 없다.)"""
    STATE.setdefault("pending_adjudication", {})[str(target)] = rec
    save()


def adjudicated_confirms():
    """판결자가 낸 확정만. 채점에서 **분리해서** 세야 한다."""
    return [v for v in (STATE.get("verdicts") or [])
            if v.get("status") == "확정" and v.get("decided_by") == "adjudicator"]


def adjudication_audit():
    """★ 내일 채점용. 판결자가 무엇을 어떤 권한으로 뒤집었는지 한 표로."""
    A = STATE.get("adjudications") or []
    if not A:
        return "판결 기록 없음."
    import collections
    c = collections.Counter(x.get("verdict") for x in A)
    L = ["판결 %d건 — %s" % (len(A), dict(c)),
         "★ confirm 이 많으면 그것 자체가 신호다: 판결자에게 확정 권한을 준 것은 "
         "2026-09-04 **하루짜리 운영자 결정**이었다. 되돌리려면 이 표를 보고 결정하라.", ""]
    for x in A:
        L.append("[%s] %s  (시도 %s회, %s)" % (x.get("verdict"), str(x.get("target"))[:60],
                                              x.get("attempts"), x.get("t")))
        L.append("   결정 앵커: %s" % (x.get("decisive") or "(없음)")[:160])
        L.append("   사유      : %s" % str(x.get("reason"))[:200])
        L.append("   남는 위험 : %s" % (x.get("residual_risk") or "(안 적음)")[:160])
        if x.get("downgraded_from"):
            L.append("   ※ %s 에서 강등됨 (결정적 앵커 없음)" % x["downgraded_from"])
    return "\n".join(L)


# ── 심문자가 표현불가 기각을 **깨지 못했다**는 사실의 보관소 ────────
# ★ 왜 필요한가 (실측 2026-09-04): `inexpressible` 은 심문자를 태우도록 배선돼 있고
#   실제로 19회 돌아 10건이 `sustained`(= 깨지 못함) 였다. 그런데 훅이 그 사실을
#   **지역 변수 `_rec` 에** 적었고, 툴 쪽 `verdict()` 는 `_reject_gate` 를 처음부터
#   다시 계산하므로 그 표시가 사라졌다. 지문 둘로 확인됨:
#     · 원장 전체에 `passed_by` 마커 0건
#     · `pending_interrog` 잔류 13건 (ASK 분기가 소비 지점보다 앞에 있어 영영 안 읽힌다)
#   ⇒ 판결자·승격자가 이미 쓰는 `stash_*` 패턴으로 건넨다. 훅에서 dict 를 고쳐도
#     툴까지 간다는 보장이 없다는 것은 이 저장소가 이미 아는 사실이다.
#
# ★ 다만 **ASK 를 취소하지는 않는다.** 심문자의 맨데이트는 "애매하면 기각이 서지 않는다"라
#   `sustained` 는 "옳다"가 아니라 "못 깼다"에 가깝다. 자동 승격은 정밀도 축을 여는 변경이고,
#   그건 별개 결정이다. 여기서는 **그 사실을 분석가에게 전달**만 한다 — 판단은 분석가가 한다.
def stash_inexpr_pass(target, rec):
    STATE.setdefault("pending_inexpr_pass", {})[str(target)] = {
        "cfg": rec.get("cfg"), "klass": rec.get("klass"),
        "reason": str(rec.get("reason") or "")[:400],
        "t": time.strftime("%m-%d %H:%M")}
    save()


def _take_inexpr_pass(target, cfg_verdict):
    """같은 벽(cfg)에 대한 것일 때만 꺼낸다 — 다른 질문에 붙으면 거짓 보증이 된다."""
    box = STATE.get("pending_inexpr_pass") or {}
    got = box.get(str(target))
    if not got:
        return None
    if cfg_verdict and got.get("cfg") and got["cfg"] != cfg_verdict:
        return None
    return box.pop(str(target), None)


def render_ask(target, a, extra=""):
    """★ ASK 문구를 **렌더 시점에** 조립한다: 정적 안내문 + 누적 선례 + 심문자 통과 사실.

    저장된 것은 정적 안내문뿐이므로 원장은 커지지 않고, 선례는 늘 최신이 붙는다.
    """
    m = str((a or {}).get("method") or "")
    try:
        m += rules_for((a or {}).get("cfg"))
    except Exception:
        pass                                   # 선례 조회 실패가 안내 자체를 죽이면 안 된다
    ip = _take_inexpr_pass(target, (a or {}).get("cfg"))
    if ip:
        m += ("\n\n★ 참고 — **독립 심문자가 이 기각을 깨지 못했다** [%s] %s\n"
              "   심문자는 주장과 근거만 보고 '애매하면 기각이 서지 않는다'를 기본값으로 돈다. "
              "그걸 넘겼다는 것은 약한 신호가 아니다.\n"
              "   게이트가 못 정한 것은 **모양을 표현하지 못해서**이지 네 논증이 틀려서가 아닐 수 있다. "
              "위 (A)/(B) 중 어느 쪽인지만 한 문장으로 못 박고 같은 표적을 다시 기각하라 — "
              "아직 부족하다고 판단하면 무엇이 부족한지 적어라."
              % (ip.get("klass") or "-", str(ip.get("reason") or "")[:300]))
    return m + (extra or "")


def ask_kind(cfg_verdict):
    """이 ASK 가 관측 부족인가, 게이트가 표현을 못 하는 것인가."""
    return "inexpressible" if cfg_verdict in _ASK_INEXPRESSIBLE else "need_observation"


def ask(rec, why, cfg_verdict=None):
    """게이트가 판정 불가일 때 **질문을 남긴다**(통과가 아니라)."""
    rec = rec if isinstance(rec, dict) else {}
    # ★ 저장하는 것은 **정적 안내문뿐**이다. 선례는 `render_ask()` 가 렌더 시점에 붙인다.
    #   생성 시점에 이어붙이면 (1) 낡은 선례가 원장에 영구히 얼어붙고(폐기 원칙과 배치),
    #   (2) ASK 하나당 ~700자씩 원장이 커져 **지휘자가 읽을 것이 늘어난다** —
    #   `reports/breaks/` 를 원장 밖에 둔 이유를 같은 파일 안에서 어기는 셈이 된다.
    rec["ask"] = {"why": why, "cfg": cfg_verdict, "kind": ask_kind(cfg_verdict),
                  "method": ASK_METHOD.get(cfg_verdict or "",
                                           "판정에 필요한 관측을 하나 더 확보하라."),
                  "t": time.strftime("%m-%d %H:%M")}
    return rec


# ── 기각 게이트 (R1~R3) ───────────────────────────────────────
# 왜: 지금까지 게이트는 **확정에만** 걸렸다. 기각은 무료라 거짓 음성이 그냥 통과했다.
# pcw.sys 실행에서 기각 18건의 앵커 98개는 전부 진짜였지만, 그건 우연이지 강제가 아니었다.
# 그리고 앵커가 진짜여도 **논증은 샐 수 있다** — fn0x9 의 기각을 떠받친 결정적 명령
# (`0x14000C262 jmp` = 실패 경로가 싱크에 안 감)은 **인용문에 아예 없었다.**
# ⇒ 인용에 기대지 말고 **계산**한다.
_REJECT_KLASS = {
    "guarded":        "가드가 싱크를 막는다 — guard=/sink= 필수, CFG 지배를 계산한다",
    "unreachable":    "도달 불가 — 도달성 근거(callpath/xref) 필요",
    "not_controlled": "값이 상수 — 그 상수의 정의 지점 앵커 필요",
    "no_sink":        "위험한 소비처가 없다 — 전수 스캔 근거 필요",
    "by_design":      "설계 의도 — 문서/출하도구 출처 필요",
    "delta_zero":     "정상 경로로도 같은 결과 — control() 실측 기록 필요",
    "decompiler_artifact": "디컴파일러 산물 — 디스어셈블 앵커 필요",
    # ★ 2026-09-05 추가. 근거: 지휘자의 `unrecordable` 재보고 76건이 **네 모양으로 접힌다**
    #   (ahcache 8·7·6·5회 / wcifs 7·6·3회). 담을 칸이 없어 여덟 회차분 판정이 증발했다.
    #   ⇒ 여기 넣는 둘은 **의무가 기계로 검사 가능한 것만**이다. 검사 못 할 의무를 단
    #   klass 는 자유 통행증이 된다 — klass 의 원래 정의가 "요구할 관측"이기 때문이다.
    "second_site": "이미 판정된 결함의 **다른 사이트** — origin_id= 로 원본 판정을 대고 그 "
                   "사이트의 앵커를 evidence 에 넣어라. 등급은 원본을 따른다",
    "bounded_absence": "**이 범위 안에서는** 전수로 없다 — scope= 로 범위를 명시하고"
                       "(function/section/image) 그 범위를 실제로 덮은 열거를 돌려라",
    # ★ 2026-09-05 추가 ②. 근거: wcifs 의 미기록 12건이 **세 요청으로 접히는데 그중 6건이
    #   같은 말을 한다** — `guarded` 의 건전성 규칙이 하나뿐이라는 것("가드가 읽은 값이 싱크
    #   오퍼랜드에 흘러야 한다"). 그 규칙에 안 맞는 **구조가 다른 두 가지**가 8회·2회씩
    #   되돌아왔고, 그 사이 wcifs 는 다섯 회차 연속 판정+0 이었다.
    #   두 klass 다 의무가 기계로 검사된다 — 인용된 니모닉을 보고 판정한다.
    # ★ 두 읽기를 **한 칸에** 담는다(어휘를 늘리기보다). 의무가 같기 때문이다 —
    #   둘 다 "그 상태를 만들 수 있는 분기를 전수로 대라"로 끝난다.
    #     (a) 가드가 오퍼랜드가 아니라 **상태**를 제약한다
    #     (b) 위험한 **간선 자체가 불가능**하다 (선행자 전부가 불변식을 세운다)
    #   (b) 는 wcifs `ABORT-ASYM:WcSetUnionContext@0x140023a2c` 가
    #   `klass=control-flow-exclusion` 이라는 이름으로 요청한 모양이고, 그 행은
    #   "분석은 끝났는데 적을 칸이 없다"로 **여섯 회차** 미분석에 머물렀다.
    "state_precondition": "가드가 싱크 **오퍼랜드**를 제약하는 게 아니라, 싱크가 위험해지는 "
                          "**상태 자체가 성립 못 하게** 한다 — 또는 위험한 **간선이 불가능**하다"
                          "(선행자 전부가 불변식을 세운다). sink= 와 함께, 그 상태를 만들 "
                          "수 있는 분기를 **전수로** evidence 에 조건분기 앵커로 넣어라(2개 이상)",
    "callsite_guarded": "공유 헬퍼라 **전역 지배는 성립하지 않지만** 이 호출지점에서는 "
                        "가드가 지배한다 — callsite= 로 그 `call` 명령 앵커를 대고 "
                        "guard= 를 같이 대라. 다른 호출자에 대해서는 아무 주장도 하지 않는다",
    # ★ 2026-09-05 추가 ③. 근거는 **사용 실적**이다: 기각 게이트가 꺼진 회차에서
    #   에이전트가 실제로 쓴 klass 중 `impact_unproven` 8건 · `gated_off` 2건이
    #   **어휘에 없는 값**이었다(게이트가 켜져 있었으면 전부 거부됐다). 그리고 게이트 신고
    #   39건 중 셋이 정확히 이 둘을 달라고 적었다. 쓰이고 있는데 없는 칸이다.
    "gated_off": "취약한 갈래가 **기능/설정 게이트 뒤에 있고 기본값이 안전한 쪽**이다 — "
                 "gate= 로 그 게이트를 지목하고, evidence 에 **접근자 `call` 앵커**와 "
                 "**안전한 갈래를 고르는 조건분기 앵커**를 둘 다 넣어라",
    "impact_unproven": "싱크는 실행되는데 **그 결과를 읽는 소비자가 없다** — sink= 와 함께 "
                       "scope= 로 **소비자를 어느 범위에서 열거했는지** 밝혀라. 이건 부재 "
                       "주장이므로 범위 없이는 성립하지 않는다",
    # ★ 2026-09-06 추가. 근거는 **집계**다: `reports/unrecordable/ahcache.sys.md` 의
    #   "필요한 칸" 제안 47건을 세면 한 개념이 다섯 이름으로 흩어져 있다 —
    #   bounded_by_saturation 10 · loop_bounded 4 · bounded_nonconstant 3 ·
    #   partially_controlled 2 · range_bounded 2 = **21제안**. 그 행(n=18)은
    #   `not_controlled` 로 시도했다가 CFG 검사에 **정당하게** 거절당했다(호출자가 값에
    #   영향을 주긴 한다). "영향은 주는데 clamp 된다"를 담을 칸이 없었을 뿐이다.
    #   그리고 privileged_principal 4제안(n=8)은 "도달하는데 경계를 안 넘는다"다.
    #   ★ 둘 다 의무가 기계로 검사된다. 검사 없는 어휘 추가는 klass 를 자유 통행증으로 만든다.
    #   ★ immutable_global(3) · intra_function_edge_enumeration(2) 는 **넣지 않았다** —
    #     그건 종착 klass 가 아니라 기존 klass 의 **근거 유형**이다. 근거를 종착지로
    #     승격시키면 결론 없이 행이 닫힌다. 그 셋은 검사기가 받아줄 근거를 넓히는 문제고,
    #     구조 변경이라 운영자 몫으로 남긴다(unrecordable 에 그대로 있다).
    "bounded_by_saturation": "공격자가 값에 **영향은 주지만** 단조 증가/포화라 범위가 clamp "
                             "된다 — `not_controlled`(상수)도 `guarded`(지배 분기)도 아니다. "
                             "sink= 와 함께 **누산 지점**(add/inc/sub/imul 앵커)과 **clamp 를 "
                             "만드는 조건분기 앵커**를 둘 다 evidence 에 넣고, scope= 에 "
                             "**무엇이 상한인지**(단조성 + clamp 값)를 적어라. clamp 앵커가 "
                             "없으면 이 주장은 'not_controlled 에 말을 붙인 것'일 뿐이다",
    "privileged_principal": "도달은 하는데 **그 싱크에 닿는 최소 principal 이 이미 그 싱크가 "
                            "주는 권한을 쥐고 있다** — 경계를 안 넘는다. sink= 와 함께 "
                            "**접근검사 `call` 앵커**를 evidence 에 넣고, scope= 에 그 최소 "
                            "principal 을 **무엇으로 확정했는지** 적어라(장치 SD / IOCTL 의 "
                            "RequiredAccess / AC ACE 등). ★ 'Everyone 이니까' 는 근거가 "
                            "아니다 — 정적 판정이 AppContainer 를 덮은 사례가 있다",
}

# ★ 2026-09-23 — **상태 의존 klass 는 실측 결박을 요구한다.**
#   근거(mrxsmb 09-22 밤 실측): `gated_off` 로 낸 기각이 **4번** 깨졌고 파손 사유 4건이
#   전부 같은 말이었다 — "the rejection never observed the value that selects the arm …
#   'shipped default 1' is seed metadata, not a measurement of eax". 그 4회 왕복이
#   23:48~02:09, 즉 **2시간 21분**(4시간 16분 런의 55%)을 먹었다.
#   klass 의 의무가 "게이트가 있다"까지만 검사하고 "기본값이 안전한 쪽"은 무검사로
#   통과시켰기 때문이다. 그 항은 런타임 값이라 앵커로는 못 세운다 — **재야 한다.**
#   ⇒ 문장을 보지 않는다(어휘 의존 금지). `measured(target)` 이 돌려주는 실측 행의
#      **존재와 kind** 만 본다. `trace` 는 관측이 아니다(closed-axis-trapped-in-notes).
#   ★ 규칙은 kind 블랙리스트가 아니다 — `trace` 도 하네스가 쏜 관측이다(655행 주석).
#     대신 **그 실측이 네가 주장하는 게이트를 건드렸는가**를 본다: gated_off 가 이미
#     기록하는 `gate_anchors`(접근자 call + 안전팔 분기)와 실측의 주소가 겹쳐야 한다.
#     mrxsmb 밤에 이 표적의 실측은 29건이었지만 **게이트 주소를 건드린 것은 0건**이었다 —
#     "재긴 쟀다"와 "이 값을 쟀다"를 가르는 자리가 여기다.
#   ★ delta_zero 는 `GATE_CONTROL_BEFORE_REJECT` 가 따로 양성대조를 요구하므로 넣지 않는다
#     (두 게이트가 같은 것을 두 번 요구하면 우회를 만든다).
_REQUIRES_MEASURE = {"gated_off"}


# ★ 2026-09-06. klass 별로 **무엇을 인용해야 하는가**. 게이트를 느슨하게 하지 않는다 —
#   "인용 1개 이상" 요구는 그대로다. 다만 거절 문구가 일반론이면 재시도가 안 된다.
#   실측: 케이스 3에서 같은 행(`fn1_AhcApiRemove … AhcpCacheEntryFilter`, klass=impact_unproven)이
#   **01:24·01:25·01:26 세 번 연속** "인용 0건"으로 막혔다. 회차 반려 5건 중 3건이 이것이다.
#   `impact_unproven` 은 "아무도 안 읽는다"는 **부재** 주장이라 인용할 명령을 못 찾은 것이다 —
#   답은 "싱크 명령 자체"인데 문구가 그 말을 안 했다.
_CITE_HINT = {
    "guarded":            "the conditional branch you call the guard, AND the sink instruction it dominates",
    "unreachable":        "the call/xref sites you enumerated (the ones that do NOT reach it)",
    "not_controlled":     "the instruction that DEFINES the constant (where the value is written)",
    "no_sink":            "the candidate sites your sweep visited and rejected as non-dangerous",
    "by_design":          "the instructions implementing the documented behaviour",
    "delta_zero":         "the sink instruction whose output you compared across the two arms",
    "decompiler_artifact": "the DISASSEMBLY that contradicts the decompiler output",
    "second_site":        "the instruction at THIS site (the origin verdict covers the other one)",
    "bounded_absence":    "the boundary instructions of the range you enumerated (first/last)",
    "state_precondition": "every conditional branch that could produce the dangerous state (2+)",
    "callsite_guarded":   "the `call` instruction at this callsite, AND the guard branch",
    "gated_off":          "the gate accessor `call`, AND the branch that selects the safe arm",
    "impact_unproven":    "the SINK INSTRUCTION ITSELF — your claim is that nothing reads its "
                          "effect, but the sink is still a real instruction and it is what the "
                          "claim is about. Cite it, plus any consumer-shaped site your sweep "
                          "visited and ruled out",
    "bounded_by_saturation": "the accumulating instruction AND the clamp branch",
    "privileged_principal":  "the access-check `call` that fixes the minimum principal",
}


def _img():
    try:
        import pe as PE
        t = STATE.get("target") or ""
        return PE.PE(t) if t and os.path.exists(t) else None
    except Exception:
        return None


_DF_RE = re.compile(r'double[ _-]?fetch|더블\s*페치|두 번 읽|재독|re-?read|같은 읽기|단일 읽기|'
                    r'ProbeFor|캡처|captur|MmProbe|__try', re.I)
_RACE_RE = re.compile(r'race|경합|레이스|async|비동기|cancel|취소|work ?item|DPC|타이머|timer|'
                      r'완료 ?루틴|completion|재검증|revalidat|Interlocked|참조 ?카운트|refcount', re.I)


def _is_neither(tgt):
    """METHOD_NEITHER 표적인가. 이름 또는 표면 레코드에서 판정한다."""
    t = (tgt or "").upper()
    if "NEITHER" in t:
        return True
    for k, v in (STATE.get("surface") or {}).items():
        if k == tgt or v.get("target") == tgt:
            blob = (k + " " + json.dumps(v, ensure_ascii=False)).upper()
            if "NEITHER" in blob:
                return True
    return False


def _cites(text):
    """근거 텍스트의 `0xADDR mnem ops` 인용 목록. evidence 모듈이 없으면 빈 목록."""
    try:
        import evidence as EV
        return EV.parse(text or "")
    except Exception:
        return []


def _reject_open_lead(tgt, args):
    """이 기각의 앵커가 **이미 깨진(broke) 열린 리드**와 겹치는지 본다. 겹치면 그 리드를
    돌려준다 — 재도출로 죽은 축을 다시 기각하는 것을 막기 위해서다.

    ★ 2026-09-25 — 실제 사건: TDIDRAIN 을 인터로게이터가 4번 깼고 break 마다 reason·
      next_method 를 남겼는데, 뒤 세션(과 모델 자신)이 그 근거를 **읽지 않고 재도출**해
      "음성"으로 다시 냈다. reject 게이트는 klass 형태만 봤지 '이 축이 이미 깨졌나'를 안 봤다.
      (memory: broke-rejections-are-open-not-negative · analysis-outran-measurement)
    접지: `open_leads(STATE.target)` — 현재 이미지로 스코프(교차오염 없음), 매 호출 재도출.
    """
    try:
        blob = " ".join(str(args.get(k) or "")
                        for k in ("evidence", "sink", "item", "target", "reason", "claim"))
        mine = set(re.findall(r'0x[0-9a-fA-F]{6,16}', (blob + " " + str(tgt)).lower()))
        if not mine:
            return None
        for L in open_leads(STATE.get("target")):
            lb = " ".join(str(L.get(k) or "")
                          for k in ("target", "claim", "reason", "next_method", "sink", "guard", "vid"))
            if mine & set(re.findall(r'0x[0-9a-fA-F]{6,16}', lb.lower())):
                return L
    except Exception:
        return None
    return None


def _reject_gate(tgt, args):
    """기각도 실측을 통과해야 한다. (ok, 메시지, 검증기록)"""
    klass = (args.get("klass") or "").strip().lower()
    ev = args.get("evidence", "") or ""
    rec = {"klass": klass}
    img = _img()

    # ★ 재도출-재기각 차단: 이 축이 이미 깨진 열린 리드면, break 근거를 보여주고
    #   설계된 출구(action='lead')로 보낸다. contest_lead= 로 명시적 반박은 통과시킨다
    #   (길 없는 거부는 헛돌기를 만든다 — predicate-cannot-ask).
    _lead = _reject_open_lead(tgt, args)
    if _lead is not None and str(args.get("contest_lead") or "").strip() != str(_lead.get("id")):
        return (False,
                "⚠ 이 축은 인터로게이터가 이미 깼다 — 열린 리드 %s (klass=%s, attempt=%s).\n"
                "재도출로 다시 기각하지 마라. 그 break 가 남긴 근거부터 반박하라:\n"
                "  reason: %s\n"
                "  next_method: %s\n"
                "설계된 출구는 `verdict(action='lead', id='%s', how='refuted'|'measured'|"
                "'reinterrogated', why=...)` — 반박·측정·재심문 중 하나로 닫아야 한다.\n"
                "이 기각이 정말로 그 break 근거를 반박하는 것이라면 `contest_lead='%s'` 를 달고 "
                "why 에 break 의 **어느 항을 어떻게** 반증했는지 적어라(그러면 통과한다)."
                % (_lead.get("id"), _lead.get("klass"), _lead.get("attempt"),
                   str(_lead.get("reason"))[:400] or "(없음)",
                   str(_lead.get("next_method"))[:250] or "(없음)",
                   _lead.get("id"), _lead.get("id")),
                rec)

    # ★ second_site — 원본 판정이 실재해야 한다(A/D형: id 조회 + 앵커 기계검증)
    if klass == "second_site":
        _oid = str(args.get("origin_id") or "").strip()
        _ids = {str(v.get("id")) for v in (STATE.get("verdicts") or [])}
        if not _oid or _oid not in _ids:
            return (False, "klass='second_site' REQUIRES `origin_id=` naming an EXISTING verdict "
                           "on this ledger (the site whose defect this repeats).\n"
                           "Known ids: %s" % ", ".join(sorted(_ids)[:12]), rec)
        rec["origin_id"] = _oid
    # ★ bounded_absence — 범위 선언이 있어야 한다. 전역 부재가 아니라는 것이 요점이다
    if klass == "bounded_absence" and img is not None:
        # ★ 2026-09-23 — 부재형에서 여기로 보냈으면(위 R4 (a)), **수를 맞추게** 한다.
        #   범위를 좁히는 것과 반례를 못 본 척하는 것은 다르다. 문장이 아니라 수로 검사한다.
        try:
            import icall as _ic2
            _sc2 = _ic2.scan(img)
            _un2 = [x for x in _sc2["stores"]
                    if not any(c["kind"] == "slot" and c.get("off") == x.get("off")
                               for c in _sc2["icalls"])]
        except Exception:
            _un2 = []
        if _un2:
            try:
                _dec = int(str(args.get("excludes_indirect") or "").strip() or -1)
            except ValueError:
                _dec = -1
            if _dec != len(_un2):
                return (False,
                        "이 이미지에는 미해소 함수포인터가 **%d개** 있다. 범위 한정 부재를 "
                        "쓰려면 그 수를 직접 적어라: `excludes_indirect=%d`.\n"
                        "(적은 값: %s) — 수를 맞추는 것이 '반례를 봤다'의 최소 증명이다. "
                        "범위를 좁히는 것과 반례를 못 본 척하는 것은 다르다."
                        % (len(_un2), len(_un2),
                           args.get("excludes_indirect") if args.get("excludes_indirect") is not None else "없음"),
                        rec)
            rec["excludes_indirect"] = len(_un2)
    if klass == "bounded_absence":
        _sc = str(args.get("scope") or "").strip()
        if len(_sc) < 12:
            return (False, "klass='bounded_absence' REQUIRES `scope=` — WHAT RANGE did you "
                           "enumerate exhaustively (a function's .pdata range / a section / the "
                           "whole image)? An absence claim without its range is a global absence "
                           "claim, and that is a different (much stronger) statement.", rec)
        rec["scope_decl"] = _sc[:200]
    # ★ state_precondition — 상태를 만드는 분기를 **전수로** 대야 한다.
    #   기계검사: 인용 중 **조건분기**가 2개 이상인가 + sink= 가 있는가.
    #   (주소 자체의 실재성은 아래 R1 이 이미지 대조로 따로 검증한다.)
    if klass == "state_precondition":
        _sk = str(args.get("sink") or "").strip()
        _br = [c for c in _cites(ev)
               if (c["mnem"] or "").startswith("j") and c["mnem"] != "jmp"]
        if not _sk or len(_br) < 2:
            return (False, "klass='state_precondition' says the guard constrains STATE, not the "
                           "sink operand. That is a legitimate shape — and it carries its own "
                           "obligation, because 'no state can make this dangerous' is an "
                           "EXHAUSTIVE claim over the branches that produce that state.\n"
                           "REQUIRED: `sink=` plus at least TWO conditional-branch anchors in "
                           "evidence (`0xADDR je ...`) — the branches you enumerated.\n"
                           "Found: sink=%s, conditional branches=%d.\n"
                           "If there is genuinely only one branch, the ordinary `guarded` rule "
                           "applies and you should be able to satisfy it."
                    % ("yes" if _sk else "MISSING", len(_br)), rec)
        rec["precondition_branches"] = ["0x%x" % c["va"] for c in _br][:8]
    # ★ callsite_guarded — 그 호출지점이 실제로 `call` 이어야 한다.
    #   요점은 **주장의 범위를 좁히는 것**이다: 다른 호출자는 여전히 미분석으로 남는다.
    if klass == "callsite_guarded":
        _cs = str(args.get("callsite") or "").strip()
        _gd = str(args.get("guard") or "").strip()
        # ★ 공백이 아니라 개행으로 잇는다 — CITE 의 ops 는 `[^\n;/]*` 라 한 줄에
        #   두 인용을 붙이면 뒤엣것이 앞 인용의 오퍼랜드로 먹힌다(방금 실측).
        _calls = [c for c in _cites(ev + "\n" + _cs) if (c["mnem"] or "") == "call"]
        if not _gd or not _calls:
            return (False, "klass='callsite_guarded' scopes the dominance claim to ONE callsite "
                           "of a shared helper — which is exactly right when no per-caller guard "
                           "can dominate globally. Then name the callsite.\n"
                           "REQUIRED: `guard=` plus a `call` anchor (`0xADDR call 0x...`) in "
                           "`callsite=` or in evidence.\n"
                           "Found: guard=%s, call anchors=%d.\n"
                           "NOTE this rejection covers THIS callsite only — the helper's other "
                           "callers stay unaudited and must not be counted as covered."
                    % ("yes" if _gd else "MISSING", len(_calls)), rec)
        rec["callsite"] = ["0x%x" % c["va"] for c in _calls][:4]
        rec["callsite_scoped"] = True
    # ★ gated_off — "기본값이 안전한 쪽"은 **두 앵커**로 증명된다: 게이트를 읽는 호출과
    #   안전한 갈래를 고르는 분기. 하나만으로는 "게이트가 있다"까지밖에 못 간다.
    #   (실측 근거: ahcache `Feature_EnsureVerBlockCanHoldFixedInfo` 는
    #    `0x1400558cf call` + `0x1400558d6 je` 두 앵커가 정확히 이 모양이다.)
    if klass == "gated_off":
        _gt = str(args.get("gate") or "").strip()
        _cs = _cites(ev)
        _ca = [c for c in _cs if (c["mnem"] or "") == "call"]
        _br = [c for c in _cs if (c["mnem"] or "").startswith("j") and c["mnem"] != "jmp"]
        if not _gt or not _ca or not _br:
            return (False, "klass='gated_off' claims the dangerous arm is behind a gate whose "
                           "DEFAULT selects the safe arm. Two different facts, two anchors:\n"
                           "  (1) the gate is READ here — a `call` anchor (the accessor), and\n"
                           "  (2) the SAFE arm is chosen — the conditional branch anchor.\n"
                           "Plus `gate=` naming it. Found: gate=%s, call=%d, branch=%d.\n"
                           "One anchor only proves 'a gate exists', which is not the claim.\n"
                           "AND: the gate's DEFAULT STATE is itself a claim. If it is a WIL "
                           "feature, the compiled default is a byte in its descriptor and the "
                           "override is a registry key — both are readable. Do not assert it."
                    % ("yes" if _gt else "MISSING", len(_ca), len(_br)), rec)
        rec["gate_name"] = _gt[:120]
        rec["gate_anchors"] = ["0x%x" % c["va"] for c in (_ca + _br)][:6]
    # ★ impact_unproven — "소비자가 없다"는 **부재 주장**이다. 범위 없이는 성립 안 한다.
    #   실측 근거: msquic V-I8-C1-CIBIR 이 "소비자 없음"으로 닫혔는데 소비자가 있었다
    #   (`0x14002ac68`/`0x14002ac8a`). 게다가 **다른 오프셋을 xref 해서** 그렇게 됐다.
    #   범위를 적게 하면 어느 오프셋을 훑었는지가 글에 드러나고, 그 오독이 보인다.
    if klass == "impact_unproven":
        _sk = str(args.get("sink") or "").strip()
        _sc = str(args.get("scope") or "").strip()
        if not _sk or len(_sc) < 12:
            return (False, "klass='impact_unproven' says the sink runs but NOTHING READS its "
                           "effect. That is an ABSENCE claim wearing an impact field's clothes, "
                           "and absence needs its range.\n"
                           "REQUIRED: `sink=` plus `scope=` — WHAT did you enumerate, over WHAT "
                           "range, to conclude there is no consumer? (e.g. 'every read of "
                           "conn+0x6E0/+0x6E8 across the whole image').\n"
                           "Found: sink=%s, scope=%d chars.\n"
                           "This exact klass was filed once with 'no consumer reads it' — and a "
                           "consumer existed; the sweep had been run on the WRONG OFFSET. "
                           "Naming the range is what makes that visible."
                    % ("yes" if _sk else "MISSING", len(_sc)), rec)
        rec["consumer_scope"] = _sc[:200]
    # ★ bounded_by_saturation — "영향은 주는데 clamp 된다"는 **두 사실**이다.
    #   (1) 값이 커지는 지점(누산)  (2) 그것을 멈추는 지점(clamp 분기)
    #   (2) 가 없으면 상한이 없는 것이고, 그러면 이 klass 가 아니라 미판정이다.
    #   실측 근거: 이 모양을 요청한 행(n=18)이 인용한 것이 정확히 산술 앵커 둘이었다
    #   (`0x1400277b9 add dword ptr [rbx+0xb0], esi; 0x1400277c6 add ...`) — clamp 는 없었다.
    if klass == "bounded_by_saturation":
        _sk = str(args.get("sink") or "").strip()
        _sc = str(args.get("scope") or "").strip()
        _cs = _cites(ev)
        _ar = [c for c in _cs
               if (c["mnem"] or "") in ("add", "inc", "adc", "sub", "dec", "imul", "shl")]
        _br = [c for c in _cs
               if (c["mnem"] or "").startswith("j") and c["mnem"] != "jmp"]
        if not _sk or len(_sc) < 12 or not _ar or not _br:
            return (False, "klass='bounded_by_saturation' says the caller INFLUENCES the value "
                           "but a monotonic/saturating step clamps its range. That is a real "
                           "shape — and it is two facts, so it needs two anchors:\n"
                           "  (1) the ACCUMULATING site — an `add`/`inc`/`sub`/`imul` anchor\n"
                           "  (2) the CLAMP — the conditional branch that stops it\n"
                           "Plus `sink=` (where the bounded value is consumed) and `scope=` "
                           "stating WHAT the bound is (monotonicity + the clamp value).\n"
                           "Found: sink=%s, scope=%d chars, arithmetic=%d, branch=%d.\n"
                           "Without the clamp anchor there is no upper bound in evidence, and "
                           "the claim is `not_controlled` with extra words — which the CFG "
                           "check already refused, correctly, because the caller DOES influence it."
                    % ("yes" if _sk else "MISSING", len(_sc), len(_ar), len(_br)), rec)
        rec["saturation_sites"] = ["0x%x" % c["va"] for c in _ar][:4]
        rec["clamp_branches"] = ["0x%x" % c["va"] for c in _br][:4]
        rec["bound_scope"] = _sc[:200]
    # ★ privileged_principal — 이 klass 는 **가장 오용하기 쉽다**. "어차피 관리자잖아"가
    #   그대로 통과하면 AppContainer/저권한 호출자가 통째로 사라진다.
    #   그래서 최소 principal 을 **무엇으로 확정했는지**를 앵커와 함께 요구한다.
    #   (memory `appcontainer-axis-ace-rule`: Everyone ACE 는 근거가 아니다.
    #    `wudfrd-boundary-is-umdf-host`: 실제로는 PID 게이트가 먼저 막고 있었다.)
    if klass == "privileged_principal":
        _sk = str(args.get("sink") or "").strip()
        _sc = str(args.get("scope") or "").strip()
        _ca = [c for c in _cites(ev) if (c["mnem"] or "") == "call"]
        if not _sk or len(_sc) < 12 or not _ca:
            return (False, "klass='privileged_principal' says the sink is REACHABLE but the "
                           "minimum principal that reaches it ALREADY holds what the sink "
                           "grants — no boundary is crossed. That is a legitimate negative, "
                           "and it stands or falls on ONE question: how do you know that is "
                           "the MINIMUM principal?\n"
                           "REQUIRED: `sink=` plus an access-check `call` anchor in evidence, "
                           "plus `scope=` naming what fixed the minimum principal — the device "
                           "SD, the IOCTL's RequiredAccess, an AppContainer ACE, a PID/token "
                           "test.\n"
                           "Found: sink=%s, scope=%d chars, call anchors=%d.\n"
                           "'Everyone has access so it must be admin-only' is NOT evidence: a "
                           "static read of an ACL has already hidden an AppContainer caller in "
                           "this project, and a PID gate has already turned out to be the real "
                           "boundary where the ACE said otherwise."
                    % ("yes" if _sk else "MISSING", len(_sc), len(_ca)), rec)
        rec["principal_check"] = ["0x%x" % c["va"] for c in _ca][:4]
        rec["principal_scope"] = _sc[:200]
    # R2 — 사유 분류 필수. 사유마다 의무가 다르다.
    if klass not in _REJECT_KLASS:
        return (False, "A rejection REQUIRES a klass — each reason carries a DIFFERENT measurement obligation.\n"
                + "\n".join("  %-20s %s" % (k, v) for k, v in _REJECT_KLASS.items())
                + "\n\nWithout choosing one, the harness cannot decide what measurement to demand of you.", rec)

    # R2b — 상태 의존 klass 는 **실측 결박** 없이는 성립하지 않는다 (_REQUIRES_MEASURE).
    if klass in _REQUIRES_MEASURE:
        _want = {str(x).lower() for x in (rec.get("gate_anchors") or [])}
        _mm = []
        for _m in measured(tgt):
            _mv = {("0x%x" % v) if isinstance(v, int) else str(v).lower()
                   for v in (_m.get("vas") or [])}
            _mv |= {("0x%x" % v) if isinstance(v, int) else str(v).lower()
                    for v in measure_vas(str(_m.get("target") or "") + " " + str(_m.get("why") or ""))}
            if (not _want) or (_mv & _want):
                _mm.append(_m)
        if not _mm:
            return (False,
                    "klass=%r 의 진리값은 **런타임 상태**에 달려 있다 — 앵커로는 못 세운다.\n"
                    "이 표적의 실측 중 **네가 지목한 게이트 주소를 건드린 것이 없다**.\n"
                    "  · gated_off → 게이트의 상태를 실제로 읽어라 (kd: featureState / "
                    "레지스트리 오버라이드 / probe). 컴파일 기본값 바이트는 메타데이터지 관측이 아니다.\n"
                    "  · delta_zero → control() 로 정상 경로를 실제로 돌려라.\n"
                    "**재기 전에는 기각이 아니라 미분석이다** — `verdict(action='gate_blocked', "
                    "gate='needs-measurement', why=…, would_be=…)` 로 봉하고 그 관측을 다음 회차에 "
                    "요구하라. (근거: 이 검사가 없어서 같은 행이 4회 왕복하며 2시간 21분을 먹었다.)"
                    % klass, rec)
        rec["measure_binding"] = [
            "%s/%s" % (str(m.get("kind"))[:12], str(m.get("principal_grade") or "?")[:14])
            for m in _mm[:4]]

    # R7 — METHOD_NEITHER 은 **더블페치 표면**이다. 유저 포인터가 커널 사본 없이 넘어온다.
    #   실측(WUDFRd 08-31 야간): 표에 NEITHER 항목이 2개 있었는데 코퍼스 전체에서
    #   `double fetch` 등장 0회. 축 자체가 한 번도 안 돌았다.
    if klass in ("guarded", "not_controlled", "no_sink") and _is_neither(tgt):
        if not _DF_RE.search(ev + " " + (args.get("claim") or "")):
            return (True, "", ask(rec,
                    "You are rejecting a METHOD_NEITHER target on a single-read assumption.",
                    "double_fetch_unchecked"))

    # R8 — 등재된 경합 쌍의 항을 **단일 요청만 보고** 기각하려 하는가.
    if klass in ("guarded", "not_controlled", "no_sink", "unreachable"):
        _partners = [k for k, v in (STATE.get("surface") or {}).items()
                     if v.get("kind") == "race" and tgt in (v.get("pair") or [])]
        if _partners and not _RACE_RE.search(ev + " " + (args.get("claim") or "")):
            rec["race_partners"] = _partners[:3]
            return (True, "", ask(rec,
                    "This target is one side of a registered race pair: " + _partners[0][:120],
                    "race_axis_unchecked"))

    # R1 — 앵커 기계검증 (확정과 동일한 G1 을 기각에도 적용)
    if img is not None:
        import evidence as EV
        res, summ = EV.check(img, ev, images=_images_for_anchor())
        rec["anchors"] = summ
        if summ["cites"] == 0 and klass not in ("by_design", "delta_zero"):
            _hint = _CITE_HINT.get(klass)
            return (False, "The rejection basis contains ZERO `0xADDR mnem ops` citations. "
                           "In this domain every basis is re-derivable — if you did not write "
                           "it that way it cannot be verified, and an unverified rejection "
                           "makes coverage a lie.\n"
                           "FORMAT: `0x140042a58 cmp dword ptr [rbx+0xb0], 3` — address, "
                           "mnemonic, operands, one per line.\n"
                           + ("WHAT TO CITE for klass='%s': %s\n" % (klass, _hint) if _hint else
                              "Pick a klass first — what you must cite depends on it.\n")
                           + "This is NOT a request for more evidence: it is a request for the "
                             "evidence you already have, written so the harness can re-derive it "
                             "against this build.", rec)
        if summ["failed"]:
            return (False, "The rejection's anchors do not verify against this build:\n"
                    + EV.render(res, summ)
                    + "\n\nThis is a hallucinated address, a typo, or a STALE-BUILD ANCHOR. Re-derive it.", rec)

    # R5 — `delta_zero`("정상 경로로도 같은 결과")는 **양성 대조 실측**을 요구한다.
    # 대조 없는 실측 기각은 하네스 고장과 구분되지 않는다.
    if klass == "delta_zero" and not has_control("positive"):
        return (False, "klass='delta_zero' is a MEASURED claim: 'the normal path yields the "
                       "same result'. But there is no positive control in the ledger. Record "
                       "'under conditions that should work, it IS observed' first via "
                       "control(kind='positive') — a broken harness and a zero delta produce "
                       "the same output.", rec)
    # ★ 대조가 **있기는 한데 같은 것을 잰 것인가.** C-029: `has_control` 이 원장 전역이라
    #   첫 대조 하나가 그 표적의 남은 모든 `delta_zero` 를 면제했다. 여기서는 **막지 않고**
    #   겹침을 계산해 붙인다(refs/05 — 결정론 층에 억제 권한을 주지 않는다).
    #   `delta_zero` 는 어차피 승격자가 blocking 으로 받으므로 판단은 거기서 난다.
    if klass == "delta_zero":
        try:
            rec["control_overlap"] = control_overlap(
                " ".join(str(args.get(k) or "") for k in ("evidence", "claim", "guard", "sink")))
        except Exception as _e:
            rec["control_overlap"] = {"verdict": "error", "why": str(_e)[:120]}

    # R6 — `not_controlled`("값이 상수다")는 그 상수를 **박아넣는 명령**을 앵커로 요구한다.
    # `mov reg, imm` / `mov [mem], imm` 형태가 아니면 상수 근거가 아니다.
    if klass == "not_controlled" and img is not None:
        import evidence as EV
        cites = EV.parse(ev)
        ok_const = False
        for c in cites:
            if c["mnem"] in ("mov", "movs", "or", "and", "xor", "lea") and \
                    re.search(r'(?:^|,)\s*(?:0x[0-9a-fA-F]+|\d+)\s*$', c["ops"] or ""):
                ok_const = True
            if c["mnem"] == "xor" and c["ops"] and "," in c["ops"]:
                a1, a2 = [x.strip() for x in c["ops"].split(",")[:2]]
                if a1 == a2:
                    ok_const = True
        if not ok_const:
            return (False, "klass='not_controlled' claims 'the caller cannot change this "
                           "value'. Then you must cite, as an anchor, THE INSTRUCTION THAT "
                           "WRITES THAT CONSTANT (`mov reg, imm` / `xor reg, reg` and "
                           "friends). Your basis does not have one — 'it looks constant' and "
                           "'the constant is written HERE' are different claims.", rec)

    # R4 — 부재형 기각(no_sink / unreachable)은 **전 실행섹션 xref** 를 요구한다.
    # `.text` 만 보고 "호출이 없다"고 쓴 실패가 실제로 있었다(ipt.sys / PAGE).
    if klass in ("no_sink", "unreachable") and img is not None:
        # ★ xref 는 **직접 참조만** 본다. WDM/KMDF 디스패치 표가 곧 함수 포인터 배열이므로,
        #   미해결 함수포인터 저장이 있으면 부재 증명이 성립하지 않는다.
        #   지금 R4 는 "기각이 문서화됨"만 보장하고 "옳음"은 보장 못 한다.
        try:
            import icall as _ic
            _sc = _ic.scan(img)
            _unres = [x for x in _sc["stores"]
                      if not any(c["kind"] == "slot" and c.get("off") == x.get("off")
                                 for c in _sc["icalls"])]
            if _unres:
                rec["indirect_unresolved"] = len(_unres)
                # ★ 2026-09-10 — **"26개"만 말하면 아무도 못 푼다.** 실측(ahcache 9168):
                #   26건 중 다수가 `base='rsp'` 즉 `mov [rsp+0x20/0x28/0x30/0x38], rax` 로,
                #   Windows x64 의 **5번째 이후 호출 인자 슬롯**이다 — 디스패치 표가 아니라
                #   **콜백을 인자로 넘기는** 코드다. 그런데 매칭은 `off` 를 구조체 오프셋처럼
                #   비교하므로 rsp 상대 오프셋은 영원히 안 맞는다.
                #   ★ 그렇다고 제외하지 않는다: 넘겨진 콜백은 **피호출자가 부를 수 있으므로**
                #     부재 주장에 여전히 유효한 반례다. 게이트는 그대로 두고 **모양만 보여준다** —
                #     "26" 은 불투명한 벽이고, 분해된 목록은 작업 지시다.
                _byb = {}
                for _u in _unres:
                    _byb.setdefault("스택 인자(rsp)" if str(_u.get("base")) == "rsp"
                                    else "구조체 슬롯(%s)" % _u.get("base"), []).append(_u)
                def _hx(v):
                    """VA 는 **16진수**로. 10진수 5368730976 은 분석자에게 아무 의미가 없다."""
                    try:
                        return "0x%X" % int(str(v), 0)
                    except (TypeError, ValueError):
                        return str(v)
                _tf = sorted({_hx(_u.get("func")) for _u in _unres})
                rec["indirect_shapes"] = {k: len(v) for k, v in _byb.items()}
                _shape = ("\n분해: " + " · ".join("%s %d" % (k, len(v))
                                                 for k, v in sorted(_byb.items()))
                          + "\n실린 함수 %d개: %s"
                          % (len(_tf), ", ".join(_tf[:8]) + (" …" if len(_tf) > 8 else ""))
                          + "\n★ `rsp` 저장은 **디스패치 표가 아니라 인자 전달**이다(5번째 이후 "
                            "인자 슬롯). 그래도 피호출자가 그 콜백을 부를 수 있으므로 부재 "
                            "주장의 반례로 유효하다 — 푸는 길은 **그 콜백을 받는 피호출자를 "
                            "짚어 그 안에서 해소**하거나, 주장을 그 함수들이 못 닿는 범위로 "
                            "좁히는 것이다.")
                # ★ 한 번에 포맷한다. `A + _shape + B % args` 로 쓰면 `%` 가 `+` 보다
                #   먼저 묶여 뒤 리터럴에만 붙고 TypeError 가 난다 — 그러면 아래
                #   `except` 가 그걸 삼켜 **게이트가 통과된다**(조용한 완화).
                #   실제로 이 수정의 첫 판이 그 모양이었다. [[refactor-loosens-guards]]
                _head = ("There are %d UNRESOLVED FUNCTION POINTERS and you are filing "
                         "an absence-form rejection (klass='%s')."
                         % (len(_unres), klass))
                _eg = ("\ne.g. %s  %s  -> function %s"
                       % (_hx(_unres[0].get("take")), _unres[0].get("insn", "?"),
                          _hx(_unres[0].get("func"))))
                # ★ 2026-09-23 — 옛 문구는 **막다른 길만** 가리켰다("File it as blocked").
                #   그 결과 mrxsmb 09-23 에 census 가 실질적으로 끝난 형제 5개가
                #   "only the verdict FORM is refused" 로 통째로 미기록됐다.
                #   탈출구는 이미 어휘에 있다 — `bounded_absence`(범위 한정 부재).
                #   다만 그리로 보내면서 **숫자를 맞추게** 한다: 미해소 포인터 개수를
                #   `excludes_indirect=` 로 직접 적어야 통과한다(문장이 아니라 수).
                _tail = ("\nxref only sees direct references — if those functions can be "
                         "called indirectly, 'there is none' does not hold.\n"
                         "TWO legitimate ways forward — do NOT reword this klass a second time:\n"
                         "  (a) NARROW IT: klass='bounded_absence' with scope= naming the range "
                         "you actually enumerated, plus `excludes_indirect=%d` (the exact count "
                         "above). That files the substance instead of losing it.\n"
                         "  (b) RESOLVE the pointers: point at the callee that receives each "
                         "callback and close it there.\n"
                         "`gate_blocked` is the LAST resort, not the first." % len(_unres))
                return (False, _head + _shape + _eg + _tail, rec)
        except Exception as _e:
            rec["indirect_unresolved"] = "check_failed:%s" % _e
    if klass in ("no_sink", "unreachable") and not has_xref():
        return (False, "klass='%s' is an ABSENCE claim, but the ledger holds no "
                       "all-executable-section xref record.\n"
                       "Run import_xref() first — driver code is scattered across "
                       ".text / PAGE / INIT / fothk. In ipt.sys, .text was 12KB and PAGE 32KB, "
                       "and ALL FIVE authorization calls sat in PAGE. Looking only at .text "
                       "makes authorization appear to be zero." % klass, rec)

    # R3 — `guarded` 는 CFG 지배를 계산한다. 짝은 **선언**해야 한다(추론 금지).
    if klass == "guarded":
        # ★ 2026-09-04: `guards=` (복수) 를 받는다. 불변식을 **여러 블록이 함께** 세우는
        #   모양(체인/인그레스별 분기)을 단일 지배로는 표현할 수 없어서, 지휘자가 09-02 부터
        #   14회 같은 것을 보고했다. n=1 이면 `gates()` 와 **verdict 문자열까지** 동일하므로
        #   옛 판정 재실행이 그대로 회귀 시험이다(test_cutgate.py).
        _gs = args.get("guards")
        if isinstance(_gs, str):
            _gs = [x.strip() for x in re.split(r'[,\s]+', _gs) if x.strip()]
        gset = []
        for _x in (_gs or []):
            try:
                gset.append(int(str(_x), 0))
            except (TypeError, ValueError):
                # ★ 2026-09-10 — **`image!VA` 는 오타가 아니라 다른 주장이다.**
                #   실측: 03:17~03:19 에 한 행(`class1-mask-delta impact rung`)에서 거부가
                #   4번 연달아 났고 그중 하나가 `guards=['apphelp!0…']` 이었다. 옛 메시지는
                #   "must be VAs (0x…)" 라고만 해서 분석자가 형식 문제로 읽고 2분간 헛돌다
                #   그 행을 BLOCKED 로 닫았다. 형식 문제가 아니다 —
                #   **CFG 지배는 이미지를 가로지를 수 없으므로 `guarded` 가 애초에 틀린 klass 다.**
                #   허용으로 바꾸지 않는다(그러면 계산할 수 없는 것을 계산했다고 기록하게 된다).
                #   대신 **갈 길을 댄다.**
                _m = re.match(r"^\s*([A-Za-z_][\w.-]*)\s*!\s*(0x[0-9A-Fa-f]+|\d+)\s*$", str(_x))
                if _m:
                    _im, _iva = _m.group(1), _m.group(2)
                    _reg = (STATE.get("images") or {}).get(_im)
                    rec["cross_image_guard"] = {"image": _im, "va": _iva,
                                                "registered": bool(_reg)}
                    _known = ("등록돼 있다 (build %s)" % str(_reg.get("guid"))[:8]
                              if _reg else "이 원장에 **등록돼 있지 않다**")
                    return (False,
                            "klass='guarded' 에 **다른 이미지의 가드**를 줬다: %r\n"
                            "  · `%s` 는 %s.\n"
                            "이건 형식 문제가 아니다. `guarded` 는 이 이미지의 CFG 로 "
                            "**지배를 계산**하는 klass인데, CFG 는 이미지 경계를 넘지 않는다 — "
                            "다른 모듈 안의 분기가 이 모듈의 싱크를 지배하는지는 계산할 수 없다. "
                            "VA 로 바꿔 적어도 계산은 여전히 거짓이 된다.\n"
                            "갈 길은 셋이다:\n"
                            "  ① 주장이 정말 `%s` **안**의 것이면 그건 그 이미지에 대한 주장이다 — "
                            "그 이미지를 측정 빌드로 놓고 거기서 판정하라.\n"
                            "  ② 이 이미지 안에 지배하는 분기가 실제로 있으면 **그 VA** 를 대라 "
                            "(호출 이전에 이 모듈이 스스로 거는 검사).\n"
                            "  ③ 둘 다 아니면 `blocked` 로 적되 **이 교차이미지 앵커를 그대로 남겨라** "
                            "— 그러면 다음 회차가 형식 문제로 오해하지 않는다.\n"
                            "(등록 현황: `images(action='list')` · 등록: "
                            "`images(action='add', name=…, path=…)`)"
                            % (_x, _im, _known, _im), rec)
                return (False, "klass='guarded': `guards=` must be VAs (0x…): %r 을 못 읽었다."
                        % _x, rec)
        g, sk = args.get("guard"), args.get("sink")
        try:
            g = int(str(g), 0) if g is not None else None
            sk = int(str(sk), 0) if sk is not None else None
        except (TypeError, ValueError):
            g = sk = None
        if g is not None and g not in gset:
            gset.insert(0, g)
        if not gset:
            g = None
        elif g is None:
            g = gset[0]
        if g is None or sk is None:
            return (False, "klass='guarded' REQUIRES you to declare guard=<VA of the "
                           "conditional branch> and sink=<VA of the dangerous operation>.\n"
                           "'A guard exists' and 'the guard blocks every path' are different "
                           "claims, and the second one is COMPUTABLE from the CFG — so it is "
                           "not yours to assert.\n"
                           "Why the pair is not inferred from your prose: in practice a wrong "
                           "pair produced a false alarm (fn0xD).", rec)
        # ★ 짝을 **저장한다.** 2026-08-29 까지 R3 은 guard/sink 를 요구해 계산만 하고
        #   기록하지 않았다. 그래서 나중에 "그 짝이 주장의 짝이었나"를 물을 수 없었고,
        #   정책이 바뀌어도(예: bound_compare 권한 회수) **옛 판정을 재실행할 수 없었다.**
        #   실제로 WUDFRd `IOCTL_0x80018483` 는 짝이 없어 sink_block 으로 근사할 수밖에 없었고,
        #   그 근사가 39건의 가짜 `dominates_only` 를 만들었다.
        rec["guard"], rec["sink"] = g, sk
        if len(gset) > 1:
            rec["guards"] = [hex(x) for x in gset]
        if img is None:
            rec["cfg"] = {"verdict": "no_image"}
            return (True, "UNDECIDABLE - no image", ask(rec, "Could not open the target image, so CFG dominance was not computed", "no_image"))
        # ── R7 — 선언된 싱크가 **실제로 위험 연산인가.**
        #   R3 은 분석자가 고른 짝을 검증한다. 그 짝이 주장의 짝인지는 아무도 안 봤다.
        #   WUDFRd `IOCTL_0x80018483`: 주장은 "유저 포인터를 probe 없이 역참조한다"인데
        #   선언된 싱크는 `mov rdx, r13`(레지스터 이동)이었다. 게이트는 **무관한 짝**에
        #   `gated` 를 내주었고, 진짜 반박(프로브 헬퍼·MmUserProbeAddress)은 아무도 안 본
        #   자유 텍스트였다.
        try:
            import cfg as _CFG
            sc = _CFG.sink_class(img, sk)
        except Exception as _e:
            sc = {"class": "unknown", "why": str(_e)}
        rec["sink_class"] = sc
        if sc.get("class") == "reg_only":
            return (False, "R7: the declared sink 0x%X is not a dangerous operation — "
                           "`%s`.\n   %s\n"
                           "Computing that a guard dominates THAT location is IRRELEVANT TO "
                           "THE CLAIM. Give the VA of the actual operation your claim is about "
                           "(dereference / call / write) as the sink."
                           % (sk, sc.get("insn", "?"), sc.get("why", "")), rec)
        try:
            import cfg as CFG
            # 단일이면 gates(), 집합이면 gates_cut(). n=1 에서 둘은 동치다 —
            # 그래도 옛 경로를 그대로 둔다: 재실행 시 **호출된 함수까지** 같아야
            # "회귀가 아니라 동치"라고 말할 수 있다.
            r = (CFG.gates(img, g, sk) if len(gset) <= 1
                 else CFG.gates_cut(img, gset, sk))
            # 함수 간이면 호출그래프로 넘긴다 — "문에서 한 번만 검사" 모양이 여기 산다.
            if r.get("verdict") == "cross_function":
                import authz as AZ
                r2 = AZ.gates_inter(img, g, sk)
                r2["intra"] = "cross_function"
                r = r2
        except Exception as e:
            rec["cfg"] = {"verdict": "error", "why": str(e)}
            return (True, "UNDECIDABLE - CFG computation failed", ask(rec, "CFG computation failed: %s" % e, None))
        rec["cfg"] = r
        if r["verdict"] == "gated_no_authority":
            return (False, "R3 HAS NO AUTHORITY TO REJECT at this location.\n   %s\n"
                           "File it with `verdict(action='blocked', reason=...)` and give "
                           "separate evidence for why the constant / sign is safe."
                           % r["why"], rec)
        if r["verdict"] in ("both_edges", "not_dominated", "other_callers",
                            "not_a_cut", "no_escape", "padded_cut"):
            # ★ 2026-09-05 실측 — **강등이 절반만 됐었다.** 이 여섯은 `ask` 가 아니라
            #   `(False, …)` 하드 거부라 GATE_COMPUTE_ONLY 가 안 닿았다.
            #   점심 실측에서 msquic 이 같은 id 로 **4회 재시도**하다 `gate_blocked` 를 내고
            #   축을 접었다. 그 신고문이 정확히 이 게이트의 한계를 짚는다:
            #     *"the guard is enforced ONCE AT THE DOOR and carried forward in a FLAG BIT,
            #       so no intra-procedural dominance relation exists for the second arm."*
            #   ⇒ `not_dominated` 는 **건전한 반증**이지만(간선이 늘면 우회도 는다)
            #     "문 앞에서 한 번 검사하고 플래그로 나른다" 같은 **함수 간 불변식**을
            #     표현하지 못하는 것은 여전히 인코딩 한계다. 판단은 적대자가 한다.
            if getattr(_cfgmod(), "GATE_COMPUTE_ONLY", True):
                rec["cfg_refutes"] = {"verdict": r["verdict"], "why": r.get("why", "")[:400]}
                return (True, "CFG REFUTES THE PAIR (attached as evidence): %s"
                        % r.get("why", "")[:200], rec)
            return (False, "THE CFG MEASUREMENT REFUTES THIS REJECTION.\n   %s\n"
                           "A guard existing and a guard dominating the sink are different "
                           "things. Name a different guard, or this is not a rejection."
                           % r["why"], rec)
        if r["verdict"] not in ("gated", "gated_inter", "gated_cut"):
            return (True, "UNDECIDABLE - %s" % r["verdict"],
                    ask(rec, r.get("why", "")[:300], r["verdict"]))
        return (True, "CFG measured: %s" % r["why"], rec)
    return (True, "", rec)


# ★ 임팩트 필드 안의 **전수 주장**을 잡는다. "소비자는 유저모드뿐" 은 부재 주장인데
#   지금까지 아무 게이트도 안 걸렸다: G2 부재 게이트는 `claim` 만 보고, 승격자는
#   `delta=0`/`owner=none` 에서만 돈다. 그 사이로 **"delta 는 non-zero 인데 소비자는 X 뿐"**
#   이 그대로 빠져나가고, 그 한 문장이 등급 상한을 혼자 정한다.
#   좁게 잡는다: **전수 단어 + 주체 단어**가 같이 있을 때만 (검출기를 넓히면 게이트가 무력해진다).
_SOLE_WORD = r"(?:뿐|유일|밖에\s*없|만이|전부(?:다|이다)|only|sole|solely|nothing\s+else|" \
             r"no\s+other|exclusively|none\s+other)"
_SOLE_SUBJ = r"(?:소비자|소비|읽는|리더|경로|호출자|매퍼|파서|consumer|reader|caller|mapper|" \
             r"parser|path|kernel|커널)"
_SOLE = re.compile(r"(?:%s[^.\n]{0,60}%s|%s[^.\n]{0,60}%s)" %
                   (_SOLE_WORD, _SOLE_SUBJ, _SOLE_SUBJ, _SOLE_WORD), re.I)

_NONE_OWNER = ("none", "없음", "no one", "nobody", "n/a", "-")
_NA_DELTA = ("n/a", "na", "해당없음", "not applicable", "n\\a")


_DEAD_STATUS = ("기각", "반박됨")


def _resolve_row(rid, state=None):
    """id 하나를 원장 전체에서 찾는다 → (kind, status, klass, reason) 또는 None.

    verdicts / graveyard / surface 세 곳을 본다. **정확 일치만** 한다 —
    부분일치를 허용하면 이 검사가 산문 매칭이 되고, 그건 오늘 밤 두 번 측정으로 죽였다.
    """
    _S = state if state is not None else STATE
    # ★ 2026-09-06 — 기각에는 **신뢰 등급이 있다.** 심문자가 깼거나 재개 표시가 붙은 행은
    #   "죽은 주장"이 아니라 "서지 않는 기각"이다. 상태 문자열은 그대로 두고(소비자의
    #   죽은-전제 판정이 바뀌면 안 된다) 사유 앞에 표식만 붙인다.
    _gy = {str(g.get("id")): g for g in (_S.get("graveyard") or [])}

    def _doubt(rid_, v_=None):
        g_ = _gy.get(rid_) or {}
        ig = v_.get("interrogation") if isinstance((v_ or {}).get("interrogation"), dict) else {}
        if g_.get("reopened") and not g_.get("rekilled"):
            return "[재개됨 — 이 음성은 철회됐다] "
        if (ig or {}).get("broke") or g_.get("broke"):
            return "[심문자가 깼다 — 이 음성은 서 있지 않다] "
        return ""

    for v in (_S.get("verdicts") or []):
        if str(v.get("id")) == rid:
            _d = _doubt(rid, v) if v.get("status") == "기각" else ""
            return ("verdict", v.get("status"), (v.get("gate") or {}).get("klass"),
                    _d + str(v.get("claim") or "")[:200])
    for g in (_S.get("graveyard") or []):
        if str(g.get("id")) == rid:
            return ("graveyard", "기각", g.get("klass"),
                    _doubt(rid) + str(g.get("reason") or "")[:200])
    row = (_S.get("surface") or {}).get(rid)
    if isinstance(row, dict):
        return ("surface", row.get("status"), None, str(row.get("why") or "")[:200])
    return None


def _reach_gate(args):
    """★ **주장 간 정합성.** 확정이 의존하는 전제가 이미 죽어 있는지 본다. (ok, note, ask_why)

    왜 (2026-09-06, wcifs 채점본 §1 이 지목한 하니스 결함):
      모든 게이트가 **주장-국소적**이다 — *이* 주장의 근거만 본다. 그래서 wcifs 확정 2건이
      같은 원장이 이미 기각한 전제 위에 서 있었다:
        · `S13-OP12-FLAGS3` 의 트리거는 포트 opcode 12 인데 `PORT-REACH`(AppContainer 도달)가
          `by_design` 으로 기각 ⇒ 트리거하려면 이미 특권이 필요하다 ⇒ 경계를 안 넘는다
        · `S13-UAF-AVLNODE-V2` 의 free 팔은 `WcRemoveUnionContext` 인데 `S13-R5-PORT8b`
          (비특권이 그걸 부를 수 있다)가 기각된 바로 그 경로다
      G0~G4 어디도 이걸 못 본다. 확정 등재 때 **그 확정이 기대는 전제의 생사**를 안 물었다.

    ★ **자동 탐지는 만들지 않았다. 두 번 재고 두 번 버렸다** (2026-09-06 실측):
      · 심볼/VA 토큰 겹침(임계 1/2/3): wcifs 는 2건 중 1건만 잡고, ahcache 는 확정당
        **19~22건**이 뜬다(141개 기각이 같은 코드 영역에 몰려 토큰이 공유된다). 과대탐지.
      · 방향형(기각의 *표적* 심볼이 확정의 *주장문*에 등장): wcifs 2건 중 **0건** —
        `S13-R5-PORT8b` 의 표적에는 그 심볼이 없고 주장문에 있었다. ahcache 는 7~13건.
      ⇒ 읽는 쪽에서 못 고르면 **쓰는 쪽이 선언한다**(C-037 과 같은 결론).

    의무: `depends_on=` 에 이 확정이 **도달성·가용성을 빌려오는 행/판정의 id** 를 댄다.
    빌려오는 게 없으면 `depends_on='none'` 이라고 **명시**한다(임팩트 게이트의 `owner='none'`
    과 같은 탈출구 — 만족 불가능한 게이트는 에이전트를 blocked 로 도망가게 만든다).
    """
    raw = str(args.get("depends_on") or "").strip()
    if not raw:
        # ★ **막지 않는다.** 임팩트 게이트가 이미 기록해 둔 교훈이다 — "게이트를 만족
        #   불가능하게 만들면 에이전트가 blocked 로 도망가고 그게 더 나쁘다". 확정은 587행 중
        #   3건인 귀한 자리라 거기서 하드 브레이크를 걸면 손해가 더 크다.
        #   대신 **선언 안 한 확정을 셀 수 있게** 만든다(`dependency_audit` 의 두 번째 통).
        return (True, "",
                "THIS CONFIRMATION DID NOT DECLARE WHAT IT BORROWS REACHABILITY FROM.\n"
                "  depends_on=<id>[,<id>...]  the rows/verdicts whose reachability or "
                "availability this claim rests on (the trigger path, the caller population, "
                "the principal that can drive it).\n"
                "  depends_on='none'          if the claim is self-contained — say it "
                "EXPLICITLY, the same way owner='none' is said.\n"
                "WHY: every other gate here is claim-local. Two wcifs confirmations were "
                "filed on premises this same ledger had already rejected, and nothing noticed. "
                "Naming the dependency is what makes that checkable, and it is what lets "
                "`dependency_audit()` re-flag this row if the premise dies LATER. "
                "Undeclared confirmations are counted separately and stay visible.")
    if raw.lower() in ("none", "-", "없음"):
        return (True, "", "")

    ids = [x.strip() for x in raw.replace(";", ",").split(",") if x.strip()]
    missing, dead, alive = [], [], []
    for rid in ids:
        r = _resolve_row(rid)
        if r is None:
            missing.append(rid)
        elif r[1] in _DEAD_STATUS or r[0] == "graveyard":
            dead.append((rid, r))
        else:
            alive.append((rid, r[1]))
    if missing:
        known = [str(v.get("id")) for v in (STATE.get("verdicts") or [])][-14:]
        return (False,
                "depends_on names ids that do not exist on this ledger: %s\n"
                "Use an EXACT id from verdicts / graveyard / the surface table — no partial "
                "matches (a fuzzy dependency is not checkable).\nRecent verdict ids: %s"
                % (", ".join(missing), ", ".join(known)), "")
    if dead:
        lines = "\n".join(
            "  · %s  [%s%s]  %s" % (rid, r[1], ("/" + str(r[2])) if r[2] else "", r[3][:150])
            for rid, r in dead)
        return (True, "", 
                "THIS CONFIRMATION RESTS ON A PREMISE THIS LEDGER HAS ALREADY KILLED:\n"
                + lines +
                "\nA rejection can NARROW a claim instead of contradicting it — that is common "
                "and legitimate (a sibling caller ruled out, a wider variant killed). So this "
                "is a QUESTION, not a refusal. Answer one of:\n"
                "  (a) the rejection kills a DIFFERENT claim than the one I depend on — say "
                "which, and why the part I need survives;\n"
                "  (b) the rejection is wrong and should be reopened — "
                "`verdict(action='reopen', ...)` with the new observation;\n"
                "  (c) it does undercut me — then this is not a confirmation. Lower it.\n"
                "★ If the dependency dies LATER, `dependency_audit()` will surface this row "
                "again. That is the point of declaring it.")
    return (True, "", "")


def surface_sites(state=None):
    """★ **행이 아니라 사이트로 센다.** 반환: (사이트수, 행수, 중복행수, 최다중복 목록)

    ★ 2026-09-07 실측 — 표면 키가 자유 문자열이라 같은 주소를 여러 행이 문다:
      ahcache 620행 / 고유주소 309 / 중복을 문 행 267, wcifs 583행 / 333 / 377.
      `0x140038850` 하나를 여러 행이 각각 문다
      (`IOCTL f6 -> 0x140038850`, `0x140038850`, `S14-AZ-f6_…_ungated`).
      결과가 두 겹이다: ① **분모가 구조적으로 부풀려진다** — "620행 중 미분석 607" 의
      620 은 고유 조사 대상 수가 아니다 ② **한 사이트의 이력이 분산된다** — 같은 주소인데
      한 행은 판정, 다른 행은 미분석이다.
    ★ 합치지 않는다. 원장을 자동으로 병합하는 것은 되돌릴 수 없고, 어느 행의 판정이
      사이트 전체를 대표하는지는 기계가 정할 일이 아니다. **세는 방법만 고친다.**
    """
    _S = (state if state is not None else STATE).get("surface") or {}
    import collections as _c
    own = _c.defaultdict(list)
    noaddr = 0
    for k, v in _S.items():
        va = set(x.lower() for x in re.findall(r'0x[0-9a-fA-F]{6,16}', k))
        if not va:
            noaddr += 1
            continue
        for a in va:
            own[a].append(k)
    dup_rows = {k for ks in own.values() if len(ks) > 1 for k in ks}
    top = sorted(((a, ks) for a, ks in own.items() if len(ks) > 1),
                 key=lambda x: -len(x[1]))[:5]
    # 사이트 수 = 고유 주소 + 주소 없는 행(각자 하나의 사이트로 센다)
    return len(own) + noaddr, len(_S), len(dup_rows), top


def site_history(va, state=None):
    """한 주소를 문 행들의 **상태를 한 줄로** 모은다. 이력 분산을 눈으로 보게 한다."""
    _S = (state if state is not None else STATE).get("surface") or {}
    a = str(va).lower()
    out = []
    for k, v in _S.items():
        if a in k.lower():
            out.append((k[:70], v.get("status"), bool(v.get("blocked"))))
    return out


def graveyard_trust(state=None, limit=40):
    """★ **묘지를 등급별로 센다.** 에이전트는 묘지를 사실로 읽는다 — 그러면 묘지가 틀린 만큼
    다음 회차가 틀린다. 반환: (counts, suspect_rows, n_suspect)

    등급 (배타적, 위에서부터):
      · `orphan`      판정 레코드가 아예 없다 — 사유·심문 이력을 대조할 수 없다
      · `reopened`    재개 표시가 붙었는데 묘지에 그대로 있다(= 철회된 음성)
      · `broke`       심문자가 깼는데 그대로 있다(= 서지 않는 음성)
      · `unexamined`  적대자를 **한 번도 안 거쳤다**
      · `verified`    심문자가 못 깼다 — 이것만이 검증된 음성이다

    ★ 왜 이게 필요한가 (2026-09-06 실측): ahcache 묘지 167행 중 `verified` 는 **54행(32%)**,
      wcifs 76행 중 **25행(33%)** 뿐이었다. 나머지가 같은 무게로 프라이밍에 실려
      "CLAIMS ALREADY KILLED (do not resurrect)" 로 나갔다.
    """
    _S = state if state is not None else STATE
    V = {str(v.get("id")): v for v in (_S.get("verdicts") or [])}
    # ★ 2026-09-07 자기 정정 — 첫 판에서 `orphan` 이 **후보 집합에서 닫힌 행을 잡아먹었다.**
    #   `close_candidate` 는 후보 id(`C<n>`)로 묘지에 넣는다. 그 행의 근거는 `verdicts` 가 아니라
    #   `candidates` 에 산다(claim/basis/evidence/anchors 다 있다). 실측: ahcache 10 · wcifs 14
    #   전부 그 경우였고 **진짜 미아는 0** 이었다. 다른 저장소를 안 보고 "판정이 없다"고 세면
    #   그건 [[queue-mixes-two-kinds]] 와 같은 오류다.
    CAND = {str(c.get("id")): c for c in (_S.get("candidates") or [])}
    counts = {"orphan": 0, "candidate": 0, "reopened": 0, "broke": 0,
              "unexamined": 0, "verified": 0}
    rows = []
    for g in (_S.get("graveyard") or []):
        gid = str(g.get("id"))
        v = V.get(gid)
        ig = v.get("interrogation") if isinstance((v or {}).get("interrogation"), dict) else {}
        if v is None and gid in CAND:
            # 후보로 닫힌 행. 적대자를 거쳤는지는 origin 이 말한다.
            k = "verified" if g.get("origin") == "refuted" else "candidate"
        elif v is None:
            k = "orphan"
        elif g.get("reopened") and not g.get("rekilled"):
            k = "reopened"
        elif (ig or {}).get("broke") or g.get("broke"):
            k = "broke"
        elif v.get("interrogated") is True or g.get("interrogated") is True:
            k = "verified"
        else:
            k = "unexamined"
        counts[k] += 1
        if k in ("reopened", "broke"):
            rows.append({"id": gid, "grade": k, "klass": g.get("klass"),
                         "target": str(g.get("target"))[:90],
                         "why": str((ig or {}).get("reason")
                                    or ((g.get("reopens") or [{}])[-1].get("why")))[:160]})
    return counts, rows[:limit], len(rows)


def untouched_regions(image_path, state=None, page=0x1000, limit=12):
    """판정·표면 **어느 행도 주소로 언급한 적 없는** 실행 영역. (구간, 함수수, 총바이트)

    ★ 왜 (2026-09-09 야간런 실측): 지휘자의 pick 스키마는 *"lead id or track name **that
      exists in the digest**"* 인데 digest 에 **헌팅 땅이 아예 없다.** 그래서 운영자 목표가
      "근본원인의 변종을 인구 단위로 찾아라"일 때조차 지휘자는 리드/트랙 밖으로 라우팅할
      **수단이 없었다** — 케이스 1·2·3 이 연속으로 리드/트랙을 골랐고, 3회차는 목표를 읽고
      *"표류: 다섯 회차가 인접 축의 음성만 닫았다"* 라고 **스스로 진단하면서도** 리드를 골랐다.
      불복종이 아니라 구조적 불능이다.

    ★ **표면 행으로 등재하지 않는다.** 이건 뷰이지 분모가 아니다 — 등재하면 하니스가
      시드가 금지한 "분모 팽창"을 스스로 하게 된다. 지휘자에게 **보여주기만** 한다.

    ★ 계기의 한계를 같이 말한다: "언급됐다"는 판정/표면 **문자열에 그 주소가 나타났다**는
      뜻이지 그 코드가 분석됐다는 뜻이 아니다. 과소·과대 둘 다 가능하다.
    """
    import struct
    _S = state if state is not None else STATE
    try:
        raw = open(image_path, "rb").read()
        off = struct.unpack_from("<I", raw, 0x3c)[0]
        nsec = struct.unpack_from("<H", raw, off + 6)[0]
        optsz = struct.unpack_from("<H", raw, off + 20)[0]
        base = struct.unpack_from("<Q", raw, off + 24 + 24)[0]
        sbase = off + 24 + optsz
    except Exception as e:
        return [], 0, 0
    buckets, execranges = {}, []
    for i in range(nsec):
        e = sbase + i * 40
        nm = raw[e:e + 8].rstrip(b"\0").decode("ascii", "replace")
        vs, va = struct.unpack_from("<II", raw, e + 8)[0:2]
        ch = struct.unpack_from("<I", raw, e + 36)[0]
        if ch & 0x20000000:                       # MEM_EXECUTE
            execranges.append((base + va, base + va + vs, nm))
            for b in range((base + va) // page, (base + va + vs + page - 1) // page):
                buckets[b] = nm
    if not buckets:
        return [], 0, 0
    seen = set()
    _re = re.compile(r'0x([0-9a-fA-F]{6,16})')
    for blob in ([" ".join(str(v.get(k) or "") for k in ("target", "id", "claim"))
                  for v in (_S.get("verdicts") or [])]
                 + list((_S.get("surface") or {}).keys())
                 + [str(a.get("target") or "") for a in (_S.get("asks") or [])]):
        for h in _re.findall(blob):
            seen.add(int(h, 16) // page)
    un = sorted(b for b in buckets if b not in seen)
    runs = []
    for b in un:
        if runs and b == runs[-1][-1] + 1:
            runs[-1].append(b)
        else:
            runs.append([b])
    # .pdata 로 각 구간의 함수 수를 센다 — "몇 KB 남았나"보다 "몇 함수냐"가 고를 수 있는 단위다
    fns = []
    try:
        import pe as _PE
        fns = [f[0] for f in _PE.PE(image_path).runtime_functions()]
    except Exception:
        pass
    rows, tot_f, tot_b = [], 0, 0
    for r in runs:
        lo, hi = r[0] * page, (r[-1] + 1) * page - 1
        nf = sum(1 for a in fns if lo <= a <= hi)
        sec = buckets[r[0]]
        rows.append({"lo": lo, "hi": hi, "sec": sec, "funcs": nf, "bytes": hi - lo + 1})
        tot_f += nf
        tot_b += hi - lo + 1
    rows.sort(key=lambda x: -x["funcs"])
    return rows[:limit], tot_f, tot_b


def untouched_digest(image_path, state=None, n=6):
    """`untouched_regions` 를 지휘자 digest 에 실을 문자열로. 비어 있으면 빈 문자열."""
    try:
        rows, tf, tb = untouched_regions(image_path, state)
    except Exception as e:
        return "\n[미접촉 실행영역: 계산 실패 %s]" % type(e).__name__
    if not rows:
        return ""
    L = ["", "[★ 아직 아무 행도 주소로 언급하지 않은 실행 영역 — %d구간 · 함수 %d개 · %dKB]"
         % (len(rows), tf, tb // 1024),
         "  이건 **표면 행이 아니다**(분모가 아니다). 헌팅 목표일 때 `pick.what='row'` 로",
         "  이 중 한 구간을 지목할 수 있다 — 리드/트랙 밖으로 나가는 유일한 길이다.",
         "  ※ '언급됨'은 문자열에 주소가 나타났다는 뜻이지 분석됐다는 뜻이 아니다."]
    for r in rows[:n]:
        L.append("  0x%x–0x%x [%s] 함수 %d개 · %dKB"
                 % (r["lo"], r["hi"], r["sec"], r["funcs"], r["bytes"] // 1024))
    return "\n".join(L)


def resisted(target=None, state=None, min_n=2, limit=40):
    """★ **죽이려다 실패한 행.** (rows, counts) — 이 하네스에 없던 방향의 큐다.

    왜 (2026-09-08 실측, 전 원장):
      이 하네스의 압력은 전부 "죽이기"다. 확정은 반박자가, 기각은 심문자가 죽이러 온다.
      그런데 **죽이려다 실패한 사건은 아무 데도 안 간다.** 기각 시도가 게이트에 반려되면
      `denials` 평면 로그에 규칙별로만 쌓이고(`denial_report` 는 "어느 규칙이 잡았나"를
      답하지 "어느 행이 버텼나"를 답하지 않는다), CFG 가 짝을 반증해도
      `GATE_COMPUTE_ONLY` 가 증거로 첨부만 하고 지나간다.
      실측: 기각 시도가 **2회 이상** 반려된 표적 30개(최대 12회), `cfg_refutes` 27건.
      그리고 축이 **겹치는** 행이 있다 — `dispatcher 0x140038360` 은 반려 4회 +
      cfg_refutes(no_escape) + 심문자 파기 + reopened 를 동시에 갖고 있었다.

    ★ 자동 승격은 **하지 않는다.** 여기서 상태를 바꾸면 "양을 질의 대리변수"로 쓰는 것이다
      (`threshold-triggers-audit-not-rollback`). 이 함수는 큐만 만든다 — 재분석은 사람/
      다음 회차가 한다.

    ★ 같은 klass 로 5번 반려된 것과 **서로 다른 klass 3개**로 반려된 것은 다른 사건이다.
      전자는 서류 문제(짝 선언·인용 형식)고, 후자는 **여러 사망 가설이 전부 안 먹혔다**는
      뜻이다. 그래서 `klasses` 를 따로 세고 랭킹의 1순위로 쓴다.

    ★ `broke` 축은 **세기만** 한다. 그 큐는 `reports/breaks/` 리드 큐가 이미 갖고 있으므로
      여기서 다시 닫게 하면 두 큐가 같은 일을 두 번 시킨다(`queue-mixes-two-kinds`).
      대신 그 행의 리드 id 를 실어 보내 **중복 작업을 막는다.**

    ★ 저항 0 인 행은 큐에 **안 나온다** — 0 이 아니라 "시도된 적 없음"이고, 그건
      `worklist`/`unfinished` 소관이다. 두 값을 한 칸에 섞지 않는다.
    """
    _S = state if state is not None else STATE
    K = lambda t: str(t or "")[:100]
    rows = {}

    def _row(t):
        return rows.setdefault(K(t), {"target": K(t), "denied": 0, "klasses": set(),
                                      "cfg": [], "broke": 0, "lead_ids": [],
                                      "verdicts": [], "last_t": ""})

    # 축 B — 기각 시도가 게이트에 반려됐다
    for d in (_S.get("denials") or []):
        if str(d.get("act")) != "reject":
            continue
        r = _row(d.get("target"))
        r["denied"] += 1
        if d.get("klass"):
            r["klasses"].add(str(d["klass"]))
        if str(d.get("t") or "") > r["last_t"]:
            r["last_t"] = str(d.get("t") or "")

    # 축 C — CFG 가 짝을 반증했는데 기각이 등재됐다
    # 축 A — 심문자가 그 기각을 깼다 (세기만 한다)
    _gy = {str(g.get("id")): g for g in (_S.get("graveyard") or [])}
    for v in (_S.get("verdicts") or []):
        if str(v.get("status")) != "기각":
            continue
        g = v.get("gate") or {}
        cr = g.get("cfg_refutes")
        ig = v.get("interrogation") if isinstance(v.get("interrogation"), dict) else {}
        broke = bool((ig or {}).get("broke")) or bool(_gy.get(str(v.get("id")), {}).get("broke"))
        if not cr and not broke:
            continue
        r = _row(v.get("target"))
        r["verdicts"].append(str(v.get("id")))
        if cr:
            r["cfg"].append(str(cr.get("verdict") or "?"))
        if broke:
            r["broke"] += 1
        if str(v.get("t") or "") > r["last_t"]:
            r["last_t"] = str(v.get("t") or "")

    # 리드 id 를 실어 보낸다 (중복 작업 방지)
    try:
        for b in breaks(_S.get("target"), open_only=True, queue="lead"):
            k = K(b.get("target"))
            if k in rows:
                rows[k]["lead_ids"].append(str(b.get("id")))
    except Exception:
        pass

    out = []
    for r in rows.values():
        r["klasses"] = sorted(r["klasses"])
        r["axes"] = ((1 if r["denied"] else 0) + (1 if r["cfg"] else 0)
                     + (1 if r["broke"] else 0))
        r["score"] = (r["axes"], len(r["klasses"]), r["denied"] + len(r["cfg"]) + r["broke"])
        # ★ 축마다 문턱이 다르다 — 신호의 세기가 다르기 때문이다.
        #   · `cfg` 는 **1건이면 든다.** 기계가 "선언한 짝이 지배하지 않는다"를 계산했는데
        #     기각이 등재된 것이고, 지금 이걸 보는 소비자가 **하나도 없다**.
        #   · `denied` 는 **min_n 이상**이어야 든다. 한 번은 서류 문제(짝 선언·인용 형식)일
        #     수 있다. 반복돼야 행의 성질이다.
        #   · `broke` **단독**은 안 든다 — `reports/breaks/` 리드 큐가 이미 그 일을 시킨다.
        #     여기서는 다른 축과 **겹칠 때만** 의미가 있다(겹침이 이 큐의 존재 이유다).
        if r["cfg"] or r["axes"] >= 2 or r["denied"] >= min_n:
            out.append(r)
    out.sort(key=lambda r: r["score"], reverse=True)
    counts = {"rows": len(out), "multi_axis": sum(1 for r in out if r["axes"] >= 2),
              "denied_only": sum(1 for r in out if r["axes"] == 1 and r["denied"]),
              "cfg_refuted": sum(1 for r in out if r["cfg"]),
              "attempts_total": sum(r["denied"] + len(r["cfg"]) + r["broke"] for r in out)}
    return out[:limit], counts


def backfill_ask_fields(state=None):
    """옛 질문에 `kind`/`by` 를 **소급**한다. (kind채움, by채움)

    ★ 지어내지 않는다 — 둘 다 **이미 있는 칸에서 유도**한다:
        kind ← `ask_kind(cfg)`   (cfg 가 없으면 손대지 않는다. 0 과 미측정을 안 섞는다)
        by   ← 기존 `by`, 없으면 id 접두(CQ/RQ/XQ) — 어휘에 없으면 `gate`(옛 기본값)
    ★ 왜 필요한가: 전수 231/231 · 125/125 가 `kind=None` 이라 **단일 큐를 정렬할 축이
      없었다.** 새 행만 고치면 옛 356행이 영원히 랭킹 바닥/중간에 깔린다.
    """
    S = state if state is not None else STATE
    nk = nb = 0
    for a in (S.get("asks") or []):
        if not a.get("kind") and a.get("cfg"):
            a["kind"] = ask_kind(a.get("cfg"))
            nk += 1
        _b = normalize_ask_by(a.get("by"), a.get("id"))
        if a.get("by") != _b:
            a["by"] = _b
            nb += 1
    return nk, nb


def ask_queue(state=None, n=10, audience="analyst"):
    """★ **하나의 큐.** 출처별 실측 수율로 정렬해 렌더한다.

    ★ 이 함수가 답하는 것: "지금 열린 질문 중 **답해질 가능성이 가장 높은 것**이 무엇인가."
      출처가 랭킹 축인 근거는 원장 실측이다 — `by=conductor` 는 ahcache 185건 중
      answered **0건**, 게이트·반박자는 46건 중 15건(32.6%)이었다. 그런데 열린 질문의
      113/115 가 지휘자 것이라 회전 창이 돌아도 보이는 것은 사실상 지휘자 질문뿐이었다.
    """
    S = state if state is not None else STATE
    Q = open_asks(S, audience=audience, rank=True, include_leads=True)
    if not Q:
        return ""
    y = ask_yield(S)
    import collections as _c
    byo = _c.Counter(normalize_ask_by(a.get("by"), a.get("id")) for a in Q)
    byk = _c.Counter(str(a.get("kind") or "(미분류)") for a in Q)
    L = ["## ⟂ 질문 큐 — 열린 질문 %d건 (하나의 큐다: 게이트·반박자·심문자·저항·지휘자)" % len(Q), ""]
    L.append("  출처: " + " · ".join("%s %d" % kv for kv in byo.most_common()))
    L.append("  종류: " + " · ".join("%s %d" % kv for kv in byk.most_common()))
    _yl = [("%s %d/%d닫힘(전체%d)" % (o, d["answered"], d["closed"], d["n"]) +
            ("" if d["rate"] is None else " (%.0f%%)" % (d["rate"] * 100)))
           for o, d in sorted(y.items(), key=lambda kv: -(kv[1]["rate"] or 0))]
    L.append("  이 원장의 출처별 **답해진 비율**: " + " · ".join(_yl))
    L += ["  ★ 정렬은 수율 > 시도횟수 > 오래된 순이다. `inexpressible` 은 관측 부족이 아니라",
          "    **게이트가 그 모양을 표현 못 하는 것**이다 — 답이 판정이 아니라 `gate_blocked` 다.", ""]
    for a in Q[:n]:
        o = normalize_ask_by(a.get("by"), a.get("id"))
        L.append("- `%s` [%s/%s] %s%s"
                 % (a.get("id"), o, a.get("kind") or "?", str(a.get("target"))[:62],
                    ("  (시도 %d회)" % len(a.get("attempts") or []))
                    if (a.get("attempts") or []) else ""))
        if a.get("why"):
            L.append("    왜: %s" % str(a["why"]).replace("\n", " ")[:200])
        if a.get("method"):
            L.append("    다음 수: %s" % str(a["method"]).replace("\n", " ")[:260])
        if a.get("_close_via"):
            L.append("    닫기: %s" % a["_close_via"])
    return "\n".join(L)


def resisted_to_asks(target=None, state=None, save_now=True):
    """★ 저항 행을 **질문으로 낸다.** 별도 큐를 두지 않는다. (생성수, 시도증가수)

    ★ 왜 큐가 아니라 질문인가 (2026-09-08 운영자 지적):
      큐를 종류별로 만들면 회차마다 어느 큐를 볼지가 임의가 되고 큐끼리 경쟁한다.
      실측이 그 모양이었다 — ahcache 에 저항 31 · 재심 34 · 리드 23 이 겹침 4/12/8 로
      서 있었고, 45분 케이스가 셋을 다 볼 수 없다.
      그리고 **단일 질문 큐는 이미 있었다**(`asks`). 필드도(target/claim/klass/guard/sink/
      cfg/why/method/status/**attempts**) 기제도(같은 행 재질문은 새 행이 아니라 attempts
      증가, `render_ask` 가 렌더 시점에 선례 조립) 맞다. 없던 것은 **정렬 축**뿐이었고
      그게 `kind`(계산해놓고 안 저장) 와 `by`(출처) 다.

    ★ 저항이 `asks` 와 **겹치지 않는다**는 것이 이 함수의 존재 이유다: 실측 교집합
      ahcache 0/31 · wcifs 1/8. `asks` 는 게이트가 UNDECIDABLE 일 때만 질문을 만들고,
      DENIED(요건 미충족)·CFG반증은 질문을 안 만들었다. 같은 "죽이려다 실패"인데
      한쪽만 큐를 가졌던 것이다.

    ★ 지어내지 않는다: 축이 하나뿐이고 klass 도 하나면 **서류 문제**일 가능성이 높아
      질문을 내지 않는다(`axes>=2` 또는 klass 2종 이상 또는 CFG반증).
    """
    S = state if state is not None else STATE
    rows, _ = resisted(target, S)
    made = bumped = 0
    for r in rows:
        multi_klass = len(r["klasses"]) >= 2
        if not (r["axes"] >= 2 or multi_klass or r["cfg"]):
            continue
        tgt = r["target"]
        # CFG 가 반증했다 = 게이트가 이 불변식을 **표현 못 한다**(함수 간 / 문앞 1회 검사).
        kind = "inexpressible" if r["cfg"] else "need_observation"
        if multi_klass:
            why = ("죽이려다 실패했다 — 서로 다른 사망 가설 %d개(%s)가 전부 안 먹혔다"
                   % (len(r["klasses"]), ", ".join(r["klasses"][:4])))
            method = ("반려 사유가 **매번 달랐다**면 서류 문제가 아니다. 이 행이 안 죽는 "
                      "이유가 결함이기 때문인지 물어라 — `confirm` 의 임팩트 3항을 써 "
                      "보는 것이 가장 빠른 판별이다(못 쓰면 그건 그것대로 답이다). "
                      "쓸 수 있으면 그게 답이고, 못 쓰면 `exhaust` 로 정직하게 닫아라.")
        elif r["cfg"]:
            why = ("기계가 네 짝을 반증했는데 기각이 등재됐다 (%s)" % ",".join(sorted(set(r["cfg"]))[:3]))
            method = ("짝을 다시 선언하거나(`guards=` 로 컷 전체), 불변식이 **함수 간**이면 "
                      "(문 앞에서 한 번 검사하고 플래그로 나르는 모양) 그건 이 게이트가 "
                      "표현 못 하는 것이다 — `gate_blocked` 로 무엇을 못 적었는지 남겨라.")
        else:
            why = "죽이려다 %d번 실패했다 (반려 %d · 파기 %d)" % (
                r["denied"] + r["broke"], r["denied"], r["broke"])
            method = "같은 klass 로 반복 반려됐다면 요건을 갖춰 다시 내라. 그것도 닫은 것이다."
        if r["lead_ids"]:
            method += ("  ★ 이 행은 리드 %s 로도 서 있다 — **거기서** 닫아라(두 큐가 같은 "
                       "일을 두 번 시키지 않는다)." % ",".join(r["lead_ids"][:2]))
        # ★ 2026-09-08 자기 정정 — id 가 **위치 기반**(`XQ%d`)이었다. 이 함수는 시드
        #   렌더(파일 사본)와 라이브 원장 **양쪽에서** 돌기 때문에, 위치 기반이면 같은 행이
        #   두 곳에서 **다른 id** 를 받는다: 분석가가 SEED 에서 본 `XQ3` 을
        #   `verdict(action='asks')` 로 못 찾는다. ⇒ **표적에서 결정적으로** 만든다.
        qid = "XQ-" + hashlib.sha1(tgt.encode("utf-8", "replace")).hexdigest()[:8]
        cur = r["denied"] + len(r["cfg"]) + r["broke"]      # 이 행의 저항 총량
        # ★ **열린 행만** 잡는다. id 로만 잡으면 닫힌 XQ 에 attempts 를 올리게 되고,
        #   아래의 "닫힌 것은 되살리지 않는다" 분기에 영영 도달하지 못한다(테스트가 잡았다).
        prev = None
        for q in (S.get("asks") or []):
            if (q.get("status") or "open") != "open":
                continue
            if str(q.get("id")) == qid or q.get("target") == tgt:
                prev = q
                break
        if prev is not None:
            # ★ **재생성으로 시도를 부풀리지 않는다.** 이 함수는 매 회차(그리고 시드 렌더마다)
            #   돈다 — 무조건 attempts 를 올리면 랭킹 2순위 축이 "몇 번 돌았나"가 되어 버린다.
            #   저항이 **실제로 늘었을 때만** 올린다.
            if cur > int(prev.get("resist_n") or 0):
                prev.setdefault("attempts", []).append(
                    {"t": time.strftime("%m-%d %H:%M"), "cfg": "resisted", "kind": kind})
                prev["resist_n"] = cur
                if kind == "inexpressible":
                    prev["kind"] = "inexpressible"
                elif not prev.get("kind"):
                    prev["kind"] = kind
                bumped += 1
            continue
        # ★ 닫힌 XQ 는 **되살리지 않는다.** 저항이 그 뒤로 더 늘었으면 그건 닫은 뒤에 생긴
        #   새 관측이므로 **새 질문**이다(`-2`). 되살리면 `_ask_close` 의 일괄 종결과 맞물려
        #   열림↔닫힘을 무한히 오간다.
        _closed = [q for q in (S.get("asks") or []) if str(q.get("id")).startswith(qid)]
        if _closed:
            if cur <= max(int(q.get("resist_n") or 0) for q in _closed):
                continue
            qid = "%s-%d" % (qid, len(_closed) + 1)
        S.setdefault("asks", []).append(
            {"id": qid, "target": tgt,
             "why": why, "method": method, "kind": kind, "by": "resisted",
             "cfg": (sorted(set(r["cfg"]))[0] if r["cfg"] else None),
             "klass": (r["klasses"][0] if r["klasses"] else None),
             "resist_n": cur,
             "status": "open", "attempts": [], "t": time.strftime("%m-%d %H:%M")})
        made += 1
    if save_now and state is None and (made or bumped):
        save()
    return made, bumped


def resisted_digest(target=None, state=None, n=8):
    """`resisted()` 를 시드·상태블록에 실을 문자열로. 비어 있으면 빈 문자열."""
    try:
        rows, c = resisted(target, state)
    except Exception as _e:
        return "(⛔ resisted 실패: %s)" % _e
    if not rows:
        return ""
    L = ["## ⟂ 저항 큐 — **죽이려다 실패한 행** %d건 (축 2개 이상: %d)"
         % (c["rows"], c["multi_axis"]), "",
         "  이 행들은 누군가 이미 죽이려 했고 **실패했다.** 반려는 서류 문제일 수 있지만,",
         "  **서로 다른 klass 로 반복 반려된 행**은 사망 가설이 여러 개 안 먹혔다는 뜻이다.",
         "  `cfg` 는 기계가 짝을 반증했는데 기각이 등재된 것이고, `broke` 는 심문자가 깬 것이다.",
         "  ★ 자동 승격은 없다 — 이건 **재분석 대상 목록**이지 확정 후보 목록이 아니다.", ""]
    for r in rows[:n]:
        bits = []
        if r["denied"]:
            bits.append("반려 %d회%s" % (r["denied"],
                        (" [klass %s]" % ",".join(r["klasses"][:4])) if r["klasses"] else ""))
        if r["cfg"]:
            bits.append("CFG반증 %s" % ",".join(sorted(set(r["cfg"]))[:3]))
        if r["broke"]:
            bits.append("심문자파기 %d" % r["broke"])
        L.append("- %s" % r["target"][:78])
        L.append("    %s%s" % (" · ".join(bits),
                               ("  (리드 %s — 거기서 닫아라)" % ",".join(r["lead_ids"][:2]))
                               if r["lead_ids"] else ""))
    L += ["", "전체는 `verdict(action='resisted')`."]
    return "\n".join(L)


def dependency_audit(limit=40, state=None):
    """확정 중 **선언한 전제가 죽어 있는** 것을 이름째 돌려준다. (rows, n)

    ★ 게이트는 등재 **시점**만 본다. 전제는 나중에 죽는다 — 그때 아무도 다시 안 본다.
      이 함수가 그 되돌아보기다. `reach_unknown` / `dead_claim_open` 과 같은 계열:
      **게이트가 요구하는 것을 열거 가능하게 만든다.**
    """
    # ★ `state=` 로 **스냅샷**을 받는다. `nightrun.build_carryover` 는 파일에서 읽은 dict
    #   으로 이어받기를 만들고 `ledger.STATE` 를 안 쓴다 — STATE 만 읽게 짜면 부모
    #   프로세스에서 **조용히 0건**이 나온다. 오늘 이 함정을 두 번 밟았다
    #   (`verify-through-the-production-path`). 로직은 한 벌, 출처만 인자로.
    _S = state if state is not None else STATE
    out, undeclared = [], []
    for v in (_S.get("verdicts") or []):
        if v.get("status") != "확정":
            continue
        dep = str(v.get("depends_on") or "").strip()
        if not dep:
            # ★ 두 번째 통: **선언 자체를 안 한 확정.** 막지 않기로 했으므로 이게
            #   유일한 가시성이다. 안 세면 "선택적 기제는 안 쓰인다"가 그대로 재현된다
            #   (scope: 560행에 1회, 안내는 104회 나갔다).
            undeclared.append({"verdict": str(v.get("id")), "target": str(v.get("target"))[:80]})
            continue
        if dep.lower() in ("none", "-", "없음"):
            continue
        for rid in [x.strip() for x in dep.replace(";", ",").split(",") if x.strip()]:
            r = _resolve_row(rid, _S)
            if r is not None and (r[1] in _DEAD_STATUS or r[0] == "graveyard"):
                out.append({"verdict": str(v.get("id")), "target": str(v.get("target"))[:80],
                            "depends_on": rid, "now": r[1], "klass": r[2]})
    return out[:limit], len(out), undeclared[:limit], len(undeclared)


def dead_premise_rejections(limit=20, state=None):
    """**기각** 중 선언한 전제가 죽어 있는 것. (rows, n)

    ★ 2026-09-10 — `dependency_audit` 는 `status == "확정"` 만 본다. 그런데 이 도메인에서
      **기각 하나는 버그 하나를 영구히 잃는 결정**이고(CLAUDE.md), 전제는 나중에 죽는다.
      실측: ahcache 기각 195건 중 6건이 전제를 선언했는데 **아무도 그 6건을 다시 안 본다.**
      `rejaudit` 은 게이트 품질로 등급을 매길 뿐 전제 사망은 안 본다 — 다른 축이다.

      확정 쪽과 **같은 규칙**을 쓴다. 반환 형태를 따로 둔 이유는 기존 호출부의 4-튜플
      언패킹을 안 깨기 위해서다(`built-but-never-wired` 를 피하려다 회귀를 내면 안 된다).
    """
    _S = state if state is not None else STATE
    out = []
    for v in (_S.get("verdicts") or []):
        if v.get("status") != "기각":
            continue
        dep = str(v.get("depends_on") or "").strip()
        if not dep or dep.lower() in ("none", "-", "없음"):
            continue
        for rid in [x.strip() for x in dep.replace(";", ",").split(",") if x.strip()]:
            r = _resolve_row(rid, _S)
            if r is not None and (r[1] in _DEAD_STATUS or r[0] == "graveyard"):
                out.append({"verdict": str(v.get("id")), "target": str(v.get("target"))[:80],
                            "depends_on": rid, "now": r[1], "klass": r[2]})
    return out[:limit], len(out)


def _impact_gate(args):
    """★ L2 — **확정은 임팩트 3항을 들고 와야 한다.** (ok, note, impact)

    왜: 이 하네스의 압력은 전부 아래(위양성 방지)였다. 그래서 "검사 우회를 확정"한 지점에서
    그냥 멈췄고, 실제로 값을 낸 발견들은 거기서 **질문을 한 번 튼** 결과였다.
    세 항은 `methodology/references/escalation.md` 의 §1~§3 을 그대로 옮긴 것이다.

      owner    이 바이트/리소스의 **소유자**. 없으면 침해할 경계도 없다
      delta    **정상 경로 대비** 공격자가 더 얻는 것. 0이면 코드 결함이어도 보안 영향 0
      boundary 침해되는 **경계**를 벤더 문서의 언어로 한 문장

    거부가 아니라 **상한**으로 처리하는 경우가 둘 있다 — 게이트를 만족 불가능하게 만들면
    에이전트가 blocked 로 도망가고 그게 더 나쁘다:
      · owner='none'  → 통과시키되 `grade_cap='경계 없음'` 을 박는다
      · delta='n/a'   → **더 강한 발견이다**(정상 경로 비교가 성립하지 않는 클래스). 통과
    유일한 강제 되돌림은 **delta=0 인데 principal 을 안 찾아본 경우**다. 그게 §3 이다.
    """
    ow = (args.get("owner") or "").strip()
    dl = str(args.get("delta") or "").strip()
    bd = (args.get("boundary") or "").strip()
    pr = (args.get("principal") or "").strip()
    if not (ow and dl and bd):
        return (False,
                "A confirmation REQUIRES ALL THREE IMPACT FIELDS (`escalation.md` 1-3):\n"
                "  owner=    who owns these bytes / this resource. If nobody, owner='none'\n"
                "  delta=    what the attacker gets BEYOND what the legitimate path already\n"
                "            gives them. If nothing, delta='0'. If the comparison does not\n"
                "            apply, delta='n/a: <why>'\n"
                "  boundary= the boundary crossed, in ONE sentence, IN THE VENDOR'S OWN LANGUAGE\n"
                "STRONGLY RECOMMENDED — declare the crossing as TWO TOKENS, not prose. Prose is\n"
                "parsed by regex and in this ledger that caught 1 of 6 confirmations:\n"
                "  from_principal= / to_principal=  one of: remote-anonymous | "
                "remote-authenticated | appcontainer | low-il | standard-user | container-admin "
                "| admin | system | kernel | hypervisor\n"
                "  If you cannot establish the MINIMUM principal that reaches the sink, write\n"
                "  from_principal='unproven' — the row is then recorded as 경계보류, not 확정,\n"
                "  and the escalator takes exactly that one question.\n"
                "Missing: %s\n"
                "'I found a path that skips a check' is not yet a vulnerability. If you cannot "
                "write these three, it is not a defect but UNAUDITED work — file it as `blocked`."
                % ", ".join(k for k, v in (("owner", ow), ("delta", dl), ("boundary", bd)) if not v),
                None)
    imp = {"owner": ow[:300], "delta": dl[:400], "boundary": bd[:300]}
    if pr:
        imp["principal"] = pr[:300]

    # ★ 전수 주장 검문 — "소비자는 유저모드뿐" 류는 **부재 주장**이다.
    #   이 한 문장이 등급 상한을 혼자 정하는데 지금까지 어떤 게이트도 안 봤다.
    _blob = " / ".join((ow, dl, bd))
    _m = _SOLE.search(_blob)
    if _m:
        _en = (args.get("enumerated") or "").strip()
        if len(_en) < 30 and not has_xref():
            return (False,
                    "The impact contains an EXHAUSTIVENESS CLAIM: %r\n"
                    "That is an absence claim (\"there is nothing else\"), and this single "
                    "sentence sets the grade ceiling by itself.\n"
                    "But the ledger holds no basis for it. Do one of these:\n"
                    "  (1) Run a BEHAVIOUR-BASED sweep over ALL executable sections (e.g. via\n"
                    "      `import_xref`) and leave the record. Name-based xref misses wrappers;\n"
                    "      looking only at `.text` misses every call sitting in PAGE.\n"
                    "  (2) Pass `enumerated='<what you swept and by what method>'` with the "
                    "verdict.\n"
                    "This gate exists to stop premature certainty. IF YOU DO NOT KNOW, "
                    "WRITING 'the rest is unaudited' PASSES FREELY — writing 'only X' and "
                    "writing 'X is all I verified' are different claims."
                    % _m.group(0)[:80], None)
        imp["sole_claim"] = _m.group(0)[:120]
        if _en:
            imp["enumerated"] = _en[:400]
    low_o, low_d = ow.lower(), dl.lower()
    if low_o in _NONE_OWNER:
        imp["grade_cap"] = "no boundary (unowned data)"
    if low_d in _NA_DELTA or low_d.startswith("n/a"):
        imp["delta_kind"] = "not_applicable"      # 더 강한 클래스
    elif re.fullmatch(r'0+(\.0+)?|없음|zero|none', low_d):
        imp["delta_kind"] = "zero"
        if not pr:
            return (False,
                    "delta=0. DO NOT THROW IT AWAY HERE — you may be looking in the wrong "
                    "place.\n"
                    "Turn the question around:  ~~is there a delta~~ -> WHICH PRINCIPAL HAS A "
                    "NONZERO DELTA?\n"
                    "  (1) PARSE the object's security descriptor and read EVERY ACE "
                    "(free text is not accepted)\n"
                    "  (2) Read the ACEs not as 'who can write this' but as 'WHICH SANDBOX CAN "
                    "GET OUT THROUGH THIS DOOR'\n"
                    "  (3) Look for a principal that is GRANTED ACCESS HERE yet BLOCKED on the "
                    "path it would otherwise use\n"
                    "If you find one, put it in `principal=` and confirm again. If you "
                    "enumerated and found nothing, write "
                    "`principal='none: <what you enumerated>'` — that is an honest negative "
                    "and it passes.\n"
                    "(This single pivot really did revive a dead finding: a sandbox SID "
                    "explicitly allowed in the SD was blocked on another axis, so "
                    "unreachability and granted-access held in the same process.)",
                    None)
    else:
        imp["delta_kind"] = "nonzero"
    # ── 경계: 칸이 있으면 칸이 정본, 없으면 산문 폴백 ────────────────────
    #   막지 않는다(계산+첨부). 다만 **무엇으로 판정했는지**를 `boundary_src` 로 남겨
    #   "정규식이 읽어준 것"과 "분석자가 선언한 것"이 원장에서 구분되게 한다.
    _fp = (args.get("from_principal") or "").strip().lower()
    _tp = (args.get("to_principal") or "").strip().lower()
    if _fp and _tp:
        _isb, _bwhy = boundary_typed(_fp, _tp)
        imp.update({"boundary_from": _fp, "boundary_to": _tp,
                    "is_security_boundary": _isb, "boundary_why": _bwhy[:240],
                    "boundary_src": "typed"})
        if _isb in ("no", "unknown"):
            imp["out_of_scope"] = ("%s→%s" % (_fp, _tp)) if _isb == "no" else "principal-unproven"
            imp["grade_cap"] = (imp.get("grade_cap") or "") + \
                (" · " if imp.get("grade_cap") else "") + "boundary %s: %s" % (_isb, _bwhy[:160])
    else:
        imp["boundary_src"] = "prose"
        _lab, _why = scope_verdict(imp)
        if _lab:
            imp["out_of_scope"] = _lab
            imp["grade_cap"] = (imp.get("grade_cap") or "") + (" · " if imp.get("grade_cap") else "") + \
                "out-of-scope boundary (%s): %s" % (_lab, _why)

    # ── 선언한 출발 principal 을 실측이 뒷받침하는가 (1순위 T46 의 소비부) ──
    _pv, _pnote = principal_evidence(args.get("target") or STATE.get("target"), _fp)
    if _pv != "n/a":
        imp["principal_evidence"] = _pv
        if _pnote:
            imp["principal_evidence_why"] = _pnote[:300]
        if _pv in ("mismatch", "unmeasured"):
            imp["grade_cap"] = (imp.get("grade_cap") or "") + \
                (" · " if imp.get("grade_cap") else "") + "principal %s" % _pv
    return (True, "", imp)


def _cfgmod():
    import config as _c
    return _c


def _bump(key):
    """★ 툴 쪽 거부를 계기판에 올린다. 훅의 `deny()` 만 `gate_denials` 를 세고 있어서
    `[REJECTION REFUSED]` / `[REJECTION HELD - QUESTION]` / `[CONFIRMATION HELD - IMPACT]` /
    `[VERDICT REFUSED]` 는 **한 번도 세어진 적이 없다**(ledger 전체에 runlog 호출 1곳뿐).
    2026-09-04 밤 msquic 회차에서 완결된 분석 5건이 사라졌는데 **왜인지 알 수 없었다** —
    반환값은 모델에게만 가고 stdout·runs.jsonl 어디에도 안 남기 때문이다."""
    try:
        import runlog as _rl
        _rl.bump(key)
    except Exception:
        pass


def _blocked_rows():
    """표면 행 중 `BLOCKED:` 로 남은 것. 부채의 한 축이다."""
    n = 0
    for r in (STATE.get("surface") or {}).values():
        if isinstance(r, dict) and str(r.get("why") or "").lstrip().upper().startswith("BLOCKED"):
            n += 1
    return n


def open_debt():
    """이번 회차가 **연 것 − 닫은 것**. 세 축을 다 센다.

    ★ 한 축만 세면 물량이 옆으로 샌다. 실측 근거: 이 원장에는 이미 `BLOCKED:` 행이
      546개 있고, 원장 자신이 "blocked 행의 **56%가 '다음 단계 있음'을 뜻하는 어떤 산문
      술어에도 매칭된다**"고 재놨다 — 즉 blocked 는 기계로 구분되지 않는 값싼 출구다.
      리드에만 상한을 걸면 그리로 전량이 샌다.
    """
    _l0 = _RUN.get("leads0") or set()
    try:
        now = {str(x.get("id")) for x in open_leads(STATE.get("target"))}
    except Exception:
        now = set(_l0)
    lead_up, lead_dn = len(now - _l0), len(_l0 - now)
    _a0 = _RUN.get("asks0") or set()
    A = STATE.get("asks") or []
    ask_up = sum(1 for a in A if str(a.get("id")) not in _a0
                 and (a.get("status") or "open") == "open")
    ask_dn = sum(1 for a in A if str(a.get("id")) in _a0
                 and (a.get("status") or "") == "answered")
    blk_up = max(0, _blocked_rows() - int(_RUN.get("blocked0") or 0))
    opened, closed = lead_up + ask_up + blk_up, lead_dn + ask_dn
    return {"lead_up": lead_up, "lead_dn": lead_dn, "ask_up": ask_up, "ask_dn": ask_dn,
            "blocked_up": blk_up, "opened": opened, "closed": closed,
            "net": opened - closed}


def _wip_note():
    """상한에 걸렸을 때 내보낼 문구. **행을 지목하지 않으면 지시가 아니다** —
    실측: klass 게이트처럼 행동만 막으면 에이전트는 우회를 찾는다(같은 id 7연속 재제출).
    종료 게이트가 깊이를 만든 회차는 심문자가 **이름 붙은 다음 수**를 남긴 회차뿐이었다.
    """
    d = open_debt()
    cap = int(getattr(_cfgmod(), "WIP_CAP", 12))
    L = ["[DEBT CAP] 이번 회차가 연 것 %d − 닫은 것 %d = **순증 %d** (상한 %d).\n"
         "  열림: 리드 +%d · 질문 +%d · blocked +%d   |   닫힘: 리드 %d · 질문 %d"
         % (d["opened"], d["closed"], d["net"], cap,
            d["lead_up"], d["ask_up"], d["blocked_up"], d["lead_dn"], d["ask_dn"]),
         "",
         "새 기각·blocked 는 받지 않는다. **닫아야 연다.** 확정(`confirm`)·실측"
         "(`measure`)·범위선언(`scope`)·트랙(`track`)은 그대로 열려 있다.", ""]
    try:
        ol = open_leads(STATE.get("target"))
    except Exception:
        ol = []
    if ol:
        L.append("가장 오래 열려 있는 리드 — 심문자가 남긴 다음 수가 이미 붙어 있다:")
        for b in ol[:2]:
            L.append("  · `%s` [%s] %s" % (b.get("id"), b.get("klass") or "-",
                                           str(b.get("target"))[:70]))
            nm = (b.get("next_method") or b.get("reason") or "").replace("\n", " ")
            if nm:
                L.append("      %s" % nm[:420])
        L.append("")
        L.append("닫는 길은 셋뿐이다 — `verdict(action='lead', id=<위 id>, "
                 "how=refuted|measured|reinterrogated, why=…)`. 소진(exhausted)은 없다.")
    else:
        L.append("열린 리드가 없다 ⇒ 순증은 질문·blocked 에서 났다. "
                 "연 질문에 답하거나, blocked 행 하나를 판정까지 끌고 가라.")
    return "\n".join(L)


SURFACE_SCHEMA = 1      # 표면 아티팩트 스키마. 모양이 바뀌면 올린다 → 옛 파일은 자동 무효


def _env_stamp():
    """gate_block 을 낸 **그때의 실측 채널 상태**. 나중에 다르면 재확인 대상이다."""
    c = _cfgmod()
    return {k: int(bool(getattr(c, k, False)))
            for k in ("ALLOW_PROBE", "ALLOW_VM_PROBE", "ALLOW_KDNET")}


def export_surface(state=None, img_path=None, out_dir=None):
    """원장의 **표면**을 지문 달린 아티팩트로 내보낸다.

    ★ RAPTOR 에서 가져온 것(`/understand` → 스캔 → `/validate` 브리지): 공격면을
      파일로 내보내 다음 단계가 **자동으로 집어 쓰되**, 아티팩트가 입력의 지문을 들고
      다니고 소비자가 재계산해 불일치면 재사용을 거부한다.
      우리 지문은 CodeView GUID 다(파일 md5 보다 빌드 정체에 가깝다).

    왜: 지금까지 표면은 **원장 안에만** 있었다. 밖으로 못 나가니 ① 빌드 간 diff 가
      안 되고 ② 다른 도구가 못 읽고 ③ "이 표는 어느 빌드의 것인가"를 아무도 안 물었다.
    """
    S = state if state is not None else STATE
    name = str(S.get("target") or "unknown")
    out_dir = out_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "out", "surface")
    os.makedirs(out_dir, exist_ok=True)
    guid = None
    if img_path:
        try:
            import pe as _pe
            cv = _pe.PE(img_path).codeview()
            guid = cv[0] if cv else None
        except Exception:
            guid = None
    surf = S.get("surface") or {}
    rows = [{"name": k, "status": (v or {}).get("status"), "why": (v or {}).get("why")}
            for k, v in (surf.items() if isinstance(surf, dict) else [])]
    doc = {"schema": SURFACE_SCHEMA, "target": name,
           "build": {"cv_guid": guid, "source": img_path},
           "generated": time.strftime("%Y-%m-%d %H:%M"),
           "counts": {"surface": len(rows),
                      "verdicts": len(S.get("verdicts") or []),
                      "measures": len(S.get("measures") or []),
                      "populations": len(S.get("populations") or [])},
           "surface": rows,
           "populations": S.get("populations") or []}
    path = os.path.join(out_dir, _key(name) + ".json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    return path


def load_surface(path, img_path=None):
    """내보낸 표면을 **신선할 때만** 돌려준다. 반환: (doc, fresh, why).

    ★ 규약 3항 (RAPTOR): 지문 불일치면 재사용 거부. 지문을 못 구하면 **재사용하지
      않는다**(조용한 재사용이 가장 위험하다). 스키마가 다르면 역시 거부.
    """
    try:
        doc = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError) as e:
        return (None, False, "읽기 실패: %s" % e)
    if doc.get("schema") != SURFACE_SCHEMA:
        return (doc, False, "스키마 %s ≠ %s — 재사용하지 않는다"
                % (doc.get("schema"), SURFACE_SCHEMA))
    want = ((doc.get("build") or {}).get("cv_guid") or "")
    if not img_path:
        return (doc, False, "대조할 바이너리가 없다 — 재사용하지 않는다")
    got = None
    try:
        import pe as _pe
        cv = _pe.PE(img_path).codeview()
        got = cv[0] if cv else None
    except Exception as e:
        return (doc, False, "바이너리 지문을 못 읽었다(%s) — 재사용하지 않는다" % e)
    if not want or not got:
        return (doc, False, "지문이 비었다 — 재사용하지 않는다")
    if want.lower() != got.lower():
        return (doc, False, "빌드가 다르다: 표면 %s… / 바이너리 %s…" % (want[:8], got[:8]))
    return (doc, True, "")


def gate_block_digest(state=None, n=8):
    """지휘자가 볼 gate_block 목록. **오래된 미해결부터** + 같은 벽의 반복 횟수.

    ★ 왜 (2026-09-23): 옛 출력은 `tax[-4:]` / `oth[-5:]` 즉 **최신 LIFO** 였다.
      ahcache 는 47건인데 5건만 보였다 — `break_digest` 가 09-07 에 고친 바로 그 병이
      이 출력에 남아 있었다. 누적 123건 중 아무도 옛것을 못 봤다.
    반환: (rows, summary) — rows 는 오래된 순, summary 는 {계열라벨: 건수}.
    """
    S = state if state is not None else STATE
    gb = [x for x in (S.get("gate_blocks") or []) if isinstance(x, dict)]
    now = _env_stamp()
    cnt = {}
    for x in gb:
        cnt[str(x.get("gate"))[:40]] = cnt.get(str(x.get("gate"))[:40], 0) + 1
    rows = sorted(gb, key=lambda r: str(r.get("t") or ""))
    out = []
    for x in rows:
        if x.get("resolved"):
            continue
        e = x.get("env")
        x = dict(x)
        x["repeat"] = cnt.get(str(x.get("gate"))[:40], 1)
        x["stale_env"] = bool(e) and e != now
        out.append(x)
    # taxonomy 를 먼저(가장 위험), 그 안에서 오래된 순
    out.sort(key=lambda r: (r.get("kind") != "taxonomy", str(r.get("t") or "")))
    return out[:n], cnt


def verdict(args):
    act = (args.get("action") or "").lower()
    tgt = args.get("target", "?")
    # ★ 2026-09-07 — **부채 상한.** `reject`/`blocked` 만 막는다.
    #   확정은 막지 않는다: 확정은 행을 여는 것이 아니라 닫는 것이고, 이 하니스의 병목은
    #   반박자 입력율(17일에 41회)이지 위양성이 아니다.
    if act in ("reject", "blocked") and getattr(_cfgmod(), "GATE_WIP", True):
        _cap = int(getattr(_cfgmod(), "WIP_CAP", 12))
        _d = open_debt()
        if _d["net"] >= _cap:
            _bump("wip_blocked")
            record_denial(tgt, "[DEBT CAP] 순증 %d ≥ 상한 %d" % (_d["net"], _cap),
                          act=act, rule="debt cap: opened-closed >= WIP_CAP")
            return _wip_note()
    # ★ 2026-09-24 — **patch-anchored census 완결 게이트** (Move 2).
    #   벤더가 고친 버그의 형제를 census 하는 인구를 `population(invariant=...)` 로 표시하면,
    #   그 census 를 "완전 수정 / 형제 없음" 으로 닫는 판정은 반드시 `completes=<인구명>` 을
    #   달아야 하고, 여기서 열거 완전성(미분석 0)과 심문자 SUSTAINED 를 강제한다.
    #   어젯밤 mrxsmb 과대-닫힘(심문자가 BROKE 했는데도 비차단이라 기각이 먼저 카운트됨)이
    #   구조적으로 파일 불가가 된다. RI-태그 인구가 없으면 이 블록은 전부 통과(런 무영향).
    _completes = args.get("completes")
    if _completes:
        try:
            _cok, _creason = population_closure_status(str(_completes))
        except Exception as _e:      # 게이트 자신이 판정을 크래시시키지 않는다
            _cok, _creason = True, "closure gate error: %s" % type(_e).__name__
        if not _cok:
            _bump("held_closure")
            record_denial(tgt, "[CLOSURE HELD] completes=%s: %s" % (_completes, _creason[:150]),
                          act=act, rule="patch-anchored census not closable")
            return ("[CLOSURE HELD - PATCH-ANCHORED CENSUS] `%s`\n%s\n\n"
                    "이 census 는 벤더가 복원한 불변식의 형제 모집단이다. 완결로 닫으려면 "
                    "① 미분석=0 (알려진 멤버 전수) ② 닫는 서술에 심문자를 돌려 SUSTAINED. "
                    "심문자가 깨면 그건 열거가 불완전하다는 뜻이니 놓친 멤버를 set_b 에 넣고 다시 세라."
                    % (_completes, _creason))
    if act in ("confirm", "reject"):
        vid = args.get("id") or f"V{len(STATE['verdicts']) + 1}"
        # ★ basis 검사는 기각 게이트와 무관하다 — confirm 에도 걸려야 하므로 **먼저** 본다.
        # ★ 2026-09-08 — **거부는 '기록이 아예 없을 때'만이다.**
        #   09-08 런 실측: 분석가가 라이브 게스트에서 기준선→처치→사후 3단을 **대조군 3/3**
        #   으로 돌리고(`latch=1 → class-8 요청 → latch=1`, 섹션 핸들 바이트 동일)
        #   `basis=measured` 로 냈는데 거부됐다. 이유는 `measure(action='classify')` 를 안
        #   불렀기 때문 — 그 관측은 `kd`+`ioctl` 로 했고 **`kd` 는 원장에 아무것도 안 남겼다**
        #   (툴 설명은 `target=` 을 "so the ledger can bind it" 이라고 약속하는데 배선이 없었다).
        #   그 회차의 유일한 등재 판정이 `basis=disassemble` 로 내려앉았다.
        #   ⇒ ① `kd` 가 `trace` 를 남기고 ② `measured()` 가 주소 겹침으로 찾고
        #     ③ 여기서는 **무엇이 뒷받침했는지 도장만 찍는다.**
        #   ★ 느슨해지지 않는 이유: `trace` 도 하네스가 실행한 기록이지 자기 신고가 아니고,
        #     `basis=measured` 기각은 `GATE_CONTROL_BEFORE_REJECT` 가 **양성 대조를 따로**
        #     요구한다(agent_sdk:764). 그 검문은 그대로 있다.
        # ★ 2026-09-08 — **정본화 후 비교한다.** 여기가 `== "measured"` 정확일치라
        #   `basis="live kd read of the governing feature cache dword…"` 같은 산문이
        #   **이 검문을 통째로 건너뛰었다**(09-08 2회차 실측: 그렇게 통과한 판정 2건).
        #   09-07 에 `agent_sdk` 의 `GATE_CONTROL_BEFORE_REJECT` 에서 고친 **바로 그 버그**가
        #   원장 쪽 쌍둥이에 그대로 남아 있었다 — 그때 수정이 절반만 적용된 것이다.
        if normalize_basis(args.get("basis"))[0] == "measured":
            _mrec = measured(tgt)
            if not _mrec:
                _bump("held_basis"); record_denial(tgt, "[VERDICT REFUSED] basis=measured without a measurement record",
                                                    act=act, klass=args.get("klass") or "", rule="basis=measured but no measurement record")
                return ("[VERDICT REFUSED] basis='measured' but THERE IS NO MEASUREMENT RECORD "
                        "bound to this target — not by name and not by address.\n"
                        "Two ways to bind one:\n"
                        "  · `measure(action='classify', target=..., a=<fill A hex>, "
                        "b=<fill B hex>, status=..., info=...)` — a GRADED measurement.\n"
                        "  · `kd(cmds=..., target=...)` / `ioctl(...)` — the harness records a "
                        "TRACE of what it actually executed, and binds it by the addresses in "
                        "your command chain. Put the VA this verdict is about IN the chain "
                        "(`dd <mod>+0x…`), or name it in `target=`.\n"
                        "Without either, 'I measured it' is SELF-REPORTED, and the reason "
                        "measured outranks disassemble in BASIS_RANK disappears.")
            _kinds = {str(m.get("kind") or "classify") for m in _mrec}
            # ★ 2026-09-10 — **뒷받침 자격을 판정에 박는다.** 안 박으면 이 판정을 3주 뒤에
            #   읽는 쪽이 "저권한에서 쟀다"와 "어느 토큰인지 아무도 안 적었다"를 구분 못 한다.
            #   막지 않는다 — 사실만 싣는다(계산+첨부).
            _pg = "unknown"
            _rank = {"verified_low": 5, "verified_default": 4, "verified_elevated": 3,
                     "kernel-debugger": 2, "declared": 1, "unknown": 0}
            for _m in _mrec:
                _c = _m.get("principal_grade") or principal_grade(_m.get("principal"))
                if _rank.get(_c, 0) > _rank.get(_pg, 0):
                    _pg = _c
            _pending_meas[0] = {"n": len(_mrec), "kinds": sorted(_kinds),
                                # ★ 2026-09-13 — 서열 3단. `before_after` 는 채점된
                                #   관측이므로 `trace`(실행 사실만)와 같은 칸에 넣으면
                                #   증거 무게가 거짓이 된다.
                                "by": ("classify" if "classify" in _kinds
                                       else "before_after" if "before_after" in _kinds
                                       else "trace"),
                                "principal": _pg}
        gate_note, gate_rec = "", None
        impact = None
        if act == "confirm":
            _ok, _note, impact = _impact_gate(args)
            if not _ok:
                _bump("held_impact"); return "[CONFIRMATION HELD - IMPACT] %s\n\n%s" % (tgt, _note)
            # ★ 2026-09-06 — **주장 간 정합성.** 다른 게이트는 전부 주장-국소적이다.
            #   이 확정이 빌려오는 전제가 이미 죽었는지는 아무도 안 봤다(wcifs 채점본 §1).
            _rok, _rnote, _rask = _reach_gate(args)
            if not _rok:
                _bump("held_reach")
                record_denial(tgt, "[CONFIRMATION HELD - DEPENDENCY] " + _rnote[:150],
                              act=act, rule="depends_on: missing or unresolvable")
                return "[CONFIRMATION HELD - DEPENDENCY] %s\n\n%s" % (tgt, _rnote)
        if act == "reject":
            # ★ 2026-09-05 실측: `GATE_REJECT=0` 은 **훅 쪽만** 껐다(agent_sdk:614).
            #   툴 쪽 이 호출은 무조건 돌아서, 껐는데도 기각이 막혔다.
            #   trust-arm 첫 회차에서 `gate_denials=0` 인데 `refused_reject=1` 로 잡혔다 —
            #   오늘 만든 계측기가 첫 회차에서 스위치 누수를 찾아냈다.
            if not getattr(_cfgmod(), "GATE_REJECT", True):
                ok, gate_note, gate_rec = True, "", {"klass": (args.get("klass") or "")}
            else:
                ok, gate_note, gate_rec = _reject_gate(tgt, args)
            if not ok:
                _bump("refused_reject"); return "[REJECTION REFUSED] %s\n\n%s" % (tgt, gate_note)
            # ★ 2026-09-05 재설계 — 게이트를 **계산기로 강등**한다.
            #   옛 동작: 못 정하면 판정으로 안 세고 질문 큐로 보냈다. 그 결과가 짝 탐색 루프다
            #   (열린질문 208건 중 72건이 게이트 판정, 짝 붙은 것 66건, 재시도 17건 중 8건이 탐색).
            #   게이트가 반려한 것은 **결론이 아니라 인코딩**이었다 — 안전한 진짜 이유가
            #   "분기 하나 + 싱크 하나" 형태가 아니면 만족하는 짝이 존재하지 않는다.
            #   새 동작: 판정은 **그대로 등재**하고, 게이트가 계산한 것과 **못 한 것**을
            #   판정에 실어 적대자에게 증거로 넘긴다. 판단은 심문자가 한다.
            # ★ 예외 하나: **이미지를 못 열면** 아무것도 검증 못 한다. 그건 인코딩 문제가
            #   아니라 사실 문제이고, 심문자도 바이너리를 못 보니 넘겨도 판단이 안 된다.
            #   강등 대상은 "게이트 모델이 표현 못 하는 모양"이지 "측정 불가"가 아니다.
            _ask_kind = ((gate_rec or {}).get("ask") or {}).get("cfg") if isinstance(gate_rec, dict) else None
            if (isinstance(gate_rec, dict) and gate_rec.get("ask")
                    and _ask_kind != "no_image"
                    and getattr(_cfgmod(), "GATE_COMPUTE_ONLY", True)):
                _a = gate_rec["ask"]
                gate_rec["computed_but_unexpressed"] = {
                    "cfg": _a.get("cfg"), "why": _a.get("why"),
                    "guard": gate_rec.get("guard"), "sink": gate_rec.get("sink")}
                gate_rec.pop("ask", None)          # 질문으로 강등하지 않는다
            if isinstance(gate_rec, dict) and gate_rec.get("ask"):
                a = gate_rec["ask"]
                prev = _ask_open(tgt)
                if prev is not None:
                    # 같은 표적에 이미 열린 질문이 있다 — 새로 쌓지 말고 **시도**를 센다.
                    prev.setdefault("attempts", []).append(
                        {"t": a.get("t"), "cfg": a.get("cfg"), "kind": a.get("kind"),
                         "guard": gate_rec.get("guard"), "sink": gate_rec.get("sink")})
                    # ★ `inexpressible` 은 **하네스 부채**다(게이트가 이 모양을 표현 못 한다).
                    #   뒤늦게 와도 앞선 `need_observation` 에 가려지면 안 된다 — 승격시킨다.
                    #   반대 방향으로는 안 내린다: 한 번 표현 불가였던 것이 관측으로 바뀌지 않는다.
                    if a.get("kind") == "inexpressible":
                        prev["kind"] = "inexpressible"
                    elif not prev.get("kind"):
                        prev["kind"] = a.get("kind")
                    q = prev
                else:
                    # ★ 2026-09-08 — `kind`/`by` 를 **저장한다.** `ask()` 가
                    #   `ask_kind()` 로 계산해 `rec["ask"]["kind"]` 에 넣는데 이 dict 이
                    #   안 복사해서 버려지고 있었다: 원장 전수 231/231 · 125/125 가 `None`.
                    #   그 결과 need_observation(더 재면 된다) 과 inexpressible(게이트가
                    #   표현 못 한다)이 안 갈렸고, **단일 큐를 정렬할 축이 없었다.**
                    q = {"id": vid, "target": tgt, "claim": (args.get("claim") or "")[:300],
                         "klass": args.get("klass"), "guard": gate_rec.get("guard"),
                         "sink": gate_rec.get("sink"), "cfg": a.get("cfg"),
                         "why": a.get("why"), "method": a.get("method"),
                         "kind": a.get("kind"), "by": "gate",
                         "status": "open", "attempts": [], "t": a.get("t")}
                    STATE.setdefault("asks", []).append(q)
                _k = _surface_key(tgt) if "_surface_key" in globals() else tgt
                if tgt in STATE.get("surface", {}):
                    STATE["surface"][tgt]["status"] = "미분석"
                    STATE["surface"][tgt]["blocked"] = True
                    STATE["surface"][tgt]["why"] = "ASK: " + (a.get("why") or "")[:220]
                save()
                try:
                    _ah = anchor_hits(" ".join(str(args.get(k) or "")
                                               for k in ("claim", "evidence", "guard", "sink")),
                                      exclude_id=vid)
                except Exception:
                    _ah = ""
                _bump("held_ask")
                # ★ 이 ASK 가 2026-09-05 에 심문자·승격자를 동시에 음소거한 경로다(→ R-05 ②d).
                #   게이트가 강등된 지금도 **무엇을 못 정했는지**는 남겨야 규칙별 실적이 나온다.
                record_denial(tgt, "[REJECTION HELD] cfg=%s %s"
                              % (a.get("cfg") or "undecidable", str(a.get("why") or "")[:120]),
                              act=act, klass=args.get("klass") or "",
                              rule="[ASK] cfg=%s" % (a.get("cfg") or "undecidable"))
                return ("[REJECTION HELD - QUESTION] %s\n\nThe gate could not adjudicate "
                        "(%s). THIS IS NOT A NEGATIVE, IT IS UNAUDITED.\n\n"
                        "Why: %s\n\nDo this next: %s\n\n"
                        "The question stays in the queue (check with "
                        "`verdict(action='asks')`). Once you have the answer, reject the same "
                        "target again.%s"
                        % (tgt, a.get("cfg") or "undecidable", a.get("why"),
                           render_ask(tgt, a),
                           ("\n" + _ah) if _ah else ""))
        # ★ 인용 상수 실재 대조 (`claimaudit.constants_cited`).
        #   2026-08-30 실측: 하니스가 by-design 논거의 초석으로 `0xFFFF00FF` 를 들었는데
        #   그 즉치는 **이 바이너리에 0건**이었다(실제 마스크는 0xFFFF109F / 0xFFFF013F).
        #   그 상수가 틀리자 결론이 뒤집혔다. 도구는 이미 있었고 **연결만 안 돼 있었다**
        #   (`measure.py` 와 같은 상태). 차단은 하지 않는다 — 계산된 값일 수 있다 — 꼬리로 알린다.
        _const_note = ""
        try:
            import claimaudit as _CA
            _t = STATE.get("target") or ""
            if _t and os.path.exists(_t):
                _cc = _CA.constants_cited(args.get("claim", "") + " " + args.get("evidence", ""),
                                          pe_path=_t)
                _ghosts = [c for c in (_cc or []) if not c[1] and not c[2]]
                if _ghosts:
                    _const_note = ("\nWARNING: the constant %s cited by the claim occurs "
                                   "ZERO times in this binary. If it is a computed value, say "
                                   "how you derived it; otherwise re-derive it — one wrong "
                                   "constant flips the conclusion." %
                                   ", ".join("0x%X" % c[0] for c in _ghosts[:4]))
        except Exception:
            pass
        # ★ 주장↔앵커 연결 (`refs/00-gate-gaming.md`). 외연적 검증만으로는 근거를 게이트 모양에
        #   맞춰 다시 만드는 것을 못 막는다. 확정에만 건다 — 기각은 klass 별 의무가 따로 있다.
        _link_note = ""
        _scope_warn = ""
        if act == "confirm" and impact and impact.get("out_of_scope"):
            _scope_warn = ("\nRECORDED AS `경계보류` (BOUNDARY-HELD), NOT AS A CONFIRMATION "
                           "— out-of-scope boundary (%s): %s\n"
                           "THIS IS NOT A REJECTION. The code defect stands and its basis is "
                           "kept. It cannot be promoted because the grade is zero across THIS "
                           "boundary.\n"
                           "The remaining question has narrowed to one: IS THERE A "
                           "LOWER-PRIVILEGED PRINCIPAL THAT REACHES THE SAME SINK? A non-admin "
                           "inside a container, AppContainer / sandbox, a lower-privileged "
                           "service, a bypass path via another port or device. Find ONE and "
                           "this row becomes a confirmation immediately.\n"
                           "   `escalation.md` section 3 (principal pivot) + escalator axis "
                           "`principal_sd_ace`."
                           % (impact["out_of_scope"],
                              impact.get("grade_cap", "").split(": ", 1)[-1][:120]))
        if act == "confirm":
            _ul, _ln = claim_anchor_link(args.get("claim", ""), args.get("_anchors") or [])
            if _ul:
                _link_note = "\n⚠ " + _ln
                rec_link = _ul

        staged_a, staged_r = _take(tgt, args.get("claim", ""))
        # ★ 2026-09-07 — basis 를 정본 어휘로 접고, 등록되지 않은 선두 토큰은 **반려한다.**
        #   산문은 버리지 않고 `basis_note` 로 옮긴다(논증은 claim/reason 이 나른다).
        _bcanon, _braw = normalize_basis(args.get("basis"))
        # ★ **비워둔 것은 잘못 쓴 것이 아니다.** 옛 기본값을 지킨다 —
        #   안 그러면 `GATE_REJECT=0` 같은 스위치의 약속까지 깨진다(회귀로 잡혔다).
        if not _braw:
            _bcanon = "decompile"
        if _bcanon is None:
            return ("`basis` MUST LEAD WITH ONE OF: measured | disassemble | decompile | doc.\n"
                    "You wrote: %r\n"
                    "This field is not prose — `BASIS_RANK` reads it, and "
                    "`GATE_CONTROL_BEFORE_REJECT` fires on `measured`. When it is a sentence, "
                    "both silently degrade: in this ledger the same thing carried four names "
                    "(disassemble 83 / disassembly 30 / static 22 / disasm 3) and a rejection "
                    "reading `measured on the live kernel…` skipped the positive-control check "
                    "entirely.\n"
                    "Keep your sentence — just LEAD with the token: "
                    "`basis='measured on the live kernel, kd against the running guest'` or "
                    "`basis='disassemble of the whole function body'`. The rest is preserved "
                    "in `basis_note`." % _braw[:120])
        rec = {"id": vid, "target": tgt, "claim": args.get("claim", "?"),
               "basis": _bcanon,
               "basis_note": (_braw[:600] if _braw.lower() != _bcanon else None),
               "evidence": (args.get("evidence", ""))[:4000],
               "anchors": args.get("_anchors") or staged_a,
               "refute": args.get("_refute") or staged_r,
               "measured_by": (_pending_meas[0] or {}).get("by"),
               "measured_n": (_pending_meas[0] or {}).get("n"),
               "measured_principal": (_pending_meas[0] or {}).get("principal"),
               "status": ("경계보류" if (act == "confirm" and (impact or {}).get("out_of_scope"))
                          else "확정" if act == "confirm" else "기각"),
               "gate": gate_rec, "impact": impact,
               # ★ 선언한 전제를 판정에 박는다. 게이트는 **등재 시점**만 보고,
               #   전제는 나중에 죽는다 — `dependency_audit()` 이 그때 이 필드로 되돌아본다.
               "depends_on": (str(args.get("depends_on") or "").strip() or None),
               "unlinked_addrs": ["0x%X" % u for u in (locals().get("rec_link") or [])],
               "t": time.strftime("%m-%d %H:%M")}
        # ★ 사전 게이트가 남겨둔 심문 결과를 **이 판정에 박는다**. 안 박으면
        #   `verified_negatives()` 와 `rejects_interrogated` 가 심문을 못 본다.
        _pe = (STATE.get("pending_escalation") or {}).pop(tgt, None)
        if _pe is not None:
            rec["escalation"] = _pe
        # ★ 2026-09-04 — 판결자가 낸 확정은 **다른 종류의 확정**이다.
        #   반박자를 통과한 것이 아니라 종결자가 이력을 보고 낸 것이다. 표시가 없으면
        #   내일 채점에서 액면가로 세어지고, 하루짜리 권한 실험이 조용히 정책이 된다.
        _adj = (STATE.get("pending_adjudication") or {}).pop(tgt, None) \
            or args.get("_adjudicated")
        if isinstance(_adj, dict):
            rec["decided_by"] = "adjudicator"
            rec["adjudication"] = _adj
        _interrog_note = ""
        # ★ 2026-09-06: id 로 먼저 찾는다. target 폴백은 **그 결과가 이 행 것이라고
        #   주장하지 않을 때만** 쓴다(`for_id` 가 다른 행을 가리키면 남의 심문이다).
        _pq = STATE.get("pending_interrog") or {}
        _pi = _pq.pop(vid, None) if vid else None
        if _pi is None:
            _cand = _pq.get(tgt)
            if isinstance(_cand, dict) and not _cand.get("for_id"):
                _pi = _pq.pop(tgt, None)
        if _pi is not None and act == "reject":
            rec["interrogated"] = bool(_pi.get("ok"))
            if _pi.get("ok"):
                rec["interrogation"] = {"klass": _pi.get("klass"),
                                        "reason": _pi.get("reason"),
                                        # ★ 산출물 판정의 기준. 없으면 깨진 기각이 산출물로 샌다.
                                        "broke": bool(_pi.get("broke"))}
            # ★ 비차단이라도 **사유는 분석가에게 간다.** 안 그러면 루프 대신 침묵이 된다.
            if _pi.get("broke") and _pi.get("note"):
                _interrog_note = "\n\n" + str(_pi.get("note"))
        STATE["verdicts"].append(rec)
        _scope_note = ""
        if act == "reject":
            _res = _settle_reject(vid, tgt, rec["claim"], args.get("item"), args.get("sink"))
            _st = _res[0][1] if _res else "no_scope"
            if _st == "no_scope":
                _scope_note = ("\nTHE CLAIM DIED BUT THE SURFACE IS NOT CLOSED. No candidate set "
                               "has been declared for this surface - refuting one sink and "
                               "closing an entire handler is the wrong answer this ledger has "
                               "produced again and again.\n   Declare the denominator with "
                               "`verdict(action='scope', target=..., items=['0xVA name', ...], "
                               "method='how you enumerated')`, then adjudicate each candidate.")
            elif _st == "open":
                _rest = _res[0][2] or []
                _scope_note = ("\nThe surface is still UNAUDITED — %d candidates remain: %s"
                               % (len(_rest), ", ".join(i["label"] for i in _rest[:6])))
            else:
                _scope_note = "\nAll candidates are adjudicated => the surface CLOSES AS A REJECTION."
        else:
            _settle(vid, tgt, rec["status"], rec["claim"][:80])
        _closed = _ask_close(tgt, vid, "answered", rec["claim"][:200])
        if act == "reject":
            # ★ 2026-09-04 실측: 묘지 394건 중 반박자 킬은 **24건(6%)** 뿐이고
            #   370건이 이 경로 — **분석가 자신의 기각**이다. 그런데 프라이밍 문구는
            #   양쪽에 똑같이 "CLAIMS ALREADY KILLED (do not resurrect)" 를 쓴다.
            #   자기 판정이 적대자 판정과 같은 무게로 다음 회차의 자신을 막는다.
            #   (심문자 파기율 67% 를 생각하면 그 370건 중 상당수는 안 섰을 기각이다.)
            #   ⇒ 출처를 박는다. 그리고 `t` — close_candidate 에만 넣어서 394/394 가
            #     날짜 없음이었다. 6% 경로만 고친 셈이었다.
            # ★ 2026-09-06 — **묘지 행에 심문 상태를 같이 박는다.**
            #   전에는 `broke` 가 verdicts 레코드에만 있었다. 그래서 묘지를 읽는 소비자
            #   (이어받기·`_resolve_row` 폴백·프라이밍)에게는 **깨진 기각도 깨끗한 음성**으로
            #   보였다. 실측: 묘지 167행 중 심문 통과는 54행(32%)뿐인데 표식이 없어
            #   나머지 113행이 같은 무게로 다음 회차를 막고 있었다.
            _ig = rec.get("interrogation") if isinstance(rec.get("interrogation"), dict) else {}
            STATE["graveyard"].append({"id": vid, "target": tgt,
                                       "claim": rec["claim"][:120],
                                       "klass": (args.get("klass") or "self-reject"),
                                       "reason": args.get("reason", "")[:300],
                                       "origin": "self",
                                       "interrogated": rec.get("interrogated"),
                                       "broke": bool(_ig.get("broke")) if _ig else None,
                                       "t": time.strftime("%m-%d %H:%M")})
        save()
        tail = ""
        # ★ 2026-09-07 — **실측 축이 판정 사다리에 안 붙어 있었다.**
        #   실측: ahcache 는 kd·ioctl·vmprobe 로 **97번** 쟀는데 그것을 근거로 올라간 판정은
        #   2건이고, 확정 7건 중 실측 기반은 **0건**이다(전부 disassemble). 재는 것과
        #   판정하는 것이 나란히 쌓이기만 하고 승격 경로가 없었다.
        #   ⇒ 막지 않는다(판단은 쓰는 쪽이 한다). 다만 **같은 표적의 실측을 세어 보여준다.**
        try:
            _va = set(re.findall(r'0x[0-9a-fA-F]{6,16}', str(tgt).lower()))
            _mine_m = []
            for m in (STATE.get("measures") or []):
                _mt = str(m.get("target") or "").lower()
                if not _mt:
                    continue
                # 주소가 겹치거나(정확), 이름이 서로를 포함하면 같은 표적으로 본다.
                if (_va & set(re.findall(r'0x[0-9a-fA-F]{6,16}', _mt))) or \
                        (len(_mt) > 8 and (_mt[:40] in str(tgt).lower()
                                           or str(tgt).lower()[:40] in _mt)):
                    _mine_m.append(m)
        except Exception:
            _mine_m = []
        if _mine_m and rec["basis"] != "measured":
            tail += ("\n\n★ 이 표적에는 실측이 %d건 있는데 이 판정의 basis 는 `%s` 다.\n"
                     "   실측을 근거로 쓸 것이면 `basis='measured …'` 로 올려라 — 그러면 "
                     "양성 대조 검사(GATE_CONTROL_BEFORE_REJECT)를 받는다.\n"
                     "   정적으로만 판정하는 것이 맞다면 그대로 두어라. 다만 이 원장에서 "
                     "실측 97건 대 measured 판정 2건이라는 간극이 이렇게 벌어졌다.\n"
                     "   최근 실측: %s"
                     % (len(_mine_m), rec["basis"],
                        " · ".join("%s(%s)" % (str(m.get("target"))[:38], m.get("grade"))
                                   for m in _mine_m[-2:])))
        # ★ 죽은 전제 위에 선 확정은 **막지 않고 묻는다**. 기각은 주장을 반박하는 게 아니라
        #   좁히는 경우가 흔하다(형제 호출자 배제, 더 넓은 변종 사망). 판단은 쓰는 쪽이 한다.
        if act == "confirm" and locals().get("_rask"):
            tail += "\n\n★ " + _rask
            rec_dead = True
        # ★ 앵커 역색인. 방금 낸 판정의 앵커가 원장 어디에 이미 있는지 **자동으로** 보여준다.
        #   에이전트가 물어봐야만 보이면 안 본다 — 다섯 회차가 그렇게 갔다.
        try:
            _ah = anchor_hits(" ".join(str(args.get(k) or "")
                                       for k in ("claim", "evidence", "reason")), exclude_id=vid)
        except Exception:
            _ah = ""
        if _ah:
            tail += "\n" + _ah
            # ★ 툴 **결과**는 transcript 에 안 남는다([tool ] 은 호출만 기록). 이 장치가
            #   실제로 발화했는지 사후에 확인할 방법이 없어서 한 줄 남긴다. 침묵은 증거가 아니다.
            try:
                import runlog as _rl
                _rl.transcript("[anchoridx] %s — 선행 %d행 제시"
                               % (str(tgt)[:60], _ah.count("\n   [")))
            except Exception:
                pass
        if BASIS_RANK.get(rec["basis"], 0) < 3:
            tail = ("\nWARNING: weak basis (decompile/doc). This confirmation may only be used as INFERRED.")
        if act == "reject" and BASIS_RANK.get(rec["basis"], 0) < 4:
            # 리콜 최대화 목적함수에서 **거짓 기각 = 버그 상실**이다. 확정보다 여기가 더 비싸다.
            tail += ("\nWARNING: this is a STATIC rejection (basis=%s). Do not put this row in "
                     "the same column as 'measured clean' - that makes coverage a lie. Three "
                     "steps to promote it: (1) did the handler actually execute "
                     "(INVALID_PARAMETER / NOT_SUPPORTED / TOOSMALL + zero bytes written = "
                     "UNMEASURED); (2) was it observed with a DUAL FILL; (3) did that run pass "
                     "the scanner's positive AND negative controls. Using dual_fill / classify / "
                     "kernel_ptrs in `measure.py` enforces all three."% rec["basis"])
        tail += _const_note
        if rec["anchors"]:
            tail += f"\n앵커 {len(rec['anchors'])}건이 이 빌드에서 기계 검증되어 함께 저장됐다."
        if gate_note:
            tail += "\n" + gate_note
        # ★ 싱크 하류 게이트 — 확정 게이트(G0~G5)가 전부 앵커·반박 축이라 이 축은 아무도 안 봤다.
        #   실측 실패 2건이 **둘 다** 여기서 났다(globmerger 언더플로: 할당 호출이 그 뒤에 있었다 /
        #   cng QUERY_VOLUME: ntoskrnl 이 클래스별 최소 길이를 강제했다).
        #   차단하지 않는다 — 리콜 최대화 목적함수에서 확정을 더 막을 이유가 없다. **보여만 준다.**
        if act == "confirm":
            try:
                import cfg as _cfg
                _p = _pe_for_gates()
                _sv = _sink_va(rec)
                if _p is not None and _sv is not None:
                    _r = _cfg.sink_gates(_p, _sv)
                    if _r and (_r["gates"] or _r.get("nearby")):
                        tail += "\n" + _cfg.render_sink_gates(_r)
            except Exception as _e:
                tail += "\n(sink-gate analysis failed: %s - that is UNAUDITED, not 'no gate')" % _e
        return (f"[{vid}] {tgt} → {rec['status']}. claim={rec['claim']!r} "
                f"basis={rec['basis']}{tail}{_link_note}{_scope_warn}{_scope_note}"
                f"{_interrog_note}")

    if act == "blocked":
        # 스모크에서 모델이 reason 없이 세 번 재시도했다. claim 을 폴백으로 받는다.
        why = args.get("reason") or args.get("claim") or ""
        if not why:
            return ("`blocked` REQUIRES why you could not adjudicate (reason=). Write in one line "
                    "WHAT YOU WOULD HAVE TO LOOK AT to move this to confirm or reject - that line "
                    "becomes the next session's work list.")
        # ★ 2026-09-04: 예전엔 `id` 와 `tgt` 를 **둘 다 무조건** 표면 행으로 만들었다.
        #   그래서 `blocked(id='V-I5-REAL', target='I-5 QuicConnRecvRetry@0x…')` 이
        #   `V-I5-REAL` 이라는 **가짜 행**을 새로 만들었다. msquic r1 에서 V-I3 / V-I5-REAL /
        #   V-I5-TOKEN / V-UNOPENED 네 개가 그렇게 생겨 분모를 부풀렸고, 다음 회차는
        #   닫아야 할 행이 늘어난 표를 물려받는다 — **판정이 다음 회차로 안 이어지는 실체.**
        #   바로 밑 `scope` 핸들러는 같은 자리에서 이미 올바르게 하고 있었다(`and k in STATE`).
        _bk = [k for k in (args.get("id"), tgt) if k and k in STATE["surface"]] \
            or [k for k in (tgt,) if k]
        # ★ 2026-09-05 (C-037): 다음 한 걸음을 **칸으로** 받는다. 산문에서 못 뽑기 때문이다.
        #   측정: blocked 498행에 (동사|물음표)+앵커 를 걸면 278행(56%)이 걸리고,
        #   앵커 접지(판정이 안 덮은 VA 보유)로 걸면 245행인데 **C-034 가 지목한 4행 중 3행이 탈락**한다.
        #   ⇒ 산문 분류는 불가능하다는 것이 실측 결과다. 쓰는 쪽에서 칸에 넣게 한다.
        # ★ `next_step` 은 스키마에 없다 — 일부러 그렇다. 모델에게는 `next` 하나만
        #   보여 이름을 하나로 유지하되, 모델이 동의어를 뱉는 슬립은 받아준다.
        #   `agent_sdk._mk` 는 인자를 **필터링하지 않으므로** 미선언 키도 여기 도달한다.
        #   이 관용은 test_argschema 의 TOLERATED_ALIASES 에 사유와 함께 등재돼 있다.
        _nx = str(args.get("next") or args.get("next_step") or "").strip()
        _ok, _miss = _next_step_ok(_nx)
        for _k in _bk:
            surface_set(_k, "미분석", "BLOCKED: " + why)
            if _k in STATE["surface"]:
                STATE["surface"][_k]["blocked"] = True
                if _ok:
                    STATE["surface"][_k]["next"] = {"step": _nx[:400],
                                                    "t": time.strftime("%m-%d %H:%M")}
        save()
        _tail = ("\n★ RETURNABLE: 다음 한 걸음이 칸에 들어갔다 — 이 행은 worklist 상단과 "
                 "`verdict(action='unfinished')` 목록에 뜬다.\n   next: " + _nx[:200]) if _ok else (
                "\n★ 이 행에는 **다음 걸음 칸이 비어 있다**(next=). 사유 산문은 다음 회차가 "
                "기계로 못 고른다 — 측정된 사실이다(498행 표본에서 '사유에 다음 수가 있는가'를 "
                "묻는 술어는 전부 56%%를 걸거나, 되찾아야 할 행을 떨어뜨렸다). "
                "칸을 채우면 저수지가 아니라 **작업 목록**이 된다:\n"
                "   verdict(action='blocked', target=..., reason=..., next='<한 걸음>')\n"
                "   요건: %s. 예) 'disassemble 0x14004efc0 and check whether "
                "SdbpInitializeSearchDBContext admits a caller-chosen absolute directory into "
                "v15[12*i+2]'" % (_miss or "-"))
        return (str(tgt) + " -> UNAUDITED (BLOCKED). It is NOT removed from the table. "
                "Reason: " + why[:200] +
                "\nIt does not count toward coverage - unaudited work with a reason is HONEST "
                "UNAUDITED WORK, not an achievement." + _tail)

    if act == "scope":
        #   기각은 후보 하나를 죽일 뿐이고, 표면은 후보가 전부 죽었을 때만 닫힌다.
        items = args.get("items") or []
        method = (args.get("method") or "").strip()
        if isinstance(items, str):
            items = [x.strip() for x in items.split(",") if x.strip()]
        if not items:
            record_denial(tgt, "[SCOPE REFUSED] items= 누락 — 후보 집합이 없다",
                          act="scope", rule="scope: items= missing")
            return ("`scope` REQUIRES the CANDIDATE SET for this surface (items=['0x14000e4b3 "
                    "ProbeForWrite call site', ...]). If the denominator is sinks, list the "
                    "sinks; if it is the authorization axis, list the gates; if it is races, list "
                    "the shared-object access points.")
        # ★ 하한 30자. 2026-09-03 번역 때 `len(method) < 30` 이 `not method` 로 줄어
        #   `method="봤음"` 이 분모로 통과했다. R-A 상 기각은 scope 위에 서므로
        #   이 한 줄이 풀리면 그 위의 모든 기각이 같이 약해진다.
        if len(method) < 30:
            record_denial(tgt, "[SCOPE REFUSED] method= %d자 (30자 하한)" % len(method),
                          act="scope", rule="scope: method< 30 chars")
            return ("`scope` REQUIRES HOW you enumerated (method=, AT LEAST 30 CHARS). "
                    "Name-based xref misses wrappers - say what you swept, behaviourally. "
                    "Without an enumeration method it is not a denominator, just a list, and no "
                    "rejection built on it holds.")
        norm = []
        for it in items:
            lab = it if isinstance(it, str) else (it.get("label") or str(it))
            m = re.search(r'0x[0-9a-fA-F]+', lab)
            norm.append({"label": lab[:120], "va": int(m.group(0), 16) if m else None,
                         "done": None})
        keys = [k for k in (args.get("id"), tgt) if k and k in STATE["surface"]] or [tgt]
        for k in keys:
            row = STATE["surface"].setdefault(
                k, {"status": "미분석", "kind": "ad-hoc", "reach": "unknown", "why": ""})
            prev = (row.get("cand") or {}).get("items") or []
            done = {i["label"]: i.get("done") for i in prev}
            for i in norm:
                i["done"] = done.get(i["label"])
            row["cand"] = {"items": norm, "method": method[:500],
                           "t": time.strftime("%m-%d %H:%M")}
        save()
        return ("%s candidate set registered (%d items). Now adjudicate EACH CANDIDATE - a "
                "rejection must name which candidate it kills via `item='<label>'` or `sink=<VA>` "
                "before that candidate closes. When all of them close, the surface becomes a "
                "rejection.\n%s"
                % (tgt, len(norm), "\n".join("  - " + i["label"] for i in norm[:12])))
    if act == "track":
        # ★ `tgt` 의 기본값이 "?" 라 그대로 쓰면 **이름 없는 트랙이 생긴다.**
        #   조용히 만들어지는 트랙은 단계표를 오염시킨다 — 거부한다.
        nm = (args.get("name") or "").strip() or (tgt if tgt not in ("?", "", None) else "")
        nm = (nm or "").strip()
        if not nm or nm == "?":
            return ("`track` REQUIRES name= (the investigation track's name). An unnamed track "
                    "pollutes the stage table.")
        # ★ 2026-09-05 실측 버그: `of` 가 **두 가지를 겸하고 있었다.**
        #   `ledger.track()` 의 `of` 는 **단계 이름 배열**(정적확정/트리거/실측/…)인데
        #   여기서 `evidence_ids` 를 그 자리에 넣었다. 에이전트가 `of='0'` 같은 값을 주면
        #   **단계표가 ["0"] 으로 통째로 덮여** 5단 사다리가 1/1 완료로 표시된다.
        #   실측: 트랙 6개가 그 상태였고(quirks-rw · versionblock-parse ·
        #   telemetry-doublefree-gate · uaf-avlnode · lockfree-cacheref · AhcpCacheBuild…),
        #   `stage_sum` 지표도 그만큼 거짓이었다.
        #   ⇒ 단계표는 `stages=` 로만 바꾼다. `of`/`evidence_ids` 는 **증거로만** 쓴다.
        _stages = args.get("stages")
        if isinstance(_stages, str):
            _stages = [x.strip() for x in _stages.split(",") if x.strip()]
        # ★ 2026-09-05 — **`stages=` 에 문장을 넣어 단계표가 깨진 트랙이 31개 중 4개.**
        #   실측 예: stages=['static-confirm -> trigger(CQ57 answered', 'key is name-only',
        #                    'hit does not re-match) -> measure -> impact -']
        #   에이전트가 진행 상황을 산문으로 적었고(`a -> b -> c` 에 콤마가 섞임) 그게 콤마로
        #   쪼개져 **사다리 자체가 됐다.** 그러면 `stage N/M` 이 의미를 잃고,
        #   "다음 칸은 무엇인가"가 문장 조각으로 나온다(계기판에서 그렇게 나왔다).
        #   ⇒ **사다리는 라벨이지 서술이 아니다.** 형식으로 거른다: 칸이 너무 길거나
        #     화살표/괄호가 섞이면 산문이므로 받지 않는다(기존 표를 지키는 쪽이 안전하다).
        if _stages:
            _bad = [x for x in _stages
                    if len(str(x)) > 24 or "->" in str(x) or "(" in str(x)]
            if _bad:
                _stages = None      # 기존 단계표를 보존한다
        of = _stages if (_stages and len(_stages) >= 2) else None
        _more = args.get("evidence_ids") or args.get("of")
        if isinstance(_more, str):
            _more = [x.strip() for x in _more.split(",") if x.strip()]
        _ev = args.get("evidence_ids") or ([args["id"]] if args.get("id") else None)
        _ev = list(_ev or []) + list(_more or [])
        # ★ 2026-09-06 실측(야간런 케이스 5): **읽기 모양의 호출 하나가 트랙을 4→0 으로 지웠다.**
        #   모델이 스키마의 모든 칸을 빈값으로 채워 보내면 int 칸은 **0** 이 된다 —
        #   `stage: int` 는 "바꾸지 마라"를 나를 수 없다(memory `predicate-cannot-ask`
        #   와 같은 병: 매체가 unknown 을 못 나른다). 그러고서 도구는 "stage 0/5" 를
        #   돌려주고, 에이전트는 그걸 **원장의 상태로** 읽는다 — 실측된 문장:
        #   *"The state demoted per-class-authz to 0/5"* (자기가 지운 것을 상태로 오독).
        #   직전 회차까지 4단까지 쌓은 기록이 눈앞에서 사라졌고, 그 회차는 사라진 것을
        #   전제로 목표를 잡았다. ⇒ **강등은 이유를 달아야** 통과시킨다.
        #   지휘자의 강등은 항상 why 를 달고 있고(conductor.apply), 이 도구의 안내문
        #   ("반박당하면 내리는 게 정직하다")도 이유의 존재를 이미 전제한다.
        #   올리는 쪽·유지는 영향 없다 — 읽기 모양의 호출은 이제 그대로 읽기다.
        _note = args.get("note") or args.get("why") or ""
        _st = args.get("stage")
        _cur = int(((STATE.get("tracks") or {}).get(nm) or {}).get("stage", 0))
        _kept = ""
        if isinstance(_st, int) and not isinstance(_st, bool) and _st < _cur and not str(_note).strip():
            _kept = ("\n\n[STAGE KEPT AT %d] You passed stage=%d, which would MOVE THIS TRACK "
                     "BACK %d rung(s), but gave no reason. A demotion is a refutation, so it has "
                     "to say what refuted the rung: re-send with note='<what knocked it down>'. "
                     "(If you meant to READ the track, you already have - stage is unchanged. "
                     "An int field cannot say 'leave it alone', so a blank-filled call used to "
                     "erase depth silently. That is what this refusal exists to stop.)"
                     % (_cur, _st, _cur - _st))
            _st = None
        t = track(nm, _st, of, _note, _ev,
                  target=args.get("target"))
        return ("Track `%s` - stage %d/%d (%s)\n%s\nStages CAN MOVE BACK - lowering one after a "
                "refutation is the honest thing to do.\nThis table rides in the next session's "
                "carry-over. FOR SIX SESSIONS TO CLIMB SIX RUNGS, YOU HAVE TO MOVE IT."
                % (nm, t["stage"], len(t["stages"]),
                   t["stages"][t["stage"]] if t["stage"] < len(t["stages"]) else "완료",
                   track_render()) + _kept)
    if act == "anchors":
        # 수동 조회. 자동 부착이 있어도, 판정을 **내기 전에** 물어볼 수 있어야 한다.
        _q = " ".join(str(args.get(k) or "") for k in ("evidence", "claim", "target", "text"))
        r = anchor_hits(_q)
        if not r:
            n = len(_vas(_q))
            return ("None of the %d anchors already appear in the ledger. This is new "
                    "ground.\n(Only 0x-form addresses of 6+ digits are considered. If you gave "
                    "none, put anchors in evidence=.)" % n)
        return r
    if act == "reopen":
        return reopen(args.get("id") or args.get("gid"), args.get("ground"),
                      args.get("why") or args.get("reason"), args.get("evidence") or "")
    if act == "gate_blocked":
        # ★ 게이트가 **구조적으로** 판정을 막을 때의 신고 채널.
        #   2026-09-02: 함수포인터 카운터가 부재형 기각을 전면 차단하자 에이전트가
        #   두 회차를 다른 축으로 돌았다. 우회밖에 길이 없으면 우회한다 — 신고할 데를 만든다.
        g = (args.get("gate") or "").strip()
        w = (args.get("why") or args.get("reason") or "").strip()
        wo = (args.get("would_be") or args.get("claim") or "").strip()
        # kind: gate(게이트가 막음) · taxonomy(**원장에 적을 칸이 없음**) · tool(도구가 못 함)
        kd = (args.get("kind") or "gate").strip().lower()
        if kd not in ("gate", "taxonomy", "tool"):
            kd = "gate"
        if not g or len(w) < 20:
            return ("`gate_blocked` REQUIRES WHICH gate (gate=) and WHAT it blocked you on (why=, "
                    "at least 20 chars).\nOptional: would_be= 'what you would have filed had it "
                    "not blocked' - kind='taxonomy' WHEN THE LEDGER HAS NO SLOT AT ALL - "
                    "kind='tool' when a tool cannot do it.")
        STATE.setdefault("gate_blocks", []).append(
            {"gate": g[:80], "why": w[:500], "would_be": wo[:400], "target": tgt,
             "kind": kd, "evidence": (args.get("evidence") or "")[:1500],
             # ★ 2026-09-23 — **환경 도장.** 실측채널 신고 39건이 "그때 채널이 닫혀 있었다"
             #   인데, 채널이 열린 뒤에도 영원히 쌓여 있었다. 지금 상태를 같이 박아 두면
             #   나중에 **다르면 재확인 대상**으로 기계가 가른다(문장을 읽지 않는다).
             "env": _env_stamp(),
             "t": time.strftime("%m-%d %H:%M")})
        save()
        # ★ 2026-09-23 — 영수증이 아니라 **행**으로 남긴다.
        #   실측: gate_blocks 가 8개 표적에 123건 누적됐는데(09-02~), 소비자는 BRIEF 에
        #   최근 4건을 찍는 것과 지휘자 화면뿐이다. census·coverage·채점 어디에도 안 잡히고,
        #   would_be 400자로 잘려 다음 세션이 그 행을 **처음부터 다시 만든다**.
        #   가장 오래된 신고(09-02 wcifs)가 어젯밤과 **같은 문장**이었다 —
        #   "no value expresses 'real defect, gated off'". 3주간 아무도 안 봤다는 뜻이다.
        #   ⇒ 미분석 판정으로 적재한다. 3분류(확정/기각/미분석)의 셋째 칸이 이제 채워진다.
        STATE.setdefault("verdicts", []).append(
            {"id": "GB-%s" % time.strftime("%m%d%H%M%S"), "target": tgt,
             "status": "미분석", "basis": "blocked", "blocked_by": g[:80],
             "blocked_kind": kd, "claim": (wo or w)[:400],
             "evidence": (args.get("evidence") or "")[:1500], "why": w[:500],
             "t": time.strftime("%m-%d %H:%M")})
        save()
        if kd == "taxonomy":
            save()
            return ("Accepted as a report that THE LEDGER HAS NO SLOT for this: `%s`\nThis is not "
                    "a gate problem, it is a SCHEMA problem - a measured truth the ledger cannot "
                    "hold, and left alone that finding disappears silently.\nBetween sessions the "
                    "conductor reads this and writes it OUTSIDE the schema to "
                    "`reports/unrecordable/<target>.md`, proposing the slot that should exist. If "
                    "you passed `evidence=`, that is carried too.\nSO DO NOT ABANDON THIS AXIS. "
                    "'There is no slot to write it in' and 'there is no defect' are different "
                    "things." % (w[:200]))
        return ("Gate-blocked report accepted: `%s`\nTHIS IS NOT A VERDICT - it does not count "
                "toward coverage. But it stays in the ledger and rides into the next session's "
                "carry-over and the report.\nAnd do not drop the axis just because you filed "
                "this. If another basis can route around it, take that; if not, leave a `blocked` "
                "with the reason - QUIETLY MOVING TO A DIFFERENT AXIS IS THE WORST OUTCOME."
                % (g[:80]))
    if act == "goal":
        return set_goal(args.get("text") or args.get("claim") or "",
                        (args.get("kind") or "judge").lower())
    if act == "worklist":
        return worklist(int(args.get("n") or 12))
    if act == "unfinished":
        return unfinished(int(args.get("n") or 12), int(args.get("offset") or 0))
    if act == "status":
        return status_block(None, None)
    if act == "exhaust":
        # ★ 3-way settle 의 세 번째 칸. **기각이 아니다.**
        #   "더 쓸 방법이 없다"를 기각으로 세탁하면 재심 전체가 무의미해진다.
        why = (args.get("reason") or "").strip()
        tried = args.get("tried") or ""
        if len(why) < 20:
            return ("`exhaust` REQUIRES what you tried and why it blocked you (reason=). State "
                    "whether you actually ran the question's `method` - if you did not, it is not "
                    "exhaustion.")
        if not _ask_open(tgt):
            return "That target has no open question. (check with `verdict(action='asks')`)"
        n = _ask_close(tgt, args.get("id") or "-", "exhausted", why)
        for _k in [k for k in (tgt,) if k in STATE.get("surface", {})]:
            STATE["surface"][_k]["status"] = "미분석"
            STATE["surface"][_k]["blocked"] = True
            STATE["surface"][_k]["exhausted"] = True
            STATE["surface"][_k]["why"] = "METHOD EXHAUSTED: " + why[:220]
        save()
        return (str(tgt) + " -> METHOD EXHAUSTED (%d " % n +
                "questions closed). This is NOT a rejection - the row stays UNAUDITED in the "
                "table and does not become part of coverage's numerator.\nTried: " + str(tried)[:300])
    if act in ("lead", "leads"):
        # ★ 2026-09-07 — 리드 큐를 **행동 가능하게** 만든다. 기록부(reports/breaks/)는
        #   09-04 부터 있었지만 소비 경로가 `break_digest` 최신 3건뿐이었고 닫는 길이
        #   아예 없었다. 상태 없는 큐는 줄지 않는다.
        if act == "leads" or not args.get("id"):
            _ol = open_leads(STATE.get("target"))
            if not _ol:
                return ("열린 리드 0건. (`reports/breaks/` 누적 %d건, 전부 닫혔거나 "
                        "재제출 큐다.)" % len(breaks(STATE.get("target"))))
            L = ["=== 리드 큐 — 열림 %d건, 오래된 것부터 ===" % len(_ol)]
            for b in _ol:
                L.append("· `%s` [%s] %s  (%s)"
                         % (b.get("id"), b.get("klass") or "-",
                            str(b.get("target"))[:70], str(b.get("t") or "")[:10]))
                nm = (b.get("next_method") or b.get("reason") or "").replace("\n", " ")
                if nm:
                    L.append("    다음 수: %s" % nm[:300])
            L += ["", "닫는 길은 셋뿐이다 — `verdict(action='lead', id=…, how=…, why=…)`"]
            L += ["  · %s — %s" % kv for kv in CLOSE_HOWS.items()]
            L += ["소진(exhausted)은 **없다.** 못 닫으면 열어 둔 채로 두는 것이 정직하다."]
            return "\n".join(L)
        _r = close_break(args["id"], args.get("how") or args.get("klass") or "",
                         args.get("why") or args.get("reason") or "")
        if not str(_r).startswith("[CLOSE"):
            _bump("leads_closed")
        return _r

    if act == "reaudit":
        # ★ 2026-09-07 — **오기각 방어가 기록 시점 1회뿐이었다.**
        #   설계 의도는 "오기각은 영구 손실이니 비싸게 막는다"인데, 실제로는 한 번 통과하면
        #   영원히 다시 안 본다: `reopen()` 은 에이전트가 스스로 근거를 들고 부를 때만 돌고
        #   `rejaudit.audit()`/`regrade()` 는 라이브 경로에서 **한 번도 호출되지 않는다**
        #   (`RA.classify` 만 쓰인다 — 등급 계산이지 재심이 아니다).
        #   실측: 묘지의 `verified` 는 ahcache 34% · wcifs 37% 뿐이고
        #   `INTERROGATE_RATE=1.0` 인데도 절반이 미심문이다.
        #   ⇒ **행동 가능한 큐**를 준다. 등급을 세는 것(`graveyard_trust`)은 이미 있었지만
        #     그것만으로는 아무도 움직이지 않았다.
        _c, _rows, _n = graveyard_trust()
        # ★ 큐가 비어도 **계약은 같은 모양**이어야 한다 — 0 을 안 찍으면 소비자가
        #   "그 등급이 없다"와 "그 칸이 없다"를 구분 못 한다.
        L = ["=== 묘지 재심 큐 — 검증된 음성 %d / 전체 %d ==="
             % (_c.get("verified", 0), sum(_c.values())),
             "  " + " · ".join("%s %d" % (k, _c.get(k, 0)) for k in
                               ("verified", "unexamined", "broke", "reopened",
                                "candidate", "orphan")), ""]
        L.append("① 서 있지 않은 기각 %d건 — 이건 부활이 아니라 **정리**다. "
                 "`verdict(action='reopen', gid=<id>, ground='new_evidence', why=…)`" % _n)
        if _rows:
            for r in _rows[:8]:
                L.append("   [%s] %s (%s) — %s"
                         % (r["grade"], r["id"], r.get("klass"), str(r.get("why") or "")[:90]))
        else:
            L.append("   (없음 — 깨진 기각도 철회 표시도 잔류하지 않는다)")
        _un = [g for g in (STATE.get("graveyard") or [])
               if not g.get("reopened")
               and not any(str(v.get("id")) == str(g.get("id"))
                           and (v.get("interrogated") is True
                                or ((v.get("interrogation") or {}) if isinstance(
                                    v.get("interrogation"), dict) else {}).get("broke"))
                           for v in (STATE.get("verdicts") or []))]
        if _un:
            import collections as _c2
            _byk = _c2.Counter(g.get("klass") for g in _un)
            L += ["", "② 적대자를 한 번도 안 거친 기각 %d건 — 사유 분포: %s"
                  % (len(_un), " · ".join("%s %d" % kv for kv in _byk.most_common(6))),
                  "   ★ '안 검증됨'은 '틀림'이 아니다. 표본으로 확인한 결과 이 버킷은",
                  "     정확성 결함이 아니라 **절차 결함**이었다 — 새 실측·새 빌드·형제 함수의",
                  "     반례가 생겼을 때 다시 볼 후보 목록으로 써라.",
                  "   사유별 대표 1건:"]
            _seen = set()
            for g in reversed(_un):
                if g.get("klass") in _seen:
                    continue
                _seen.add(g.get("klass"))
                L.append("     [%s] %s — %s" % (g.get("klass"), str(g.get("id"))[:44],
                                                str(g.get("target"))[:50]))
                if len(_seen) >= 6:
                    break
        return "\n".join(L)

    if act == "resisted":
        # ★ 2026-09-08 — **죽이려다 실패한 행.** 이 하네스의 압력은 전부 "죽이기"인데
        #   그 시도가 실패한 사건에는 소비 경로가 없었다. `denial_report()` 는 규칙별
        #   집계라 "어느 행이 버텼나"를 답하지 않는다.
        _rw, _c = resisted(STATE.get("target"))
        if not _rw:
            return ("저항 큐 0건 — 이 표적에서 기각 시도가 반려된 적도, CFG 가 짝을 "
                    "반증한 적도, 심문자가 깬 기각도 없다. (0 이지 미측정이 아니다: "
                    "반려 기록 %d건 · 판정 %d건을 봤다.)"
                    % (len(STATE.get("denials") or []), len(STATE.get("verdicts") or [])))
        L = [resisted_digest(STATE.get("target"), n=12), "",
             "축 %d개 이상 겹친 행 %d건 — 겹침이 1순위 신호다. 한 축(반려만)은 서류 문제일 "
             "수 있으나, **klass 를 바꿔가며 반복 반려된 행**은 사망 가설이 여러 개 안 "
             "먹혔다는 뜻이다." % (2, _c["multi_axis"]),
             "",
             "★ 이 큐를 닫는 길은 **재분석**뿐이고 셋 중 하나로 끝난다:",
             "  · 요건을 갖춘 기각을 다시 낸다 (반려가 서류 문제였다면 그것이 정답이다)",
             "  · `verdict(action='confirm', …)` — 죽지 않는 이유가 결함이기 때문이라면",
             "  · `verdict(action='exhaust', …)` — 더 쓸 방법이 없다. 기각이 아니다",
             "리드 id 가 붙은 행은 **거기서** 닫아라 — 같은 일을 두 큐가 시키지 않는다."]
        return "\n".join(L)

    if act == "asks":
        # ★ 2026-09-07 — **수신자로 가른다.** 옛 동작은 전부를 한 통에 쏟았고, 그 통의
        #   40%가 `harness /…` 로 시작하는 원장·게이트 감사 질문이었다. 분석가가 답할 수
        #   있는 질문이 아니어서 소진으로 닫혔고, 그게 "포기율 49%"로 계기판에 잡혔다.
        mine = open_asks(audience="analyst", rank=True, include_leads=True)
        ops = open_asks(audience="operator")
        if not mine and not ops:
            return "No open questions."
        L = ["열린 질문 — 네 몫 %d건 · 운영자 몫 %d건. "
             "THESE ARE NOT NEGATIVES, THEY ARE UNAUDITED." % (len(mine), len(ops))]
        for q in mine:
            # ★ 2026-09-08 — **출처와 종류를 같이 보여준다.** 이 큐는 정렬이 출처별
            #   실측 수율이고(지휘자 0/72 대 게이트 15/40), 심문자 리드는 `_ask_close`
            #   가 아니라 `verdict(action='lead')` 로 닫힌다 — 닫는 길이 다르면 말해줘야 한다.
            L.append("\n[%s] (%s/%s) %s  (cfg=%s, %d attempts)\n  why   : %s\n  method: %s%s"
                     % (q["id"], normalize_ask_by(q.get("by"), q.get("id")),
                        q.get("kind") or "?", q["target"], q.get("cfg"),
                        len(q.get("attempts") or []),
                        (q.get("why") or "")[:200], (q.get("method") or "")[:260],
                        ("\n  close : " + q["_close_via"]) if q.get("_close_via") else ""))
        if ops:
            L.append("\n— 운영자 몫 %d건 (하니스·원장 감사. **네 일이 아니다** — 답하지도 "
                     "소진시키지도 마라. 같은 벽을 또 만나면 `gate_blocked` 로 새로 적어라):"
                     % len(ops))
            for q in ops[:8]:
                L.append("  · [%s] %s" % (q["id"], str(q["target"])[:70]))
            if len(ops) > 8:
                L.append("  · … 그리고 %d건" % (len(ops) - 8))
        return "\n".join(L)
    return ("action must be one of: confirm | reject | blocked | scope | goal | track | "
            "gate_blocked | reopen | reaudit | asks | exhaust | lead | leads | "
            "worklist | unfinished | status.")


def stash_escalation(tgt, v):
    """승격자는 판정이 기록되기 **전에** 도는 사전 게이트다 ⇒ 붙일 판정이 아직 없다.
    보관해 두고 `verdict()` 가 기록 시점에 박는다. (심문 결과가 통째로 증발했던 것과 같은 자리)"""
    STATE.setdefault("pending_escalation", {})[tgt] = {
        "escalated": bool(v.get("escalated")), "axis": v.get("axis"),
        "principal": (v.get("principal") or "")[:300],
        "reason": (v.get("reason") or "")[:400],
        "enumerated": (v.get("enumerated") or "")[:400]}
    save()



_NEXT_ANCHOR = re.compile(r"0x[0-9a-fA-F]{6,16}|\b[A-Z][a-z]+[A-Z][A-Za-z]{5,}\b")


def _next_step_ok(s):
    """`next=` 가 '다음 한 걸음'으로 인정되는가. **산문 분류가 아니라 형식 검사다.**

    산문 분류를 시도했고 실패했다(2026-09-05 실측, C-037): blocked 498행에
    (방법동사|물음표)+앵커 → 278행(56%), 미판정 앵커 접지 → 245행이고 그마저
    C-034 가 지목한 4행 중 3행을 떨어뜨린다. 사유가 중앙값 882자라 거의 모든 행에
    동사와 주소가 들어 있기 때문이다. ⇒ **읽는 쪽에서 못 고르면 쓰는 쪽이 선언한다.**

    요건 둘 (scope 의 method 30자 하한과 같은 계열):
      · 40자 이상 — "재확인 필요" 같은 한 마디는 다음 회차가 집을 수 없다
      · 앵커 하나 — VA(0x…) 또는 CamelCase 심볼. **무엇에 대고 할지가 없으면 걸음이 아니다**
    """
    t = (s or "").strip()
    if not t:
        return (False, "next= 자체가 비어 있다")
    if len(t) < 40:
        return (False, "40자 이상 (지금 %d자)" % len(t))
    if not _NEXT_ANCHOR.search(t):
        return (False, "앵커 하나 — VA(0x14004efc0) 또는 심볼(SdbpInitializeSearchDBContext)")
    return (True, "")


_ALIAS_MARK = re.compile(r"\bALIAS\b|ALREADY ADJUDICATED", re.I)


def _is_alias_row(why):
    """이 BLOCKED 행이 **부기용 별칭**인가 (판정이 다른 행에 산다).

    ★ 2026-09-05 최종점검에서 잡은 오제외: 처음엔 `lives on|canonical row` 도 봤는데
      그건 **코드에 대한 산문**에 걸린다 — 55행 중 3행이 오제외였고 그 셋이 하필
      되찾아야 할 행이었다("NEXT STEP for…", "the constraint genuinely lives only in the
      caller"). 내가 방금 C-037 에 적은 병리를 제외 규칙에서 그대로 재현한 것이다.
    ★ 그리고 **위치를 요구한다**(앞 120자). 별칭 행은 첫 문장이 부기다
      ("DUPLICATE ALIAS from a FRESH=1 restore. Judgement lives on fn2_AhcApiUpdate…").
      뒤쪽에서만 걸린 1행은 오히려 **정본**이었다 — 자기 밑에 별칭 9개가 있다고 적은 행이라,
      위치를 안 보면 정본을 지우고 별칭을 남기게 된다.
    실측: 앞120자 한정 51행 전수 표본이 진짜 별칭 · 오제외 0.
    """
    w = re.sub(r"^BLOCKED[:\s—-]*", "", str(why or "")).strip()
    return bool(_ALIAS_MARK.search(w[:120]))


def unfinished(n=12, offset=0):
    """★ **blocked 저수지를 열거한다.** 순위가 아니라 목록이다 — 그게 정직하다.

    C-034 는 "사유에 다음 단계가 적힌 BLOCKED 행을 worklist 상단으로 올려라"였다.
    구현하려고 술어를 셋 만들어 재봤더니 전부 실패했다(C-037):
      현행 키워드 61/498 · (동사|?)+앵커 278/498(56%) · 미판정앵커 접지 245/498
      그리고 접지형은 **C-034 가 지목한 바로 그 4행 중 3행을 떨어뜨린다.**
    ⇒ 기계가 못 고른다. 그래서 **고르는 대신 세어서 보여준다** — 저수지의 진짜 크기를
      먼저 말하고(수백 행), 페이지로 넘긴다. 고르는 것은 분석가·목표의 일이다.
      (C-021 의 교훈: 열거할 수 없는 행은 ~150회 이름 탐침으로 되돌아온다.)

    제외: 별칭·이미 판정된 행(판정이 다른 행에 산다) · 소진된 행.
    정렬: `next=` 칸이 있는 행 → 비특권 도달 → 미착수 → 사유가 긴 행.
    """
    surf = STATE.get("surface") or {}
    V = STATE.get("verdicts") or []
    judged = set()
    for v in V:
        judged |= {a.lower() for a in re.findall(r'0x[0-9a-fA-F]{6,16}',
                                                 json.dumps(v, ensure_ascii=False))}
    rows, alias, exh = [], 0, 0
    for k, r in surf.items():
        if not r.get("blocked"):
            continue
        w = str(r.get("why") or "")
        if r.get("exhausted"):
            exh += 1; continue
        if _is_alias_row(w):
            alias += 1; continue
        nx = (r.get("next") or {}).get("step") if isinstance(r.get("next"), dict) else None
        rch = (r.get("reach") or "").lower()
        up = any(t in rch for t in ("user-direct", "user-trigger", "unprivileged"))
        fresh = len({a.lower() for a in re.findall(r'0x[0-9a-fA-F]{6,16}', k + " " + w)} - judged)
        rows.append((bool(nx), up, int(r.get("picks") or 0) == 0, len(w), k, r, nx, rch, fresh))
    rows.sort(key=lambda x: (not x[0], not x[1], not x[2], -x[3]))
    withnext = sum(1 for x in rows if x[0])
    tot = len(rows)
    if not tot:
        return "blocked 저수지가 비어 있다."
    off = max(0, int(offset or 0))
    if off >= tot:
        return ("blocked 저수지 %d행 — offset=%d 는 끝을 넘었다. 마지막 페이지는 offset=%d."
                % (tot, off, max(0, tot - 12)))
    page = rows[off:off + max(1, int(n or 12))]
    L = ["blocked 저수지 **%d행** (별칭 %d · 소진 %d 제외) — %d~%d 표시. 더 보려면 offset=%d"
         % (tot, alias, exh, off + 1, off + len(page), off + len(page)),
         "★ 그중 다음 걸음이 **칸에 선언된 것은 %d행**. 나머지는 사유 산문뿐이고, "
         "어느 것에 다음 수가 적혔는지 **기계는 못 고른다**(측정됨) — 읽고 골라라." % withnext]
    for hasnx, up, fresh_pick, _wl, k, r, nx, rch, fresh in page:
        w = re.sub(r"^BLOCKED[:\s—-]*", "", str(r.get("why") or "")).strip()
        head = re.split(r"(?<=[.?!])\s", w)[0] if w else "(사유 없음)"
        L.append("\n· %s%s\n    reach=%s · 미판정앵커 %d · picks=%s"
                 % (k[:72], "  [next 칸 있음]" if hasnx else "", rch[:20] or "-", fresh,
                    r.get("picks") or 0))
        L.append("    %s: %s" % ("NEXT" if hasnx else "사유", (nx or head)[:220]))
    L.append("\n이 행들은 커버리지 분모에 남아 있다. 하나를 골라 끝까지 닫거나, "
             "`verdict(action='blocked', ..., next='<한 걸음>')` 로 칸을 채워 다음 회차가 집게 하라.")
    return "\n".join(L)


def _ask_for(target):
    """표면 키에 걸린 열린 질문. 없으면 None. worklist 점수축이 쓴다."""
    t = str(target)
    best = None
    for a in (STATE.get("asks") or []):
        at = str(a.get("target") or "")
        if at == t or (len(at) > 12 and (at in t or t in at)):
            # 시도가 많은 쪽을 우선 — 그게 지금 막고 있는 것이다
            if best is None or len(a.get("attempts") or []) > len(best.get("attempts") or []):
                best = a
    return best


def worklist(n=12):
    """★ **무엇을 다시 까야 하는가.** 전수조사의 반대말.

    표가 크면(수백 행) "전부 다시 본다"는 실행 불가능하고, 실행해도 값이 안 난다.
    골라야 하는데 그 고르는 규율이 코드에 없으면 매 회차 즉흥으로 정해진다.
    여기서 점수는 하나의 축이 아니라 **"이 행이 손에 든 결함의 등급을 움직이는가"** 다.

    양수 축 — 움직이는 행:
      +4 살아있는 **확정의 체인 위**에 있다 (확정의 target/claim/impact 가 이 행을 가리킨다)
      +3 **근거 없는 전수 주장**을 담은 확정 (그 한 문장이 등급 상한을 혼자 정한다)
      +3 **약한 기각** — klass 는 있는데 CFG 판정도 심문도 없다 (검증된 음성이 아니다)
      +2 **비특권 도달** (user-direct / user-triggerable)
      +2 다음 수가 적힌 blocked (움직이는 데 드는 비용이 이미 적혀 있다)
      +1 `scope` 는 선언됐는데 후보가 남음 (반쯤 닫힌 것 — 마무리가 싸다)
    음수 축 — 건드려도 값이 안 나는 행:
      -4 방법 소진(exhaust)  -3 이미 확정  -2 kernel-only 도달
    """
    surf = STATE.get("surface") or {}
    V = STATE.get("verdicts") or []
    conf = [v for v in V if v.get("status") == "확정"]
    conftext = " ".join(json.dumps(v, ensure_ascii=False) for v in conf).lower()
    byt = {}
    for v in V:
        byt.setdefault(str(v.get("target")), []).append(v)

    def addrs(k):
        return set(re.findall(r'0x[0-9a-fA-F]{6,16}', k))

    rows = []
    for k, r in surf.items():
        st = r.get("status") or ""
        sc, why = 0, []
        kl = k.lower()
        if kl[:60] in conftext or (addrs(k) and any(a.lower() in conftext for a in addrs(k))):
            sc += 4; why.append("확정의 체인 위")
        if st == "확정":
            sc -= 3
            for v in byt.get(k, []):
                imp = v.get("impact") or {}
                if imp.get("sole_claim") and not imp.get("enumerated"):
                    sc += 3; why.append("근거 없는 전수 주장")
        for v in byt.get(k, []):
            if v.get("status") != "기각":
                continue
            g = v.get("gate") or {}
            if (g.get("klass") in ("not_controlled", "by_design", "delta_zero", "no_sink")
                    and not ((g.get("cfg") or {}).get("verdict"))
                    and not v.get("interrogated")):
                sc += 3; why.append("약한 기각(%s, CFG·심문 없음)" % g.get("klass")); break
        rch = (r.get("reach") or "").lower()
        if any(w in rch for w in ("user-direct", "user-triggerable", "unprivileged")):
            sc += 2; why.append("비특권 도달")
        elif "kernel-only" in rch:
            sc -= 2
        # ★ 2026-09-03: `asks` 가 점수축에 **아예 없었다.** 원장은 재시도를 세고 있는데
        #   (`asks[].attempts`) 점수 계산이 그걸 안 읽어서, 같은 질문이 5회까지 다시 뽑혔다
        #   (ahcache VARIANT-AXIS-S22 5회 / D_axis_quirks_section 4회, 전부 결국 exhausted).
        #   ⇒ 질문을 **양방향 축**으로 쓴다: 아직 안 해본 질문은 올리고, 반복 실패는 내린다.
        _aq = _ask_for(k)
        if _aq is not None:
            _at = len(_aq.get("attempts") or [])
            _ast = (_aq.get("status") or "open").lower()
            if _ast == "answered":
                sc += 3; why.append("★ 열린 질문이 **답해졌다** — 이제 판정 가능하다")
            elif _ast == "exhausted":
                sc -= 4; why.append("질문 소진(%d회 시도)" % _at)
            elif _at == 0:
                sc += 2; why.append("the question is open WITH A METHOD and has never been "
                                    "attempted")
            else:
                sc -= min(6, 2 * _at)
                why.append("같은 질문 %d회 실패 — 같은 방법을 또 쓰지 마라(%s)"
                           % (_at, str(_aq.get("method"))[:40]))

        w = str(r.get("why") or "")
        # ★ 예전엔 `blocked` + '다음 수' 만으로 무조건 +2 였다. 즉 **막혀 있는 것 자체가
        #   가산점**이었고, 그래서 blocked 476/518(92%) 인 표에서 같은 행이 계속 위로 왔다.
        #   ⇒ 다음 수가 적혀 있어도 **뽑혀 나간 뒤 안 움직였으면** 내린다.
        _picks = int(r.get("picks") or 0)
        # ★ 2026-09-05 (C-037): 두 등급으로 가른다. **칸에 선언된 것**(next=)과 산문 매치.
        #   정규식을 넓히지 않는다 — 넓히면 blocked 의 56%가 걸려 축이 정보를 잃는다(실측).
        _nxs = r.get("next") if isinstance(r.get("next"), dict) else None
        _nxs = (_nxs or {}).get("step")
        _prose = bool(re.search(r"TO MOVE|다음 수|다음 방법|next step", w, re.I))
        if r.get("blocked") and (_nxs or _prose):
            if _picks == 0:
                sc += 3 if _nxs else 2
                why.append(("★ 다음 한 걸음이 **칸에 선언돼 있다**: " + str(_nxs)[:90]) if _nxs
                           else "다음 수가 사유 산문에 적혀 있다(칸 아님)")
            else:
                sc -= min(4, _picks)
                why.append("picked %d times with the next move already written down, and it never "
                           "moved - change the method" % _picks)
        cand = (r.get("cand") or {}).get("items") or []
        if cand and any(not i.get("done") for i in cand):
            sc += 1; why.append("scope 후보 %d/%d 남음"
                                % (sum(1 for i in cand if not i.get("done")), len(cand)))
        # ★ 차분 축(refs/03): 확정 7건이 전부 **모집단을 세우고 튀는 하나**에서 나왔다.
        #   같은 계열에 형제가 있고 그중 판정된 게 있으면, 나머지는 비교 대상이 된다 —
        #   "위험해 보이는 코드"가 아니라 **형제와 다른 코드**가 사냥터다.
        fam = re.match(r'^([A-Za-z_][A-Za-z0-9_]{2,}?)[._:@\-]', k)
        if fam:
            sib = [kk for kk in surf if kk != k and kk.startswith(fam.group(1))]
            done_sib = [kk for kk in sib if surf[kk].get("status") in ("확정", "기각", "경계보류")]
            if len(sib) >= 2 and done_sib:
                sc += 2
                why.append("차분 가능(형제 %d, 판정된 형제 %d)" % (len(sib), len(done_sib)))
        for _v in byt.get(k, []):
            if (_v.get("impact") or {}).get("out_of_scope"):
                # 내리지 않는다. 남은 질문이 **하나**로 좁혀진 행이고, 그 하나를 채우면
                # 곧바로 확정이 된다 — 원장에서 가장 싼 확정 후보다.
                sc += 3
                why.append("경계보류(%s) — 더 낮은 권한 principal 하나면 확정된다"
                           % _v["impact"]["out_of_scope"])
                break
        if r.get("incidental"):
            sc += 3; why.append("incidental find (%s)" % str(r["incidental"])[:40])
        if r.get("exhausted"):
            sc -= 4; why.append("method exhausted")
        if sc > 0:
            rows.append((sc, k, st, "; ".join(why)))
    rows.sort(key=lambda x: -x[0])
    if not rows:
        return ("worklist: no row has a positive score. Either the table is empty or everything "
                "is exhausted or confirmed. If you need a new denominator, that is a different "
                "session's job.")
    surf = STATE.get("surface") or {}
    L = ["%d ROWS STILL WORTH DIGGING (this is not an exhaustive sweep - it is the order that "
         "MOVES THE GRADE of a finding you already hold)" % min(n, len(rows))]
    for sc, k, st, why in rows[:n]:
        # ★ 내보낸 행을 **센다.** 이 카운터가 없으면 "다음 수가 적혀 있다"는
        #   영원히 가산점이다 — 적혀 있는 것과 시도한 것은 다르다.
        _r = surf.get(k)
        if isinstance(_r, dict):
            _r["picks"] = int(_r.get("picks") or 0) + 1
        L.append("  [%+d] %-58s %s" % (sc, k[:58], st))
        L.append("       %s" % why)
    save()
    L += ["", "Work top down, one at a time. Close a row to the end before moving on - do not "
              "touch several shallowly.",
          "The score is not 'importance' - it is MOVABILITY x EFFECT ON THE GRADE."]
    return "\n".join(L)


def record_image(meta):
    """★ 크로스 이미지에서 쓴 **모든** 이미지의 빌드 동일성을 남긴다.

    왜 필수인가: `nt!0x14098f670` 이 검증됐다는 기록은, **어느 ntoskrnl 인지**가 같이
    남지 않으면 재현 불가능하다. 다른 빌드로 검증한 앵커는 검증이 아니라 우연이다.
    """
    imgs = STATE.setdefault("images", {})
    imgs[meta["name"]] = dict(meta, t=time.strftime("%m-%d %H:%M"))
    save()
    return imgs[meta["name"]]


def record_xref(desc, sections, names, nhits):
    """전 실행섹션 xref 를 돌렸다는 사실을 남긴다. 부재 주장 게이트가 이걸 요구한다.

    `.text` 만 보고 'API 호출이 없다'고 쓴 실패(ipt.sys / SeSinglePrivilegeCheck @PAGE)가
    실제로 있었다. 무엇을 어느 섹션에서 훑었는지가 근거의 일부다.
    """
    STATE.setdefault("xrefs", []).append(
        {"desc": desc, "sections": list(sections), "names": list(names)[:40],
         "hits": nhits, "t": time.strftime("%m-%d %H:%M")})
    save()


PRIORART_AXES = ("device", "ioctl", "symbol")

# 표적/주장에서 **선행연구로 검색했어야 할 문자열**을 유도하는 패턴.
_DEV_RE = re.compile(r'\\{1,2}(?:Device|GLOBAL\?\?|DosDevices|\?\?)\\{1,2}[A-Za-z0-9_.\-]{2,48}')
# CTL 코드: `_CODE_RE`(0x8xxxxxxx) 는 좁다 — 이 원장의 실제 확정에 0x2A400C·0x22C00C·
# 0x39006F 가 있고 전부 안 걸린다. IOCTL/CTRL/FASTIO 문맥의 5~8자리도 같이 본다.
_IOCTL_CTX = re.compile(r'(?:IOCTL|CTL_CODE|CTRL|FASTIO)[^\n]{0,16}?(0x[0-9a-fA-F]{4,8})', re.I)
# 핸들러/구조체 이름 후보: 대문자 2개 이상을 포함한 6자 이상의 식별자
_SYMB_RE = re.compile(r'\b(?=[A-Za-z_]*[A-Z][A-Za-z_]*[A-Z])[A-Za-z_][A-Za-z0-9_:]{5,60}\b')
_SYMB_STOP = {"IOCTL", "METHOD_NEITHER", "METHOD_BUFFERED", "METHOD_IN_DIRECT",
              "METHOD_OUT_DIRECT", "PAGE_READWRITE", "PAGE_WRITECOPY", "FILE_ANY_ACCESS",
              "FILE_READ_ACCESS", "FILE_WRITE_ACCESS", "CONFIRMED", "INFERRED", "TODO"}


def priorart_tokens(target="", text=""):
    """이번 확정에서 **선행연구로 찾았어야 할 문자열**을 원장과 주장에서 유도한다.

    ★ 유도되지 않는 축은 요구하지 않는다. 만족 불가능한 게이트를 만들면 에이전트가
      `blocked` 로 도망가고 그게 더 나쁘다 — `_impact_gate` 가 owner='none' 을
      거부가 아니라 등급 상한으로 처리하는 것과 같은 이유다.
    """
    blob = " ".join([str(target or ""), str(text or ""),
                     " ".join(STATE.get("surface") or {})])
    out = {}
    dev = _DEV_RE.findall(blob)
    if dev:
        out["device"] = sorted(set(dev))[:4]
    codes = set(_IOCTL_CTX.findall(blob)) | set(_CODE_RE.findall(blob)) | set(code_index())
    # 표적 자체가 코드 하나를 가리키면 그것만 요구한다(전 표적의 코드를 다 요구하지 않는다)
    own = set(_IOCTL_CTX.findall(str(target or ""))) | set(_CODE_RE.findall(str(target or "")))
    if own:
        codes = own
    if codes:
        out["ioctl"] = sorted(codes)[:4]
    syms = [s for s in _SYMB_RE.findall(blob)
            if s not in _SYMB_STOP and not s.startswith("0x")]
    if syms:
        # 가장 긴 것 몇 개 — 짧은 약어보다 검색 가치가 있다
        out["symbol"] = sorted(set(syms), key=len, reverse=True)[:4]
    return out


def priorart_gaps(target="", text=""):
    """(축, 기대 토큰, 사유) 목록. 비어 있으면 확정해도 된다.

    ★ 왜 축이냐 — 예전 게이트는 `has_priorart()` 가 **비어 있지 않은가**만 봤다.
      `priorart(what='x', where='y', result='없음')` 한 줄로 열렸다는 뜻이다.
      프롬프트는 "최소한 (1) 디바이스 이름 (2) IOCTL 코드 (3) 핸들러/구조체 이름
      셋 다 찾아라"라고 적어놓고 **코드는 세지 않았다.**
      ksecdd 는 앵커 32건 기계검증 + 반박자 생존을 통과하고도 2024년 공개물이었고,
      그 IOCTL 에는 `IOCTL_KSEC_IPC_SET_FUNCTION_RETURN` 이라는 공개된 이름까지 있었다.
      ⇒ "찾았다고 적었나"가 아니라 **"이 문자열로 찾았나"** 를 본다.
    """
    recs = STATE.get("priorart") or []
    want = priorart_tokens(target, text)
    gaps = []
    for ax in PRIORART_AXES:
        toks = want.get(ax) or []
        if not toks:
            continue
        mine = [r for r in recs if (r.get("axis") or "").lower() == ax]
        if not mine:
            gaps.append((ax, toks, "이 축으로 검색한 기록이 없다"))
            continue
        blob = " ".join(" ".join(str(r.get(k) or "") for k in ("what", "where", "result"))
                        for r in mine).lower()
        if not any(t.lower() in blob for t in toks):
            gaps.append((ax, toks, "기록은 있는데 그 문자열이 안 보인다"))
    return gaps


def render_priorart_gaps(gaps):
    L = ["You have NOT SEARCHED FOR PRIOR ART on every axis this claim needs. "
         "Anchors and the refuter cannot catch a published finding — ksecdd passed both and was "
         "a 2024 public writeup with a documented IOCTL name."]
    for ax, toks, why in gaps:
        L.append("  · axis=%-6s %s — 검색했어야 할 문자열: %s"
                 % (ax, why, ", ".join(str(t) for t in toks[:4])))
    L.append("Record each with priorart(axis='device'|'ioctl'|'symbol', what=<the exact string "
             "you searched>, where=<source>, result=<what you found>). If an axis genuinely does "
             "not apply, file it with result='n/a: <why>' — that is an honest negative and it is "
             "recorded; silence is not.")
    return "\n".join(L)


def record_priorart(what, where, result, axis=""):
    """선행연구 조사 기록. 확정 게이트가 이걸 요구한다.

    왜: ksecdd.sys 확정이 앵커 32건 기계검증 + 반박자 생존을 통과했는데
    **2024년에 이미 공개된 것**이었다(KExecDD / SCRT). IOCTL 0x39006F 는
    `IOCTL_KSEC_IPC_SET_FUNCTION_RETURN` 이라는 이름까지 붙어 있었다.
    코드만 보는 게이트는 이걸 절대 못 잡는다 — 그래서 별도 기록을 요구한다.

    ★ `axis` 는 셋 중 하나여야 한다. 축 없는 기록은 게이트가 세지 않는다 —
      한 줄로 세 축을 다 덮었다고 주장하는 것을 막는 것이 이 필드의 존재 이유다.
    """
    ax = (axis or "").strip().lower()
    if ax and ax not in PRIORART_AXES:
        return ("axis 는 %s 중 하나여야 한다 (받은 값: %r)." % (" / ".join(PRIORART_AXES), axis))
    STATE.setdefault("priorart", []).append(
        {"what": what, "where": where, "result": result[:600], "axis": ax,
         "t": time.strftime("%m-%d %H:%M")})
    save()
    tail = ""
    if not ax:
        tail = ("\n⚠ axis 를 안 줬다 — 이 기록은 **확정 게이트에서 세지 않는다.** "
                "axis='device'|'ioctl'|'symbol' 로 다시 남겨라.")
    return ("선행연구 기록됨: %s (%s)%s\n%s" % (what, where, "" if not ax else " [axis=%s]" % ax,
                                            result[:200]) + tail)


def has_priorart():
    return list(STATE.get("priorart") or [])


# ── 범위 정책 (운영자가 정한다) ────────────────────────────────
# ★ 2026-09-02 사용자 결정: **"어드민 → 커널은 전부 의미 없으니 기각."**
#   MSRC 도 admin→kernel 을 보안 경계로 서비싱하지 않는다. 그런데 wcifs 확정 4건이 전부
#   거기 걸려 있었고, 하네스는 그걸 모른 채 계속 그 축에 시간을 썼다.
#   ⇒ **완전 기각은 하지 않는다** — 같은 싱크에 더 낮은 권한이 닿는 길이 남아 있을 수 있고,
#     그 길을 찾는 것이 이 축의 유일한 값이다(운영자 결정 2026-09-02).
#   ⇒ **확정으로만 올리지 않는다.** status=경계보류 로 살려두고 승격자에게 넘긴다.
# ★ 규칙은 **boundary 필드만** 본다. 그리고 admin 토큰이 화살표 **왼쪽**(출발지)에 있어야 한다.
#   1차 구현은 owner/principal 까지 이어붙여 훑었고, 우리 원장에서 **즉시 2건을 오탐**했다:
#     · S13-OP12-FLAGS3 — boundary 는 "컨테이너(서버 사일로) → 호스트 커널"인데
#       principal 문장이 "…BUILTIN\\Administrators or SYSTEM per the fltMgr default SD —
#       **including a container-local administrator, which is a different principal**" 라고
#       적고 있었다. 즉 **논증 안에서 admin 을 언급한 것**을 경계로 오독했다.
#     · S13-UAF-AVLNODE-V2 — boundary 헤드라인이 "**Unprivileged** file I/O → host kernel
#       memory corruption"이고, admin 은 "다만 내가 증명한 free 쪽은 특권이다"라는
#       **스스로 밝힌 한계** 문장에 있었다.
#   ⇒ 논증이 정교할수록 반대편 주체를 더 많이 언급한다. 넓은 시드는 **잘 쓴 행부터** 죽인다.
#     (`detector-seed-too-broad` 와 같은 계열)
_ARROW = re.compile(r'(→|->|=>|➜|\bto\b)')
_ADMIN = re.compile(r'BUILTIN\\Administrators|S-1-5-32-544|Administrators?\b|'
                    r'\bSYSTEM\b|elevated|관리자|어드민', re.I)
# 왼쪽에 이것들이 있으면 **출발지가 admin 이 아니다** — 정책 대상이 아니다.
_LOWER = re.compile(r'unprivileged|non-?admin|standard user|low(-| )?priv|AppContainer|sandbox|'
                    r'container|silo|anonymous|unauthenticated|remote|guest|비특권|표준 사용자|'
                    r'샌드박스|컨테이너|비인증', re.I)


# ─── 경계를 칸으로 (2026-09-10, 2순위) ────────────────────────────────────────
#   ★ 왜: `scope_verdict()` 는 `boundary` **산문**을 정규식으로 읽는다. 실측 — 전 표적
#     확정 16건 중 boundary 칸 자체가 있는 것이 6건이고, 그 6건에서 정책이 발동한 것은
#     **1건**이다(분석자가 우연히 "Administrators/SYSTEM -> kernel" 이라고 적은 행).
#     그리고 그 1건조차 원장에는 `확정` 으로 앉아 있다 — `경계보류` 사용 0건.
#     ⇒ 산문은 술어를 못 나른다 (memory `prose-cannot-carry-a-predicate`).
#
#   격자는 **호스트 기준 권한 순서**다. 컨테이너 관리자가 standard-user 와 같은 칸인 것은
#   실수가 아니다 — 호스트 커널 기준으로 둘 다 비특권이고, wcifs 확정 하나가 정확히
#   그 주장(Windows Server Container → host kernel)이다.
PRINCIPAL_LATTICE = {
    "remote-anonymous": 0, "remote-authenticated": 1,
    "appcontainer": 2, "low-il": 3,
    "standard-user": 4, "container-admin": 4,
    "admin": 5, "system": 6, "kernel": 7, "hypervisor": 8,
}
# 분석자가 확정을 낼 수 없다고 선언하는 값. 통과하되 **확정이 아니라 경계보류**로 간다.
PRINCIPAL_UNPROVEN = "unproven"


def boundary_typed(frm, to):
    """선언된 두 principal → (is_boundary, why). `is_boundary` 는 yes | no | unknown.

    정책 출처: MSRC servicing criteria + 운영자 결정(2026-09-02, admin→kernel 은 경계가
    아니다). **이건 그래프가 답하는 사실이 아니라 벤더의 정책이다** — 그래서 표로 둔다.
    """
    f, t = str(frm or "").strip().lower(), str(to or "").strip().lower()
    if f == PRINCIPAL_UNPROVEN or t == PRINCIPAL_UNPROVEN:
        return ("unknown", "출발지/도착지 중 하나가 unproven — 최소 principal 이 아직 안 섰다")
    if f not in PRINCIPAL_LATTICE or t not in PRINCIPAL_LATTICE:
        return ("unknown", "격자에 없는 principal (%s → %s)" % (frm, to))
    lf, lt = PRINCIPAL_LATTICE[f], PRINCIPAL_LATTICE[t]
    if lt <= lf:
        return ("no", "권한이 올라가지 않는다 (%s ≥ %s) — 승격이 아니다" % (f, t))
    if lf >= PRINCIPAL_LATTICE["admin"]:
        # admin→kernel · admin→system · system→kernel …
        return ("no", "admin 이상에서 출발한다 — MSRC servicing criteria 상 보안 경계가 "
                      "아니다(운영자 결정 2026-09-02). 같은 싱크에 더 낮은 principal 이 "
                      "닿는 길이 남아 있으면 그게 이 행의 값이다")
    return ("yes", "%s → %s 는 벤더가 인정하는 경계다" % (f, t))


def principal_evidence(target, frm, state=None):
    """선언한 출발 principal 을 **실측이 뒷받침하는가.** (verdict, note)

    ★ 1순위(T46)가 심은 `principal_grade` 를 여기서 처음 소비한다. 이게 이 두 단계를
      잇는 자리다 — 실측이 어느 토큰에서 났는지 모르면 "저권한이 도달한다"는 확정할 수 없다.
      실사례: ahcache `S9-D4`/`S10-VA1` 이 `boundary=standard-user → machine-wide integrity`
      로 확정돼 있는데, 저권한이 실제로 받는 것은 `PAGE_WRITECOPY` 뿐이다
      (memory `ahcache-authz-population-half`: "근거가 없다 — 등급 재검토 대상").
    """
    f = str(frm or "").strip().lower()
    if f not in PRINCIPAL_LATTICE:
        return ("n/a", "")
    grade, recs = measured_principal(target, state=state)
    if PRINCIPAL_LATTICE[f] >= PRINCIPAL_LATTICE["admin"]:
        return ("n/a", "출발지가 admin 이상이라 저권한 실측이 필요 없다")
    if grade == "none":
        return ("unmeasured", "이 표적에 실측 기록이 없다 — 출발 principal 은 정적 논증뿐이다")
    if grade == "verified_low":
        return ("verified", "비승격 토큰에서 난 실측이 뒷받침한다")
    if grade in ("verified_elevated", "verified_default"):
        return ("mismatch",
                "출발지를 %s 로 선언했는데 뒷받침 실측은 **승격된 토큰**에서 났다(%s). "
                "저권한이 같은 결과를 받는지는 아직 안 쟀다 — 등급 상한이 걸린다." % (f, grade))
    return ("unmeasured",
            "뒷받침 실측의 자격이 %s 다. 어느 토큰에서 났는지 원장에 없으므로 "
            "'%s 가 도달한다'를 실측이 뒷받침하지 못한다. "
            "ioctl(where='guest', principal='low') 로 다시 쏘면 하네스가 토큰을 검증한다."
            % (grade, f))


def scope_verdict(impact):
    """**경계가 범위 밖인가.** 반환 (label, why) 또는 (None, '').

    ★ 2026-09-02 운영자 결정 2단: "어드민 커널은 확정으로 **승격만** 하지 말자."
      완전 기각이 아니다 — 같은 싱크에 더 낮은 권한이 닿는 길이 남아 있을 수 있고,
      그 길을 찾는 것이 이 축의 유일한 값이다.
    """
    b = str((impact or {}).get("boundary") or "")
    if not b:
        return None, ""
    m = _ARROW.search(b)
    left = b[:m.start()] if m else b          # 화살표가 없으면 문장 전체를 출발지로 본다
    if not _ADMIN.search(left):
        return None, ""
    if _LOWER.search(left):
        # 출발지에 더 낮은 주체가 같이 적혀 있다 = 이 행은 admin 을 헤드라인으로 주장하지 않는다.
        return None, ""
    return ("admin→kernel",
            "admin->kernel is not a security boundary (MSRC servicing criteria; operator decision "
            "2026-09-02)")


_ADDRLIKE = re.compile(r'0x[0-9a-fA-F]{5,16}')


def claim_anchor_link(claim, anchors):
    """★ **주장이 이름 댄 주소가 앵커에 있는가.** (unlinked_addrs, note)

    왜: 우리 게이트는 전부 **외연적**이다 — "인용한 VA 에 그 명령이 있는가"만 본다.
    *그 명령이 주장을 뒷받침하는지는 아무도 안 본다.* 그래서 근거를 게이트 모양에 맞춰
    다시 만드는 것이 통한다(2026-09-02 회차: "게이트가 기계검증 앵커를 원한다. 그대로 다시 가져온다").
    문헌의 처방은 **동형 검증** — 문제를 변형해도 답이 유지되는지 본다 (`refs/00-gate-gaming.md`).
    바이너리 판정에서 그 대응물이 이것이다: **주장의 하중을 받는 주소가 검증된 앵커 집합에
    실제로 들어 있는가.** 없으면 그 주장은 그 앵커로 검증된 것이 아니다.

    주소형(≥5자리 hex)만 본다. 작은 상수까지 요구하면 검출기가 넓어져 게이트가 무력해진다.
    """
    have = set()
    for a in anchors or []:
        va = a.get("va")
        if isinstance(va, int):
            have.add(va)
        for m in _ADDRLIKE.finditer(str(a.get("insn") or "") + " " + str(a.get("actual") or "")):
            try:
                have.add(int(m.group(0), 16))
            except ValueError:
                pass
    want = set()
    for m in _ADDRLIKE.finditer(claim or ""):
        try:
            want.add(int(m.group(0), 16))
        except ValueError:
            pass
    unlinked = sorted(w for w in want if w not in have)
    if not unlinked:
        return [], ""
    return unlinked, (
        "The address %s named in the claim IS NOT AMONG THE VERIFIED ANCHORS.\nAnchor "
        "verification only asks 'does the cited instruction exist' - whether that instruction "
        "SUPPORTS THIS CLAIM is a separate question. Cite the address the claim's weight rests on "
        "so it gets machine-checked.\n(If an address appears only in the claim and not in the "
        "evidence, that is narration, not evidence.)")


def _images_for_anchor():
    """앵커 검증에 쓸 보조 이미지. **순환 임포트를 피하려 지연 임포트**한다.

    ★ 2026-09-02 버그: 크로스 이미지 배선 때 확정 경로(`agent_sdk._anchor_gate`)와 `anchor` 툴에는
      `images=` 를 넘겼는데 **기각 경로(`_reject_gate`)만 빠뜨렸다.** 그래서 같은 `nt!0x…` 인용이
      `anchor` 툴에서는 9/9 통과하는데 `verdict(action='reject')` 에서는 전부 실패했다
      — 에이전트가 회차 로그에 그대로 보고했다. 배선은 **모든 경로에 같이** 해야 한다.
    """
    try:
        import tools as _T
        return _T.images_all()
    except Exception:
        return {}


def has_xref(kind=None):
    for x in STATE.get("xrefs") or []:
        if kind is None or kind.lower() in (x.get("desc") or "").lower():
            return x
    return None


def control(kind, what, result):
    kind = (kind or "").lower()
    if kind not in ("positive", "negative", "swap"):
        return "kind 는 positive | negative | swap."
    STATE["controls"].setdefault(kind, []).append({"what": what, "result": result})
    save()
    return f"대조군 기록: {kind} — {what} → {result}"


# ── 게이트 반려 기록 (D형 접지: 하네스가 관측한 행위) ────────
# ★ 왜 (2026-09-05, 운영자 질문 "게이트가 실제로 도움이 되고 있는거야?"):
#   실측으로 **판정 툴 호출 3,506회 중 692회(20%)가 게이트에 반려됐는데 무엇을 막았는지가
#   어디에도 없다.** 반려 지점은 49곳(`_reject_gate` 21 · `_gate_verdict` 11 · `verdict()` 17)
#   인데 남는 것은 `gate_denials` 카운터 하나뿐이다. 사고기록은 `[tool ]`/`[think]` 만 찍고
#   툴 결과를 안 찍으므로 게이트 자기 문구("STALE-BUILD ANCHOR" 등)를 전수 grep 해도 0건이다
#   — 잡은 적이 없어서가 아니라 **기록이 없어서**다.
#
#   그 결과 적대층은 감사 가능한데(승격 6/8 · 심문 93/152 · 반박 8/13) 결정론층은 감사 불가능한
#   비대칭이 생겼고, 지난 며칠의 진단이 전부 적대자 쪽에서만 나온 이유가 이것이다.
#
# ★ 이 함수는 **아무것도 막지 않는다.** 관측만 한다. 한 회차 뒤에 `denial_report()` 로
#   "어느 규칙이 무엇을 몇 번 잡았나"가 표로 나오고, 그때 안 잡는 게이트를 데이터로 지운다.
#   memory `grounding-decides-gate` 가 "D형은 거의 안 쓰인다"고 적어둔 구멍이 여기다.
DENIAL_CAP = 400


def _rule_key(reason):
    """반려 문구의 앞머리를 규칙 식별자로 쓴다. 게이트 메시지는 고정 문자열이라 잘 뭉친다."""
    r = " ".join(str(reason or "").split())
    return r[:56] or "(사유 없음)"


def record_denial(target, reason, act="", klass="", rule=""):
    D = STATE.setdefault("denials", [])
    D.append({"t": time.strftime("%m-%d %H:%M"), "rule": (rule or _rule_key(reason))[:64],
              "target": str(target or "")[:100], "act": str(act or "")[:12],
              "klass": str(klass or "")[:24], "reason": " ".join(str(reason or "").split())[:200]})
    if len(D) > DENIAL_CAP:
        del D[:len(D) - DENIAL_CAP]
    return len(D)


def denial_report(limit=25):
    """규칙별 반려 횟수 — "이 게이트가 실제로 무엇을 잡는가" 의 유일한 1차 자료."""
    D = STATE.get("denials") or []
    if not D:
        return "반려 기록 없음 (아직 한 건도 안 막았거나 배선 전이다)"
    agg = {}
    for d in D:
        k = d.get("rule") or "(사유 없음)"
        a = agg.setdefault(k, {"n": 0, "acts": set(), "klasses": set(), "targets": set()})
        a["n"] += 1
        a["acts"].add(d.get("act") or "?")
        if d.get("klass"):
            a["klasses"].add(d["klass"])
        a["targets"].add(str(d.get("target"))[:40])
    out = ["반려 %d건 · 규칙 %d종 (표적 기준)" % (len(D), len(agg))]
    for k, a in sorted(agg.items(), key=lambda x: -x[1]["n"])[:limit]:
        out.append("  %3d× [%s] 표적 %d개 %s  %s"
                   % (a["n"], "/".join(sorted(a["acts"])), len(a["targets"]),
                      ("klass=" + ",".join(sorted(a["klasses"]))) if a["klasses"] else "", k))
    return "\n".join(out)


def control_overlap(text, kind="positive"):
    """청구의 앵커 주소와 대조 기록의 앵커 주소가 겹치는가. **A형 접지** — 양쪽 다 주소 집합이다.

    ★ 왜 (2026-09-05, C-029): R5 는 `klass='delta_zero'` 에 양성 대조를 요구하는데
      `has_control()` 이 **원장 전역**이라, 표적에 아무 대조나 하나 있으면 그 뒤 모든
      `delta_zero` 기각이 무료 통과했다. `ahcache.sys` 의 positive 15건은 전부 다른 것을
      잰 대조(게이트 도구 검증 · sink_gates 검출 · 레지스트리 프로브)였고, S46 이 주장한
      채널을 잰 것은 0건이었다. 08-30 이후 `delta_zero` 6건 중 5건이 그렇게 통과했다.

    ★ **막지 않는다.** 오늘의 결론이 "결정론 층에 억제 권한을 주지 마라"(refs/05)이므로
      여기서 그것을 뒤집지 않는다. 겹침을 **계산해서 붙이고** 승격자에게 넘긴다 —
      `delta_zero` 는 어차피 승격자가 blocking 으로 받는다.
    """
    want = set(x.lower() for x in re.findall(r'0x[0-9a-fA-F]{6,16}', str(text or "")))
    pool = STATE.get("controls", {}).get(kind) or []
    if not want:
        return {"verdict": "no_anchor_in_claim", "n_controls": len(pool), "shared": []}
    best, bestov = None, set()
    for c in pool:
        have = set(x.lower() for x in re.findall(r'0x[0-9a-fA-F]{6,16}',
                                                 json.dumps(c, ensure_ascii=False)))
        ov = want & have
        if len(ov) > len(bestov):
            best, bestov = c, ov
    return {"verdict": ("overlaps" if bestov else "no_overlap"),
            "n_controls": len(pool), "shared": sorted(bestov)[:8],
            "control": (str(best.get("what"))[:120] if best else "")}


def has_control(kind="positive"):
    return bool(STATE["controls"].get(kind))


# ── 5) 종료 검문 (task verification) ─────────────────────────
# ── 조사 트랙 ────────────────────────────────────────────────
# ★ 왜: 확정 3건(`S7-D4`/`S9-D4`/`S10-VA1`)은 **세 개의 결함이 아니라 한 결함의 세 단계**다.
#   그런데 원장은 셋을 따로 셌고, 어디에도 "이 조사가 몇 단계인가"가 없었다. 그래서 매 회차가
#   "표 479행 중 미분석 461" 을 보고 **어디부터 팔지 다시 정했다** — 6회차가 6단계를 간 게 아니라
#   각자 "1단계 수준의 일"을 여섯 번 했다. 사람은 이미 이걸 손으로 하고 있다
#   (`poc/*.criteria.md`, `RESUME.md`). 하네스가 그걸 못 읽을 뿐이었다.
DEFAULT_STAGES = ["정적확정", "트리거", "실측", "임팩트", "경계/제출"]


def track(name, stage=None, of=None, note="", evidence=None, target=None):
    """조사 트랙의 단계를 읽거나 올린다. 단계는 **되돌릴 수도 있다** — 반박당하면 내리는 게 정직하다."""
    T = STATE.setdefault("tracks", {})
    t = T.get(name)
    if t is None:
        t = {"stages": list(of or DEFAULT_STAGES), "stage": 0, "evidence": {},
             "note": "", "t": time.strftime("%m-%d %H:%M")}
        T[name] = t
    # ★ 2026-09-05: 트랙 레코드에 `target` 이 **아예 없었다**(필드 전수: stages/stage/
    #   evidence/note/t). 그래서 "이 트랙의 표적에 앵커 검증된 확정이 있나" 를 계산할 수
    #   없었고, `GOAL(track:X)` 의 X 는 지시대상 없는 자유 문자열이었다.
    if target:
        t["target"] = str(target)[:160]
    if of:
        t["stages"] = list(of)
    if stage is not None:
        t["stage"] = max(0, min(int(stage), len(t["stages"])))
    if note:
        t["note"] = note[:400]
    for e in (evidence or []):
        t["evidence"].setdefault(str(t["stage"]), []).append(str(e)[:60])
    t["t"] = time.strftime("%m-%d %H:%M")
    save()
    return t


def track_render(compact=False):
    T = STATE.get("tracks") or {}
    if not T:
        return ""
    L = []
    for n, t in T.items():
        st, names = t.get("stage", 0), t.get("stages") or DEFAULT_STAGES
        bar = " ".join(("[x]" if i < st else ("**[ ]←지금**" if i == st else "[ ]")) + nm
                       for i, nm in enumerate(names))
        L.append("- `%s`  %s" % (n, bar))
        if t.get("note") and not compact:
            L.append("    %s" % str(t["note"])[:160])
    return "\n".join(L)



# ── 원장이 못 담던 세 모양 (2026-09-14) ─────────────────────────────────────
# ★ 왜 추가하나. 09-14 야간런이 `reports/unrecordable/` 에 **다섯 건**을 쌓았고, 지휘자가
#   세 번 "필요한 칸"을 구체적으로 요청했다. 그중 하나는 그 밤의 **가장 강한 발견**이었다:
#     "FltCreateFileEx* 13호출부/11함수 중 인가 가드를 자기 본문에 가진 것은 1개뿐"
#   원장에는 행 모양이 둘뿐이다 — 「한 표적의 한 결함 주장」과 「채점된 관측 하나」.
#   그래서 ① 결함 주장이 아닌 **측정된 속성** ② 표적 이미지에 안 묶이는 **OS 경로 사실**
#   ③ 멤버와 쿼리를 함께 지닌 **인구** 가 전부 갈 곳이 없었다.
#   그런데 이 저장소의 규율은 *"실제 결함은 부재가 아니라 **덜 적용됨**이고 그건 인구로만
#   보인다"* 고 말한다. 도구가 방법론의 핵심 산출물을 표현하지 못하고 있었다.
#
# ★ 세 칸 모두 **판정이 아니다.** 확정/기각을 담지 못한다 — 승격은 여전히 `verdict()` 를
#   거치고 거기 붙은 게이트(basis·대조군·부채상한)를 그대로 받는다. 이 칸들은 **판정의
#   재료를 잃지 않게** 하는 것이지 게이트를 우회하는 뒷문이 아니다.

POP_MEMBER_STATES = ("미분석", "안전", "의심", "승격됨", "무효")


def population(name, query_a=None, set_a=None, query_b=None, set_b=None,
               differentiator=None, note="", member_state=None, target=None,
               invariant=None):
    """**인구 기록.** 집합 A, 집합 B, 그 **교집합은 하니스가 계산한다.**

    ★ 교집합을 호출자가 선언하게 두면 그건 자기신고다. 여기서는 A·B 를 받고 셈은 코드가 한다.
    ★ 멤버 기본 상태는 `미분석` 이고, 렌더링이 **미분석 수를 항상 같이 낸다** —
      부분 전수가 완전 전수로 읽히는 것이 이 방법론에서 가장 비싼 거짓말이기 때문이다.
    ★ 이 기록은 **판정이 아니다.** 멤버를 `승격됨` 으로 바꾸는 것은 `verdict()` 가 실제로
      등재된 뒤에만 의미가 있고, 그 게이트는 그대로 남는다.

    member_state: {"0x140057D00": "안전", ...} — 부분 갱신. 어휘 밖이면 거부한다.
    """
    P = STATE.setdefault("populations", {})
    r = P.get(name)
    if r is None:
        r = {"name": name, "query_a": "", "set_a": [], "query_b": "", "set_b": [],
             "differentiator": "", "note": "", "members": {}, "target": "",
             "invariant": "", "t": time.strftime("%m-%d %H:%M")}
        P[name] = r
    if target:
        r["target"] = str(target)[:160]
    if invariant:
        # ★ 2026-09-24 — patch-anchored census 마커. 이 필드가 있으면 이 인구는
        #   "벤더가 복원한 불변식 I 를 강제해야 할 모집단" 이고, 완결 주장(verdict completes=)
        #   은 `population_closure_status()` 게이트를 통과해야 한다(Move 2).
        r["invariant"] = str(invariant)[:400]
    if query_a:
        r["query_a"] = str(query_a)[:300]
    if query_b:
        r["query_b"] = str(query_b)[:300]
    if differentiator:
        r["differentiator"] = str(differentiator)[:400]
    if note:
        r["note"] = str(note)[:400]
    if set_a is not None:
        r["set_a"] = sorted({str(x).strip() for x in set_a if str(x).strip()})
    if set_b is not None:
        r["set_b"] = sorted({str(x).strip() for x in set_b if str(x).strip()})
    # ★ 교집합·차집합은 **코드가 센다.**
    A, B = set(r["set_a"]), set(r["set_b"])
    r["inter"] = sorted(A & B)
    r["only_a"] = sorted(A - B)
    for m in r["only_a"]:
        r["members"].setdefault(m, "미분석")
    bad = []
    for k, v in (member_state or {}).items():
        v = str(v)
        if v not in POP_MEMBER_STATES:
            bad.append("%s=%s" % (k, v)); continue
        r["members"][str(k).strip()] = v
    r["t"] = time.strftime("%m-%d %H:%M")
    save()
    if bad:
        r = dict(r); r["_rejected"] = bad
    return r


def population_render(name=None, compact=False):
    P = STATE.get("populations") or {}
    if not P:
        return ""
    L = []
    for n, r in P.items():
        if name and n != name:
            continue
        todo = sum(1 for v in r["members"].values() if v == "미분석")
        L.append("- 인구 `%s`  A=%d B=%d  **A∩B=%d**  A만=%d  (**미분석 %d**)"
                 % (n, len(r["set_a"]), len(r["set_b"]), len(r["inter"]),
                    len(r["only_a"]), todo))
        if r.get("differentiator") and not compact:
            L.append("    판별식: %s" % r["differentiator"][:200])
        if todo and not compact:
            L.append("    미분석 멤버: %s"
                     % ", ".join([m for m, v in r["members"].items() if v == "미분석"][:10]))
        if todo:
            L.append("    ★ **미분석이 %d 이므로 이 전수는 아직 닫히지 않았다.**" % todo)
        if r.get("invariant"):
            L.append("    ⚑ patch-anchored (RI: %s) — 완결 주장은 게이트 통과 필요"
                     % r["invariant"][:120])
    return "\n".join(L)


def population_closure_status(name):
    """**patch-anchored census 를 '완전 수정'으로 닫아도 되는가** (Move 2 게이트).

    반환 (ok, reason).
    · patch-anchored 가 아니면 → (True, "") — 이 게이트의 소관이 아니다.
    · 미분석 멤버가 남았으면 → (False, ...): 알려진 멤버조차 다 안 봤다.
    · closure_interrog 가 이 census 이름으로 **SUSTAINED** 되지 않았으면 → (False, ...):
      어젯밤 mrxsmb 실패의 진짜 원인은 미분석이 아니라 **set_b 열거 자체가 멤버를 놓친 것**
      이었고, 그걸 잡는 유일한 도구가 재-스윕 심문자다. 그래서 완결은 심문자 SUSTAINED 를
      요구한다 — 심문자가 BROKE 했거나(=열거 불완전) 아예 안 돌았으면 닫지 못한다.
    · 그 외 → (True, "").
    """
    P = STATE.get("populations") or {}
    r = P.get(name)
    if not r:
        return (False, "그런 인구가 없다: %s" % name)
    if not r.get("invariant"):
        return (True, "")  # patch-anchored 아님 — 소관 밖
    todo = [m for m, v in r.get("members", {}).items() if v == "미분석"]
    if todo:
        return (False, "미분석 %d 멤버 남음: %s" % (len(todo), ", ".join(todo[:12])))
    ci = (STATE.get("closure_interrogs") or {}).get("by_name") or {}
    res = ci.get(name)
    if res != "SUSTAINED":
        return (False, "closure_interrog 상태=%s — patch-anchored census 는 심문자가 "
                       "SUSTAINED 해야만 완결로 닫힌다(set 열거 불완전이 미분석으로는 안 잡힌다). "
                       "닫는 서술로 심문자를 돌리고(name='%s'), 깨지면 놓친 멤버를 set_b 에 넣어라."
                       % (res or "미실행", name))
    return (True, "")


def posture(subject, prop, value, derivation, body_read=False, anchors=None,
            note="", target=None):
    """**측정된 속성.** 결함 주장이 아니다 — 그래서 `verdict()` 의 어휘로는 담을 수 없었다.

    ★ 09-14 사고: IOCTL 두 팔의 access mask 를 **완전히 측정**하고도 칸이 없어
      `blocked`("못 정했다")로 밀려났다. 참인 측정이 실패로 기록되는 건 분모를 거짓으로 만든다.
    ★ `body_read=False` 를 **보존한다** — "자세는 쟀지만 본문은 안 읽었다"가 이 기록의 내용이고,
      그걸 지우면 나중에 이 행이 도달성 주장으로 승격될 때 근거가 부풀려진다.
    """
    R = STATE.setdefault("postures", [])
    rec = {"target": str(target or STATE.get("target") or "?")[:160],
           "subject": str(subject)[:200], "prop": str(prop)[:120],
           "value": str(value)[:200], "derivation": str(derivation)[:300],
           "body_read": bool(body_read), "anchors": sorted(set(_vas(
               "%s %s %s" % (subject, value, " ".join(anchors or [])))))[:12],
           "note": str(note)[:300], "t": time.strftime("%m-%d %H:%M")}
    R.append(rec)
    save()
    return rec


_OSFACT_PATH = [None]


def _osfact_file():
    if _OSFACT_PATH[0]:
        return _OSFACT_PATH[0]
    base = os.path.dirname(_PATH[0]) if _PATH[0] else "state"
    _OSFACT_PATH[0] = os.path.join(base or "state", "_osfacts.json")
    return _OSFACT_PATH[0]


def os_fact(routine=None, arm=None, validated=None, omitted=None, anchors=None,
            applies_to=None, image="", build="", note=""):
    """**표적 이미지에 안 묶이는 OS 경로 사실.** 읽기만 하려면 인자 없이 부른다.

    ★ 09-14 사고: `nt!NtSetEaFile` 의 BUFFERED/DIRECT 팔 비대칭을 측정했는데, 원장의 모든
      행이 `target` 한 이미지에 묶여 있어 갈 곳이 없었다. cldflt 밑에 넣으면 표적 이탈이고
      ntoskrnl 밑에 넣으면 cldflt 작업 중엔 아무도 안 본다 ⇒ **표적마다 재도출된다.**
      (실측으로 그랬다: 같은 밤에 fltmgr 사실을 bfs·cldflt 회차에 걸쳐 두 번 재도출했다.)
    ⇒ 그래서 **공유 파일**에 둔다. 어느 표적에서 attach 하든 같은 것을 본다.
    """
    f = _osfact_file()
    try:
        with open(f, encoding="utf-8") as fh:
            D = json.load(fh)
    except (OSError, ValueError):
        D = {"facts": []}
    if routine:
        # ★ 같은 routine 은 **갈아끼운다.** 09-14 실측: 야간런이 "팔 둘"로 적은 것을
        #   감시자가 "셋"으로 재도출했는데, append 만 하면 **낡은 버전이 같이 읽힌다** —
        #   공유 사실이 두 값을 동시에 주장하면 재도출 금지의 의미가 없어진다.
        D["facts"] = [x for x in D["facts"] if x.get("routine") != str(routine)[:200]]
        D["facts"].append({
            "routine": str(routine)[:200], "arm": str(arm or "")[:200],
            "validated": str(validated or "")[:300], "omitted": str(omitted or "")[:300],
            "anchors": sorted(set(_vas("%s %s %s %s" % (routine, arm, validated,
                                                        " ".join(anchors or [])))))[:12],
            "applies_to": str(applies_to or "")[:300],
            "image": str(image)[:80], "build": str(build)[:80],
            "note": str(note)[:300], "t": time.strftime("%m-%d %H:%M")})
        try:
            tmp = f + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(D, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, f)
        except OSError:
            pass
    return D["facts"]


def osfact_render(n=6, compact=False):
    try:
        facts = os_fact()
    except Exception:
        return ""
    if not facts:
        return ""
    L = ["**OS 경로 사실 (표적 무관 · 공유)** — 재도출 금지:"]
    for r in facts[-int(n):]:
        _ib = (" [%s %s]" % (r.get("image"), r.get("build"))).replace(" ]", "]") \
            if r.get("image") else ""
        L.append("- `%s` %s%s" % (r.get("routine"), r.get("arm") or "", _ib))
        if not compact:
            if r.get("validated"):
                L.append("    검증함: %s" % str(r["validated"])[:180])
            if r.get("omitted"):
                L.append("    **생략함: %s**" % str(r["omitted"])[:180])
            if r.get("applies_to"):
                L.append("    적용 대상: %s" % str(r["applies_to"])[:180])
    return "\n".join(L)

def seed_goal(text, kind="judge", by="operator"):
    """**운영자가 박는 목표.** 에이전트는 이걸 덮어쓸 수 없다.

    ★ 2026-09-02 사고: 목표를 에이전트가 선언하게 했더니 `kind='measure'` 목표를 등록한 뒤
      같은 회차에서 `kind='judge'` 로 **덮어쓰고** 판정 1건으로 종료 조건을 만족시켰다.
      실측은 0건이었다 — 시킨 일이 그거였는데. 자기 시험 문제를 자기가 내는 구조였다.
    ⇒ 목표는 운영자가 박는다. **다만 달성 후 자율 헌팅은 막지 않는다** — 게이트는 미달일 때만 운다.
    """
    STATE["goal"] = {"text": (text or "")[:400], "kind": kind, "by": by,
                     "at": {"verdicts": len(STATE.get("verdicts") or []),
                            "measures": len(STATE.get("measures") or []),
                            "tracks": {n: t.get("stage", 0)
                                       for n, t in (STATE.get("tracks") or {}).items()}},
                     "t": time.strftime("%m-%d %H:%M")}
    # ★ 2026-09-05 — **집행 불가능한 목표를 조용히 넘기지 않는다.**
    #   `judge`/`both` 목표의 축 검사는 목표문에서 VA 를 뽑아낼 때만 작동한다(_goal_unmet).
    #   실측: 내가 쓴 목표문이 `+0x56`/`+0x57`(필드 오프셋)만 담고 **완전한 VA 가 없어서**
    #   검사가 no-op 이 됐고, 회차는 그 축을 한 건도 안 건드린 채 13건으로 통과했다.
    #   게이트가 안 도는 것보다 나쁜 건 **안 도는 줄 모르는 것**이다. 설치 시점에 말한다.
    STATE["goal"]["enforceable"] = bool(
        kind.startswith("track:") or re.search(r'0x1[0-9a-fA-F]{6,15}', text or ""))
    # ★ 2026-09-05 — **목표가 결론을 처방하지 않는가.** (C-030 원인2)
    #   실측: 내가 쓴 목표가 "막고 있는 것은 **하나뿐이다** … 아니면 `delta_zero` 로 닫아라"
    #   였고, 분석가는 그대로 실행했다 ("I could not name it. Closed delta_zero.").
    #   그건 승격자 맨데이트("델타 0을 종착지로 받지 않는다")와 **정면 모순**인데, 그날
    #   승격자가 꺼져 있어 중재할 것이 없었다. 같은 자리에서 사람이 던진 **열린 질문**
    #   ("진짜 0이 맞아?")은 재도출을 강제해 신규 후보를 냈다.
    #
    #   ★ 거부하지 않는다 — 목표는 운영자의 것이고 알고도 쓸 수 있어야 한다. 다만
    #     **목표는 이 판에서 유일하게 어떤 적대자도 검사하지 않는 입력**이라(게이트는 거절이
    #     로그에 남지만 목표는 탐색 공간을 소리 없이 자른다) 설치 시점에 소리를 낸다.
    _t = text or ""
    _bad = []
    for _k in _REJECT_KLASS:
        if _k in _t:
            _bad.append("종착 klass `%s` 를 목표가 지정한다 — 분석가에게 출구를 주는 것이다" % _k)
            break
    if re.search(r'하나뿐|뿐이다|only one blocker|the only thing blocking', _t, re.I):
        _bad.append("단일 블로커 단정('하나뿐') — 다른 채널을 안 보게 만든다. "
                    "S46 이 정확히 이렇게 죽었다")
    if re.search(r'아니면\s*[`\'"]?\w+[`\'"]?\s*(으로|로)\s*닫|or close|otherwise close', _t, re.I):
        _bad.append("'못 하면 …로 닫아라' 형태 — 종료를 허가한다. 질문만 써라")
    STATE["goal"]["prescriptive"] = _bad
    save()
    if _bad:
        return dict(STATE["goal"], _warn=(
            "⚠ 이 목표는 **결론을 처방한다**. 분석가는 그 출구로 나간다(2026-09-05 실측: S46).\n"
            + "\n".join("  · " + b for b in _bad)
            + "\n  고치려면: 목표에는 **질문만** 쓴다. 열린 질문은 재도출을 강제하고, "
              "닫힌 처방은 종료를 허가한다."))
    if not STATE["goal"]["enforceable"]:
        return dict(STATE["goal"], _warn=(
            "⚠ 이 목표는 **집행되지 않는다**. kind='%s' 의 축 검사는 목표문에 **완전한 VA**"
            "(0x1........)가 있을 때만 작동하는데 하나도 없다. 지금 상태로는 '판정이 하나라도 "
            "늘었나'만 본다 — 전혀 다른 축의 판정으로도 닫힌다(2026-09-05 실측).\n"
            "  고치려면: 목표문에 그 축의 앵커를 하나 넣거나, kind='track:<이름>' 을 써라." % kind))
    return STATE["goal"]


def set_goal(text, kind="judge"):
    """이 회차의 **목표 한 줄**. 종료 게이트가 이걸 본다.

    ★ 2026-09-02 사고: cap 120분 회차가 **19분에 정상 종료**했다. 한도도 오류도 아니었고,
      처리율이 이미 100%(표 467행이 거의 전부 '사유 붙은 blocked')라 종료 게이트가 통과시켰다.
      시드가 시킨 과제(RW 뷰 실측)는 **어떤 게이트도 검사하지 않으니** 에이전트에게는 선택
      사항이었고, 표 정리가 종료로 가는 최단 경로였다. 판정률은 1% 였다.
      ⇒ 회차 목표를 게이트가 알아야 한다.
    kind: judge(판정 1건 이상) · measure(실측 1건 이상) · both
    """
    cur = STATE.get("goal") or {}
    if cur.get("by") == "operator":
        _u = _goal_unmet()
        return ("This session's goal was SET BY THE OPERATOR and cannot be changed.\n  goal[%s]: "
                "%s\n%s\nPursuing another axis AFTER you have met the goal is not blocked - it is "
                "encouraged. But you cannot REPLACE the goal. Mark anything you stumble into with "
                "`surface(action='incidental', found_while=...)`."
                % (cur.get("kind"), str(cur.get("text"))[:200],
                   ("  now: " + _u.splitlines()[0]) if _u
                   else "  now: MET — you are free from here"))
    if not (text or "").strip():
        return "`goal` requires text=. An empty goal makes the finish gate meaningless."
    # ★ 2026-09-04 밤: 에이전트가 지휘자 목표를 **"한 일의 요약"으로 덮어썼다.**
    #   (`SESSION GOAL, restated to what was actually achieved…`)
    #   종료 게이트는 안 뚫렸다 — `at` 이 현재 카운트로 재설정돼 델타 요구가 살아 있었다.
    #   하지만 **지휘자가 내린 지시가 기록에서 사라진다.** 다음 회차 digest 는 지시가 있어야 할
    #   자리에서 완료 보고를 읽게 된다. 정책은 안 바꾼다(지휘자 목표는 설계상 교체 가능) —
    #   대신 **덮인 목표를 보존**해서 무엇이 무엇으로 바뀌었는지 감사 가능하게 한다.
    _old = STATE.get("goal")
    if _old and (_old.get("text") or "") != (text or ""):
        STATE.setdefault("goal_history", []).append(
            {"replaced_at": time.strftime("%m-%d %H:%M"), "by_new": "agent",
             "was_by": _old.get("by"), "was_kind": _old.get("kind"),
             "was_text": str(_old.get("text"))[:400], "now_text": (text or "")[:400]})
        STATE["goal_history"] = STATE["goal_history"][-10:]
    STATE["goal"] = {"text": (text or "")[:400], "kind": kind, "by": "agent",
                     "at": {"verdicts": len(STATE.get("verdicts") or []),
                            "measures": len(STATE.get("measures") or [])},
                     "t": time.strftime("%m-%d %H:%M")}
    save()
    return ("Session goal registered (kind=%s): %s\nThe finish gate checks this - tidying the "
            "table alone will not end the session." % (kind, text[:200]))


def _goal_unmet():
    g = STATE.get("goal")
    if not g:
        return None
    at = g.get("at") or {}
    dv = len(STATE.get("verdicts") or []) - (at.get("verdicts") or 0)
    dm = len(STATE.get("measures") or []) - (at.get("measures") or 0)
    kind = g.get("kind") or "judge"
    need = []
    if kind.startswith("track:"):
        # ★ 목표가 "트랙 X 를 한 단계 올려라" 일 때. 판정 수가 아니라 **진도**를 본다.
        nm = kind.split(":", 1)[1].strip()
        tr = (STATE.get("tracks") or {}).get(nm) or {}
        cur = tr.get("stage", 0)
        was = (at.get("tracks") or {}).get(nm, 0)
        if cur <= was:
            names = tr.get("stages") or DEFAULT_STAGES
            need.append("track `%s` stage unchanged (%d/%d — next is %s)"
                        % (nm, was, len(names), names[was] if was < len(names) else "done"))
    if kind in ("judge", "both") and dv <= 0:
        need.append("zero verdicts")
    # ★ 2026-09-05 — **`judge` 목표는 축을 안 본다.** `track:` 목표는 그 트랙의 단계 이동을
    #   요구하는데, `judge` 는 `dv > 0`(판정이 하나라도 늘었나)만 본다. 그래서 특정 축을
    #   지목한 judge 목표를 **전혀 다른 축의 판정 10건으로** 만족시킬 수 있다.
    #   실측 2026-09-05: ahcache(kind=track:) 회차는 게이트가 4번 막아 목표를 답하게 했고
    #   (`gate_denials: 4`), 같은 밤 msquic(kind=judge) 회차는 CidLen 캡 축을 **한 건도**
    #   건드리지 않고 다른 축 10건으로 통과했다(`gate_denials: 0`).
    #   ⇒ 목표문이 **주소를 지목하면** 그 주소가 이번 회차 판정에 인용됐는지 본다.
    #     접지는 A형이다(앵커는 재표현을 견디는 유일한 키 — 이 저장소의 기존 원칙).
    #     주소가 없는 목표문이면 아무것도 요구하지 않는다(억지 게이트를 만들지 않는다).
    if kind in ("judge", "both", "measure") and dv > 0:
        _gvas = set(re.findall(r'0x1[0-9a-fA-F]{6,15}', str(g.get("text") or "")))
        if _gvas:
            _new = (STATE.get("verdicts") or [])[(at.get("verdicts") or 0):]
            _blob = json.dumps(_new, ensure_ascii=False).lower()
            if not any(v.lower() in _blob for v in _gvas):
                need.append(
                    "the goal names %d address(es) and NONE of them appears in this session's "
                    "%d verdict(s): %s" % (len(_gvas), dv, ", ".join(sorted(_gvas)[:6]))
                    + "\n  Filing verdicts on a DIFFERENT axis does not close this goal. If the "
                      "goal's axis is wrong or already settled, say so with "
                      "verdict(action='gate_blocked', gate='goal', why=...) or close it with an "
                      "explicit reject/exhaust that CITES one of those addresses - either is "
                      "accepted. Silently working elsewhere is not.")
    if kind in ("measure", "both") and dm <= 0:
        need.append("zero measurements")
    if not need:
        return None
    return ("This session's goal is not closed: %s\n  goal: %s\n  this session's delta - verdicts "
            "%+d, measurements %+d (%s)\nTidying the table and closing the goal are different "
            "things. A high processed rate may be WHAT EARLIER SESSIONS LEFT BEHIND, not this "
            "session's work." % ("; ".join(need), str(g.get("text"))[:200],
                                 dv, dm, ", ".join(need)))


def session_products():
    """★ **이번 회차가 만든 산출물.** 종료 조건의 정의다.

    산출물 = **적대자가 승복한 판정**. 두 형태뿐이고 둘 다 대등하다:
      · 확정인데 반박자가 **못 죽였다**            → 결함 후보
      · 기각인데 심문자가 **못 깼다**              → 검증된 음성

    왜 이게 종료 조건인가 (2026-09-05 재설계):
      옛 `can_finish` 의 요구 8개는 전부 정리(커버리지·처리율·reach·race·열린질문)였다.
      즉 "표를 정돈했나"를 물었지 "무엇을 만들었나"를 묻지 않았다. 그래서 확정은
      비싼 선택이고 기각은 싼 의무가 됐다 — 실측 9시간에 reject 170 : distinct confirm 1.
      종료를 **산출물**에 걸면 확정이 정상 종료 경로가 되고, 기각은 목적지가 아니라
      중간 상태가 된다. 깨끗한 표적이면 **심문자가 승복한 기각**이 정상 종료다.

    ★ 소진(exhaust)은 여기 안 들어간다. 못 정한 것은 끝난 것이 아니다 —
      그 경우 회차는 예산 한도로 잘리고 미완으로 기록되면 된다. 게이트가
      **우아한 값싼 출구**를 줄 이유가 없다(그게 옛 '표 정리 후 조기 종료'였다).

    반환: (산출물 리스트, 이번 회차 판정 수)
    """
    V = STATE.get("verdicts") or []
    base = int(_RUN.get("verdicts0") or 0)
    mine = V[base:]
    out = []
    for v in mine:
        st = v.get("status")
        if st == "확정" and not (v.get("refute") or {}).get("refuted", False):
            out.append(("확정", v.get("id"), "반박자를 통과했다"))
        elif st == "기각" and v.get("interrogated") is True:
            _ig = v.get("interrogation") or {}
            if not _ig.get("broke"):
                out.append(("검증된 음성", v.get("id"), "심문자가 못 깼다"))
    return out, len(mine)


def unsettled_axes():
    """이번 회차가 **열어놓고 안 닫은 축** 중 열린 질문이 하나도 없는 것.

    ★ 왜 (2026-09-05, ablation 실측):
      같은 조건의 두 팔이 갈렸다. `armC` 는 목표 축을 못 닫았지만 **열린 질문 3개**를 남겼고
      (`SdbpResolveMatchingFile → AslPathToNetworkPathNt → …` 등 사슬 전체가 주소째로),
      `armA` 는 같은 축을 `impact_unproven` 으로 남기고 **노트 0 · 질문 0** 으로 끝냈다.
      즉 armA 는 "다음 세션에 넘겼다"가 아니라 **넘길 손잡이를 안 만들었다.**

    ★ 이건 "목표 축을 파라"는 처방이 **아니다.** 어느 축을 파든 상관없다 —
      **연 것을 열린 채로 적어라**만 요구한다. 목표 축 강제는 `reports/corrections.md`
      C-030/C-032 가 결함으로 기록한 바로 그 처방이므로 쓰지 않는다.

    ★ 접지: 판정의 앵커 주소 ∩ 열린 질문의 앵커 주소 (A형). 다만 **요구 자체는 절차 강제**다
      — 질문을 쓴다고 그 축이 실제로 열려 있음이 증명되지는 않는다(memory `grounding-decides-gate`).

    반환: [(판정 id, 그 축의 앵커 표본)] — 비어 있으면 통과.
    """
    V = STATE.get("verdicts") or []
    base = int(_RUN.get("verdicts0") or 0)
    try:
        prod = {p[1] for p in (session_products()[0] or [])}
    except Exception:
        prod = set()
    # ★ 손잡이로 인정하는 것 둘 (실측 근거):
    #   (a) 열린 질문 — armC 의 RQ120~122 가 그것이고, **하네스가 자동 생성했다**
    #       ("반박자가 죽인 확정 …" + `method`). 즉 확정을 시도했다가 죽으면 공짜로 생긴다.
    #   (b) 사유가 붙은 BLOCKED 표면 행 — C-034 가 보인 대로 그 사유란에 다음 한 걸음이 있다.
    #   분석가가 직접 만들 수 있는 것은 (b) 이고(`verdict(action='blocked', reason=…)`),
    #   (a) 는 확정을 밀다가 지면 따라온다. 둘 다 "다음 회차가 집을 것"이라 대등하게 센다.
    _a0 = _RUN.get("asks0") or set()
    _s0 = _RUN.get("surface0") or set()
    ask_va = set()
    for a in STATE.get("asks") or []:
        if a.get("status") == "open" and str(a.get("id")) not in _a0:
            ask_va |= set(x.lower() for x in re.findall(
                r'0x[0-9a-fA-F]{6,16}', json.dumps(a, ensure_ascii=False)))
    for k, sv in (STATE.get("surface") or {}).items():
        if k in _s0:
            continue
        if str(sv.get("why", "")).startswith("BLOCKED"):
            ask_va |= set(x.lower() for x in re.findall(
                r'0x[0-9a-fA-F]{6,16}', k + " " + str(sv.get("why", "")) + " " + str(sv.get("reach_why", ""))))
    out = []
    for v in V[base:]:
        if v.get("id") in prod:
            continue                      # 산물 = 적대자가 승복함 = 닫힌 것
        blob = " ".join(str(v.get(k) or "") for k in ("evidence", "target", "claim"))
        va = set(x.lower() for x in re.findall(r'0x[0-9a-fA-F]{6,16}', blob))
        if not va:
            continue                      # 앵커가 없으면 축을 특정할 수 없다 — 다른 게이트의 일
        if not (va & ask_va):
            out.append((v.get("id"), sorted(va)[:6]))
    return out


def can_finish():
    """끝내도 되는가. 안 되면 사유 목록. '조용한 성공'을 막는 게이트."""
    bad = []
    # ★ 2026-09-05 — 종료 조건이 **정리에서 산출물로** 바뀌었다. 자세한 근거는 session_products().
    if getattr(config, "FINISH_ON_PRODUCT", True):
        _prod, _n = session_products()
        if not _prod:
            _conf = sum(1 for v in (STATE.get("verdicts") or [])[int(_RUN.get("verdicts0") or 0):]
                        if v.get("status") == "확정")
            _rej = sum(1 for v in (STATE.get("verdicts") or [])[int(_RUN.get("verdicts0") or 0):]
                       if v.get("status") == "기각")
            bad.append(
                "NOTHING SURVIVED AN ADVERSARY THIS SESSION. The session ends on a PRODUCT, "
                "not on a tidy table.\n"
                "  A product is one of exactly two things, and they count equally:\n"
                "    · a CONFIRMATION the refuter could not kill\n"
                "    · a REJECTION the interrogator could not break  (a verified negative)\n"
                "  This session: %d verdicts (%d confirm / %d reject), 0 of them adversary-tested "
                "and surviving.\n"
                "  Filing more rejections does not end the session. Take ONE thing all the way: "
                "either confirm it and let the refuter try to kill it, or reject it and let the "
                "interrogator try to break it. Bring the evidence that beats them.\n"
                "  METHOD EXHAUSTED IS NOT AN ENDING — an unsettled row is not a product." 
                % (_n, _conf, _rej))
    # ★ 2026-09-05 — **연 것을 열린 채로 적어라.** 산물로 닫지 못한 축에 열린 질문이
    #   하나도 없으면 그 축은 조용히 버려진다(실측: armA — 목표 축을 impact_unproven 으로
    #   남기고 노트 0·질문 0 으로 종료). 어느 축을 파라고 지시하지 않는다 — 다만 다음
    #   회차가 집을 손잡이를 만들게 한다. → unsettled_axes() 독스트링
    if getattr(config, "FINISH_ON_PRODUCT", True):
        _un = unsettled_axes()
        if _un:
            bad.append(
                "YOU OPENED AXES AND LEFT NO HANDLE ON THEM. %d verdict(s) this session were not "
                "settled by an adversary, and NO OPEN QUESTION cites their anchors — so the next "
                "session inherits a dead end, not a next step.\n"
                % len(_un)
                + "\n".join("  · %s  (anchors %s)" % (i, ", ".join(a)) for i, a in _un[:6])
                + "\n  Two ways to leave a handle, both cheap:\n"
                  "    · `verdict(action='blocked', target='<the row>', reason='<why you could "
                  "not settle it>', next='<the ONE next step, >=40 chars, naming a VA or symbol>')` "
                  "— the row stays UNAUDITED, not a fake negative, and `next=` is the field the NEXT "
                  "session's work list reads. Prose in reason= is NOT machine-selectable: measured, "
                  "56%% of blocked rows match any prose predicate for 'has a next step'.\n"
                  "    · push it to `confirm`: if the refuter kills it, the harness files the open "
                  "question FOR you, with the method that would settle it.\n"
                  "  This is NOT a request to work the axis, and NOT a request to work any "
                  "particular axis — only to write down what is left.")
    _gu = _goal_unmet()
    if _gu:
        bad.append(_gu)
    # ★ 2026-09-05 — 아래 정리(housekeeping) 항목들은 **차단이 아니라 자문**으로 내린다.
    #   근거: 옛 요구 8개가 전부 정리라 "표를 정돈했나"만 물었고, 그래서 확정이 선택이 됐다.
    #   값은 여전히 계산·보고한다 — 소비자는 분석가가 아니라 **지휘자**다(다음 목표를 정한다).
    #   FINISH_ON_PRODUCT 가 꺼져 있으면 옛 동작(전부 차단) 그대로다.
    _adv = [] if getattr(config, "FINISH_ON_PRODUCT", True) else bad
    pct, done, tot = coverage()
    spct, sdone, _ = settled()
    if not tot:
        bad.append("The enumeration table is EMPTY — register the ingress first with "
                   "surface(action='add'). A conclusion drawn without the table has false "
                   "coverage.")
    elif spct < config.MIN_COVERAGE:
        _adv.append(f"Processed rate {spct*100:.0f}% < floor {config.MIN_COVERAGE*100:.0f}% "
                   f"(adjudicated {done} + blocked-with-reason {sdone-done} / {tot} total). "
                   f"Adjudicate the remaining {tot-sdone}, or use "
                   f"verdict(action='blocked', reason=...) to state WHY YOU CANNOT. "
                   f"Unaudited rows with no reason make coverage a lie.")
    elif config.MIN_ADJUDICATED and pct < config.MIN_ADJUDICATED:
        _adv.append(f"Adjudication rate {pct*100:.0f}% < floor "
                   f"{config.MIN_ADJUDICATED*100:.0f}%. "
                   f"[verified negatives {verified_negatives()[1]}/{verified_negatives()[2]}] "
                   f"Those {sdone-done} blocked rows are HONEST UNAUDITED WORK, NOT AN "
                   f"ACHIEVEMENT — adjudicate more of the ones your tools can actually settle.")
    _cc = code_coverage()
    if _cc[0] is not None and _cc[0] < 0.25:
        _adv.append("ACTUAL CODE COVERAGE is %d/%d = %.0f%%. `coverage()` is a ratio over the "
                   "surfaces YOU wrote down, so it measures 'did you tidy your list', not 'how "
                   "much did you audit'. Enumerate entry points and never look past them and "
                   "you get a high adjudication rate on rock-bottom coverage."
                   % (_cc[1], _cc[2], _cc[0] * 100))
    _den, _ko, _unk, _c = reach_breakdown()
    if _unk:
        _adv.append("%d surfaces still have reach=`unknown` — THE DENOMINATOR IS FALSE. "
                   "Settle each as user-direct / user-triggerable-async / kernel-only. "
                   "(kernel-only drops out of the denominator but STAYS IN THE TABLE — it is a "
                   "candidate race partner.)" % _unk)
    if not races():
        _adv.append("There are ZERO race entries. If your surface unit is a single request, "
                   "races never even get registered — `coverage()` at 100%% still says nothing "
                   "about concurrency. Enumerate asynchronous entry points with `async_entry` "
                   "(cancel, completion, work item, DPC, timer, PnP), then register the pairs "
                   "that touch shared state via `surface(action='race', ...)` — or state "
                   "explicitly that RACES WERE NOT INVESTIGATED.")
    _open = asks("open")
    if _open:
        _adv.append("%d open questions remain — THESE ARE NOT NEGATIVES, THEY ARE UNAUDITED. "
                   "Run each one's `method` and answer it, or if there is genuinely no method "
                   "left, declare METHOD EXHAUSTED with "
                   "`verdict(action='exhaust', target=..., reason=...)` (do NOT file it as a "
                   "rejection). Targets: %s"
                   % (len(_open), ", ".join(q["target"] for q in _open[:6])))
    if not STATE["verdicts"] and not STATE["candidates"]:
        bad.append("Zero verdicts. Even with no confirmations, YOU MUST LEAVE REJECTIONS AND "
                   "BLOCKED ROWS for coverage to mean anything.")
    weak = [v["id"] for v in STATE["verdicts"]
            if v["status"] in ("확정", "경계보류") and not v.get("anchors")]
    if weak:
        bad.append(f"Confirmations whose anchors were never machine-verified: "
                   f"{', '.join(weak)}. A confirmation without citations is INFERRED.")
    # ★ 2026-09-05 — 자문 항목은 **분석가를 막지 않고 지휘자에게 간다.**
    #   분석가를 정리 노동으로 모는 것이 옛 구조의 병목이었다. 값은 계속 계산하되
    #   소비자를 바꾼다: 커버리지·reach·race·열린질문은 **다음 목표를 정하는 재료**다.
    if getattr(config, "FINISH_ON_PRODUCT", True):
        STATE["housekeeping"] = _adv
        save()
    return bad


# ── 6) 상태 블록 ──────────────────────────────────────────────
# ── status_block 델타 ────────────────────────────────────────
# ★ 왜: 이 블록은 툴 4회마다 + 모든 verdict 뒤에 `additionalContext` 로 주입된다.
#   API 는 무상태라 한 번 들어간 것은 **그 뒤 모든 턴의 요청에 다시 실린다.**
#   실측(09-04 wcifs, 165턴): 블록 1332자 × 약 45회 주입 × 평균 잔여 82턴
#   ≈ 220만 토큰 재읽기. 그 회차의 cache_read 28.4M 중 약 8%.
#   그런데 그 1332자의 대부분(미분석 목록·묘지)은 **회차 내내 거의 안 변한다.**
#
# ★★ 단, 접으면 안 되는 것이 있다. **"무엇을 이미 해봤는가"** 다.
#   그게 사라지면 다음 턴의 분석가가 같은 방법을 다시 쓴다 — 원장이 `attempts` 를
#   세는 이유가 통째로 무의미해진다. 실측으로 같은 질문에 4~5회 부딪힌 것이
#   ahcache 6건 · wcifs 8건이고, 판결자를 만든 이유가 그 루프다.
#   ⇒ 변동 없는 큰 덩어리는 접고, **시도 이력은 항상 싣는다.** 순증이 아니라 교환이다.
_SB = {"digest": None}


def status_reset(why=""):
    """델타 캐시를 비운다 — 다음 블록은 **전문**이 나간다.

    ★ 압축(PreCompact) 직후에는 반드시 불러야 한다. 모델이 앞 블록을 잃었는데
      '변동 없음' 한 줄만 주면 그 회차는 상태를 영영 못 본다.
    """
    _SB["digest"] = None
    return why


def _tried_line():
    """★ 절대 접지 않는 부분 — 무엇을 이미 시도했고 무엇이 닫혔는가."""
    out = []
    qs = [q for q in (STATE.get("asks") or []) if (q.get("attempts") or [])
          or (q.get("status") or "open").lower() in ("exhausted", "answered")]
    qs.sort(key=lambda q: -len(q.get("attempts") or []))
    if qs:
        mark = {"exhausted": "소진", "answered": "★답함"}
        bits = ["[%s]%s×%d%s" % (str(q.get("id"))[:16],
                                 (":" + str(q.get("cfg") or q.get("klass"))[:18])
                                 if (q.get("cfg") or q.get("klass")) else "",
                                 len(q.get("attempts") or []),
                                 "·" + mark[(q.get("status") or "").lower()]
                                 if (q.get("status") or "").lower() in mark else "")
                for q in qs[:6]]
        out.append("  ★ 이미 시도함(같은 방법을 또 쓰지 마라): " + " · ".join(bits)
                   + (" …외 %d" % (len(qs) - 6) if len(qs) > 6 else ""))
    adj = STATE.get("adjudications") or []
    if adj:
        out.append("  ⚖ 판결자가 닫은 행 %d건 — 다시 논쟁하지 마라 (%s)"
                   % (len(adj), ", ".join(str(a.get("target"))[:22] for a in adj[-3:])))
    return out


def status_block(i, total):
    parts = []
    if i and total:
        parts.append(f"[state] tool {i}/{total} · 남은 예산 {total - i}")
    pct, done, tot = coverage()
    if tot:
        parts.append(f"  커버리지 {done}/{tot} ({pct*100:.0f}%)")
        un = unaudited()
        if un:
            _shape = unaudited_shape()
            _n = sum(_shape.values())
            parts.append("  미분석 %d행 — 도달성 구성: %s"
                         % (_n, " · ".join("%s %d" % (k, v)
                                           for k, v in _shape.most_common(4))))
            parts.append("  이번 표본(회전 중, %d행 전체를 순회한다): " % _n + " / ".join(un))
    else:
        parts.append("WARNING: the enumeration table is empty. Register the ingress first with "
                     "surface(action='add').")

    # 예산을 40% 넘게 쓰고도 판정이 0건이면 그 자체가 이탈이다.
    # (실사례: clfs 61턴 · $9.87 · 원장 판정 0건 — 발견은 note 에만 남고 커버리지 0%)
    if i and total and not STATE["verdicts"] and i >= total * 0.4:
        parts.append(
            "  BUDGET: %d/%d of budget spent with ZERO verdicts. note() is not a verdict.\n"
            "     Register what you have read so far as verdicts RIGHT NOW (rejections and "
            "unaudited rows count).\n"
            "     A rejection IS a verdict - record 'the guard is real, the candidate died' "
            "with basis='decompile'." % (i, total))

    conf = [v for v in STATE["verdicts"] if v["status"] == "확정"]
    if conf:
        weak = [v["id"] for v in conf if BASIS_RANK.get(v["basis"], 0) < 3]
        parts.append(f"  확정 {len(conf)}건" + (f" (근거 약함: {', '.join(weak)})" if weak else ""))
    # ★ 2026-09-05 — **계기판이 "안 한 것"만 보여줬다.**
    #   실측(밤샘 9시간): 매 4툴호출마다 주입되는 이 블록이 커버리지 2% · 미분석 544행 ·
    #   회전 표본 8행 · 묘지 6건 · 실패이력 101건을 보여주는데, **"거의 다 된 것"은 한 줄도 없었다.**
    #   결과: 판정 134건 중 `reject` 170 : `confirm` 4(그마저 같은 후보 재시도라 **distinct 1건**).
    #   그동안 wcifs 에는 4/5 트랙이 셋, ahcache 에 하나가 **손도 안 닿은 채** 있었다.
    #   ⇒ 남은 사다리가 1~2칸인 트랙을 **매 턴 보여준다.** 할당량이 아니라 **가시성**이다.
    _near = []
    for _n, _t in (STATE.get("tracks") or {}).items():
        _st = _t.get("stage", 0); _names = _t.get("stages") or DEFAULT_STAGES
        _left = len(_names) - _st
        if 0 < _left <= 2:
            _near.append((_left, _n, _names[_st] if _st < len(_names) else "?"))
    if _near:
        _near.sort()
        parts.append("  ★ 사다리 끝이 가까운 트랙 %d개 — **다음 칸을 올려라**: %s"
                     % (len(_near), " / ".join("`%s` %d칸 남음(다음: %s)" % (n, l, nx)
                                               for l, n, nx in _near[:4])))
    # ★ 재개로 **종결 주장이 상한** 트랙을 매 턴 보여준다. 노트는 "끝났고 음성"이라고
    #   말하는데 그 축이 다시 열렸으면, 그 노트를 믿고 시작하는 다음 회차가 통째로 헛돈다.
    _stale = [(n, t) for n, t in (STATE.get("tracks") or {}).items() if t.get("stale_closure")]
    if _stale:
        parts.append("  ⚠ 종결 주장이 **상한** 트랙 %d개 — 노트는 '끝났다'는데 그 축이 재개됐다: %s"
                     % (len(_stale),
                        " / ".join("`%s`(재개 %d회: %s)"
                                   % (n, len(t["stale_closure"]),
                                      ", ".join(str(x.get("by"))[:28] for x in t["stale_closure"][:2]))
                                   for n, t in _stale[:3])))
    # ★ 2026-09-05 (C-037) — **저수지를 매 턴 보이게 한다.** C-034 가 잰 격차의 자리다:
    #   하네스가 결함까지 한 질문 남기고 규율상 옳게 멈춘 행 넷이 `BLOCKED` 로 있었는데,
    #   BLOCKED 는 커버리지에서 정당하게 빠지고 worklist 에서도 내려가므로 **아무도 안 돌아갔다.**
    #   순위를 매기지 않는다(산문에서 '다음 수가 있는가'는 판별 불가 — 측정됨). **크기만 말한다.**
    _bl = [r for r in (STATE.get("surface") or {}).values()
           if r.get("blocked") and not r.get("exhausted")
           and not _is_alias_row(r.get("why"))]
    if _bl:
        _wn = sum(1 for r in _bl if isinstance(r.get("next"), dict))
        parts.append("  ★ blocked 저수지 %d행 — 다음 걸음이 **칸에 선언된 것은 %d행**. "
                     "`verdict(action='unfinished')` 로 열거하라. 분석이 이미 일어났고 "
                     "한 걸음 앞에서 멈춘 행들이다." % (len(_bl), _wn))
    _prop = [c for c in (STATE.get("candidates") or []) if c.get("state") == "proposed"]
    if _prop:
        parts.append("  ★ 반박자를 아직 안 거친 후보 %d건: %s"
                     % (len(_prop), ", ".join(str(c.get("id")) for c in _prop[:6])))
    r = STATE["refutes"]
    if r["run"]:
        parts.append(f"  반박 {r['run']}회 — 킬 {r['killed']} / 생존 {r['survived']}"
                     + (f" / 실행실패 {r['failed']}" if r["failed"] else ""))
    if STATE["graveyard"]:
        parts.append("  묘지(재개 금지): " + " / ".join(
            f"{g['id']}:{g['target']}[{g.get('klass') or '-'}]" for g in STATE["graveyard"][-6:]))
    miss = [k for k in ("positive", "negative", "swap") if not STATE["controls"].get(k)]
    if STATE["controls"] or miss != ["positive", "negative", "swap"]:
        parts.append("  대조군 미확보: " + (", ".join(miss) if miss else "없음 (3종 완비)"))

    # ── 델타 ──────────────────────────────────────────────────
    # 첫 줄(예산)은 매 호출 달라지므로 지문에서 뺀다 — 안 그러면 델타가 절대 안 걸린다.
    # ★ 회전 표본도 같은 이유로 뺀다. 안 빼면 매 호출 본문이 달라져 **델타가 영영 안 걸린다**
    #   (unaudited 회전을 넣자마자 실제로 그렇게 됐다). 표본은 접힌 블록에도 계속 싣는다 —
    #   회차 안에서 표 전체를 훑는 것이 그 줄의 목적이라 접으면 목적이 사라진다.
    body = [x for x in (parts[1:] if (i and total) else parts)
            if not x.startswith("  이번 표본")]
    sample = [x for x in parts if x.startswith("  이번 표본")]
    dig = hashlib.sha1("\n".join(body).encode("utf-8")).hexdigest()
    tried = _tried_line()
    if body and _SB["digest"] == dig:
        # 변동 없음 → 큰 덩어리는 접는다. 시도 이력은 **접지 않는다.**
        head = parts[0] if (i and total) else ""
        return "\n".join(([head] if head else [])
                         + ["  (표·확정·묘지·대조군 변동 없음)"] + sample + tried)
    _SB["digest"] = dig
    return "\n".join(parts + tried)
