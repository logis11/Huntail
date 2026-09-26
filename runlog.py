# runlog.py — 실행 지표 기록. 실행 방식은 안 건드린다.
#
# work/ 는 예전처럼 하나만 쓴다 (지우고 싶으면 `rm -rf work/*`).
# 대신 실행이 끝나면 지표 한 줄을 runs.jsonl 에 append 한다. bench.py 가 그걸 표로 뽑는다.
import json, os, re, time
import config

_JSONL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runs.jsonl")
STATE = {"t0": None, "meta": {}, "transcript": None}


def _transcript_path(target=None):
    """★ 표적별 사고 기록. 예전엔 `work/transcript.log` **하나**였다.

    표적 2개를 병렬로 돌린 순간(2026-09-01 23:04) 두 에이전트가 같은 파일을 truncate 하고
    append 해서 **사고 기록이 섞였다.** 원장·stdout 은 프로세스별로 갈려 있어 결과 데이터는
    무사했지만, "왜 그렇게 판단했는가"는 그 회차 것이 통째로 못 쓰게 됐다.
    락을 표적별로 가른 것과 같은 이유다 — 공유 자원을 표적 키로 가른다.
    """
    if target:
        key = re.sub(r'[^A-Za-z0-9._-]', '_', os.path.basename(str(target)))[:50]
        return os.path.join(config.WORK_DIR, "transcript.%s.log" % key)
    return STATE.get("transcript") or os.path.join(config.WORK_DIR, "transcript.log")


# ── 추론 기록 아카이브 ────────────────────────────────────────
# ★ 왜: `work/transcript.<표적>.log` 는 **회차마다 truncate** 된다("이번 실행분만").
#   그 안에 들어 있는 것이 판정 결과가 아니라 **"왜 그렇게 판단했는가"** 이고,
#   그건 원장 어디에도 없다. 실측으로 잃은 것:
#     · 심문자가 기각을 깬 213건의 사유가 여기로만 갔고 회차마다 지워졌다
#     · 살아남은 1줄에서도 새 리드가 하나 딸려 나왔다(AhcDispatch 의 unprobed 0x1B8 memcpy)
#   `reports/logs/*.transcript.log` 에 보존본이 있는데 **사람이 손으로 옮긴 것**이다.
#   관찰자(회차·표적을 가로질러 읽는 층)의 주 재료가 이것이므로 자동화한다.
#
# ★ 원장이 아니라 파일로 간다 — 지휘자는 `state/*.json` 만 읽으므로 부하 0.
ARCHIVE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "reports", "transcripts")


def _archive(path, target=""):
    """직전 회차분을 표적별 누적 파일에 append 한다. 실패해도 실행을 막지 않는다."""
    try:
        if not (path and os.path.exists(path) and os.path.getsize(path) > 0):
            return None
        os.makedirs(ARCHIVE_DIR, exist_ok=True)
        key = re.sub(r'[^A-Za-z0-9._-]', '_', os.path.basename(str(target or "unknown")))[:50]
        dst = os.path.join(ARCHIVE_DIR, key + ".log")
        with open(path, encoding="utf-8", errors="replace") as f:
            body = f.read()
        with open(dst, "a", encoding="utf-8") as f:
            f.write("\n\n===== ROUND ARCHIVED %s · %s (%d bytes) =====\n"
                    % (time.strftime("%Y-%m-%d %H:%M"), key, len(body)))
            f.write(body)
        return dst
    except OSError:
        return None


_RUN = {}


def note_usage(u):
    """★ 2026-09-07 — 스트리밍 중 `AssistantMessage.usage` 를 누적한다.

    왜: 비용/토큰은 `ResultMessage` 에만 실려 오는데, 타임아웃은 **SIGKILL** 이라
    `finish()` 가 못 돈다. 실측(최근 20케이스): 성공 5건은 $6~12 가 찍히고
    **타임아웃 15건은 전부 $0.00** — 그런데 그 15건이 벽시계 45분씩 실제로 돌았다.
    runs.jsonl 합계 $46.77 대 실제 추정 ~$180. **0 과 미측정이 같은 칸에 들어가 있었다.**
    ⇒ 토큰은 매 어시스턴트 메시지에서 실제로 누적하고, 달러는 **지어내지 않는다**
      (`total_cost_usd=None` + `cost_unknown=True` 로 0 과 구분한다).
    """
    if not isinstance(u, dict):
        return
    acc = _RUN.setdefault("usage_acc", {})
    for k in ("input_tokens", "output_tokens",
              "cache_read_input_tokens", "cache_creation_input_tokens"):
        v = u.get(k)
        if isinstance(v, int):
            acc[k] = acc.get(k, 0) + v
    acc["messages"] = acc.get("messages", 0) + 1


def mark_baseline(triage_state):
    """★ 원장 누적 카운터의 **회차 기준선**을 잡는다.

    ★ 2026-09-07 — 전에는 `denials0` **하나만** 잡았다. 그래서 `rejected`(=len(graveyard)),
      `interrog_run`, `refute_killed` 이 **누적값인 채로 회차 칸에 앉아 있었다**:
        interrog_run  165 → 168 → 184 → 192 → 202 → 204   (회차분은 실제로 2~3)
        refute_killed   8 →   8 →   9 →   9 →  10 →  10   (회차분은 0~1)
        rejected      = len(graveyard) 누적
      `score_arms.py:52` 는 이걸 알고 **읽는 쪽에서** 빼고 있었다 — 수정이 기록자가 아니라
      독자에게 들어갔으니 다음 독자는 또 밟는다. 기준선을 넓히고 `*_delta` 칸을 따로 낸다.
      (memory `cumulative-counter-in-delta-column` 이 경고한 바로 그 모양이다.)
    """
    _RUN["denials0"] = len(triage_state.get("denials") or [])
    _RUN["graveyard0"] = len(triage_state.get("graveyard") or [])
    _RUN["verdicts0"] = len(triage_state.get("verdicts") or [])
    _ig = triage_state.get("interrogs") or {}
    _rf = triage_state.get("refutes") or {}
    _RUN["interrog_run0"] = int(_ig.get("run") or 0)
    _RUN["interrog_broke0"] = int(_ig.get("broke") or 0)
    _RUN["interrog_sustained0"] = int(_ig.get("sustained") or 0)
    _RUN["refute_killed0"] = int(_rf.get("killed") or 0)
    _RUN["refute_survived0"] = int(_rf.get("survived") or 0)
    # ★ 2026-09-07 — **부채 기준선은 여기서 잡는다.** 처음엔 `ledger._RUN` 을 읽었는데
    #   그건 `ledger.attach()` 시점에 잡히고, 지표는 **nightrun 프로세스**에서 계산된다.
    #   그 프로세스의 attach 는 최종 상태를 읽은 뒤라 기준선이 곧 종료 상태가 되고,
    #   델타 칸에 **누계**가 들어간다. 실측 2026-09-07 18:45 회차: `debt_ask_dn=15` 가
    #   원장의 answered **총계** 15 와 정확히 같았다 — 그 회차가 답한 질문은 0건이었다.
    #   (memory `cumulative-counter-in-delta-column` 과 같은 사고를 새 칸에서 재현했다.)
    _A = triage_state.get("asks") or []
    _RUN["asks_open0"] = sum(1 for a in _A if (a.get("status") or "open") == "open")
    _RUN["asks_answered0"] = sum(1 for a in _A if a.get("status") == "answered")
    _RUN["blocked0"] = sum(1 for v in (triage_state.get("surface") or {}).values()
                           if isinstance(v, dict)
                           and str(v.get("why") or "").lstrip().upper().startswith("BLOCKED"))
    try:
        import ledger as _L0
        _RUN["leads_open0"] = len(_L0.open_leads(triage_state.get("target")))
    except Exception:
        _RUN["leads_open0"] = None
    return _RUN["denials0"]


def _deltas(triage_state, m):
    """누적 칸 옆에 **회차분** 칸을 나란히 낸다. 기준선이 없으면 `None` — 0 이 아니다.
    (0 과 미측정을 같은 칸에 넣지 않는다.)"""
    _ig = triage_state.get("interrogs") or {}
    _rf = triage_state.get("refutes") or {}
    src = {"rejected_delta": (len(triage_state.get("graveyard") or []), "graveyard0"),
           "verdicts_delta": (len(triage_state.get("verdicts") or []), "verdicts0"),
           "interrog_run_delta": (int(_ig.get("run") or 0), "interrog_run0"),
           "interrog_broke_delta": (int(_ig.get("broke") or 0), "interrog_broke0"),
           "interrog_sustained_delta": (int(_ig.get("sustained") or 0), "interrog_sustained0"),
           "refute_killed_delta": (int(_rf.get("killed") or 0), "refute_killed0"),
           "refute_survived_delta": (int(_rf.get("survived") or 0), "refute_survived0")}
    for k, (cur, base) in src.items():
        b = _RUN.get(base)
        m[k] = (cur - int(b)) if b is not None else None
    # ★ 2026-09-07 — **부채 흐름을 계기판에 올린다.** 상한(WIP cap)의 효과를 재려면
    #   "연 것 − 닫은 것"이 회차마다 기록돼야 한다. 특히 `debt_blocked_up` 은
    #   ablation 의 3번 지표다 — 상한을 걸었는데 이 칸이 늘면 물량이 blocked 로 샌 것이고,
    #   그건 실험 실패가 아니라 상한을 blocked 까지 확장 안 한 **설정 실수**다.
    #   ★ 값을 못 구하면 0 이 아니라 None 이다 (미측정과 0 을 같은 칸에 넣지 않는다).
    # ★ 기준선은 이 모듈이 회차 시작에 잡은 것만 쓴다(`_RUN[...0]`). `ledger._RUN` 은
    #   다른 프로세스·다른 시점의 것이라 델타가 누계로 샌다(위 baseline 주석의 실측).
    #   ★ 기준선이 없으면 **0이 아니라 None** 이다 — 미측정과 0 을 같은 칸에 넣지 않는다.
    try:
        import ledger as _L
        _A2 = triage_state.get("asks") or []
        _open_now = sum(1 for a in _A2 if (a.get("status") or "open") == "open")
        _ans_now = sum(1 for a in _A2 if a.get("status") == "answered")
        _blk_now = sum(1 for v in (triage_state.get("surface") or {}).values()
                       if isinstance(v, dict)
                       and str(v.get("why") or "").lstrip().upper().startswith("BLOCKED"))
        _leads_now = len(_L.open_leads(triage_state.get("target")))
        m["leads_open"] = _leads_now
        _b = _RUN.get("leads_open0")
        m["debt_lead_delta"] = (_leads_now - int(_b)) if _b is not None else None
        _b = _RUN.get("asks_answered0")
        m["debt_ask_dn"] = (_ans_now - int(_b)) if _b is not None else None
        _b = _RUN.get("asks_open0")
        m["debt_ask_up"] = (_open_now - int(_b)) if _b is not None else None
        _b = _RUN.get("blocked0")
        m["debt_blocked_up"] = (_blk_now - int(_b)) if _b is not None else None
        _parts = [m.get("debt_lead_delta"), m.get("debt_ask_up"), m.get("debt_blocked_up")]
        m["debt_net"] = (sum(_parts) if all(x is not None for x in _parts) else None)
    except Exception:
        for _k in ("lead_delta", "ask_up", "ask_dn", "blocked_up", "net"):
            m.setdefault("debt_" + _k, None)
    return m


def start(target, tag=""):
    STATE["t0"] = time.time()
    STATE["meta"] = {
        "run_id": time.strftime("%m-%d %H:%M"),
        "challenge": os.path.basename(os.path.dirname(os.path.abspath(target))),
        "tag": tag, "model": config.MODEL, "max_turns": config.MAX_TURNS,
        "tools": {}, "gate_denials": 0,
    }
    STATE["transcript"] = _transcript_path(target)
    _archive(STATE["transcript"], target)                     # ★ 지우기 전에 보존
    open(STATE["transcript"], "w").close()                    # 이번 실행분만
    # 호환: 단일 실행이면 예전 경로도 같이 비워 둔다(도구·문서가 그 이름을 참조한다)
    try:
        open(os.path.join(config.WORK_DIR, "transcript.log"), "w").close()
    except OSError:
        pass


def bump(key, n=1):
    STATE["meta"][key] = STATE["meta"].get(key, 0) + n


def tool(name):
    t = STATE["meta"].setdefault("tools", {})
    t[name] = t.get(name, 0) + 1


def transcript(line):
    try:
        with open(_transcript_path(), "a") as f:
            f.write(line.rstrip() + "\n")
    except OSError:
        pass


def snapshot(triage_state, key=""):
    """★ 진행 중 지표 스냅샷. **타임아웃은 SIGKILL 이라 자식이 마무리를 못 한다** —
    2026-09-04 밤 msquic 회차가 그렇게 잘려 `runs.jsonl` 에 줄이 아예 안 남았고,
    `gate_denials` 조차 없어 "완결된 분석 5건이 왜 사라졌나"를 진단할 수 없었다.
    부모(nightrun)가 타임아웃 경로에서 이 파일을 주워 기록한다."""
    try:
        m = dict(STATE.get("meta") or {})
        if not m:
            return None
        m["wall_seconds"] = round(time.time() - (STATE["t0"] or time.time()), 1)
        m["subtype"] = "partial"
        surf = triage_state.get("surface", {}) or {}
        m["surface_total"] = len(surf)
        m["confirmed"] = sum(1 for v in (triage_state.get("verdicts") or [])
                             if v.get("status") == "확정")
        m["rejected"] = len(triage_state.get("graveyard") or [])
        # ★ 2026-09-07 — 표면을 **세 칸으로** 낸다. 하나의 %로 접으면 거짓이 된다:
        #   실측 coverage()=2.1% 대 settled()=90.2% (같은 표, 45배).
        m["surface_judged"] = sum(1 for v in surf.values() if v.get("status") != "미분석")
        m["surface_blocked"] = sum(1 for v in surf.values()
                                   if v.get("blocked")
                                   or str(v.get("why", "")).startswith("BLOCKED"))
        m["surface_untouched"] = max(0, len(surf) - m["surface_judged"] - m["surface_blocked"])
        m["verdicts_total"] = len(triage_state.get("verdicts") or [])
        try:
            import ledger as _L
            m["surface_sites"], _sr, m["surface_dup_rows"], _st = _L.surface_sites(triage_state)
        except Exception:
            pass
        # ★ 2026-09-05 — 부분 스냅샷에도 **반려 분포**를 넣는다. 타임아웃은 SIGKILL 이라
        #   `finish()` 가 못 돌고, 그러면 회차 요약이 통째로 안 남는다(실측: 09-05 msquic).
        #   반려 자체는 원장에 있어 살아남지만, "이번 회차분이 몇 건인지"는 기준선을 아는
        #   이 프로세스만 안다. 그걸 여기서 건져 둔다.
        _dn = triage_state.get("denials") or []
        _mine = _dn[int(_RUN.get("denials0") or 0):]
        _agg = {}
        for _d in _mine:
            _k = _d.get("rule") or "(사유 없음)"
            _agg[_k] = _agg.get(_k, 0) + 1
        m["denials_this_run"] = len(_mine)
        _deltas(triage_state, m)
        # ★ 부분 스냅샷은 `ResultMessage` 를 못 본다 — 달러를 0 으로 찍지 않는다.
        _acc = _RUN.get("usage_acc") or {}
        if _acc:
            m["tokens"] = dict(_acc)
        m["total_cost_usd"] = None
        m["cost_unknown"] = True
        m["denial_rules"] = sorted(_agg.items(), key=lambda x: -x[1])[:12]
        p = os.path.join(config.WORK_DIR, "partial.%s.json" %
                         (re.sub(r'[^A-Za-z0-9._-]', '_', str(key or m.get("challenge") or "x"))[:40]))
        with open(p, "w", encoding="utf-8") as f:
            json.dump(m, f, ensure_ascii=False)
        return p
    except Exception:
        return None


def finish(result_msg, flag, triage_state):
    m = STATE["meta"]
    if not m:
        return {}
    m["wall_seconds"] = round(time.time() - (STATE["t0"] or time.time()), 1)
    m["flag"], m["solved"] = flag, bool(flag)
    for k in ("num_turns", "total_cost_usd", "session_id", "subtype", "is_error"):
        v = getattr(result_msg, k, None)
        if v is not None:
            m[k] = v
    u = getattr(result_msg, "usage", None)
    if isinstance(u, dict):
        m["tokens"] = {k: u[k] for k in ("input_tokens", "output_tokens",
                                         "cache_read_input_tokens") if u.get(k)}
    surf = triage_state.get("surface", {})
    done = sum(1 for v in surf.values() if v["status"] in ("확정", "기각"))
    m["surface_total"] = len(surf)
    m["surface_done"] = done
    m["coverage"] = round(done / len(surf), 3) if surf else 0.0
    m["confirmed"] = sum(1 for v in triage_state.get("verdicts", []) if v["status"] == "확정")
    m["rejected"] = len(triage_state.get("graveyard", []))
    m["unaudited"] = len(surf) - done
    # ★ 2026-09-07 — partial 과 같은 세 칸. `coverage` 는 남기되 **혼자 읽히지 않게** 한다.
    m["surface_judged"] = sum(1 for v in surf.values() if v.get("status") != "미분석")
    m["surface_blocked"] = sum(1 for v in surf.values()
                               if v.get("blocked") or str(v.get("why", "")).startswith("BLOCKED"))
    m["surface_untouched"] = max(0, len(surf) - m["surface_judged"] - m["surface_blocked"])
    m["verdicts_total"] = len(triage_state.get("verdicts") or [])
    try:
        import ledger as _L
        m["surface_sites"], _sr, m["surface_dup_rows"], _st = _L.surface_sites(triage_state)
    except Exception:
        pass
    m["blocked"] = sum(1 for v in surf.values()
                       if str(v.get("why", "")).startswith("BLOCKED"))
    rf = triage_state.get("refutes", {})
    m["refute_killed"], m["refute_survived"] = rf.get("killed", 0), rf.get("survived", 0)
    ig = triage_state.get("interrogs", {}) or {}
    m["interrog_run"] = ig.get("run", 0)
    m["interrog_broke"] = ig.get("broke", 0)
    m["interrog_sustained"] = ig.get("sustained", 0)
    _deltas(triage_state, m)
    m["interrog_failed"] = ig.get("failed", 0)
    m["interrog_skipped"] = ig.get("skipped", 0)
    # ★ 검증된 음성 = 심문을 받고 살아남은 기각. 심문 안 받은 기각은 여기 안 들어간다.
    m["rejects_interrogated"] = sum(1 for v in triage_state.get("verdicts", [])
                                    if v.get("status") == "기각" and v.get("interrogated"))
    m["refute_failed"] = rf.get("failed", 0)
    m["anchored_confirms"] = sum(1 for v in triage_state.get("verdicts", [])
                                 if v["status"] == "확정" and v.get("anchors"))
    m["hedges"] = triage_state.get("hedges", 0)
    m["controls"] = {k: len(v) for k, v in triage_state.get("controls", {}).items()}
    # ★ 게이트 반려의 **사유별 분포**. 카운터 하나만 있던 시절엔 692회 반려의 내용이
    #   어디에도 없었다(→ refs/05 · C-031). 이제 규칙별로 무엇을 잡았는지 회차마다 나온다.
    _dn = triage_state.get("denials") or []
    _base = int(_RUN.get("denials0") or 0)
    _mine = _dn[_base:] if len(_dn) >= _base else _dn
    _agg = {}
    for _d in _mine:
        _k = _d.get("rule") or "(사유 없음)"
        _agg[_k] = _agg.get(_k, 0) + 1
    m["denials_this_run"] = len(_mine)
    m["denial_rules"] = sorted(_agg.items(), key=lambda x: -x[1])[:12]
    m["harness_tool_calls"] = sum(v for k, v in m["tools"].items() if k.startswith("mcp__vuln__"))
    m["total_tool_calls"] = sum(m["tools"].values())
    try:
        with open(_JSONL, "a") as f:
            f.write(json.dumps(m, ensure_ascii=False) + "\n")
    except OSError:
        pass
    return m


def summary(m):
    if not m:
        return ""
    dead = (m.get("harness_tool_calls", 0) == 0)
    top = ", ".join(f"{k.replace('mcp__vuln__', 'v:')}×{v}"
                    for k, v in sorted(m.get("tools", {}).items(), key=lambda x: -x[1])[:6])
    sid = m.get("session_id")
    return "\n".join([
        "",
        "══ RUN SUMMARY ═══════════════════════════════════════════",
        f"  판정      : 확정 {m.get('confirmed',0)} · 기각 {m.get('rejected',0)} · "
        f"미분석 {m.get('unaudited',0)}"
        + (f" (그중 BLOCKED {m['blocked']} — 사유 있음)" if m.get('blocked') else "")
        + f"  ({m.get('subtype','?')})",
        f"  근거      : 앵커검증된 확정 {m.get('anchored_confirms',0)}/{m.get('confirmed',0)}"
        + (f" · 반박 킬 {m.get('refute_killed',0)} / 생존 {m.get('refute_survived',0)}"
           + (f" / 실행실패 {m['refute_failed']}" if m.get('refute_failed') else "")
           if (m.get('refute_killed') or m.get('refute_survived') or m.get('refute_failed'))
           else " · 반박자 미가동"),
        (f"  기각검증  : 심문 {m.get('interrog_run',0)}회 — "
         f"깨짐 {m.get('interrog_broke',0)} / 유지 {m.get('interrog_sustained',0)}"
         + (f" / 실행실패 {m['interrog_failed']}" if m.get('interrog_failed') else "")
         + (f" / 미표본 {m['interrog_skipped']}" if m.get('interrog_skipped') else "")
         + f"  ⇒ 검증된 음성 {m.get('rejects_interrogated',0)}/{m.get('rejected',0)}"
         if m.get('interrog_run') or m.get('interrog_skipped')
         else f"  기각검증  : \033[91m심문자 미가동 — 기각 {m.get('rejected',0)}건이 "
              f"전부 미검증 음성이다\033[0m"),
        f"  커버리지  : {m.get('surface_done',0)}/{m.get('surface_total',0)} "
        f"({(m.get('coverage',0) or 0)*100:.0f}%)"
        + ("   ⚠ 미분석을 표에서 빼지 말 것" if m.get('unaudited') else ""),
        f"  턴/툴호출 : {m.get('num_turns','?')} 턴 · {m.get('total_tool_calls',0)} 호출 "
        f"(하네스 툴 {m.get('harness_tool_calls',0)})",
        f"  시간/비용 : {m.get('wall_seconds','?')}s · ${m.get('total_cost_usd', 0) or 0:.4f}",
        f"  품질      : 대조군 {m.get('controls',{}) or '없음'} · "
        f"헤지 {m.get('hedges',0)}회 · 게이트차단 {m.get('gate_denials',0)}",
        (("  게이트반려: %d건 — " % m.get("denials_this_run", 0))
         + " · ".join("%d×%s" % (n, k[:44]) for k, n in (m.get("denial_rules") or [])[:4])
         if m.get("denials_this_run") else
         "  게이트반려: 0건 (막은 것이 없다 — 게이트가 놀았거나 배선이 끊겼다)"),
        f"  툴 분포   : {top}",
        f"  이어하기  : RESUME={sid} python agent_sdk.py <target>" if sid else "",
        ("\n  \033[91m✗ 하네스 툴 호출 0회 — 대상을 한 번도 만지지 않았다. "
         "이 실행의 '확정 0건' 은 결과가 아니라 **고장**이다. "
         "(한도/인증/네트워크를 먼저 확인하라)\033[0m" if dead else ""),
        "══════════════════════════════════════════════════════════",
    ])
