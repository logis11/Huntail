# nav.py — 코퍼스 항해 색인.
#
# Slyp(COTS 바이너리 에이전트) 가 33개 툴 중 절반을 항해에 쓴 이유:
# 툴셋을 붙이는 것만으로 Claude Code 의 F1 이 +0.214 올랐다. 모델이 아니라 **항해**가 병목이다.
# 이 하네스는 3884 함수를 이름 grep 하나로 다니고 있었다.
#
# 여기서 만드는 것: 이름→본문, VA→함수, callees/callers, 콜패스(도달성 논증의 축), 패밀리 인구조사.
import os, pickle, re, hashlib
from collections import deque

BANNER = re.compile(r'^/\*\s*=+\s*(\S+)\s*@\s*(0x[0-9a-fA-F]+)\s*=+\s*\*/', re.M)
IDENT  = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(')
# 디컴파일러 로컬/타입/키워드 — 콜 그래프 노이즈
NOISE = {"if", "while", "for", "switch", "return", "sizeof", "return_address",
         "LOBYTE", "HIBYTE", "LOWORD", "HIWORD", "LODWORD", "HIDWORD", "BYTE1",
         "BYTE2", "BYTE3", "WORD1", "WORD2", "DWORD1", "SLOBYTE", "SHIBYTE"}


class Index:
    def __init__(self, path, cache_dir=None):
        self.path = os.path.abspath(path)
        raw = open(self.path, encoding="utf-8", errors="replace").read()
        self.text = raw
        key = hashlib.sha1((self.path + str(len(raw))).encode()).hexdigest()[:12]
        cf = os.path.join(cache_dir or os.path.dirname(self.path), f".navidx-{key}.pkl")
        if os.path.exists(cf):
            try:
                with open(cf, "rb") as f:
                    d = pickle.load(f)
                self.__dict__.update(d)
                self.text = raw
                return
            except Exception:
                pass
        self._build()
        try:
            with open(cf, "wb") as f:
                d = {k: v for k, v in self.__dict__.items() if k != "text"}
                pickle.dump(d, f)
        except OSError:
            pass

    def _build(self):
        t = self.text
        bans = [(m.group(1), int(m.group(2), 16), m.start(), m.end())
                for m in BANNER.finditer(t)]
        self.fn = {}                      # name -> (va, body_start, body_end)
        self.byva = []                    # [(va, name)] sorted
        for i, (n, va, s, e) in enumerate(bans):
            end = bans[i + 1][2] if i + 1 < len(bans) else len(t)
            if n in self.fn:              # 동명이인은 VA 로 구분
                n = f"{n}@{va:x}"
            self.fn[n] = (va, e, end)
            self.byva.append((va, n))
        self.byva.sort()
        names = set(self.fn)
        self.out, self.inn = {}, {}
        for n, (va, s, e) in self.fn.items():
            cs = set()
            for m in IDENT.finditer(t, s, e):
                c = m.group(1)
                if c != n and c in names and c not in NOISE:
                    cs.add(c)
            self.out[n] = sorted(cs)
            for c in cs:
                self.inn.setdefault(c, set()).add(n)
        self.inn = {k: sorted(v) for k, v in self.inn.items()}

    # ── 조회 ────────────────────────────────────────────────
    def body(self, name):
        h = self.resolve(name)
        if not h:
            return None
        va, s, e = self.fn[h]
        return h, va, self.text[s:e]

    def resolve(self, name):
        if name in self.fn:
            return name
        if isinstance(name, str) and name.lower().startswith("0x"):
            return self.func_at(int(name, 16))
        low = name.lower()
        hits = [n for n in self.fn if n.lower() == low]
        return hits[0] if hits else None

    def func_at(self, va):
        """VA 를 감싸는 함수. 코퍼스는 시작 VA 만 알므로 '직전 함수' 로 근사한다."""
        lo, hi = 0, len(self.byva) - 1
        best = None
        while lo <= hi:
            m = (lo + hi) // 2
            if self.byva[m][0] <= va:
                best = self.byva[m]; lo = m + 1
            else:
                hi = m - 1
        return best[1] if best else None

    def search(self, pattern, limit=80):
        rx = re.compile(pattern, re.I)
        hits = [(n, self.fn[n][0]) for n in self.fn if rx.search(n)]
        hits.sort(key=lambda x: x[1])
        return hits[:limit], len(hits)

    def callees(self, name):
        h = self.resolve(name)
        return (h, self.out.get(h, [])) if h else (None, [])

    def callers(self, name):
        h = self.resolve(name)
        return (h, self.inn.get(h, [])) if h else (None, [])

    def callpath(self, src, dst, maxdepth=8):
        """src → dst 최단 호출 경로. 도달성 논증(=대부분의 기각 사유)의 축이다."""
        a, b = self.resolve(src), self.resolve(dst)
        if not a or not b:
            return None, f"미해결: {'src ' + str(src) if not a else ''}{'dst ' + str(dst) if not b else ''}"
        if a == b:
            return [a], "same"
        seen, q = {a}, deque([(a, [a])])
        while q:
            cur, path = q.popleft()
            if len(path) > maxdepth:
                continue
            for nx in self.out.get(cur, []):
                if nx in seen:
                    continue
                if nx == b:
                    return path + [nx], "found"
                seen.add(nx)
                q.append((nx, path + [nx]))
        return None, f"깊이 {maxdepth} 안에 경로 없음 (간접 호출/함수포인터는 이 그래프에 없다)"

    def reaches(self, src, maxdepth=4):
        """src 에서 도달 가능한 함수 집합 (깊이 제한)."""
        a = self.resolve(src)
        if not a:
            return set()
        seen, q = {a}, deque([(a, 0)])
        while q:
            cur, d = q.popleft()
            if d >= maxdepth:
                continue
            for nx in self.out.get(cur, []):
                if nx not in seen:
                    seen.add(nx); q.append((nx, d + 1))
        return seen

    def census(self, mentioned=()):
        """접두 패밀리별 인구 + (선택) 미언급 비율. coverage_map.md 를 자동 생성한다."""
        fam = {}
        for n in self.fn:
            m = re.match(r'^([A-Z][a-z]{0,3}p?)', n)
            k = m.group(1) if m else "other"
            fam.setdefault(k, []).append(n)
        rows = []
        ment = set(mentioned)
        for k, v in sorted(fam.items(), key=lambda x: -len(x[1])):
            un = [n for n in v if n not in ment]
            rows.append((k, len(v), len(un), len(un) / len(v)))
        return rows
