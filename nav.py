# nav.py — the corpus navigation index.
#
# Why a COTS-binary agent spent half of its 33 tools on navigation: just
# attaching a toolset lifted Claude Code's F1 by **+0.214**. The bottleneck was
# not the model, it was **navigation**. Before this file, the harness got around
# a 3,884-function corpus with a single grep over names.
#
# What it builds: name -> body, VA -> function, callees/callers, call paths (the
# axis every reachability argument runs on), and a per-family census.
import os, pickle, re, hashlib
from collections import deque

BANNER = re.compile(r'^/\*\s*=+\s*(\S+)\s*@\s*(0x[0-9a-fA-F]+)\s*=+\s*\*/', re.M)
IDENT  = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(')
# Decompiler locals, types and keywords — call-graph noise.
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
            if n in self.fn:              # same name twice -> disambiguate by VA
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

    # ── lookups ─────────────────────────────────────────────
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
        """The function containing `va`. The corpus only records each
        function's start VA, so this approximates by "the nearest one before"."""
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
        """The shortest call path from `src` to `dst` — the axis a reachability
        argument runs on, and most rejections are reachability arguments."""
        a, b = self.resolve(src), self.resolve(dst)
        if not a or not b:
            return None, f"unresolved: {'src ' + str(src) if not a else ''}{'dst ' + str(dst) if not b else ''}"
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
        return None, (f"no path within depth {maxdepth} (indirect calls and function "
                      f"pointers are not in this graph)")

    def reaches(self, src, maxdepth=4):
        """The set of functions reachable from `src`, up to `maxdepth`."""
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
        """Population per name-prefix family, plus the unmentioned fraction when
        `mentioned` is given. This is what generates the coverage map."""
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
