#!/usr/bin/env python3
# deadrun.py — the SINGLE SOURCE for "this run is not a result".
#
# A run that the API refused, or that the transport dropped mid-stream, produced
# no analysis. Scoring it as a negative ("0 confirmations") is a lie: it counts a
# malfunction as evidence of absence. This module is the one place that decides
# whether a run happened at all — everything downstream (round accounting,
# consensus, coverage) is built on top of that decision.
#
# Why it is its own file: the same regexes were once COPIED into the orchestrator
# and five runner shell scripts. The Python copy was fixed twice; the five shells
# kept the old version. A copy diverges silently. So the regex lives here once and
# the shells pull it with `python3 -c 'import deadrun; print(deadrun.DEAD)'`. If a
# copy reappears, the set-difference regression in test_deadrun.py breaks.
#
# The two axes have DIFFERENT characters — and the asymmetry drives the design:
#   DEAD  = the API refused the run (session/usage limit, auth, billing). The
#           runner reacts by resting that target.
#           => a false positive is expensive: it kills a healthy run and can
#              trigger a multi-hour quota wait. So DEAD EXCLUDES the agent's own
#              content lines, and never fires on a bare number (429) alone.
#   TRANS = the transport layer broke (stream disconnect, 5xx). The SDK can still
#           close such a run with `DONE: success`.
#           => a false negative is expensive: a dead run's "0 confirmations" gets
#              scored as a real negative. So TRANS looks at EVERY line — these
#              strings are not something the agent would author.
import re

# Text the AGENT wrote — not something the API said. DEAD excludes these lines so
# that a run which merely ANALYSES quota/rate-limit logic is not read as a run the
# API rate-limited.
CONTENT = r'^\s*\[(tool|think|interrogate|refute|escalate|images|ida)\b'

# A bare `\b429\b` CANNOT be used: the harness's own summary lines print bare
# numbers that happen to be 429 —
#     "verdict: confirmed 3 · rejected 15 · unanalysed 429"
#     "coverage: 3/429 (1%)"   "429 turns · 640 calls"
# These lines do not start with `[tool]`/`[think]`, so they pass the CONTENT
# exclusion. Incident: one run (27 min, 100 turns, 98 tool calls, subtype=success)
# had a surface of 429 items; the summary printed "unanalysed 429", and a bare
# `\b429\b` rule read that count as an API 429 and stamped dead='429' into the
# ledger. => 429 is honoured ONLY when it comes with API context.
DEAD = (r"hit your (session|usage) limit|usage limit reached|"
        r"rate[_ ]limit_?error|credit balance is too low|"
        r"authentication_error|invalid_api_key|overloaded_error|"
        r"\b429\b[^\n]{0,40}(too many requests|rate.?limit|retry-after)|"
        r"(http|status(_code)?|error)[^\n]{0,15}\b429\b")

# Transport layer. `(?:...)` is avoided on purpose so shell `grep -E` (POSIX ERE)
# can read the exact same pattern.
TRANS = (r"API Error|Server error mid-response|"
         r"response above may be incomplete|"
         r"Connection error|stream (disconnected|interrupted)|"
         r"Internal server error|\b5[0-9][0-9]\b Internal")

_CONTENT_RE = re.compile(CONTENT)
_DEAD_RE = re.compile(DEAD, re.I)
_TRANS_RE = re.compile(TRANS, re.I)


def api_lines(out):
    """Everything except the agent's content lines — only what the API said."""
    return "\n".join(l for l in out.splitlines() if not _CONTENT_RE.match(l))


def dead(out):
    """Did the API refuse the run (limit/auth/billing)? Match object or None."""
    return _DEAD_RE.search(api_lines(out))


def trans(out):
    """Did the transport layer break? Looks at EVERY line. Match object or None."""
    return _TRANS_RE.search(out)


if __name__ == "__main__":
    import sys
    # Push the PREDICATE to the shell too, not just the regex string. Once the
    # shells pulled only the `DEAD` string and grepped it over the WHOLE log,
    # while the Python side ran `dead()`, which first strips the agent's content
    # lines via `api_lines()`. That means the side with false-positive defence and
    # the side that triggers a multi-hour sleep were DIFFERENT predicates (the
    # "built but never wired" family: one source, two consumption paths).
    # `--check <log>` hands the shell the exact Python predicate: rc=0 if dead.
    if len(sys.argv) > 2 and sys.argv[1] == "--check":
        try:
            _t = open(sys.argv[2], encoding="utf-8", errors="replace").read()
        except OSError as e:
            sys.stderr.write("deadrun --check: %s\n" % e)
            raise SystemExit(2)
        raise SystemExit(0 if dead(_t) else 1)
    print({"DEAD": DEAD, "TRANS": TRANS, "CONTENT": CONTENT}[
        sys.argv[1] if len(sys.argv) > 1 else "DEAD"])
