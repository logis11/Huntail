#!/usr/bin/env python3
# verifier_guard.py — **a verifier that has not passed its positive control has
# no right to emit a result.**
#
# Why this is code and not a rule: two verifiers broke silently on the same day.
#   1) An exhaustive control-code extractor could not follow a chained-sub
#      dispatch and found 1 of 4 known codes.
#   2) A "known-vulnerable driver" matcher keyed off a filename convention and so
#      missed several publicly documented vulnerable drivers.
#      **That fact was already written down in memory.** It was not wrong for
#      lack of knowledge; it was known and not applied. That is a failure class
#      adding more knowledge does not fix.
#
# Same pattern as taking the rejection authority away from an agent that kept
# misusing it — **a rule a human has to remember does not get followed, and one
# the code enforces does.**


class ControlFailed(RuntimeError):
    """The positive control failed. Raise this instead of returning a result."""


def guarded(name, controls, probe, expect=None):
    """Wrap a verifier. It cannot produce a result until `controls` check out
    through `probe`.

    name     : verifier name (for the error message)
    controls : {label: expected} — inputs whose answer is known
    probe    : callable(label) -> actual
    expect   : callable(expected, actual) -> bool. Defaults to equality
               (or subset, when the expected value is a set)

    Usage:
        @guarded("codes", {"<known image>": {0x2A4000, 0x2A4004}},
                 probe=lambda k: set(exhaustive_codes(PE(paths[k]))))
        def run(...): ...
    """
    eq = expect or (lambda a, b: a == b or (isinstance(a, set) and a <= b))

    def deco(fn):
        def wrapped(*a, **kw):
            bad = []
            for label, want in controls.items():
                try:
                    got = probe(label)
                except Exception as e:
                    bad.append("%s: probe raised %s" % (label, e))
                    continue
                if not eq(want, got):
                    bad.append("%s: expected %s / actual %s" % (label, want, got))
            if bad:
                raise ControlFailed(
                    "** '%s' did not pass its positive control — **it has no right to emit a "
                    "result.**\n"
                    "   %s\n"
                    "   A broken verifier and a clean target produce the same output. "
                    "Fix it first." %
                    (name, "\n   ".join(bad)))
            return fn(*a, **kw)
        wrapped.__name__ = getattr(fn, "__name__", "wrapped")
        wrapped.__doc__ = getattr(fn, "__doc__", None)
        wrapped._guarded_by = controls
        return wrapped
    return deco


def assert_controls(name, checks):
    """For places where the decorator does not fit.
    checks = [(label, passed, description), ...]"""
    bad = [(l, d) for l, ok, d in checks if not ok]
    if bad:
        raise ControlFailed(
            "** '%s' positive control failed — no result may be emitted:\n   %s" %
            (name, "\n   ".join("%s: %s" % (l, d) for l, d in bad)))
    return True
