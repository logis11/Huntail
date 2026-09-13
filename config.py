# config.py — every knob is an environment variable, and every gate can be
# turned off.
#
# Why each gate has an off switch: a gate you cannot disable cannot be measured.
# The benchmark runs arms (`full`, `no-gates`, ...) against each other, and that
# is the only way to tell a gate that carries its weight from one that only
# feels rigorous. The rule that goes with it:
# **if you produce a result with gates off, say so in the report.**
#
# This file currently carries the adversarial stage and the verdict gates. The
# measurement side (guest VM, kernel debugger, probe directories) is per-lab and
# arrives with the modules that use it.
import os


def _flag(name, default="1"):
    return os.environ.get(name, default) not in ("0", "false", "no")


# ── model / loop ────────────────────────────────────────────────
MODEL     = os.environ.get("MODEL", "claude-opus-5")
MAX_TURNS = int(os.environ.get("MAX_TURNS", "120"))
MAX_TOOL_CALLS = int(os.environ.get("MAX_TOOL_CALLS", "250"))

# Whether to pull in the operator's own CLAUDE.md and skills. Unlike a CTF
# harness, here it is **on by default** — the discipline lives there.
SETTING_SOURCES = [s for s in os.environ.get("SETTING_SOURCES", "user").split(",") if s]

RUN_TAG = os.environ.get("RUN_TAG", "")
RESUME  = os.environ.get("RESUME", "")

# ── verdict gates ───────────────────────────────────────────────
# An absence / no-check confirmation is only allowed after that function has
# actually been disassembled.
GATE_DISASM_BEFORE_ABSENCE = _flag("GATE_DISASM")
# A measurement-based rejection is only allowed with a positive control in the
# ledger.
GATE_CONTROL_BEFORE_REJECT = _flag("GATE_CONTROL")
# Machine-verify every address cited as evidence against the measured build.
GATE_ANCHOR = _flag("GATE_ANCHOR")
# Rejections must pass too. The gates used to apply **only to confirmations**,
# which made false negatives free: klass required, anchors machine-verified.
GATE_REJECT = _flag("GATE_REJECT")
# The termination gate.
GATE_STOP   = _flag("GATE_STOP")

# Throughput floor — verdicts plus `blocked` rows **that carry a reason**.
MIN_COVERAGE = float(os.environ.get("MIN_COVERAGE", "0.0"))
# Adjudication floor — confirms and rejects only, so a run cannot escape into
# `blocked`. 0 disables it.
MIN_ADJUDICATED = float(os.environ.get("MIN_ADJUDICATED", "0.0"))

TOOL_OUT_CAP = int(os.environ.get("TOOL_OUT_CAP", "12000"))

# ── the adversarial stage ───────────────────────────────────────
# Run an independent, context-asymmetric refuter immediately before a confirm.
GATE_REFUTE = _flag("GATE_REFUTE")
# Put a model from a different family here for cross-model critique — one family
# misses correlated errors together.
REFUTER_MODEL   = os.environ.get("REFUTER_MODEL", "") or None
REFUTER_TURNS   = int(os.environ.get("REFUTER_TURNS", "30"))
REFUTER_TIMEOUT = int(os.environ.get("REFUTER_TIMEOUT", "900"))

# Require the three impact terms (owner / delta / boundary) **before** the
# refuter rather than at recording time. With the old ordering the refuter killed
# claims on `impact_unproven` while the agent had nowhere to state the impact.
GATE_IMPACT_BEFORE_REFUTE = _flag("GATE_IMPACT_BEFORE_REFUTE")

# The mirror of the refuter: the interrogator attacks rejections.
GATE_INTERROGATE     = _flag("GATE_INTERROGATE")
INTERROGATOR_MODEL   = os.environ.get("INTERROGATOR_MODEL", "") or None
INTERROGATOR_TURNS   = int(os.environ.get("INTERROGATOR_TURNS", "25"))
INTERROGATOR_TIMEOUT = int(os.environ.get("INTERROGATOR_TIMEOUT", "900"))
# Sampling rate. 1.0 is exhaustive. Lower it and **rejections that were never
# interrogated do not count as verified negatives** (the ledger records this per
# rejection) — lowering the sample rate and inflating coverage are different acts.
INTERROGATE_RATE     = float(os.environ.get("INTERROGATE_RATE", "1.0"))

# The only pressure that pushes upward.
GATE_ESCALATE      = _flag("GATE_ESCALATE")
ESCALATOR_MODEL    = os.environ.get("ESCALATOR_MODEL", "") or None
ESCALATOR_TURNS    = int(os.environ.get("ESCALATOR_TURNS", "25"))
ESCALATOR_TIMEOUT  = int(os.environ.get("ESCALATOR_TIMEOUT", "900"))
ESCALATE_RATE      = float(os.environ.get("ESCALATE_RATE", "1.0"))

# ── the adjudicator ─────────────────────────────────────────────
# After a row has been argued N times, call the **terminator**. This is not
# another adversary; it is the thing that breaks the loop.
# 3 is not arbitrary — in the ledger, attempts 4 and 5 produced nothing.
GATE_ADJUDICATE  = _flag("GATE_ADJUDICATE")
ADJUDICATE_AFTER = int(os.environ.get("ADJUDICATE_AFTER", "3"))
ADJUDICATOR_MODEL = os.environ.get("ADJUDICATOR_MODEL", "") or None
ADJUDICATOR_TURNS = int(os.environ.get("ADJUDICATOR_TURNS", "30"))
ADJUDICATOR_TIMEOUT = int(os.environ.get("ADJUDICATOR_TIMEOUT", "900"))
# Whether the adjudicator may `confirm`. The design recommendation was
# `reject|exhaust` only, so as not to open the precision direction; it is on
# here because every such decision is auditable in the ledger. Set 0 to narrow it.
ADJUDICATOR_MAY_CONFIRM = _flag("ADJUDICATOR_MAY_CONFIRM")
