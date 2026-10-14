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
import shutil


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


# ── measurement side (per-lab; arrives with the modules that use it) ─────
# The agent loop, the ledger and the tool registry reference these. They are
# OFF or gracefully-degrading by default: with USE_IDA unset the decompile
# path reports "USE_IDA=0" instead of failing, and the kd/probe/vm tools stay
# disabled until a lab explicitly opts in. A published skeleton run touches
# none of them — the capstone disassembler + anchor gate + panel need nothing
# here.
WINE        = os.environ.get("WINE", "wine" if shutil.which("wine") else "")
IDAT        = os.environ.get("IDAT", "/mnt/c/Program Files/IDA Professional 9.0/idat64.exe")
IDA_WORKER  = os.path.abspath(os.path.join(os.path.dirname(__file__), "ida_worker.py"))
IDA_TIMEOUT = int(os.environ.get("IDA_TIMEOUT", "900"))
USE_IDA     = os.environ.get("USE_IDA", "1") not in ("0", "false", "no")

WORK_DIR = os.path.abspath(os.environ.get("WORK_DIR")
                           or os.path.join(os.path.dirname(__file__), "work"))
os.makedirs(WORK_DIR, exist_ok=True)

# Kernel debugger / live probe / guest VM — opt-in only.
ALLOW_PROBE    = os.environ.get("ALLOW_PROBE", "0") in ("1", "true")
ALLOW_VM_PROBE = os.environ.get("ALLOW_VM_PROBE", "0") in ("1", "true")
ALLOW_KDNET    = os.environ.get("ALLOW_KDNET", "0") in ("1", "true")

# Prior-art dedup gate (G3) and the Stop-gate block budget.
GATE_PRIORART = os.environ.get("GATE_PRIORART", "1") not in ("0", "false", "no")
STOP_BLOCKS   = int(os.environ.get("STOP_BLOCKS", "2"))

# The non-circular negative control for the double-fetch detector. It must be a
# real image where the detector has been **hand-verified to produce a false
# positive** (the IO_STACK_LOCATION.Parameters union misread). Fixing the
# detector's answer there to zero is what stops the union bug coming back.
# Leave it unset and that one control does not run — every result then says so,
# because a control that did not run is not a control that passed.
DBLFETCH_FP_CONTROL = os.environ.get("DBLFETCH_FP_CONTROL", "")

# An optional real-image positive control for the asynchronous-registrar sweep.
# The synthetic controls always run and prove the recovery path works; this one,
# when set, additionally pins the sweep against a real compiler's output.
ASYNC_CONTROL_IMAGE = os.environ.get("ASYNC_CONTROL_IMAGE", "")
