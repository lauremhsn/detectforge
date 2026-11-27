"""Home: what DetectForge is, the problem it solves, how, for whom, what it has measured, and its scope.

Written for someone who has never heard of Sigma (a professor, a manager) and still accurate enough
for a detection engineer. Every number here is computed from the saved results (ui/results.py), the
same way as the report; nothing is hard-coded except the published study it starts from.
"""

from pathlib import Path

import streamlit as st

from detectforge.ui.components import pct
from detectforge.ui.navigation import go
from detectforge.ui.results import headline

# Fixed markup written here (never built from data), so it carries no injection risk.
_PIPELINE = """
<style>
.df-flow { display:flex; gap:.6rem; flex-wrap:wrap; margin:.4rem 0 1rem 0; }
.df-step { flex:1 1 150px; background:#131D33; border:1px solid #22304D; border-radius:.8rem;
  padding:.9rem 1rem; position:relative; opacity:0; animation: dfin .6s ease forwards; }
.df-step b { display:block; color:#E5ECF6; margin:.35rem 0 .2rem 0; font-size:1rem; }
.df-step span { color:#9FB0CC; font-size:.86rem; line-height:1.35; }
.df-step .n { font-size:1.5rem; }
.df-step.human { border-color:#3B82F6; box-shadow:0 0 0 1px #3B82F6 inset; }
.df-step:nth-child(1){animation-delay:.05s} .df-step:nth-child(2){animation-delay:.35s}
.df-step:nth-child(3){animation-delay:.65s} .df-step:nth-child(4){animation-delay:.95s}
.df-step:nth-child(5){animation-delay:1.25s} .df-step:nth-child(6){animation-delay:1.55s}
.df-loop { color:#9FB0CC; font-size:.85rem; margin-top:-.4rem; }
.df-loop i { color:#60A5FA; font-style:normal; animation: dfpulse 2.4s ease-in-out infinite; }
@keyframes dfin { from {opacity:0; transform:translateY(8px)} to {opacity:1; transform:none} }
@keyframes dfpulse { 0%,100% {opacity:.45} 50% {opacity:1} }
@media (prefers-reduced-motion: reduce) { .df-step, .df-loop i { animation:none; opacity:1; } }
</style>
<div class="df-flow">
 <div class="df-step"><div class="n">🔎</div><b>1 · Find</b>
  <span>Ask in plain words ("ransomware deleting backups") or paste a threat report. DetectForge maps it
  to attacker techniques and finds the community rules that claim to catch them.</span></div>
 <div class="df-step"><div class="n">🧪</div><b>2 · Attack</b>
  <span>Replays each rule against real attack commands and the disguises attackers use (inserted
  characters, swapped flags, shortened names, reordered or re-encoded arguments).</span></div>
 <div class="df-step"><div class="n">🛠️</div><b>3 · Harden</b>
  <span>An AI agent reads exactly what slipped past, edits the rule, re-tests it, and repeats. If no
  rule exists, it writes one.</span></div>
 <div class="df-step"><div class="n">✅</div><b>4 · Check</b>
  <span>Fixed, automatic quality checks (not the AI) decide if a proposal is good enough: it must still
  catch every plain attack, add no false alarms, and not be trivially bypassable.</span></div>
 <div class="df-step human"><div class="n">🧑‍⚖️</div><b>5 · Approve</b>
  <span>A person reviews the evidence, including look-alike commands it might wrongly flag, and
  decides. The agent can propose; it can never deploy.</span></div>
 <div class="df-step"><div class="n">📤</div><b>6 · Export</b>
  <span>The approved rule goes to your SIEM as Sigma or a ready-to-paste Elastic query, with a report
  of what changed and why.</span></div>
</div>
<div class="df-loop"><i>↻</i> Steps 3 and 4 loop until the evidence passes or the budget runs out; then
it stops and asks a human, never fails silently.</div>
"""


def _role(column, icon: str, who: str, need: str, page: str, button: str) -> None:
    with column.container(border=True):
        st.markdown(f"#### {icon} {who}")
        st.caption(need)
        st.button(button, key=f"home_{page}_{who}", on_click=go, args=(page,), width="stretch")


def home_page(data_dir: Path, runs_dir: Path, pending: int) -> None:
    st.markdown("# Your detection rules exist. Do they actually catch the attacker?")
    st.markdown(
        "**DetectForge** tests every detection rule against the ways real attackers disguise their "
        "commands, fixes the gaps with an AI agent that has to prove each fix, and lets a person approve "
        "every change before it reaches your SIEM."
    )

    st.markdown("### The problem")
    p1, p2, p3 = st.columns(3)
    p1.metric(
        "Widely used rules a simple disguise beats",
        "129 of 292",
        help="Uetz et al., USENIX Security 2024: five simple command-line tricks evade 44% of popular "
        "Windows process-creation Sigma rules (110 fully, 19 partly).",
    )
    p1.caption("Published study of community rules (Uetz et al., 2024).")
    h = headline(data_dir, runs_dir)
    p2.metric(
        "Variations the rules miss in our library",
        pct(1 - h.community_unseen) if h.community_unseen is not None else "n/a",
        help="Share of unseen attacker variations that the community rules, as published, let through, "
        f"on the {h.community_scored} test rules that have such variations.",
    )
    p2.caption("Measured here, on SigmaHQ rules as published.")
    p3.metric("Manual effort it replaces", "hours per rule", help="Writing dozens of attack variations, "
              "replaying them, editing the rule, and re-checking for false alarms, by hand, per rule.")  # fmt: skip
    p3.caption("Writing variations, replaying, editing, re-checking, for every rule.")
    st.markdown(
        "A rule *existing* is not the same as being *covered*. Most teams can't say which of their rules "
        "an attacker walks past, because testing that by hand is slow."
    )

    st.markdown("### How it works")
    st.html(_PIPELINE)

    st.markdown("### Why it's agentic, not a chatbot")
    a1, a2, a3 = st.columns(3)
    with a1.container(border=True):
        st.markdown("**It acts, measures, and tries again**")
        st.caption(
            "The agent uses tools: it runs the rule on attacks, reads which ones it missed, edits, and "
            "re-tests, choosing its own next step, until the checks pass or its budget is spent."
        )
    with a2.container(border=True):
        st.markdown("**Its claims are checked, not trusted**")
        st.caption(
            "Whether a rule is good is decided by deterministic checks and by attacks the agent never "
            "saw, never by the model's own say-so. Every call it makes is recorded."
        )
    with a3.container(border=True):
        st.markdown("**It can't do damage**")
        st.caption(
            "Five narrow tools, no file or network access, no way to approve or deploy. Text in threat "
            "reports and community rules is treated as data, not instructions."
        )

    st.markdown("### What it has measured (held-out test, run once after freezing the agent)")
    r1, r2, r3, r4 = st.columns(4)
    r1.metric(
        "Community rules, as published",
        pct(h.community_unseen),
        help="Share of unseen attacker variations caught, mean over test rules that have such variations.",
    )
    r1.caption("of unseen variations caught")
    hd = h.hardened
    r2.metric(
        "After the agent hardened them",
        f"{pct(hd.before)} → {pct(hd.after)}",
        help=f"The same rules before and after hardening, on variation types the agent never saw: "
        f"{hd.runs} runs on {hd.rules} rules (3 runs each). Few rules needed hardening; read as evidence "
        "it works without new false alarms, not as a general rate.",
    )
    r2.caption(f"{hd.rules} rules needed it · {hd.new_false_alarm_runs} new false alarms")
    wr = h.written
    r3.metric(
        "Rules the agent wrote itself",
        f"{pct(wr.before)} → {pct(wr.after)}",
        help=f"With the technique's community rules hidden: {wr.runs} runs, {wr.passed} passed the checks, "
        f"{wr.approved} approved by a reviewer.",
    )
    r3.caption(f"{wr.approved} of {wr.runs} approved by a reviewer")
    r4.metric(
        "Rules deployed without a human",
        "0",
        help="Every rule leaves the agent as a proposal. Review also caught rules that passed every "
        "automatic check but would fire on everyday admin commands.",
    )
    r4.caption("every change was a person's decision")
    st.caption("Details, method and limits: **Lab → Evaluation**. Numbers update as runs are reviewed.")

    st.markdown("### Start where your job is")
    c1, c2, c3, c4 = st.columns(4)
    _role(c1, "📊", "SOC lead", "Where are we weak, and can I show it?", "coverage", "See our posture →")
    _role(
        c2,
        "🧑‍💻",
        "Detection engineer",
        "A new threat came in: are we covered?",
        "request",
        "Check a threat →",
    )
    waiting = f"{pending} waiting for you" if pending else "Nothing waiting"
    _role(
        c3,
        "🧑‍⚖️",
        "Approver",
        f"Is this change safe to ship? ({waiting})",
        "review",
        "Open the review queue →",
    )
    _role(c4, "🗂️", "Manager", "A summary I can share", "reports", "Build a report →")

    st.markdown("### Scope, honestly")
    s1, s2 = st.columns(2)
    with s1.container(border=True):
        st.markdown("**What it does today**")
        st.markdown(
            "- Windows process-creation rules (Sysmon event 1) written in **Sigma**, the open standard\n"
            "- The five evasion tricks from the published study, on 19 attacker techniques\n"
            "- Hardens existing rules, writes new ones when none exist, checks for false alarms\n"
            "- Exports approved rules as Sigma or Elastic queries (Lucene, EQL)\n"
            "- Records every agent step, cost and decision (audit trail)"
        )
    with s2.container(border=True):
        st.markdown("**What it does not do (yet)**")
        st.markdown(
            "- It is **not a SIEM** and doesn't watch live logs: it tests and improves the rules a SIEM runs\n"
            "- Not connected to a SIEM: you paste the exported query (live integration is future work)\n"
            "- Attacks come from Atomic Red Team and their variations are generated, not captured from a "
            "real breach\n"
            "- No rule is evasion-proof: it raises resistance to known tricks and measures it\n"
            "- Linux, cloud and other log sources are out of scope"
        )
    st.caption("A product prototype built for the Agentic Systems course (EECE 798S, AUB, Fall 2026).")
