"""The landing page: what DetectForge is, the problem, how it works, the evidence, for whom, scope.

A standalone page in front of the platform (no app tabs), built around DetectForge's own story: a
replay console in the hero (a real, approved case: a community rule misses two disguised versions of
an attack, the agent's fix catches both, including a trick it never saw, and stays silent on legitimate
use), the five evasion tricks on real commands,
the forge loop, and the measured evidence. Its buttons are plain links into the platform (?page=...).

Every number is computed from the saved results (ui/results.py) the same way as the report; the only
fixed figures are the published study and the Elastic parity run (data/eval/results). All markup is
written in this file, never built from rule or model text, so it carries no injection risk.
"""

import json
from pathlib import Path

import streamlit as st

from detectforge.ui.components import pct
from detectforge.ui.results import headline

INK, STONE, CARD, LINE = "#1F2328", "#F3F0EB", "#FBF9F6", "#D8D1C6"
EMBER, EMBER_DARK, STEEL, GREEN, AMBER = "#C2551F", "#A8461A", "#3D5A73", "#2F7D4F", "#B7791F"

_CSS = f"""
<style>
.block-container{{padding-top:0!important;max-width:100%!important;padding-left:0!important;padding-right:0!important}}
.lp{{font-family:Inter,system-ui,sans-serif;color:{INK};margin:0 -1rem;background:{STONE}}}
.lp a{{text-decoration:none}}
.lp-nav{{display:flex;align-items:center;justify-content:space-between;padding:1rem 2.4rem;background:{INK};color:#F3F0EB;
 position:sticky;top:0;z-index:5}}
.lp-nav .brand{{display:flex;align-items:center;gap:.7rem;font-weight:800;font-size:1.15rem;letter-spacing:.01em}}
.lp-nav .mark{{width:2.1rem;height:2.1rem;border-radius:.45rem;background:{EMBER};display:flex;align-items:center;
 justify-content:center;font-size:1.1rem}}
.lp-nav .links{{display:flex;gap:1.6rem;align-items:center;font-size:.9rem}}
.lp-nav .links a{{color:#D9D2C7}}.lp-nav .links a:hover{{color:#fff}}
.lp-btn{{display:inline-block;border-radius:.55rem;padding:.8rem 1.35rem;font-weight:700;font-size:1rem;transition:transform .15s}}
.lp-btn:hover{{transform:translateY(-1px)}}
.lp-btn.fire{{background:{EMBER};color:#fff!important;box-shadow:0 6px 16px rgba(194,85,31,.28)}}
.lp-btn.line{{border:1.5px solid {INK};color:{INK}!important}}
.lp-btn.small{{padding:.45rem .9rem;font-size:.85rem}}
.lp-hero{{position:relative;overflow:hidden;padding:4.5rem 2.4rem 4rem;border-bottom:1px solid {LINE}}}
.lp-matrix{{position:absolute;inset:0;display:grid;grid-template-columns:repeat(26,1fr);gap:6px;padding:14px;opacity:.55}}
.lp-matrix i{{border-radius:4px;background:#E7E1D7}}
.lp-matrix i.e{{background:#F0C9B0;animation:lpGlow 4.5s ease-in-out infinite}}
.lp-matrix i.g{{background:#CFE3D5;animation:lpGlow 5.5s ease-in-out infinite}}
.lp-hero .in{{position:relative;display:grid;grid-template-columns:1.05fr 1fr;gap:3rem;max-width:1220px;margin:0 auto;align-items:center}}
.lp-eyebrow{{font-size:.78rem;font-weight:800;letter-spacing:.14em;color:{EMBER_DARK}}}
.lp-hero h1{{font-size:3.4rem!important;line-height:1.06!important;font-weight:800;margin:.9rem 0 1.1rem;padding:0!important;color:{INK}}}
.lp-hero h1 span{{background:linear-gradient(transparent 62%,#F3C3A4 62%);padding:0 .1em}}
.lp-hero p{{font-size:1.12rem;line-height:1.6;color:#3F3A33;margin:0 0 1.8rem;max-width:560px}}
.lp-cta{{display:flex;gap:.8rem;flex-wrap:wrap}}
.lp-console{{background:{INK};border-radius:.9rem;padding:1.1rem 1.2rem 1.2rem;color:#E9E4DC;font-family:'JetBrains Mono',Consolas,monospace;
 font-size:.86rem;box-shadow:0 18px 40px rgba(31,35,40,.28)}}
.lp-console .bar{{display:flex;gap:.4rem;margin-bottom:.8rem}}.lp-console .bar b{{width:.7rem;height:.7rem;border-radius:50%;background:#4A4F57}}
.lp-console .t{{color:#9AA0A8;font-size:.78rem;margin-left:.6rem;font-family:Inter,sans-serif}}
.lp-ln{{display:flex;justify-content:space-between;gap:1rem;padding:.32rem 0;opacity:0;animation:lpIn .35s ease forwards;white-space:nowrap}}
.lp-ln code{{color:#F4EFE7;font-family:inherit;overflow:hidden;text-overflow:ellipsis}}
.lp-ln.note{{display:block;color:#C9B9A4;font-family:Inter,sans-serif;font-size:.84rem;white-space:normal}}
.tag{{font-weight:800;font-size:.75rem;letter-spacing:.06em;border-radius:.3rem;padding:.1rem .45rem;flex:none}}
.tag.ok{{background:#23452F;color:#7EE2A0}}.tag.si{{background:#2A3542;color:#A9C4DD}}.tag.ev{{background:#4A2618;color:#FF9F6B}}.tag.fa{{background:#4A3A12;color:#F7C873}}
.hid{{background:{EMBER};color:#fff;border-radius:.15rem;padding:0 .15rem}}
.lp-sec{{max-width:1220px;margin:0 auto;padding:4rem 2.4rem 0}}
.lp-sec h2{{font-size:2.1rem!important;font-weight:800;margin:0 0 .4rem;padding:0!important;color:{INK}}}
.lp-sec .lead{{color:#5B5348;font-size:1.05rem;margin:0 0 1.8rem;max-width:760px}}
.lp-tricks{{display:grid;grid-template-columns:repeat(5,1fr);gap:.9rem}}
.lp-trick{{background:{CARD};border:1px solid {LINE};border-radius:.8rem;padding:1rem;font-size:.88rem}}
.lp-trick b{{display:block;font-size:.98rem;margin-bottom:.25rem}}
.lp-trick small{{color:#5B5348;display:block;margin-bottom:.6rem;line-height:1.4}}
.lp-trick code{{display:block;font-family:'JetBrains Mono',Consolas,monospace;font-size:.78rem;padding:.35rem .45rem;border-radius:.35rem;margin-top:.3rem;word-break:break-all}}
.lp-trick .was{{background:#EFEAE2;color:#5B5348}}.lp-trick .now{{background:#FBEDE4;color:{INK}}}
.lp-trick mark{{background:#F3C3A4;color:{INK};border-radius:.15rem;padding:0 .1rem}}
.lp-loop{{position:relative;display:grid;grid-template-columns:repeat(6,1fr);gap:.8rem;padding-top:1.2rem}}
.lp-loop:before{{content:"";position:absolute;top:2.35rem;left:6%;right:6%;height:3px;background:{LINE}}}
.lp-spark{{position:absolute;top:2.05rem;left:6%;width:.75rem;height:.75rem;border-radius:50%;background:{EMBER};
 box-shadow:0 0 0 6px rgba(194,85,31,.18);animation:lpRun 7s cubic-bezier(.6,0,.4,1) infinite}}
.lp-st{{position:relative;text-align:center;padding:0 .3rem}}
.lp-st .dot{{width:2.4rem;height:2.4rem;margin:0 auto .8rem;border-radius:50%;background:{CARD};border:2px solid {STEEL};
 display:flex;align-items:center;justify-content:center;font-weight:800;color:{STEEL};position:relative;z-index:1}}
.lp-st.h .dot{{border-color:{EMBER};color:{EMBER};background:#FBEDE4}}
.lp-st b{{display:block;margin-bottom:.3rem}}.lp-st span{{color:#5B5348;font-size:.86rem;line-height:1.45}}
.lp-ev{{display:grid;grid-template-columns:repeat(4,1fr);gap:.9rem}}
.lp-card{{background:{CARD};border:1px solid {LINE};border-radius:.8rem;padding:1.15rem 1.2rem}}
.lp-card .k{{font-size:.76rem;letter-spacing:.08em;font-weight:700;color:#6B6257;text-transform:uppercase}}
.lp-card .v{{font-size:1.9rem;font-weight:800;margin:.25rem 0 .5rem}}
.lp-card p{{color:#5B5348;font-size:.86rem;line-height:1.45;margin:.5rem 0 0}}
.bar2{{height:.5rem;border-radius:999px;background:#E7E1D7;position:relative;margin:.35rem 0}}
.bar2 i{{position:absolute;left:0;top:0;bottom:0;border-radius:999px}}
.bar2 .b{{background:#E0A458}}.bar2 .a{{background:{STEEL}}}
.lp-roles{{display:grid;grid-template-columns:repeat(4,1fr);gap:.9rem}}
.lp-roles .lp-card b{{font-size:1.05rem}}.lp-roles .go{{margin-top:.9rem}}
.lp-scope{{display:grid;grid-template-columns:1fr 1fr;gap:.9rem}}
.lp-scope ul{{margin:.5rem 0 0 1.1rem;padding:0;line-height:1.75;color:#3F3A33;font-size:.94rem}}
.lp-foot{{margin-top:4rem;background:{INK};color:#C9C1B5;padding:1.8rem 2.4rem;text-align:center;font-size:.86rem;line-height:1.7}}
.lp-foot a{{color:#F3C3A4;margin:0 .5rem}}
@keyframes lpIn{{from{{opacity:0;transform:translateX(-4px)}}to{{opacity:1;transform:none}}}}
@keyframes lpGlow{{0%,100%{{opacity:.35}}50%{{opacity:1}}}}
@keyframes lpRun{{0%{{left:6%}}85%{{left:calc(94% - .75rem)}}100%{{left:calc(94% - .75rem);opacity:0}}}}
@media (prefers-reduced-motion: reduce){{.lp-ln{{animation:none;opacity:1}}.lp-spark,.lp-matrix i{{animation:none}}}}
@media (max-width:900px){{.lp-hero .in,.lp-scope{{grid-template-columns:1fr}}.lp-tricks,.lp-ev,.lp-roles{{grid-template-columns:1fr 1fr}}
 .lp-loop{{grid-template-columns:1fr 1fr 1fr}}.lp-loop:before,.lp-spark{{display:none}}.lp-hero h1{{font-size:2.4rem!important}}
 .lp-nav .links a.hide{{display:none}}}}
</style>
"""

# Which matrix tiles glow (ember: evaded; green: caught). A fixed pattern, so the page is stable.
_MATRIX = "".join(
    "<i class='e'></i>" if i % 17 == 3 or i % 23 == 11 else "<i class='g'></i>" if i % 13 == 5 else "<i></i>"
    for i in range(26 * 9)
)

# Run 1045b6d8 (frozen prompt, approved): the insertion example from Uetz et al., caught after hardening
# although the agent never saw an insertion, and still silent on legitimate scheduled tasks.
_CONSOLE = [
    ("note", "▸ replaying <b>Schtasks Creation With SYSTEM Privileges</b> (SigmaHQ)"),
    ("ok", "schtasks /create /tn Upd /sc onstart /ru system …"),
    (
        "ev",
        "schtasks /<span class='hid'>\"</span>create<span class='hid'>\"</span> /tn Upd /sc onstart /ru system …",
    ),
    (
        "ev",
        "schtasks <span class='hid'>-</span>create <span class='hid'>-</span>tn Upd <span class='hid'>-</span>sc onstart …",
    ),
    ("note", "⚒ agent: reads the misses, edits the rule, re-tests. It never sees the quoted trick."),
    (
        "ok",
        "schtasks /<span class='hid'>\"</span>create<span class='hid'>\"</span> /tn Upd /sc onstart /ru system …",
    ),
    (
        "ok",
        "schtasks <span class='hid'>-</span>create <span class='hid'>-</span>tn Upd <span class='hid'>-</span>sc onstart …",
    ),
    ("si", "schtasks /create /tn CompanyUpdate /sc daily …"),
    ("note", "🧑‍⚖️ reviewer: <b>approved</b>. Exported to the SIEM as an EQL query."),
]
_TAG = {
    "ok": ("ok", "DETECTED"),
    "ev": ("ev", "EVADED"),
    "fa": ("fa", "FALSE ALARM"),
    "si": ("si", "SILENT · LEGIT"),
}

_TRICKS = [
    (
        "Insertion",
        "Add characters Windows ignores",
        "schtasks /create /tn X",
        'schtasks /<mark>"</mark>create<mark>"</mark> /tn X',
    ),
    (
        "Substitution",
        "Swap a character for an equivalent one",
        "schtasks /create /tn X",
        "schtasks <mark>-</mark>create /tn X",
    ),
    ("Omission", "Drop what isn't needed", "cscript<mark>.exe</mark> evil.vbs", "cscript evil.vbs"),
    (
        "Reordering",
        "Same arguments, another order",
        "msiexec /q /i http://x",
        "msiexec <mark>/i http://x /q</mark>",
    ),
    ("Recoding", "Same value, another encoding", "ping 127.0.0.1", "ping <mark>2130706433</mark>"),
]

_LOOP = [
    (
        "1",
        "Find",
        "Plain words or a threat report → the techniques and the community rules that claim them",
        False,
    ),
    ("2", "Attack", "Replay each rule on real attack commands and their disguises", False),
    ("3", "Forge", "The agent reads what slipped past, edits, re-tests, repeats", False),
    ("4", "Check", "Fixed automatic checks, not the AI, decide if it's good enough", False),
    ("5", "Approve", "A person sees the evidence and decides; the agent can't deploy", True),
    ("6", "Export", "Sigma or an Elastic query, with the report of what changed", False),
]


def _link(page: str, text: str, kind: str = "fire") -> str:
    return f"<a class='lp-btn {kind}' href='?page={page}' target='_self'>{text}</a>"


def _bars(before: float | None, after: float | None) -> str:
    b, a = (before or 0) * 100, (after or 0) * 100
    return (
        f"<div class='bar2'><i class='b' style='width:{b:.0f}%'></i></div>"
        f"<div class='bar2'><i class='a' style='width:{a:.0f}%'></i></div>"
    )


def _parity(data_dir: Path) -> str:
    try:
        rows = json.loads(
            (data_dir / "eval" / "results" / "elastic_parity_eql.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        return "n/a"
    community = [r for r in rows if r.get("rule", "").startswith("community")]
    same = sum(1 for r in community if "error" not in r and not r["only_ours"] and not r["only_elastic"])
    return f"{same} / {len(community)}"


def landing_html(data_dir: Path, runs_dir: Path, pending: int) -> str:
    h = headline(data_dir, runs_dir)
    hd, wr = h.hardened, h.written
    waiting = f"{pending} waiting" if pending else "nothing waiting"
    delay = 0.4
    lines = []
    for kind, text in _CONSOLE:
        if kind == "note":
            lines.append(f"<div class='lp-ln note' style='animation-delay:{delay:.1f}s'>{text}</div>")
        else:
            cls, label = _TAG[kind]
            lines.append(
                f"<div class='lp-ln' style='animation-delay:{delay:.1f}s'><code>{text}</code>"
                f"<span class='tag {cls}'>{label}</span></div>"
            )
        delay += 0.7
    tricks = "".join(
        f"<div class='lp-trick'><b>{name}</b><small>{what}</small><code class='was'>{was}</code>"
        f"<code class='now'>{now}</code></div>"
        for name, what, was, now in _TRICKS
    )
    loop = "".join(
        f"<div class='lp-st{' h' if human else ''}'><div class='dot'>{n}</div><b>{title}</b><span>{text}</span></div>"
        for n, title, text, human in _LOOP
    )
    return f"""{_CSS}
<div class="lp">
 <div class="lp-nav">
  <div class="brand"><div class="mark">⚒</div>DetectForge</div>
  <div class="links"><a class="hide" href="#tricks">The problem</a><a class="hide" href="#loop">How it works</a>
   <a class="hide" href="#evidence">Evidence</a>{_link("coverage", "Open the platform →", "fire small")}</div>
 </div>

 <div class="lp-hero"><div class="lp-matrix">{_MATRIX}</div>
  <div class="in">
   <div>
    <div class="lp-eyebrow">DETECTION-RULE HARDENING FOR SOC TEAMS</div>
    <h1>Attackers disguise.<br><span>Your rules should still fire.</span></h1>
    <p>DetectForge replays your Sigma detection rules against the tricks attackers use to slip past them,
    has an AI agent forge stronger versions and prove them on attacks it never saw, and leaves every
    change to a person before it reaches your SIEM.</p>
    <div class="lp-cta">{_link("coverage", "See where you're exposed →")}{_link("request", "Check a threat report", "line")}</div>
   </div>
   <div class="lp-console"><div class="bar"><b></b><b></b><b></b><span class="t">replay · a real case from our runs</span></div>
    {"".join(lines)}
   </div>
  </div>
 </div>

 <div class="lp-sec" id="tricks">
  <h2>Five ways an attacker slips past a rule</h2>
  <p class="lead">A published study found that these simple tricks beat <b>129 of 292</b> widely used community
  rules (Uetz et al., USENIX Security 2024). Windows runs the disguised command exactly the same; the rule, looking for
  the exact text, stays silent.</p>
  <div class="lp-tricks">{tricks}</div>
 </div>

 <div class="lp-sec" id="loop">
  <h2>The forge loop</h2>
  <p class="lead">Agentic, for a reason: the agent acts, measures and tries again with its own tools, while
  fixed checks and a person, not the model, decide what ships.</p>
  <div class="lp-loop"><div class="lp-spark"></div>{loop}</div>
 </div>

 <div class="lp-sec" id="evidence">
  <h2>Measured, not claimed</h2>
  <p class="lead">Judged on disguise types the agent never saw, on techniques run once after the agent was frozen.
  Amber: before. Steel: after.</p>
  <div class="lp-ev">
   <div class="lp-card"><div class="k">Community rules as published</div><div class="v">{pct(h.community_unseen)}</div>
    {_bars(h.community_unseen, h.community_unseen)}<p>of unseen disguised attacks caught. The rest slip past today.</p></div>
   <div class="lp-card"><div class="k">After the agent hardened them</div><div class="v">{pct(hd.before)} → {pct(hd.after)}</div>
    {_bars(hd.before, hd.after)}<p>{hd.rules} rules needed it; {hd.new_false_alarm_runs} new false alarms on unseen look-alikes.</p></div>
   <div class="lp-card"><div class="k">Rules the agent wrote itself</div><div class="v">{pct(wr.before)} → {pct(wr.after)}</div>
    {_bars(wr.before, wr.after)}<p>With the community rules hidden; {wr.approved} of {wr.runs} approved by a reviewer.</p></div>
   <div class="lp-card"><div class="k">Same result in a real SIEM</div><div class="v">{_parity(data_dir)}</div>
    <p>community rules fire on exactly the same events in Elasticsearch (EQL) as in DetectForge's tests.
    And: 0 changes deployed without a person.</p></div>
  </div>
 </div>

 <div class="lp-sec">
  <h2>Who it's for</h2>
  <p class="lead">One workspace, four jobs. Start where yours is.</p>
  <div class="lp-roles">
   <div class="lp-card"><b>📊 SOC lead</b><p>Where are we exposed, and what do we fix first?</p>
    <div class="go">{_link("coverage", "Coverage map →", "line small")}</div></div>
   <div class="lp-card"><b>🧑‍💻 Detection engineer</b><p>A report came in: are we covered, and can we fix it?</p>
    <div class="go">{_link("request", "Check a threat →", "line small")}</div></div>
   <div class="lp-card"><b>🧑‍⚖️ Approver</b><p>Is this change safe to ship? ({waiting})</p>
    <div class="go">{_link("review", "Review queue →", "line small")}</div></div>
   <div class="lp-card"><b>🗂️ Manager</b><p>A clear summary to forward.</p>
    <div class="go">{_link("reports", "Build a report →", "line small")}</div></div>
  </div>
 </div>

 <div class="lp-sec">
  <h2>Scope, honestly</h2>
  <div class="lp-scope">
   <div class="lp-card"><b>What it does</b><ul>
    <li>Sigma rules for Windows process creation (Sysmon event 1)</li>
    <li>The five published evasion tricks, across 19 attacker techniques</li>
    <li>Hardens rules, writes missing ones, checks for false alarms</li>
    <li>Exports to Elastic (EQL recommended), with an audit trail of every step</li></ul></div>
   <div class="lp-card"><b>What it doesn't (yet)</b><ul>
    <li>It isn't a SIEM and doesn't watch live logs; it improves the rules a SIEM runs</li>
    <li>Not connected to your SIEM: approved queries are exported</li>
    <li>Attack variations are generated from Atomic Red Team, not captured from a breach</li>
    <li>No rule is evasion-proof; it raises and measures resistance to known tricks</li></ul></div>
  </div>
 </div>

 <div class="lp-foot">Decision support, not autopilot: every rule change is approved by a person.<br>
  EECE 798S Agentic Systems · American University of Beirut · Fall 2026 · Rules: SigmaHQ (DRL 1.1) · Attacks: Atomic Red Team (MIT)<br>
  {_link("coverage", "Open the platform", "fire small")} <a href="?page=operations" target="_self">How we evaluated it</a></div>
</div>
"""


def home_page(data_dir: Path, runs_dir: Path, pending: int) -> None:
    st.html(landing_html(data_dir, runs_dir, pending))
