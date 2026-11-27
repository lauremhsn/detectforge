"""The landing page: what DetectForge is, the problem, how it works, for whom, what it measured, scope.

A standalone page in front of the platform (no app tabs): a product page for someone who has never
heard of Sigma (a professor, a manager), still exact enough for a detection engineer. Its buttons are
plain links into the platform (?page=...). Every number is computed from the saved results
(ui/results.py) the same way as the report; the only fixed figure is the published study it starts
from. The "see it in action" example is a real run: the community rule, the agent's fix, and the
reviewer's decision on it.

All markup here is written in this file (never built from rule or model text), so it carries no
injection risk; the few numbers inserted are formatted by this code.
"""

from pathlib import Path

import streamlit as st

from detectforge.ui.components import pct
from detectforge.ui.results import headline

_CSS = """
<style>
.block-container{padding-top:0!important;max-width:100%!important;padding-left:0!important;padding-right:0!important}
.lp{font-family:Inter,system-ui,sans-serif;color:#13203A;margin:0 -1rem}
.lp a{text-decoration:none}
.lp-bar{background:linear-gradient(90deg,#0F2A5F,#1F4FB8 60%,#0E7490);color:#fff;display:flex;
 align-items:center;justify-content:space-between;padding:.85rem 2.2rem;position:sticky;top:0;z-index:5;
 box-shadow:0 2px 12px rgba(15,42,95,.25)}
.lp-brand{display:flex;gap:.8rem;align-items:center}
.lp-logo{width:2.4rem;height:2.4rem;border-radius:.6rem;background:rgba(255,255,255,.16);display:flex;
 align-items:center;justify-content:center;font-size:1.3rem}
.lp-brand b{font-size:1.2rem;display:block}.lp-brand span{font-size:.82rem;opacity:.85}
.lp-bar .right{display:flex;gap:1rem;align-items:center;font-size:.85rem}
.lp-dot{width:.5rem;height:.5rem;border-radius:50%;background:#34D399;display:inline-block;margin-right:.35rem}
.lp-btn{display:inline-block;border-radius:.6rem;padding:.75rem 1.4rem;font-weight:650;font-size:1rem;
 transition:transform .15s ease, box-shadow .15s ease}
.lp-btn:hover{transform:translateY(-1px);box-shadow:0 6px 18px rgba(31,79,184,.25)}
.lp-btn.primary{background:linear-gradient(90deg,#1F4FB8,#0E7490);color:#fff!important}
.lp-btn.ghost{background:#F6F8FB;color:#13203A!important;border:1px solid #C9D4E2}
.lp-btn.small{padding:.45rem .9rem;font-size:.85rem;background:#fff;color:#1F4FB8!important}
.lp-hero{position:relative;overflow:hidden;text-align:center;padding:5.5rem 1.5rem 4.5rem;
 background:url("NETWORK") center/cover no-repeat,radial-gradient(1200px 500px at 50% -10%,#DCE7F7 0%,#E9EEF4 60%)}
.lp-hero .in{position:relative;max-width:900px;margin:0 auto}
.lp-chip{display:inline-block;background:#DCE7F7;color:#1F4FB8;border:1px solid #B9CBEB;border-radius:999px;
 padding:.35rem .9rem;font-size:.75rem;font-weight:700;letter-spacing:.06em}
.lp-hero h1{font-size:3.6rem!important;line-height:1.08!important;margin:1.2rem 0 1rem;font-weight:800;color:#0F2A5F;padding:0!important}
.lp-hero h1 em{font-style:normal;background:linear-gradient(90deg,#1F4FB8,#0E7490);-webkit-background-clip:text;
 background-clip:text;color:transparent}
.lp-hero p{font-size:1.15rem;color:#3A4A63;max-width:720px;margin:0 auto 2rem;line-height:1.6}
.lp-cta{display:flex;gap:.9rem;justify-content:center;flex-wrap:wrap}
.lp-stats{display:flex;justify-content:center;background:#F6F8FB;border-top:1px solid #D5DEE9;
 border-bottom:1px solid #D5DEE9;flex-wrap:wrap}
.lp-stat{flex:1 1 180px;max-width:260px;text-align:center;padding:1.6rem .8rem;border-right:1px solid #D5DEE9}
.lp-stat:last-child{border-right:none}
.lp-stat b{display:block;font-size:2.1rem;color:#1F4FB8;font-weight:800}
.lp-stat span{font-size:.75rem;letter-spacing:.07em;color:#4B5B73;font-weight:600;text-transform:uppercase}
.lp-sec{max-width:1100px;margin:0 auto;padding:3.6rem 1.5rem 1rem;text-align:center}
.lp-sec h2{font-size:2.2rem!important;padding:0!important;font-weight:800;color:#0F2A5F;margin:0 0 .4rem}
.lp-sec .sub{color:#4B5B73;font-size:1.02rem;margin-bottom:2rem}
.lp-demo{background:#0F1B33;border-radius:1rem;padding:1.3rem 1.5rem;text-align:left;
 box-shadow:0 10px 30px rgba(15,27,51,.25);color:#DDE6F3;font-size:.95rem}
.lp-demo .hd{display:grid;grid-template-columns:2.4fr 1fr 1fr;gap:.6rem;color:#8EA3C4;font-size:.75rem;
 letter-spacing:.06em;text-transform:uppercase;padding-bottom:.6rem;border-bottom:1px solid #22314F}
.lp-row{display:grid;grid-template-columns:2.4fr 1fr 1fr;gap:.6rem;padding:.75rem 0;border-bottom:1px solid #1C2944;
 opacity:0;animation:lpIn .5s ease forwards}
.lp-row:nth-of-type(2){animation-delay:.4s}.lp-row:nth-of-type(3){animation-delay:1.1s}
.lp-row:nth-of-type(4){animation-delay:1.8s}
.lp-row code{font-family:'JetBrains Mono',Consolas,monospace;color:#F3F6FB;font-size:.9rem}
.lp-row small{display:block;color:#8EA3C4;font-size:.75rem;margin-top:.2rem}
.lp-row .hid{background:#B45309;color:#fff;border-radius:.2rem;padding:0 .2rem}
.ok{color:#4ADE80;font-weight:700}.bad{color:#F87171;font-weight:700}.warn{color:#FBBF24;font-weight:700}
.lp-verdict{margin-top:1rem;background:#16233F;border-left:4px solid #FBBF24;border-radius:.4rem;padding:.8rem 1rem;
 opacity:0;animation:lpIn .5s ease 2.6s forwards}
.lp-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:1.1rem;text-align:left}
.lp-card{background:#F6F8FB;border:1px solid #D5DEE9;border-radius:1rem;padding:1.4rem 1.3rem;
 box-shadow:0 2px 6px rgba(15,42,95,.05)}
.lp-card h3{font-size:1.08rem;margin:.7rem 0 .4rem;color:#0F2A5F}
.lp-card p{color:#4B5B73;font-size:.93rem;line-height:1.55;margin:0}
.lp-num{width:2.6rem;height:2.6rem;border-radius:50%;background:linear-gradient(135deg,#1F4FB8,#0E7490);color:#fff;
 display:flex;align-items:center;justify-content:center;font-weight:800}
.lp-card.human{border-color:#1F4FB8;box-shadow:0 0 0 2px #B9CBEB}
.lp-card .go{margin-top:1rem}
.lp-scope{display:grid;grid-template-columns:1fr 1fr;gap:1.1rem;text-align:left}
.lp-scope ul{margin:.6rem 0 0 1.1rem;padding:0;color:#3A4A63;line-height:1.7;font-size:.95rem}
.lp-note{max-width:1100px;margin:2.5rem auto 0;background:#FFF7E6;border:1px solid #F3D9A4;border-radius:.8rem;
 padding:1rem 1.3rem;color:#5A4510;font-size:.9rem;text-align:left}
.lp-foot{margin-top:2.5rem;padding:1.6rem;text-align:center;color:#4B5B73;font-size:.85rem;border-top:1px solid #D5DEE9}
.lp-foot a{color:#1F4FB8;margin:0 .5rem}
.lp-edge{stroke:#7C9CD6;stroke-width:1.4;fill:none;stroke-dasharray:6 6;animation:lpDash 6s linear infinite}
.lp-node{fill:#F6F8FB;stroke:#B9CBEB;stroke-width:1.4}
.lp-lbl{fill:#5B6E8C;font-size:12px;font-family:Inter,sans-serif;text-anchor:middle}
@keyframes lpIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
@keyframes lpDash{to{stroke-dashoffset:-120}}
@media (prefers-reduced-motion: reduce){.lp-row,.lp-verdict{animation:none;opacity:1}.lp-edge{animation:none}}
@media (max-width:760px){.lp-hero h1{font-size:2.3rem!important}.lp-scope{grid-template-columns:1fr}.lp-bar{padding:.7rem 1rem}}
</style>
"""

_NETWORK = """
<svg viewBox="0 0 1200 520" preserveAspectRatio="xMidYMid slice" aria-hidden="true">
 <path class="lp-edge" d="M140 120 L330 250 L560 150 L800 260 L1050 140"/>
 <path class="lp-edge" d="M330 250 L250 420 L520 410 L800 260 L960 420"/>
 <path class="lp-edge" d="M560 150 L520 410"/>
 <g><circle class="lp-node" cx="140" cy="120" r="46"/><text class="lp-lbl" x="140" y="124">Threat report</text></g>
 <g><circle class="lp-node" cx="330" cy="250" r="46"/><text class="lp-lbl" x="330" y="254">Sigma rule</text></g>
 <g><circle class="lp-node" cx="560" cy="150" r="46"/><text class="lp-lbl" x="560" y="154">Attack variants</text></g>
 <g><circle class="lp-node" cx="800" cy="260" r="46"/><text class="lp-lbl" x="800" y="264">Agent</text></g>
 <g><circle class="lp-node" cx="1050" cy="140" r="46"/><text class="lp-lbl" x="1050" y="144">Reviewer</text></g>
 <g><circle class="lp-node" cx="250" cy="420" r="46"/><text class="lp-lbl" x="250" y="424">SOC analyst</text></g>
 <g><circle class="lp-node" cx="520" cy="410" r="46"/><text class="lp-lbl" x="520" y="414">Quality checks</text></g>
 <g><circle class="lp-node" cx="960" cy="420" r="46"/><text class="lp-lbl" x="960" y="424">SIEM</text></g>
</svg>
"""


def _network_uri() -> str:
    from urllib.parse import quote

    svg = (
        _NETWORK.strip()
        .replace(
            "<svg ",
            "<svg xmlns='http://www.w3.org/2000/svg' ",
            1,
        )
        .replace(
            'aria-hidden="true">',
            'aria-hidden="true"><style>.lp-edge{stroke:#7C9CD6;stroke-width:1.4;fill:none;stroke-dasharray:6 6;'
            "animation:d 6s linear infinite}@keyframes d{to{stroke-dashoffset:-120}}.lp-node{fill:#F6F8FB;"
            "stroke:#B9CBEB;stroke-width:1.4}.lp-lbl{fill:#5B6E8C;font-size:12px;font-family:sans-serif;"
            "text-anchor:middle}</style><g opacity='0.6'>",
            1,
        )
        .replace("</svg>", "</g></svg>")
    )
    return "data:image/svg+xml;utf8," + quote(svg)


def _link(page: str, text: str, kind: str = "primary") -> str:
    return f"<a class='lp-btn {kind}' href='?page={page}' target='_self'>{text}</a>"


def landing_html(data_dir: Path, runs_dir: Path, pending: int) -> str:
    h = headline(data_dir, runs_dir)
    missed = pct(1 - h.community_unseen) if h.community_unseen is not None else "n/a"
    hd, wr = h.hardened, h.written
    waiting = f"{pending} waiting for you" if pending else "nothing waiting"
    css = _CSS.replace("NETWORK", _network_uri())
    return f"""{css}
<div class="lp">
 <div class="lp-bar">
  <div class="lp-brand"><div class="lp-logo">🛡️</div>
   <div><b>DetectForge</b><span>Adversarial validation of detection rules · Sigma · Windows process creation</span></div></div>
  <div class="right"><span><span class="lp-dot"></span>Prototype</span>{_link("coverage", "Open the platform →", "small")}</div>
 </div>

 <div class="lp-hero">
  <div class="in">
   <span class="lp-chip">SIGMA RULES · SOC · SIEM · AGENTIC VALIDATION</span>
   <h1>Your rules exist.<br><em>Do they catch the attacker?</em></h1>
   <p>DetectForge replays every detection rule against the disguises real attackers use, lets an AI agent
   fix the gaps and prove each fix on attacks it never saw, and puts every change in front of a person
   before it reaches your SIEM.</p>
   <div class="lp-cta">{_link("coverage", "See our coverage →")}{_link("request", "Check a threat", "ghost")}</div>
  </div>
 </div>

 <div class="lp-stats">
  <div class="lp-stat"><b>129 / 292</b><span>popular rules beaten by simple tricks*</span></div>
  <div class="lp-stat"><b>{missed}</b><span>disguised attacks missed as published</span></div>
  <div class="lp-stat"><b>{pct(hd.before)} → {pct(hd.after)}</b><span>caught after hardening</span></div>
  <div class="lp-stat"><b>{pct(wr.after)}</b><span>caught by rules it wrote</span></div>
  <div class="lp-stat"><b>0</b><span>changes deployed without a person</span></div>
 </div>

 <div class="lp-sec">
  <h2>See it in action</h2>
  <div class="sub">One real case: dumping Windows password hashes with <code>reg.exe</code></div>
  <div class="lp-demo">
   <div class="hd"><span>Command seen on a machine</span><span>Community rule</span><span>Agent's fix</span></div>
   <div class="lp-row"><div><code>reg save HKLM\\sam C:\\Temp\\sam</code><small>The attack, as written</small></div>
    <div class="ok">✓ caught</div><div class="ok">✓ caught</div></div>
   <div class="lp-row"><div><code>reg s<span class="hid">­</span>ave HKLM\\sam C:\\Temp\\sam</code>
    <small>Same attack, one invisible character inserted (highlighted). Windows ignores it.</small></div>
    <div class="bad">✗ missed</div><div class="ok">✓ caught</div></div>
   <div class="lp-row"><div><code>reg query HKLM\\SECURITY\\Policy</code><small>An administrator reading a setting: legitimate</small></div>
    <div class="ok">✓ silent</div><div class="warn">⚠ false alarm</div></div>
   <div class="lp-verdict">🧑‍⚖️ <b>Reviewer: rejected.</b> The fix closed the evasion but would alert on routine admin
    work, which the automatic checks couldn't see. Nothing reached the SIEM; the agent tries again.</div>
  </div>
 </div>

 <div class="lp-sec">
  <h2>How it works</h2>
  <div class="sub">From "are we covered?" to an approved, deployable rule</div>
  <div class="lp-grid">
   <div class="lp-card"><div class="lp-num">1</div><h3>Find</h3><p>Ask in plain words or paste a threat report.
    DetectForge maps it to attacker techniques and finds the community rules that claim to catch them.</p></div>
   <div class="lp-card"><div class="lp-num">2</div><h3>Attack</h3><p>Each rule is replayed against real attack
    commands and five published disguise tricks, plus legitimate commands that look alike.</p></div>
   <div class="lp-card"><div class="lp-num">3</div><h3>Harden</h3><p>An AI agent reads exactly what slipped past,
    edits the rule and re-tests it, step by step. If no rule exists, it writes one.</p></div>
   <div class="lp-card"><div class="lp-num">4</div><h3>Check</h3><p>Fixed, automatic checks, not the AI, decide if
    a proposal is good enough: it must still catch every plain attack and add no false alarms.</p></div>
   <div class="lp-card human"><div class="lp-num">5</div><h3>Approve</h3><p>A person sees the evidence and decides.
    The agent can propose; it can never deploy.</p></div>
   <div class="lp-card"><div class="lp-num">6</div><h3>Export</h3><p>Approved rules leave as Sigma or a ready
    Elastic query, with a report of what changed and why.</p></div>
  </div>
 </div>

 <div class="lp-sec">
  <h2>Agentic, for a reason</h2>
  <div class="sub">Not a chatbot that answers once: a loop that has to prove its work</div>
  <div class="lp-grid">
   <div class="lp-card"><h3>It acts and re-checks</h3><p>The agent calls tools to test its own rule, reads which
    attacks it missed, and chooses its next step until the checks pass or its budget runs out.</p></div>
   <div class="lp-card"><h3>It is judged on what it never saw</h3><p>Success is measured on disguise types kept
    hidden from it, so it can't just memorise the test. Every model and tool call is recorded.</p></div>
   <div class="lp-card"><h3>It can't do damage</h3><p>Five narrow tools, no file or network access, no way to
    approve or deploy. Threat reports and rules are treated as data, never as instructions.</p></div>
  </div>
 </div>

 <div class="lp-sec">
  <h2>Built for the people who own detection</h2>
  <div class="sub">Start where your job is</div>
  <div class="lp-grid">
   <div class="lp-card"><h3>📊 SOC lead</h3><p>Where are we weak, and can I show it?</p>
    <div class="go">{_link("coverage", "Coverage map →", "ghost")}</div></div>
   <div class="lp-card"><h3>🧑‍💻 Detection engineer</h3><p>A threat came in: are we covered, and can we fix it?</p>
    <div class="go">{_link("request", "Check a threat →", "ghost")}</div></div>
   <div class="lp-card"><h3>🧑‍⚖️ Approver</h3><p>Is this change safe to ship? ({waiting})</p>
    <div class="go">{_link("review", "Review queue →", "ghost")}</div></div>
   <div class="lp-card"><h3>🗂️ Manager</h3><p>A clear summary I can forward.</p>
    <div class="go">{_link("reports", "Build a report →", "ghost")}</div></div>
  </div>
 </div>

 <div class="lp-sec">
  <h2>Scope, honestly</h2>
  <div class="lp-scope">
   <div class="lp-card"><h3>What it does today</h3><ul>
    <li>Windows process-creation rules (Sysmon event 1) in Sigma, the open standard</li>
    <li>Five published evasion tricks across 19 attacker techniques</li>
    <li>Hardens rules, writes missing ones, checks for false alarms</li>
    <li>Exports approved rules as Sigma or Elastic queries (Lucene, EQL)</li>
    <li>Records every agent step, its cost and every decision</li></ul></div>
   <div class="lp-card"><h3>What it does not do (yet)</h3><ul>
    <li>It is not a SIEM and doesn't watch live logs: it improves the rules a SIEM runs</li>
    <li>Not connected to a SIEM: approved queries are exported and pasted</li>
    <li>Attack variations are generated from Atomic Red Team, not captured from a breach</li>
    <li>No rule is evasion-proof: it raises and measures resistance to known tricks</li>
    <li>Linux, cloud and other log sources are out of scope</li></ul></div>
  </div>
 </div>

 <div class="lp-note">🛡️ <b>Decision support, not autopilot.</b> Every rule change is reviewed by a person before
  deployment. Results are measured on generated attack variations and a fixed set of look-alike commands;
  your environment may differ. *Uetz et al., USENIX Security 2024.</div>

 <div class="lp-foot">EECE 798S Agentic Systems · American University of Beirut · Fall 2026 · Rules: SigmaHQ (DRL 1.1) ·
  Attacks: Atomic Red Team (MIT)<br>{_link("coverage", "Open the platform", "small")}
  <a href="?page=operations" target="_self">How we evaluated it</a></div>
</div>
"""


def home_page(data_dir: Path, runs_dir: Path, pending: int) -> None:
    st.html(landing_html(data_dir, runs_dir, pending))
