"""Settings: who may approve, how approval is protected, and what this workspace is made of.

Read-only on purpose: reviewer keys are secrets managed outside the app (an admin sets them in the
server's environment), so the UI only shows *who* can approve, never a key, and explains how a real
deployment would run access.
"""

from pathlib import Path

import streamlit as st

from detectforge.config import get_settings
from detectforge.gate import GateConfig
from detectforge.review import list_runs, parse_reviewer_keys
from detectforge.ui.components import md, table
from detectforge.ui.navigation import header


def settings_page(data_dir: Path, runs_dir: Path) -> None:
    header("settings", "Who can approve rules, how approval is protected, and what this workspace contains.")
    settings = get_settings()
    team, workspace, agent = st.tabs(["Team & access", "Workspace", "Agent & checks"])

    with team:
        try:
            reviewers = sorted(set(parse_reviewer_keys(settings.reviewer_keys).values()))
            problem = None
        except ValueError as e:
            reviewers, problem = [], str(e)
        st.markdown("#### Who can approve")
        if problem:
            st.error(f"The reviewer configuration is invalid: {md(problem)}")
        elif reviewers:
            st.markdown(" ".join(f"`{md(r)}`" for r in reviewers))
            st.caption(f"{len(reviewers)} reviewer(s). Their keys are never shown, logged or stored in runs.")
        else:
            st.warning("No reviewers are set up, so nothing can be approved yet.")
        st.markdown("#### How approval works")
        c1, c2, c3 = st.columns(3)
        with c1.container(border=True):
            st.markdown("**1 · An admin issues a key**")
            st.caption(
                "Each approver gets a personal key (at least 16 random characters). The admin puts "
                "`name:key` pairs in the server's secret configuration "
                "(`DETECTFORGE_REVIEWER_KEYS`), never in the code or the repository."
            )
        with c2.container(border=True):
            st.markdown("**2 · The approver signs a decision**")
            st.caption(
                "On the Review page the approver enters their key with each approve or reject. The key "
                "identifies who decided; the decision is saved with their name, the time and a comment."
            )
        with c3.container(border=True):
            st.markdown("**3 · Guessing is blocked**")
            st.caption(
                "Repeated wrong keys lock decisions for a while, from every session of the server, so a "
                "key can't be found by trying many."
            )
        st.markdown("#### In a real company")
        table(
            [
                {"role": "Viewer (manager, auditor)", "can": "see posture and reports", "how": "single sign-on group"},
                {"role": "Detection engineer", "can": "test rules, ask the agent to harden or write", "how": "single sign-on group"},
                {"role": "Approver", "can": "approve or reject proposals", "how": "personal key or SSO role; not the person who asked for the change"},
                {"role": "Admin", "can": "issue and revoke approver access, set budgets", "how": "secrets manager"},
            ]
        )  # fmt: skip
        st.caption(
            "This prototype has no login: anyone who can open it can look, but only a key holder can "
            "decide. Single sign-on and roles are the next step for a team deployment."
        )

    with workspace:
        runs = list_runs(runs_dir)
        evaluation = sorted((data_dir / "eval").glob("*.jsonl"))
        lines = {p.name: sum(1 for _ in p.open(encoding="utf-8")) for p in evaluation}
        c1, c2, c3 = st.columns(3)
        c1.metric("Agent runs saved", len(runs))
        c2.metric("Decisions recorded", sum(r.decision is not None for r in runs))
        c3.metric("Test events", sum(lines.values()))
        st.markdown("**Where things live**")
        table(
            [
                {"what": "Community rules", "where": f"{data_dir / 'sigmahq'}", "note": "a pinned SigmaHQ release"},
                {"what": "Attack library", "where": f"{data_dir / 'eval'}", "note": ", ".join(f"{k} ({v})" for k, v in lines.items())},
                {"what": "Agent runs and decisions", "where": f"{runs_dir}", "note": "one file per run, plus .review.json"},
                {"what": "Approved rules", "where": f"{runs_dir / 'approved'}", "note": "ready to deploy"},
            ]
        )  # fmt: skip
        st.caption(
            "To start from your own rules, put them through Rules → Import; to add legitimate commands "
            "from your environment, add them to the look-alike set so every rule is checked against them."
        )

    with agent:
        gate = GateConfig()
        c1, c2, c3 = st.columns(3)
        c1.metric("Minimum catch rate (tuning variations)", f"{gate.min_evasion_resistance:.0%}",
                  help="A proposal must catch at least this share of the variations it was tuned on.")  # fmt: skip
        c2.metric(
            "False alarms allowed", gate.max_false_alarms, help="On the legitimate look-alikes it can see."
        )
        c3.metric("Model calls per rule", f"{settings.max_model_calls} / {settings.write_max_model_calls}",
                  help="Hardening / writing. When spent, the run stops and asks a person.")  # fmt: skip
        st.markdown(
            f"**Model:** `{md(settings.model)}`, fallback `{md(settings.fallback_model or 'none')}` · "
            f"**daily request limit:** {settings.daily_request_limit} · **agent runs from the UI:** "
            f"{'on' if settings.ui_allow_agent_runs else 'off (set DETECTFORGE_UI_ALLOW_AGENT_RUNS)'}"
        )
        st.caption("These are set by the server's configuration, so a reviewer can't loosen the checks.")
