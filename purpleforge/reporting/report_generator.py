"""
Turns a set of simulated events + detection findings into a
human-readable Markdown coverage report — the artifact you'd actually
hand to a SOC lead after a purple-team run.
"""

from datetime import datetime, timezone

from purpleforge.simulator.mitre_map import TECHNIQUES


def build_report(events: list, findings: list) -> str:
    detected_techniques = {f.rule.technique_id for f in findings}
    simulated_techniques = {e["technique_id"] for e in events}

    lines = []
    lines.append("# PurpleForge Detection Coverage Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append(f"- Techniques simulated: **{len(simulated_techniques)}**")
    lines.append(f"- Techniques detected: **{len(detected_techniques)}**")
    coverage_pct = (
        round(100 * len(detected_techniques) / len(simulated_techniques), 1)
        if simulated_techniques
        else 0.0
    )
    lines.append(f"- Coverage: **{coverage_pct}%**")
    lines.append("")
    lines.append("## Technique Coverage")
    lines.append("")
    lines.append("| Technique | Name | Tactic | Simulated | Detected | Rule |")
    lines.append("|---|---|---|---|---|---|")

    for tid in sorted(simulated_techniques):
        meta = TECHNIQUES.get(tid, {"name": "Unknown", "tactic": "Unknown"})
        matching = [f for f in findings if f.rule.technique_id == tid]
        detected = "✅" if matching else "❌ GAP"
        rule_title = matching[0].rule.title if matching else "—"
        lines.append(
            f"| {tid} | {meta['name']} | {meta['tactic']} | ✅ | {detected} | {rule_title} |"
        )

    gaps = simulated_techniques - detected_techniques
    if gaps:
        lines.append("")
        lines.append("## Gaps to Prioritize")
        lines.append("")
        for tid in sorted(gaps):
            meta = TECHNIQUES.get(tid, {"name": "Unknown"})
            lines.append(f"- **{tid}** — {meta['name']}: no rule fired. Write or tune a detection.")

    lines.append("")
    lines.append("## Findings Detail")
    lines.append("")
    if not findings:
        lines.append("_No detections fired._")
    for f in findings:
        lines.append(f"### {f.rule.id} — {f.rule.title}")
        lines.append(f"- Technique: `{f.rule.technique_id}` ({f.rule.level})")
        lines.append(f"- Host / User: `{f.event.get('host')}` / `{f.event.get('user')}`")
        lines.append(f"- Log source: `{f.rule.log_source}`")
        if f.rule.description:
            lines.append(f"- {f.rule.description}")
        lines.append("")

    return "\n".join(lines)


def write_report(events: list, findings: list, out_path: str) -> None:
    report = build_report(events, findings)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(report)
