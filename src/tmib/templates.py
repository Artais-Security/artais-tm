from __future__ import annotations

def render_markdown(ans, model, generated_at: str) -> str:
    def yn(v: bool) -> str:
        return "Yes" if v else "No"

    lines = []
    lines.append(f"# Threat Model: {ans.project}")
    lines.append("")
    lines.append(f"- Generated: {generated_at}")
    lines.append(f"- App type: `{ans.app_type}`")
    lines.append(f"- Data sensitivity: `{ans.data_sensitivity}`")
    lines.append(f"- Auth: `{ans.auth}`")
    lines.append(f"- Hosting: `{ans.cloud}`")
    lines.append(f"- Internet-facing: **{yn(ans.internet_facing)}**")
    lines.append(f"- Stores PII: **{yn(ans.stores_pii)}**")
    lines.append("")

    lines.append("## Assumptions")
    for a in model.assumptions:
        lines.append(f"- {a}")
    lines.append("")

    lines.append("## Assets")
    for a in model.assets:
        lines.append(f"- {a}")
    lines.append("")

    lines.append("## Trust boundaries")
    for t in model.trust_boundaries:
        lines.append(f"- {t}")
    lines.append("")

    lines.append("## STRIDE threats (lightweight)")
    lines.append("")
    lines.append("| STRIDE | Threat | Example | Impact | Mitigations |")
    lines.append("|---|---|---|---|---|")
    for r in model.threats:
        mitig = "<br>".join(r.mitigations)
        lines.append(f"| {r.category} | {r.threat} | {r.example} | {r.impact} | {mitig} |")
    lines.append("")

    lines.append("## Security checklist")
    for section, items in model.checklist.items():
        lines.append(f"### {section}")
        for it in items:
            lines.append(f"- [ ] {it}")
        lines.append("")

    lines.append("## Sample abuse cases")
    for ac in model.abuse_cases:
        lines.append(f"- {ac}")
    lines.append("")

    lines.append("## Notes / Next steps")
    lines.append("- Add a DFD diagram if this is moving beyond MVP.")
    lines.append("- Validate assumptions with engineering + product.")
    lines.append("- Track mitigations as backlog items with owners and due dates.")
    lines.append("")

    return "\n".join(lines)
