"""Rendu Markdown des rapports executif et technique a partir de `ReportData`."""

from __future__ import annotations

from adsec.reporting.data import ReportData

_SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def _severity_table(data: ReportData) -> str:
    lines = ["| Severite | Nombre |", "|---|---|"]
    for sev in _SEVERITY_ORDER:
        lines.append(f"| {sev.upper()} | {data.counts_by_severity.get(sev, 0)} |")
    return "\n".join(lines)


def render_executive_markdown(data: ReportData) -> str:
    critical_and_high = [f for f in data.findings if f.severity.value in ("critical", "high")]
    lines = [
        f"# Rapport executif - {data.client_name} / {data.engagement_name}",
        "",
        f"*Genere le {data.generated_at}*" + (" - **version sanitisee**" if data.sanitized else ""),
        "",
        "## Resume executif",
        "",
        f"Cet audit a identifie **{len(data.findings)} probleme(s)**, dont "
        f"**{data.counts_by_severity.get('critical', 0)} critique(s)** et "
        f"**{data.counts_by_severity.get('high', 0)} eleve(s)**. "
        f"{len(data.attack_path_highlights)} chemin(s) d'attaque confirme(s) vers des actifs "
        "critiques ont ete identifies."
        if data.attack_path_highlights
        else "",
        "",
        "## Statistiques globales",
        "",
        _severity_table(data),
        "",
        "## Perimetre",
        "",
        *[f"- {s}" for s in data.scope_summary],
        "",
        "## Principaux constats (critiques et eleves)",
        "",
    ]
    if not critical_and_high:
        lines.append("Aucun constat critique ou eleve.")
    for f in critical_and_high:
        lines.append(f"### [{f.severity.value.upper()}] {f.title}")
        lines.append("")
        lines.append(f.description)
        lines.append("")
        lines.append(f"**Impact metier** : {f.impact}")
        lines.append("")
    if data.attack_path_highlights:
        lines.append("## Principaux chemins d'attaque")
        lines.append("")
        for p in data.attack_path_highlights:
            lines.append(
                f"- `{p.source_id}` -> `{p.target_id}` ({p.length} saut(s)) : {p.impact_summary}"
            )
        lines.append("")
    lines.append("## Limitations")
    lines.append("")
    if not data.limitations:
        lines.append("Aucune limitation particuliere n'a ete rencontree.")
    for lim in data.limitations:
        lines.append(f"- {lim}")
    return "\n".join(lines)


def render_technical_markdown(data: ReportData) -> str:
    lines = [
        f"# Rapport technique - {data.client_name} / {data.engagement_name}",
        "",
        f"*Genere le {data.generated_at}*" + (" - **version sanitisee**" if data.sanitized else ""),
        "",
        "## Methodologie",
        "",
        data.methodology,
        "",
        "## Perimetre",
        "",
        *[f"- {s}" for s in data.scope_summary],
        "",
        "## Statistiques",
        "",
        _severity_table(data),
        "",
        "## Findings",
        "",
    ]
    for f in sorted(data.findings, key=lambda x: _SEVERITY_ORDER.index(x.severity.value)):
        lines.append(f"### {f.rule_id} - {f.title}")
        lines.append("")
        lines.append(f"- **Severite** : {f.severity.value.upper()}")
        lines.append(f"- **Confiance** : {f.confidence.value}")
        lines.append(f"- **Statut** : {f.status.value}")
        lines.append(f"- **Actifs concernes** : {', '.join(f.affected_assets)}")
        lines.append("")
        lines.append(f"**Description** : {f.description}")
        lines.append("")
        lines.append(f"**Details techniques** : {f.technical_details}")
        lines.append("")
        lines.append(f"**Impact** : {f.impact}")
        lines.append("")
        lines.append(f"**Procedure de validation** : {f.validation_procedure}")
        lines.append("")
        lines.append(f"**Remediation** : {f.remediation}")
        lines.append("")
        if f.evidence:
            lines.append("**Preuves** :")
            for e in f.evidence:
                lines.append(
                    f"- `{e.source}` {e.object_id} / {e.attribute} = `{e.value}` (hash `{e.hash[:12]}`)"
                )
            lines.append("")
        if f.references:
            lines.append("**References** : " + ", ".join(f.references))
            lines.append("")
        lines.append("---")
        lines.append("")

    if data.attack_path_highlights:
        lines.append("## Chemins d'attaque")
        lines.append("")
        for p in data.attack_path_highlights:
            lines.append(f"### `{p.source_id}` -> `{p.target_id}`")
            lines.append("")
            lines.append(f"Longueur : {p.length} saut(s), confiance : {p.confidence.value}")
            lines.append("")
            lines.append(f"Resume : {p.impact_summary}")
            lines.append("")
            for edge in p.edges:
                lines.append(
                    f"- `{edge.source_id}` -[{edge.relation.value}]-> `{edge.target_id}` ({edge.confidence.value})"
                )
            lines.append("")

    lines.append("## Limitations")
    lines.append("")
    if not data.limitations:
        lines.append("Aucune limitation particuliere n'a ete rencontree.")
    for lim in data.limitations:
        lines.append(f"- {lim}")
    return "\n".join(lines)
