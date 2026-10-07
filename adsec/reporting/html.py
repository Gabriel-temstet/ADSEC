"""Rendu HTML (autonome, sans dependance externe) des rapports."""

from __future__ import annotations

from html import escape

from adsec.reporting.data import ReportData

_SEVERITY_ORDER = ["critical", "high", "medium", "low"]
_SEVERITY_COLORS = {"critical": "#7a0d0d", "high": "#b3401e", "medium": "#b38a1e", "low": "#4a7a1e"}

_STYLE = """
body { font-family: -apple-system, Segoe UI, Arial, sans-serif; max-width: 960px; margin: 2rem auto; color: #1a1a1a; line-height: 1.5; padding: 0 1rem; }
h1 { border-bottom: 3px solid #1a1a1a; padding-bottom: 0.5rem; }
h2 { margin-top: 2rem; border-bottom: 1px solid #ccc; padding-bottom: 0.3rem; }
table { border-collapse: collapse; margin: 1rem 0; }
td, th { border: 1px solid #ccc; padding: 0.4rem 0.8rem; text-align: left; }
.finding { border-left: 4px solid #ccc; padding: 0.5rem 1rem; margin: 1rem 0; background: #fafafa; }
.sev-critical { border-color: #7a0d0d; }
.sev-high { border-color: #b3401e; }
.sev-medium { border-color: #b38a1e; }
.sev-low { border-color: #4a7a1e; }
.badge { display: inline-block; padding: 0.1rem 0.6rem; border-radius: 3px; color: white; font-size: 0.85em; }
code { background: #eee; padding: 0.1rem 0.3rem; border-radius: 3px; }
.limitations { color: #555; font-style: italic; }
"""


def _badge(severity: str) -> str:
    color = _SEVERITY_COLORS.get(severity, "#555")
    return f'<span class="badge" style="background:{color}">{escape(severity.upper())}</span>'


def _header(data: ReportData, title: str) -> str:
    sanitized_note = " <em>(version sanitisee)</em>" if data.sanitized else ""
    return (
        f"<h1>{escape(title)} - {escape(data.client_name)} / {escape(data.engagement_name)}</h1>"
        f"<p><em>Genere le {escape(data.generated_at)}</em>{sanitized_note}</p>"
    )


def _severity_table(data: ReportData) -> str:
    rows = "".join(
        f"<tr><td>{_badge(sev)}</td><td>{data.counts_by_severity.get(sev, 0)}</td></tr>"
        for sev in _SEVERITY_ORDER
    )
    return f"<table><tr><th>Severite</th><th>Nombre</th></tr>{rows}</table>"


def _scope_list(data: ReportData) -> str:
    items = "".join(f"<li>{escape(s)}</li>" for s in data.scope_summary)
    return f"<ul>{items}</ul>" if items else "<p>Non precise.</p>"


def _limitations(data: ReportData) -> str:
    if not data.limitations:
        return '<p class="limitations">Aucune limitation particuliere n\'a ete rencontree.</p>'
    items = "".join(f"<li>{escape(lim)}</li>" for lim in data.limitations)
    return f'<ul class="limitations">{items}</ul>'


def _path_list(data: ReportData) -> str:
    if not data.attack_path_highlights:
        return ""
    items = "".join(
        f"<li><code>{escape(p.source_id)}</code> &rarr; <code>{escape(p.target_id)}</code> "
        f"({p.length} saut(s)) : {escape(p.impact_summary)}</li>"
        for p in data.attack_path_highlights
    )
    return f"<h2>Chemins d'attaque</h2><ul>{items}</ul>"


def render_executive_html(data: ReportData) -> str:
    critical_and_high = [f for f in data.findings if f.severity.value in ("critical", "high")]
    findings_html = (
        "".join(
            f'<div class="finding sev-{f.severity.value}">'
            f"<h3>{_badge(f.severity.value)} {escape(f.title)}</h3>"
            f"<p>{escape(f.description)}</p>"
            f"<p><strong>Impact metier</strong> : {escape(f.impact)}</p>"
            "</div>"
            for f in critical_and_high
        )
        or "<p>Aucun constat critique ou eleve.</p>"
    )

    return f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<title>Rapport executif - {escape(data.engagement_name)}</title><style>{_STYLE}</style></head>
<body>
{_header(data, "Rapport executif")}
<h2>Statistiques globales</h2>
{_severity_table(data)}
<h2>Perimetre</h2>
{_scope_list(data)}
<h2>Principaux constats</h2>
{findings_html}
{_path_list(data)}
<h2>Limitations</h2>
{_limitations(data)}
</body></html>"""


def render_technical_html(data: ReportData) -> str:
    sorted_findings = sorted(data.findings, key=lambda x: _SEVERITY_ORDER.index(x.severity.value))
    findings_html = ""
    for f in sorted_findings:
        evidence_html = "".join(
            f"<li><code>{escape(e.source)}</code> {escape(e.object_id)} / {escape(e.attribute)} "
            f"= <code>{escape(e.value)}</code> (hash <code>{escape(e.hash[:12])}</code>)</li>"
            for e in f.evidence
        )
        refs_html = ", ".join(escape(r) for r in f.references)
        findings_html += f"""<div class="finding sev-{f.severity.value}">
<h3>{_badge(f.severity.value)} {escape(f.rule_id)} - {escape(f.title)}</h3>
<p><strong>Confiance</strong> : {escape(f.confidence.value)} &middot;
<strong>Statut</strong> : {escape(f.status.value)} &middot;
<strong>Actifs</strong> : {escape(", ".join(f.affected_assets))}</p>
<p><strong>Description</strong> : {escape(f.description)}</p>
<p><strong>Details techniques</strong> : {escape(f.technical_details)}</p>
<p><strong>Impact</strong> : {escape(f.impact)}</p>
<p><strong>Validation</strong> : {escape(f.validation_procedure)}</p>
<p><strong>Remediation</strong> : {escape(f.remediation)}</p>
{f"<p><strong>Preuves</strong></p><ul>{evidence_html}</ul>" if evidence_html else ""}
{f"<p><strong>References</strong> : {refs_html}</p>" if refs_html else ""}
</div>"""

    return f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<title>Rapport technique - {escape(data.engagement_name)}</title><style>{_STYLE}</style></head>
<body>
{_header(data, "Rapport technique")}
<h2>Methodologie</h2>
<p>{escape(data.methodology)}</p>
<h2>Perimetre</h2>
{_scope_list(data)}
<h2>Statistiques</h2>
{_severity_table(data)}
<h2>Findings</h2>
{findings_html}
{_path_list(data)}
<h2>Limitations</h2>
{_limitations(data)}
</body></html>"""
