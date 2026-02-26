"""
Report Generator - Produces professional red team assessment reports.

Generates PDF and HTML reports with network graph visualizations,
exposure scores, attack path analysis, and remediation recommendations.

Author: Elijah Bellamy
"""

import base64
import json
import logging
from datetime import datetime
from pathlib import Path

from src.reporting.dashboard_template import render_dashboard

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates professional OSINT assessment reports.

    Output formats:
    - PDF: Full red team report with visualizations
    - HTML: Interactive report with embedded graph
    - JSON: Machine-readable findings for integration
    """

    # ── Brand colors (red/green scheme) ───────────────────────
    COLOR_RED = (0.85, 0.15, 0.15)
    COLOR_GREEN = (0.15, 0.65, 0.15)
    COLOR_DARK = (0.12, 0.12, 0.14)
    COLOR_LIGHT = (0.95, 0.95, 0.95)
    COLOR_WHITE = (1, 1, 1)
    COLOR_GRAY = (0.55, 0.55, 0.55)

    RISK_COLORS = {
        "critical": (0.85, 0.10, 0.10),
        "high": (0.90, 0.45, 0.10),
        "medium": (0.90, 0.75, 0.10),
        "low": (0.15, 0.65, 0.15),
        "info": (0.40, 0.55, 0.70),
    }

    def __init__(self, output_dir: str = "data/exports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    # ═══════════════════════════════════════════════════════════
    #  PDF REPORT
    # ═══════════════════════════════════════════════════════════

    def generate_pdf_report(
        self,
        org_score,
        person_scores: list,
        graph_stats: dict,
        high_value_targets: list,
        attack_paths: list,
        org_name: str = "Target Organization",
        domain: str = "",
    ) -> str:
        """
        Generate a full PDF red team assessment report.

        Report sections:
        1. Cover page
        2. Executive Summary
        3. Methodology
        4. Organizational Score Overview
        5. High-Value Targets
        6. Individual Exposure Profiles
        7. Attack Path Analysis
        8. Infrastructure Findings
        9. Remediation Recommendations
        """
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable,
        )

        filename = f"osint_assessment_{self.timestamp}.pdf"
        filepath = self.output_dir / filename

        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=letter,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            rightMargin=0.75 * inch,
        )

        styles = getSampleStyleSheet()
        story = []

        # Custom styles
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Title"],
            fontSize=28,
            textColor=colors.HexColor("#D92626"),
            spaceAfter=6,
        )
        subtitle_style = ParagraphStyle(
            "CustomSubtitle",
            parent=styles["Heading2"],
            fontSize=14,
            textColor=colors.HexColor("#26A626"),
            spaceBefore=4,
            spaceAfter=12,
        )
        heading_style = ParagraphStyle(
            "SectionHeading",
            parent=styles["Heading1"],
            fontSize=18,
            textColor=colors.HexColor("#D92626"),
            spaceBefore=20,
            spaceAfter=10,
            borderWidth=1,
            borderColor=colors.HexColor("#D92626"),
            borderPadding=4,
        )
        subheading_style = ParagraphStyle(
            "SubHeading",
            parent=styles["Heading2"],
            fontSize=13,
            textColor=colors.HexColor("#26A626"),
            spaceBefore=12,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "CustomBody",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            spaceAfter=8,
        )
        small_style = ParagraphStyle(
            "SmallText",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#888888"),
        )

        # ── Cover Page ────────────────────────────────────────
        story.append(Spacer(1, 2 * inch))
        story.append(Paragraph("OSINT RECON", title_style))
        story.append(Paragraph(
            "Social Network Attack Surface Assessment", subtitle_style
        ))
        story.append(Spacer(1, 0.5 * inch))
        story.append(HRFlowable(
            width="100%", thickness=2, color=colors.HexColor("#D92626")
        ))
        story.append(Spacer(1, 0.3 * inch))

        cover_data = [
            ["Target:", org_name],
            ["Domain:", domain or "N/A"],
            ["Assessment Date:", datetime.utcnow().strftime("%B %d, %Y")],
            ["Classification:", "CONFIDENTIAL"],
            ["Author:", "Elijah Bellamy"],
        ]
        cover_table = Table(cover_data, colWidths=[1.8 * inch, 4 * inch])
        cover_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 11),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#D92626")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(cover_table)
        story.append(Spacer(1, 1 * inch))

        # Risk badge
        risk_val = org_score.risk_level.value.upper()
        risk_hex = self._risk_hex(org_score.risk_level.value)
        story.append(Paragraph(
            f'<font color="{risk_hex}" size="20"><b>'
            f'OVERALL RISK: {risk_val} '
            f'({org_score.overall_score:.1f}/10.0)</b></font>',
            styles["Normal"],
        ))
        story.append(PageBreak())

        # ── Table of Contents ─────────────────────────────────
        story.append(Paragraph("TABLE OF CONTENTS", heading_style))
        toc_items = [
            "1. Executive Summary",
            "2. Methodology",
            "3. Organizational Score Overview",
            "4. High-Value Targets",
            "5. Individual Exposure Profiles",
            "6. Attack Path Analysis",
            "7. Infrastructure Findings",
            "8. Remediation Recommendations",
        ]
        for item in toc_items:
            story.append(Paragraph(item, body_style))
        story.append(PageBreak())

        # ── 1. Executive Summary ──────────────────────────────
        story.append(Paragraph("1. EXECUTIVE SUMMARY", heading_style))
        story.append(Paragraph(org_score.summary or "No summary available.", body_style))
        story.append(Spacer(1, 0.2 * inch))

        # Key metrics table
        story.append(Paragraph("Key Metrics", subheading_style))
        critical_count = sum(
            1 for p in person_scores if p.risk_level.value == "critical"
        )
        high_count = sum(
            1 for p in person_scores if p.risk_level.value == "high"
        )
        metrics_data = [
            ["Metric", "Value"],
            ["People Discovered", str(len(person_scores))],
            ["Critical Risk Individuals", str(critical_count)],
            ["High Risk Individuals", str(high_count)],
            ["Infrastructure Findings", str(len(org_score.infra_findings))],
            ["Attack Paths Mapped", str(len(attack_paths))],
            ["Graph Nodes", str(graph_stats.get("total_nodes", 0))],
            ["Graph Edges", str(graph_stats.get("total_edges", 0))],
            ["Overall Score", f"{org_score.overall_score:.1f}/10.0"],
        ]
        story.append(self._make_table(metrics_data))
        story.append(PageBreak())

        # ── 2. Methodology ────────────────────────────────────
        story.append(Paragraph("2. METHODOLOGY", heading_style))
        methodology = (
            "This assessment was conducted using automated Open Source Intelligence "
            "(OSINT) collection techniques. All data was gathered from publicly "
            "accessible sources without any unauthorized access or exploitation. "
            "The following data sources were queried:"
        )
        story.append(Paragraph(methodology, body_style))
        sources = [
            "GitHub API — Organizational members, repositories, commit history",
            "Hunter.io — Email pattern discovery, department mapping",
            "Certificate Transparency Logs — Subdomain enumeration via crt.sh",
            "DNS Resolution — A, MX, TXT, NS, CNAME, SOA records",
            "WHOIS/RDAP — Domain registration and registrant data",
            "Shodan — Internet-facing hosts, open ports, CVEs, SSL certificates",
            "Have I Been Pwned — Data breach and paste exposure",
            "Web Scraping — Public website analysis, technology fingerprinting",
        ]
        for src in sources:
            story.append(Paragraph(f"• {src}", body_style))
        story.append(Spacer(1, 0.15 * inch))
        story.append(Paragraph(
            "Scoring methodology uses weighted factors across breach exposure (30%), "
            "social media footprint (25%), infrastructure exposure (25%), and "
            "metadata leakage (20%).",
            body_style,
        ))
        story.append(PageBreak())

        # ── 3. Organizational Score Overview ──────────────────
        story.append(Paragraph("3. ORGANIZATIONAL SCORE OVERVIEW", heading_style))

        # Score breakdown by risk level
        story.append(Paragraph("Risk Distribution", subheading_style))
        risk_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for ps in person_scores:
            risk_dist[ps.risk_level.value] = risk_dist.get(ps.risk_level.value, 0) + 1
        dist_data = [["Risk Level", "Count", "Percentage"]]
        total_people = max(len(person_scores), 1)
        for level, count in risk_dist.items():
            pct = f"{count / total_people * 100:.0f}%"
            dist_data.append([level.upper(), str(count), pct])
        story.append(self._make_table(dist_data, risk_column=0))

        # Network stats
        if graph_stats and graph_stats.get("total_nodes", 0) > 0:
            story.append(Spacer(1, 0.2 * inch))
            story.append(Paragraph("Network Analysis", subheading_style))
            net_data = [
                ["Metric", "Value"],
                ["Total Nodes", str(graph_stats.get("total_nodes", 0))],
                ["Total Edges", str(graph_stats.get("total_edges", 0))],
                ["Graph Density", f"{graph_stats.get('density', 0):.4f}"],
                ["Connected Components", str(graph_stats.get("connected_components", 0))],
                ["Avg Clustering", f"{graph_stats.get('avg_clustering', 0):.4f}"],
            ]
            story.append(self._make_table(net_data))
        story.append(PageBreak())

        # ── 4. High-Value Targets ─────────────────────────────
        story.append(Paragraph("4. HIGH-VALUE TARGETS", heading_style))
        if high_value_targets:
            story.append(Paragraph(
                f"The following {len(high_value_targets)} individual(s) represent "
                f"the highest-value targets based on network centrality analysis:",
                body_style,
            ))
            hvt_data = [["Rank", "Name", "Role", "Composite Score"]]
            for i, target in enumerate(high_value_targets[:10], 1):
                scores = target.centrality_scores
                composite = sum(
                    scores.get(m, 0) * w
                    for m, w in [
                        ("degree", 0.2), ("betweenness", 0.3),
                        ("closeness", 0.2), ("pagerank", 0.3),
                    ]
                )
                hvt_data.append([
                    str(i),
                    target.label,
                    target.attributes.get("role", "Unknown"),
                    f"{composite:.4f}",
                ])
            story.append(self._make_table(hvt_data))
        else:
            story.append(Paragraph("No high-value targets identified.", body_style))
        story.append(PageBreak())

        # ── 5. Individual Exposure Profiles ───────────────────
        story.append(Paragraph("5. INDIVIDUAL EXPOSURE PROFILES", heading_style))
        sorted_people = sorted(
            person_scores, key=lambda p: p.overall_score, reverse=True
        )
        for ps in sorted_people[:20]:
            risk_hex = self._risk_hex(ps.risk_level.value)
            story.append(Paragraph(
                f'<font color="{risk_hex}"><b>{ps.person_name}</b></font>'
                f' — {ps.person_role}'
                f' — Score: {ps.overall_score:.1f}/10.0'
                f' ({ps.risk_level.value.upper()})',
                subheading_style,
            ))
            if ps.findings:
                finding_data = [["Finding", "Risk", "Score", "Remediation"]]
                for f in ps.findings:
                    finding_data.append([
                        Paragraph(f.title, small_style),
                        f.risk_level.value.upper(),
                        f"{f.score:.1f}",
                        Paragraph(
                            f.remediation[:100] + ("..." if len(f.remediation) > 100 else ""),
                            small_style,
                        ),
                    ])
                t = Table(finding_data, colWidths=[
                    2.2 * inch, 0.8 * inch, 0.6 * inch, 3.2 * inch
                ])
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D92626")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                        colors.HexColor("#FFFFFF"), colors.HexColor("#F5F5F5")
                    ]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                story.append(t)
                story.append(Spacer(1, 0.15 * inch))
            else:
                story.append(Paragraph("No findings.", body_style))

        if len(sorted_people) > 20:
            story.append(Paragraph(
                f"... and {len(sorted_people) - 20} more individuals "
                f"(see JSON export for full data).",
                small_style,
            ))
        story.append(PageBreak())

        # ── 6. Attack Path Analysis ───────────────────────────
        story.append(Paragraph("6. ATTACK PATH ANALYSIS", heading_style))
        if attack_paths:
            story.append(Paragraph(
                f"{len(attack_paths)} social engineering path(s) identified:",
                body_style,
            ))
            ap_data = [["#", "Entry Point", "Target", "Hops", "Risk Score", "Path"]]
            for i, ap in enumerate(attack_paths[:15], 1):
                path_str = " → ".join(ap.get("path_labels", []))
                if len(path_str) > 60:
                    path_str = path_str[:57] + "..."
                ap_data.append([
                    str(i),
                    ap.get("entry_label", "?"),
                    ap.get("target_label", "?"),
                    str(ap.get("hops", 0)),
                    f"{ap.get('risk_score', 0):.4f}",
                    Paragraph(path_str, small_style),
                ])
            t = Table(ap_data, colWidths=[
                0.35 * inch, 1.3 * inch, 1.3 * inch,
                0.5 * inch, 0.8 * inch, 2.55 * inch,
            ])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E1E23")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#26A626")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                    colors.HexColor("#FFFFFF"), colors.HexColor("#F5F5F5")
                ]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(t)
        else:
            story.append(Paragraph("No attack paths mapped.", body_style))
        story.append(PageBreak())

        # ── 7. Infrastructure Findings ────────────────────────
        story.append(Paragraph("7. INFRASTRUCTURE FINDINGS", heading_style))
        if org_score.infra_findings:
            for finding in sorted(
                org_score.infra_findings,
                key=lambda f: f.score,
                reverse=True,
            ):
                risk_hex = self._risk_hex(finding.risk_level.value)
                story.append(Paragraph(
                    f'<font color="{risk_hex}"><b>[{finding.risk_level.value.upper()}]</b></font>'
                    f' {finding.title} (Score: {finding.score:.1f})',
                    subheading_style,
                ))
                story.append(Paragraph(finding.description, body_style))
                if finding.evidence:
                    evidence_str = ", ".join(str(e) for e in finding.evidence[:8])
                    if len(finding.evidence) > 8:
                        evidence_str += f" (+{len(finding.evidence) - 8} more)"
                    story.append(Paragraph(
                        f"<b>Evidence:</b> {evidence_str}", small_style
                    ))
                if finding.remediation:
                    story.append(Paragraph(
                        f"<b>Remediation:</b> {finding.remediation}", body_style
                    ))
                story.append(Spacer(1, 0.1 * inch))
        else:
            story.append(Paragraph("No infrastructure findings.", body_style))
        story.append(PageBreak())

        # ── 8. Remediation Recommendations ────────────────────
        story.append(Paragraph("8. REMEDIATION RECOMMENDATIONS", heading_style))
        story.append(Paragraph("Priority Actions", subheading_style))

        # Gather all unique remediations, sorted by score
        all_findings = []
        for ps in person_scores:
            all_findings.extend(ps.findings)
        all_findings.extend(org_score.infra_findings)
        all_findings.sort(key=lambda f: f.score, reverse=True)

        seen_remediations = set()
        rec_num = 0
        for finding in all_findings:
            if finding.remediation and finding.remediation not in seen_remediations:
                seen_remediations.add(finding.remediation)
                rec_num += 1
                risk_hex = self._risk_hex(finding.risk_level.value)
                story.append(Paragraph(
                    f'{rec_num}. <font color="{risk_hex}">'
                    f'[{finding.risk_level.value.upper()}]</font> '
                    f'{finding.remediation}',
                    body_style,
                ))
                if rec_num >= 15:
                    break

        story.append(Spacer(1, 0.3 * inch))
        story.append(HRFlowable(
            width="100%", thickness=1, color=colors.HexColor("#26A626")
        ))
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph(
            f"Report generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} "
            f"| OSINT Recon v0.1.0 | Author: Elijah Bellamy",
            small_style,
        ))

        doc.build(story)
        logger.info(f"PDF report generated: {filepath}")
        return str(filepath)

    def _make_table(self, data, risk_column=None):
        """Create a styled table with the red/green color scheme."""
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        from reportlab.platypus import Table, TableStyle

        t = Table(data)
        style_commands = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D92626")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                colors.HexColor("#FFFFFF"), colors.HexColor("#F5F5F5")
            ]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]
        t.setStyle(TableStyle(style_commands))
        return t

    @staticmethod
    def _risk_hex(risk_level: str) -> str:
        """Get hex color for a risk level."""
        mapping = {
            "critical": "#D91A1A",
            "high": "#E67317",
            "medium": "#E6BF17",
            "low": "#26A626",
            "info": "#6690B3",
        }
        return mapping.get(risk_level, "#888888")

    # ═══════════════════════════════════════════════════════════
    #  INTERACTIVE HTML REPORT
    # ═══════════════════════════════════════════════════════════

    def generate_html_report(
        self,
        org_score,
        person_scores: list,
        graph_data: dict,
        graph_stats: dict = None,
        high_value_targets: list = None,
        attack_paths: list = None,
        org_name: str = "Target Organization",
        domain: str = "",
        pyvis_html_path: str = None,
    ) -> str:
        """
        Generate an interactive HTML dashboard report.

        Features:
        - Interactive network graph (embedded pyvis or fallback vis.js)
        - Sortable findings tables
        - Score cards with risk coloring
        - Expandable individual profiles
        - Attack path visualization
        """
        filename = f"osint_dashboard_{self.timestamp}.html"
        filepath = self.output_dir / filename

        graph_stats = graph_stats or {}
        high_value_targets = high_value_targets or []
        attack_paths = attack_paths or []

        # Build graph JSON for vis.js
        vis_nodes, vis_edges = self._build_vis_data(graph_data, person_scores)

        # Build person data for the table
        people_json = []
        for ps in sorted(person_scores, key=lambda p: p.overall_score, reverse=True):
            people_json.append({
                "name": ps.person_name,
                "role": ps.person_role,
                "score": round(ps.overall_score, 1),
                "risk": ps.risk_level.value,
                "finding_count": len(ps.findings),
                "findings": [
                    {
                        "title": f.title,
                        "category": f.category,
                        "risk": f.risk_level.value,
                        "score": f.score,
                        "description": f.description,
                        "remediation": f.remediation,
                        "evidence": f.evidence[:5],
                    }
                    for f in ps.findings
                ],
            })

        # Infrastructure findings
        infra_json = [
            {
                "title": f.title,
                "category": f.category,
                "risk": f.risk_level.value,
                "score": f.score,
                "description": f.description,
                "remediation": f.remediation,
                "evidence": f.evidence[:8],
            }
            for f in sorted(
                org_score.infra_findings,
                key=lambda f: f.score,
                reverse=True,
            )
        ]

        # Attack paths
        paths_json = [
            {
                "entry": ap.get("entry_label", "?"),
                "target": ap.get("target_label", "?"),
                "hops": ap.get("hops", 0),
                "risk_score": ap.get("risk_score", 0),
                "path": ap.get("path_labels", []),
                "edge_types": ap.get("edge_types", []),
            }
            for ap in attack_paths[:20]
        ]

        # Risk distribution for Chart.js
        risk_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for ps in person_scores:
            risk_dist[ps.risk_level.value] = risk_dist.get(ps.risk_level.value, 0) + 1

        # Read pyvis graph HTML for embedding if available
        pyvis_data_uri = ""
        if pyvis_html_path:
            try:
                pyvis_raw = Path(pyvis_html_path).read_text(encoding="utf-8")
                pyvis_b64 = base64.b64encode(pyvis_raw.encode("utf-8")).decode("ascii")
                pyvis_data_uri = f"data:text/html;base64,{pyvis_b64}"
            except Exception as e:
                logger.warning(f"Could not embed pyvis graph: {e}")

        html = render_dashboard(
            org_name=org_name,
            domain=domain,
            overall_score=round(org_score.overall_score, 1),
            risk_level=org_score.risk_level.value,
            summary=org_score.summary or "",
            people_count=len(person_scores),
            graph_stats=graph_stats,
            vis_nodes_json=json.dumps(vis_nodes),
            vis_edges_json=json.dumps(vis_edges),
            people_json=json.dumps(people_json),
            infra_json=json.dumps(infra_json),
            paths_json=json.dumps(paths_json),
            risk_dist_json=json.dumps(risk_dist),
            hvt_count=len(high_value_targets),
            attack_path_count=len(attack_paths),
            timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            pyvis_data_uri=pyvis_data_uri,
        )

        filepath.write_text(html, encoding="utf-8")
        logger.info(f"HTML dashboard generated: {filepath}")
        return str(filepath)

    def _build_vis_data(self, graph_data: dict, person_scores: list) -> tuple:
        """Convert NetworkX graph data to vis.js nodes/edges format."""
        vis_nodes = []
        vis_edges = []

        # Build a score lookup
        score_map = {}
        for ps in person_scores:
            score_map[ps.person_name.lower()] = {
                "score": ps.overall_score,
                "risk": ps.risk_level.value,
            }

        if not graph_data:
            return vis_nodes, vis_edges

        nodes = graph_data.get("nodes", {})
        edges = graph_data.get("edges", [])

        risk_colors_hex = {
            "critical": "#D91A1A",
            "high": "#E67317",
            "medium": "#E6BF17",
            "low": "#26A626",
            "info": "#6690B3",
        }

        node_type_shapes = {
            "person": "dot",
            "organization": "diamond",
            "account": "triangle",
            "domain": "square",
        }

        for node_id, attrs in nodes.items():
            label = attrs.get("label", node_id)
            ntype = attrs.get("node_type", "person")
            shape = node_type_shapes.get(ntype, "dot")

            # Color by risk
            risk_info = score_map.get(label.lower(), {})
            risk = risk_info.get("risk", "info")
            color = risk_colors_hex.get(risk, "#6690B3")
            score = risk_info.get("score", 0)

            # Size by score
            size = max(10, min(40, 10 + score * 3))

            vis_nodes.append({
                "id": node_id,
                "label": label,
                "shape": shape,
                "color": color,
                "size": size,
                "title": f"{label} | {ntype} | Score: {score:.1f} | Risk: {risk.upper()}",
                "group": ntype,
            })

        for edge in edges:
            vis_edges.append({
                "from": edge.get("source", ""),
                "to": edge.get("target", ""),
                "label": edge.get("relation", ""),
                "color": {"color": "#555555", "opacity": 0.6},
                "arrows": "to",
            })

        return vis_nodes, vis_edges

    # (Old _render_html_template removed — replaced by dashboard_template.render_dashboard())
    # See dashboard_template.py for the HTML template generation.

    #  JSON EXPORT (existing)
    # ═══════════════════════════════════════════════════════════

    @staticmethod
    def _serialize_finding(finding) -> dict:
        """Convert an ExposureFinding to a JSON-safe dict."""
        return {
            "category": finding.category,
            "title": finding.title,
            "description": finding.description,
            "risk_level": finding.risk_level.value,
            "score": finding.score,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
        }

    def generate_json_export(self, org_score, person_scores: list) -> str:
        """Export findings as structured JSON for tool integration."""
        filename = f"osint_findings_{self.timestamp}.json"
        filepath = self.output_dir / filename

        export = {
            "assessment_date": self.timestamp,
            "organization": {
                "name": org_score.org_name,
                "overall_score": round(org_score.overall_score, 2),
                "risk_level": org_score.risk_level.value,
                "summary": org_score.summary,
                "infrastructure_findings": [
                    self._serialize_finding(f)
                    for f in org_score.infra_findings
                ],
            },
            "individuals": [
                {
                    "name": ps.person_name,
                    "role": ps.person_role,
                    "score": round(ps.overall_score, 2),
                    "risk_level": ps.risk_level.value,
                    "finding_count": len(ps.findings),
                    "findings": [
                        self._serialize_finding(f) for f in ps.findings
                    ],
                }
                for ps in person_scores
            ],
        }

        with open(filepath, "w") as f:
            json.dump(export, f, indent=2)

        logger.info(f"JSON export generated: {filepath}")
        return str(filepath)
