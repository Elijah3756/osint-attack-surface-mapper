"""
Report Generator - Produces professional red team assessment reports.

Generates PDF and HTML reports with network graph visualizations,
exposure scores, attack path analysis, and remediation recommendations.

Author: Elijah Bellamy
"""

import json
import logging
from datetime import datetime
from pathlib import Path

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
    ) -> str:
        """
        Generate an interactive HTML dashboard report.

        Features:
        - Interactive network graph (vis.js)
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

        html = self._render_html_template(
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

    def _render_html_template(self, **ctx) -> str:
        """Render the full interactive HTML dashboard."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Recon — {ctx['org_name']}</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.6/vis-network.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.6/vis-network.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
    <style>
        :root {{
            --red: #D92626;
            --green: #26A626;
            --dark: #1E1E23;
            --darker: #15151A;
            --card-bg: #242429;
            --border: #333338;
            --text: #E8E8E8;
            --text-dim: #888890;
            --critical: #D91A1A;
            --high: #E67317;
            --medium: #E6BF17;
            --low: #26A626;
            --info: #6690B3;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--darker);
            color: var(--text);
            line-height: 1.6;
        }}
        .header {{
            background: linear-gradient(135deg, var(--dark), var(--darker));
            border-bottom: 3px solid var(--red);
            padding: 1.5rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{
            font-size: 1.8rem;
            color: var(--red);
        }}
        .header h1 span {{ color: var(--green); }}
        .header-meta {{ color: var(--text-dim); font-size: 0.85rem; text-align: right; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 1.5rem; }}

        /* Score cards */
        .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.2rem;
            text-align: center;
        }}
        .card-label {{ font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.1em; }}
        .card-value {{ font-size: 2rem; font-weight: 700; margin: 0.3rem 0; }}
        .card-sub {{ font-size: 0.8rem; color: var(--text-dim); }}

        /* Risk badge */
        .risk-badge {{
            display: inline-block;
            padding: 0.2em 0.6em;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .risk-critical {{ background: var(--critical); color: #fff; }}
        .risk-high {{ background: var(--high); color: #fff; }}
        .risk-medium {{ background: var(--medium); color: #1a1a1a; }}
        .risk-low {{ background: var(--low); color: #fff; }}
        .risk-info {{ background: var(--info); color: #fff; }}

        /* Sections */
        .section {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 1.5rem;
            overflow: hidden;
        }}
        .section-header {{
            background: var(--dark);
            padding: 0.8rem 1.2rem;
            border-bottom: 2px solid var(--red);
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }}
        .section-header h2 {{ font-size: 1.1rem; color: var(--green); }}
        .section-body {{ padding: 1.2rem; }}

        /* Graph */
        #network-graph {{ width: 100%; height: 500px; background: var(--darker); border-radius: 4px; }}

        /* Tables */
        table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
        th {{
            background: var(--dark);
            color: var(--green);
            padding: 0.6rem 0.8rem;
            text-align: left;
            border-bottom: 2px solid var(--red);
            cursor: pointer;
            user-select: none;
        }}
        th:hover {{ color: var(--red); }}
        td {{ padding: 0.5rem 0.8rem; border-bottom: 1px solid var(--border); }}
        tr:hover {{ background: rgba(38, 166, 38, 0.05); }}

        /* Expandable rows */
        .expand-btn {{
            cursor: pointer;
            color: var(--green);
            font-weight: bold;
            border: none;
            background: none;
            font-size: 1rem;
        }}
        .expand-btn:hover {{ color: var(--red); }}
        .detail-row {{ display: none; }}
        .detail-row.active {{ display: table-row; }}
        .detail-cell {{
            padding: 0.8rem 1.5rem;
            background: var(--darker);
            border-bottom: 1px solid var(--border);
        }}
        .finding-card {{
            background: var(--card-bg);
            border-left: 3px solid var(--border);
            padding: 0.6rem 0.8rem;
            margin-bottom: 0.5rem;
            border-radius: 0 4px 4px 0;
        }}
        .finding-card.finding-critical {{ border-left-color: var(--critical); }}
        .finding-card.finding-high {{ border-left-color: var(--high); }}
        .finding-card.finding-medium {{ border-left-color: var(--medium); }}
        .finding-card.finding-low {{ border-left-color: var(--low); }}
        .finding-title {{ font-weight: 600; font-size: 0.85rem; }}
        .finding-desc {{ font-size: 0.78rem; color: var(--text-dim); margin-top: 0.2rem; }}
        .finding-rem {{ font-size: 0.75rem; color: var(--green); margin-top: 0.3rem; }}

        /* Charts row */
        .chart-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem; }}
        .chart-container {{ position: relative; height: 280px; }}
        @media (max-width: 768px) {{ .chart-row {{ grid-template-columns: 1fr; }} }}

        /* Attack paths */
        .path-chain {{
            display: flex; flex-wrap: wrap; align-items: center;
            gap: 0.3rem; margin: 0.4rem 0;
        }}
        .path-node {{
            background: var(--dark);
            border: 1px solid var(--border);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.78rem;
        }}
        .path-arrow {{ color: var(--red); font-weight: bold; }}

        /* Footer */
        .footer {{
            text-align: center;
            padding: 1rem;
            color: var(--text-dim);
            font-size: 0.75rem;
            border-top: 1px solid var(--border);
        }}

        /* Summary section */
        .summary-text {{
            padding: 1rem;
            background: var(--darker);
            border-radius: 4px;
            border-left: 3px solid var(--red);
            margin-bottom: 1rem;
            font-size: 0.9rem;
            line-height: 1.7;
        }}

        /* Tab navigation */
        .tab-nav {{ display: flex; gap: 0; border-bottom: 2px solid var(--border); margin-bottom: 1rem; }}
        .tab-btn {{
            background: none; border: none; color: var(--text-dim);
            padding: 0.6rem 1.2rem; cursor: pointer; font-size: 0.85rem;
            border-bottom: 2px solid transparent; margin-bottom: -2px;
        }}
        .tab-btn.active {{ color: var(--green); border-bottom-color: var(--green); }}
        .tab-btn:hover {{ color: var(--text); }}
        .tab-content {{ display: none; }}
        .tab-content.active {{ display: block; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>OSINT <span>Recon</span></h1>
            <div style="color: var(--text-dim); font-size: 0.85rem;">Social Network Attack Surface Assessment</div>
        </div>
        <div class="header-meta">
            <div><strong>Target:</strong> {ctx['org_name']}</div>
            <div><strong>Domain:</strong> {ctx['domain'] or 'N/A'}</div>
            <div>{ctx['timestamp']}</div>
        </div>
    </div>

    <div class="container">
        <!-- Score Cards -->
        <div class="cards">
            <div class="card">
                <div class="card-label">Overall Score</div>
                <div class="card-value" style="color: var(--{'critical' if ctx['overall_score'] >= 8 else 'high' if ctx['overall_score'] >= 6 else 'medium' if ctx['overall_score'] >= 4 else 'low'})">{ctx['overall_score']}</div>
                <div class="card-sub"><span class="risk-badge risk-{ctx['risk_level']}">{ctx['risk_level'].upper()}</span></div>
            </div>
            <div class="card">
                <div class="card-label">People Discovered</div>
                <div class="card-value" style="color: var(--green)">{ctx['people_count']}</div>
                <div class="card-sub">employees & contributors</div>
            </div>
            <div class="card">
                <div class="card-label">Graph Nodes</div>
                <div class="card-value" style="color: var(--green)">{ctx['graph_stats'].get('total_nodes', 0)}</div>
                <div class="card-sub">{ctx['graph_stats'].get('total_edges', 0)} edges</div>
            </div>
            <div class="card">
                <div class="card-label">High-Value Targets</div>
                <div class="card-value" style="color: var(--red)">{ctx['hvt_count']}</div>
                <div class="card-sub">{ctx['attack_path_count']} attack paths</div>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="section">
            <div class="section-header"><h2>Executive Summary</h2></div>
            <div class="section-body">
                <div class="summary-text">{ctx['summary']}</div>
            </div>
        </div>

        <!-- Charts -->
        <div class="chart-row">
            <div class="section">
                <div class="section-header"><h2>Risk Distribution</h2></div>
                <div class="section-body"><div class="chart-container"><canvas id="riskChart"></canvas></div></div>
            </div>
            <div class="section">
                <div class="section-header"><h2>Score Distribution</h2></div>
                <div class="section-body"><div class="chart-container"><canvas id="scoreChart"></canvas></div></div>
            </div>
        </div>

        <!-- Network Graph -->
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)"><h2>Network Graph</h2><span>▼</span></div>
            <div class="section-body">
                <div id="network-graph"></div>
            </div>
        </div>

        <!-- Tabs: People / Infrastructure / Attack Paths -->
        <div class="section">
            <div class="section-body">
                <div class="tab-nav">
                    <button class="tab-btn active" onclick="switchTab('people', this)">People ({ctx['people_count']})</button>
                    <button class="tab-btn" onclick="switchTab('infra', this)">Infrastructure</button>
                    <button class="tab-btn" onclick="switchTab('paths', this)">Attack Paths ({ctx['attack_path_count']})</button>
                </div>

                <!-- People Tab -->
                <div id="tab-people" class="tab-content active">
                    <table id="people-table">
                        <thead>
                            <tr>
                                <th></th>
                                <th onclick="sortTable('people-table', 1)">Name</th>
                                <th onclick="sortTable('people-table', 2)">Role</th>
                                <th onclick="sortTable('people-table', 3)">Score</th>
                                <th onclick="sortTable('people-table', 4)">Risk</th>
                                <th onclick="sortTable('people-table', 5)">Findings</th>
                            </tr>
                        </thead>
                        <tbody id="people-tbody"></tbody>
                    </table>
                </div>

                <!-- Infrastructure Tab -->
                <div id="tab-infra" class="tab-content">
                    <div id="infra-list"></div>
                </div>

                <!-- Attack Paths Tab -->
                <div id="tab-paths" class="tab-content">
                    <div id="paths-list"></div>
                </div>
            </div>
        </div>
    </div>

    <div class="footer">
        OSINT Recon v0.1.0 | Author: Elijah Bellamy | Generated: {ctx['timestamp']} | CONFIDENTIAL
    </div>

    <script>
    // Data
    const visNodes = {ctx['vis_nodes_json']};
    const visEdges = {ctx['vis_edges_json']};
    const people = {ctx['people_json']};
    const infraFindings = {ctx['infra_json']};
    const attackPaths = {ctx['paths_json']};
    const riskDist = {ctx['risk_dist_json']};

    const riskColors = {{
        critical: '#D91A1A', high: '#E67317', medium: '#E6BF17',
        low: '#26A626', info: '#6690B3'
    }};

    // ── Network Graph ────────────────────────────────────
    if (visNodes.length > 0) {{
        const container = document.getElementById('network-graph');
        const data = {{
            nodes: new vis.DataSet(visNodes),
            edges: new vis.DataSet(visEdges)
        }};
        const options = {{
            physics: {{
                solver: 'forceAtlas2Based',
                forceAtlas2Based: {{ gravitationalConstant: -40, springLength: 120 }},
                stabilization: {{ iterations: 100 }}
            }},
            nodes: {{
                font: {{ color: '#E8E8E8', size: 11 }},
                borderWidth: 2,
                shadow: true
            }},
            edges: {{
                font: {{ color: '#888890', size: 9 }},
                smooth: {{ type: 'continuous' }}
            }},
            interaction: {{
                hover: true,
                tooltipDelay: 200,
                zoomView: true
            }},
            groups: {{
                person: {{ shape: 'dot' }},
                organization: {{ shape: 'diamond', color: '#D92626' }},
                account: {{ shape: 'triangle' }},
                domain: {{ shape: 'square' }}
            }}
        }};
        new vis.Network(container, data, options);
    }} else {{
        document.getElementById('network-graph').innerHTML = '<p style="text-align:center;padding:2rem;color:#888">No graph data available</p>';
    }}

    // ── Charts ───────────────────────────────────────────
    // Risk distribution doughnut
    new Chart(document.getElementById('riskChart'), {{
        type: 'doughnut',
        data: {{
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{{
                data: [riskDist.critical, riskDist.high, riskDist.medium, riskDist.low, riskDist.info],
                backgroundColor: ['#D91A1A', '#E67317', '#E6BF17', '#26A626', '#6690B3'],
                borderColor: '#1E1E23',
                borderWidth: 2
            }}]
        }},
        options: {{
            responsive: true,
            maintainAspectRatio: false,
            plugins: {{
                legend: {{ position: 'bottom', labels: {{ color: '#E8E8E8', padding: 15 }} }}
            }}
        }}
    }});

    // Score histogram
    const scoreBuckets = [0,0,0,0,0,0,0,0,0,0];
    people.forEach(p => {{ const idx = Math.min(9, Math.floor(p.score)); scoreBuckets[idx]++; }});
    new Chart(document.getElementById('scoreChart'), {{
        type: 'bar',
        data: {{
            labels: ['0-1','1-2','2-3','3-4','4-5','5-6','6-7','7-8','8-9','9-10'],
            datasets: [{{
                label: 'People',
                data: scoreBuckets,
                backgroundColor: scoreBuckets.map((_, i) =>
                    i >= 8 ? '#D91A1A' : i >= 6 ? '#E67317' : i >= 4 ? '#E6BF17' : '#26A626'
                ),
                borderRadius: 4
            }}]
        }},
        options: {{
            responsive: true,
            maintainAspectRatio: false,
            plugins: {{ legend: {{ display: false }} }},
            scales: {{
                x: {{ ticks: {{ color: '#888' }}, grid: {{ color: '#333' }} }},
                y: {{ ticks: {{ color: '#888', stepSize: 1 }}, grid: {{ color: '#333' }} }}
            }}
        }}
    }});

    // ── People Table ─────────────────────────────────────
    const tbody = document.getElementById('people-tbody');
    people.forEach((p, idx) => {{
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><button class="expand-btn" onclick="toggleDetail(${{idx}})">+</button></td>
            <td>${{p.name}}</td>
            <td>${{p.role}}</td>
            <td>${{p.score}}</td>
            <td><span class="risk-badge risk-${{p.risk}}">${{p.risk.toUpperCase()}}</span></td>
            <td>${{p.finding_count}}</td>
        `;
        tbody.appendChild(tr);

        // Detail row
        const detailRow = document.createElement('tr');
        detailRow.className = 'detail-row';
        detailRow.id = `detail-${{idx}}`;
        let findingsHtml = p.findings.map(f => `
            <div class="finding-card finding-${{f.risk}}">
                <div class="finding-title"><span class="risk-badge risk-${{f.risk}}">${{f.risk.toUpperCase()}}</span> ${{f.title}} (Score: ${{f.score}})</div>
                <div class="finding-desc">${{f.description}}</div>
                ${{f.remediation ? `<div class="finding-rem">↳ ${{f.remediation}}</div>` : ''}}
            </div>
        `).join('');
        detailRow.innerHTML = `<td colspan="6" class="detail-cell">${{findingsHtml || 'No findings'}}</td>`;
        tbody.appendChild(detailRow);
    }});

    // ── Infrastructure ───────────────────────────────────
    const infraList = document.getElementById('infra-list');
    if (infraFindings.length === 0) {{
        infraList.innerHTML = '<p style="color:#888;padding:1rem;">No infrastructure findings.</p>';
    }} else {{
        infraFindings.forEach(f => {{
            infraList.innerHTML += `
                <div class="finding-card finding-${{f.risk}}" style="margin-bottom:0.8rem;">
                    <div class="finding-title">
                        <span class="risk-badge risk-${{f.risk}}">${{f.risk.toUpperCase()}}</span>
                        ${{f.title}} (Score: ${{f.score}})
                    </div>
                    <div class="finding-desc">${{f.description}}</div>
                    ${{f.evidence.length ? `<div class="finding-desc" style="margin-top:0.3rem;"><strong>Evidence:</strong> ${{f.evidence.join(', ')}}</div>` : ''}}
                    ${{f.remediation ? `<div class="finding-rem">↳ ${{f.remediation}}</div>` : ''}}
                </div>
            `;
        }});
    }}

    // ── Attack Paths ─────────────────────────────────────
    const pathsList = document.getElementById('paths-list');
    if (attackPaths.length === 0) {{
        pathsList.innerHTML = '<p style="color:#888;padding:1rem;">No attack paths mapped.</p>';
    }} else {{
        attackPaths.forEach((ap, i) => {{
            const chain = ap.path.map(n => `<span class="path-node">${{n}}</span>`).join('<span class="path-arrow"> → </span>');
            pathsList.innerHTML += `
                <div class="finding-card" style="margin-bottom:0.8rem; border-left-color: ${{ap.risk_score > 0.5 ? '#D91A1A' : ap.risk_score > 0.3 ? '#E67317' : '#26A626'}};">
                    <div class="finding-title">#${{i+1}} — ${{ap.entry}} → ${{ap.target}} (${{ap.hops}} hops, risk: ${{ap.risk_score.toFixed(4)}})</div>
                    <div class="path-chain" style="margin-top:0.4rem;">${{chain}}</div>
                </div>
            `;
        }});
    }}

    // ── Utilities ─────────────────────────────────────────
    function toggleDetail(idx) {{
        const row = document.getElementById(`detail-${{idx}}`);
        const btn = row.previousElementSibling.querySelector('.expand-btn');
        row.classList.toggle('active');
        btn.textContent = row.classList.contains('active') ? '−' : '+';
    }}

    function toggleSection(header) {{
        const body = header.nextElementSibling;
        const arrow = header.querySelector('span');
        if (body.style.display === 'none') {{
            body.style.display = 'block';
            arrow.textContent = '▼';
        }} else {{
            body.style.display = 'none';
            arrow.textContent = '▶';
        }}
    }}

    function switchTab(tabId, btn) {{
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.getElementById(`tab-${{tabId}}`).classList.add('active');
        btn.classList.add('active');
    }}

    function sortTable(tableId, colIdx) {{
        const table = document.getElementById(tableId);
        const tBody = table.querySelector('tbody');
        const rows = Array.from(tBody.querySelectorAll('tr:not(.detail-row)'));
        const dir = table.dataset.sortDir === 'asc' ? 'desc' : 'asc';
        table.dataset.sortDir = dir;
        rows.sort((a, b) => {{
            let aVal = a.cells[colIdx].textContent.trim();
            let bVal = b.cells[colIdx].textContent.trim();
            const aNum = parseFloat(aVal);
            const bNum = parseFloat(bVal);
            if (!isNaN(aNum) && !isNaN(bNum)) {{
                return dir === 'asc' ? aNum - bNum : bNum - aNum;
            }}
            return dir === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
        }});
        // Re-insert rows with their detail rows
        rows.forEach(row => {{
            const detail = row.nextElementSibling;
            tBody.appendChild(row);
            if (detail && detail.classList.contains('detail-row')) {{
                tBody.appendChild(detail);
            }}
        }});
    }}
    </script>
</body>
</html>"""

    # ═══════════════════════════════════════════════════════════
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
