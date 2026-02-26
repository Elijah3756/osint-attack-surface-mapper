"""Tests for Phase 4: PDF and HTML report generation."""

import json
import os
import tempfile
import pytest

from src.reporting.generator import ReportGenerator
from src.scoring.exposure import (
    ExposureFinding,
    ExposureScorer,
    OrganizationScore,
    PersonScore,
    RiskLevel,
)
from src.graph.network import GraphNode


# ── Fixtures ──────────────────────────────────────────────────


def _make_person_score(name, role, score, risk, findings=None):
    ps = PersonScore(person_name=name, person_role=role)
    ps.overall_score = score
    ps.risk_level = risk
    ps.findings = findings or []
    return ps


def _make_finding(title, category, risk, score, desc="Test desc", rem="Fix it"):
    return ExposureFinding(
        category=category,
        title=title,
        description=desc,
        risk_level=risk,
        score=score,
        evidence=["evidence-1", "evidence-2"],
        remediation=rem,
    )


def _sample_org_score():
    findings = [
        _make_finding("Breach", "breach", RiskLevel.HIGH, 7.0),
        _make_finding("Social", "social_media", RiskLevel.MEDIUM, 5.0),
    ]
    p1 = _make_person_score("Jane Doe", "CTO", 7.5, RiskLevel.HIGH, findings)
    p2 = _make_person_score("Bob Smith", "Dev", 3.2, RiskLevel.LOW, [
        _make_finding("Low risk", "metadata", RiskLevel.LOW, 2.5),
    ])

    infra = [
        _make_finding(
            "CVEs found", "infrastructure", RiskLevel.CRITICAL, 9.0,
            desc="5 CVEs on exposed services", rem="Patch all systems",
        ),
        _make_finding(
            "Open Ports", "infrastructure", RiskLevel.HIGH, 6.5,
            desc="RDP and MongoDB open", rem="Close ports",
        ),
    ]

    org = OrganizationScore(
        org_name="Acme Corp",
        person_scores=[p1, p2],
        infra_findings=infra,
        overall_score=6.8,
        risk_level=RiskLevel.HIGH,
        summary="Assessment of 2 employees: 0 critical, 1 high, 0 medium risk.",
    )
    return org, [p1, p2]


def _sample_graph_stats():
    return {
        "total_nodes": 34,
        "total_edges": 570,
        "density": 0.0321,
        "connected_components": 1,
        "avg_clustering": 0.512,
    }


def _sample_high_value_targets():
    t1 = GraphNode(id="jane_doe", label="Jane Doe", node_type="person",
                   attributes={"role": "CTO"})
    t1.centrality_scores = {
        "degree": 0.65, "betweenness": 0.42,
        "closeness": 0.58, "pagerank": 0.15,
    }
    t2 = GraphNode(id="bob_smith", label="Bob Smith", node_type="person",
                   attributes={"role": "Dev"})
    t2.centrality_scores = {
        "degree": 0.30, "betweenness": 0.10,
        "closeness": 0.35, "pagerank": 0.05,
    }
    return [t1, t2]


def _sample_attack_paths():
    return [
        {
            "entry_point": "bob_smith",
            "entry_label": "Bob Smith",
            "target_label": "Jane Doe",
            "path": ["bob_smith", "repo_alpha", "jane_doe"],
            "path_labels": ["Bob Smith", "repo_alpha", "Jane Doe"],
            "edge_types": ["collaborates", "collaborates"],
            "hops": 2,
            "avg_edge_weight": 0.75,
            "risk_score": 0.4512,
        },
    ]


def _sample_graph_data():
    return {
        "nodes": {
            "jane_doe": {"label": "Jane Doe", "node_type": "person", "role": "CTO"},
            "bob_smith": {"label": "Bob Smith", "node_type": "person", "role": "Dev"},
            "acme": {"label": "Acme Corp", "node_type": "organization"},
        },
        "edges": [
            {"source": "jane_doe", "target": "acme", "relation": "colleague", "weight": 1.0},
            {"source": "bob_smith", "target": "acme", "relation": "colleague", "weight": 1.0},
            {"source": "jane_doe", "target": "bob_smith", "relation": "collaborates", "weight": 0.8},
        ],
    }


# ── ReportGenerator Init ─────────────────────────────────────


class TestReportGeneratorInit:
    def test_creates_output_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "reports", "sub")
            gen = ReportGenerator(output_dir=out)
            assert os.path.isdir(out)

    def test_timestamp_format(self):
        gen = ReportGenerator()
        assert len(gen.timestamp) == 15  # YYYYmmdd_HHMMSS

    def test_risk_hex(self):
        assert ReportGenerator._risk_hex("critical") == "#D91A1A"
        assert ReportGenerator._risk_hex("high") == "#E67317"
        assert ReportGenerator._risk_hex("low") == "#26A626"
        assert ReportGenerator._risk_hex("unknown") == "#888888"


# ── JSON Export ───────────────────────────────────────────────


class TestJSONExport:
    def test_generates_valid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            org, people = _sample_org_score()
            path = gen.generate_json_export(org, people)

            assert os.path.isfile(path)
            with open(path) as f:
                data = json.load(f)

            assert data["organization"]["overall_score"] == 6.8
            assert len(data["individuals"]) == 2
            assert data["individuals"][0]["name"] == "Jane Doe"

    def test_serializes_findings(self):
        finding = _make_finding("Test", "breach", RiskLevel.HIGH, 7.5)
        result = ReportGenerator._serialize_finding(finding)
        assert result["risk_level"] == "high"
        assert result["score"] == 7.5
        assert "evidence-1" in result["evidence"]


# ── PDF Report ────────────────────────────────────────────────


class TestPDFReport:
    def test_generates_pdf_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            org, people = _sample_org_score()
            path = gen.generate_pdf_report(
                org_score=org,
                person_scores=people,
                graph_stats=_sample_graph_stats(),
                high_value_targets=_sample_high_value_targets(),
                attack_paths=_sample_attack_paths(),
                org_name="Acme Corp",
                domain="acme.com",
            )
            assert os.path.isfile(path)
            assert path.endswith(".pdf")
            # PDF should be a reasonable size (at least a few KB)
            assert os.path.getsize(path) > 5000

    def test_generates_pdf_with_empty_data(self):
        """Should not crash with minimal/empty data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            org = OrganizationScore(
                org_name="Empty Corp",
                overall_score=0.0,
                risk_level=RiskLevel.LOW,
                summary="No findings.",
            )
            path = gen.generate_pdf_report(
                org_score=org,
                person_scores=[],
                graph_stats={},
                high_value_targets=[],
                attack_paths=[],
                org_name="Empty Corp",
            )
            assert os.path.isfile(path)

    def test_pdf_with_many_findings(self):
        """Handles large finding sets without error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            findings = [
                _make_finding(f"Finding {i}", "breach", RiskLevel.HIGH, 7.0)
                for i in range(25)
            ]
            people = [
                _make_person_score(f"Person {i}", "Role", 6.5, RiskLevel.HIGH, findings[:3])
                for i in range(30)
            ]
            org = OrganizationScore(
                org_name="Big Corp",
                person_scores=people,
                infra_findings=findings[:5],
                overall_score=7.2,
                risk_level=RiskLevel.HIGH,
                summary="Large org assessment.",
            )
            path = gen.generate_pdf_report(
                org_score=org,
                person_scores=people,
                graph_stats=_sample_graph_stats(),
                high_value_targets=_sample_high_value_targets(),
                attack_paths=_sample_attack_paths() * 10,
                org_name="Big Corp",
                domain="bigcorp.com",
            )
            assert os.path.isfile(path)
            assert os.path.getsize(path) > 10000


# ── HTML Dashboard ────────────────────────────────────────────


class TestHTMLDashboard:
    def test_generates_html_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            org, people = _sample_org_score()
            path = gen.generate_html_report(
                org_score=org,
                person_scores=people,
                graph_data=_sample_graph_data(),
                graph_stats=_sample_graph_stats(),
                high_value_targets=_sample_high_value_targets(),
                attack_paths=_sample_attack_paths(),
                org_name="Acme Corp",
                domain="acme.com",
            )
            assert os.path.isfile(path)
            assert path.endswith(".html")

            html = open(path).read()
            # Verify key elements present
            assert "Chart.js" in html or "chart.umd" in html
            assert "Acme Corp" in html
            assert "Jane Doe" in html
            assert "OSINT" in html

    def test_html_contains_risk_badges(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            org, people = _sample_org_score()
            path = gen.generate_html_report(
                org_score=org,
                person_scores=people,
                graph_data=_sample_graph_data(),
                org_name="Acme Corp",
            )
            html = open(path).read()
            assert "badge-high" in html
            assert "badge-low" in html

    def test_html_with_empty_graph(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            org, people = _sample_org_score()
            path = gen.generate_html_report(
                org_score=org,
                person_scores=people,
                graph_data={},
                org_name="No Graph Corp",
            )
            html = open(path).read()
            assert "network-graph" in html

    def test_html_with_no_people(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            org = OrganizationScore(
                org_name="Empty",
                overall_score=0.0,
                risk_level=RiskLevel.LOW,
                summary="Nothing found.",
            )
            path = gen.generate_html_report(
                org_score=org,
                person_scores=[],
                graph_data={},
                org_name="Empty",
            )
            assert os.path.isfile(path)

    def test_html_has_interactive_features(self):
        """Verify JS functions exist for interactivity."""
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            org, people = _sample_org_score()
            path = gen.generate_html_report(
                org_score=org,
                person_scores=people,
                graph_data=_sample_graph_data(),
                org_name="Acme",
            )
            html = open(path).read()
            assert "xpand" in html
            assert "sortT" in html
            assert "tab(" in html

    def test_html_contains_attack_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            org, people = _sample_org_score()
            path = gen.generate_html_report(
                org_score=org,
                person_scores=people,
                graph_data=_sample_graph_data(),
                attack_paths=_sample_attack_paths(),
                org_name="Acme",
            )
            html = open(path).read()
            assert "Bob Smith" in html
            assert "chain" in html


# ── vis.js Data Builder ───────────────────────────────────────


class TestVisDataBuilder:
    def test_build_vis_data(self):
        gen = ReportGenerator()
        _, people = _sample_org_score()
        nodes, edges = gen._build_vis_data(_sample_graph_data(), people)
        assert len(nodes) == 3
        assert len(edges) == 3

        # Jane should have HIGH risk color
        jane_node = next(n for n in nodes if n["label"] == "Jane Doe")
        assert jane_node["color"] == "#E67317"  # high color
        assert jane_node["shape"] == "dot"

        # Organization should be diamond
        org_node = next(n for n in nodes if n["label"] == "Acme Corp")
        assert org_node["shape"] == "diamond"

    def test_build_vis_data_empty(self):
        gen = ReportGenerator()
        nodes, edges = gen._build_vis_data({}, [])
        assert nodes == []
        assert edges == []
