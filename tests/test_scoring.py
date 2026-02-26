"""Tests for Phase 3 exposure scoring engine."""

import pytest
from src.scoring.exposure import (
    ExposureScorer,
    ExposureFinding,
    PersonScore,
    OrganizationScore,
    RiskLevel,
)
from src.recon.discovery import Person, Organization


# ── Helpers ────────────────────────────────────────────────────

def _make_person(**kwargs):
    defaults = {
        "name": "Jane Doe",
        "organization": "Acme",
        "role": "Engineer",
        "email": "jane@acme.com",
        "social_profiles": {},
        "metadata": {},
    }
    defaults.update(kwargs)
    return Person(**defaults)


# ── ExposureFinding / PersonScore ──────────────────────────────

class TestPersonScore:
    def test_empty_findings(self):
        ps = PersonScore(person_name="Jane", person_role="Eng")
        ps.compute_score()
        assert ps.overall_score == 0.0
        assert ps.risk_level == RiskLevel.INFO

    def test_score_computation(self):
        ps = PersonScore(person_name="Jane", person_role="Eng")
        ps.findings = [
            ExposureFinding(
                category="breach", title="T", description="D",
                risk_level=RiskLevel.HIGH, score=7.0
            ),
            ExposureFinding(
                category="social_media", title="T", description="D",
                risk_level=RiskLevel.MEDIUM, score=5.0
            ),
        ]
        ps.compute_score()
        assert ps.overall_score > 0
        assert ps.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL, RiskLevel.MEDIUM)

    def test_critical_threshold(self):
        ps = PersonScore(person_name="Jane", person_role="Eng")
        ps.findings = [
            ExposureFinding(
                category="breach", title="T", description="D",
                risk_level=RiskLevel.CRITICAL, score=9.0
            ),
            ExposureFinding(
                category="breach", title="T2", description="D2",
                risk_level=RiskLevel.CRITICAL, score=10.0
            ),
        ]
        ps.compute_score()
        assert ps.risk_level == RiskLevel.CRITICAL


# ── Breach Scoring ─────────────────────────────────────────────

class TestBreachScoring:
    def setup_method(self):
        self.scorer = ExposureScorer()

    def test_no_breach_data(self):
        person = _make_person()
        score = self.scorer.score_person(person, {}, {})
        breach_findings = [f for f in score.findings if f.category == "breach"]
        assert len(breach_findings) == 0

    def test_single_breach(self):
        person = _make_person()
        breach_data = {
            "breaches": [
                {"name": "Breach1", "data_classes": ["Emails"], "BreachDate": "2023-01-01"}
            ],
            "pastes": [],
        }
        score = self.scorer.score_person(person, breach_data, {})
        breach_findings = [f for f in score.findings if f.category == "breach"]
        assert len(breach_findings) >= 1
        assert any("Breach" in f.title for f in breach_findings)

    def test_multiple_breaches_higher_score(self):
        person = _make_person()
        many_breaches = {
            "breaches": [
                {"name": f"Breach{i}", "data_classes": ["Emails"]}
                for i in range(5)
            ],
            "pastes": [],
        }
        score_many = self.scorer.score_person(person, many_breaches, {})

        single_breach = {
            "breaches": [{"name": "Breach1", "data_classes": ["Emails"]}],
            "pastes": [],
        }
        score_single = self.scorer.score_person(person, single_breach, {})

        assert score_many.overall_score >= score_single.overall_score

    def test_high_risk_data_classes(self):
        person = _make_person()
        breach_data = {
            "breaches": [
                {
                    "name": "BigBreach",
                    "data_classes": ["Passwords", "Credit cards", "Emails"],
                }
            ],
            "pastes": [],
        }
        score = self.scorer.score_person(person, breach_data, {})
        high_risk = [
            f for f in score.findings
            if f.title == "High-Risk Data Exposed"
        ]
        assert len(high_risk) == 1
        assert high_risk[0].risk_level == RiskLevel.CRITICAL

    def test_paste_exposure(self):
        person = _make_person()
        breach_data = {
            "breaches": [],
            "pastes": [
                {"source": "Pastebin", "title": "Dump", "date": "2024-01-01"}
            ],
        }
        score = self.scorer.score_person(person, breach_data, {})
        paste_findings = [f for f in score.findings if "Paste" in f.title]
        assert len(paste_findings) == 1


# ── Social Media Scoring ───────────────────────────────────────

class TestSocialMediaScoring:
    def setup_method(self):
        self.scorer = ExposureScorer()

    def test_no_profiles(self):
        person = _make_person(social_profiles={})
        score = self.scorer.score_person(person, {}, {})
        social_findings = [
            f for f in score.findings if f.category == "social_media"
        ]
        assert len(social_findings) == 0

    def test_single_profile(self):
        person = _make_person(
            social_profiles={"github": {"username": "janedoe"}}
        )
        score = self.scorer.score_person(person, {}, {})
        social_findings = [
            f for f in score.findings if f.category == "social_media"
        ]
        assert len(social_findings) >= 1

    def test_multiple_profiles_higher_score(self):
        person_many = _make_person(
            social_profiles={
                "github": {"username": "janedoe"},
                "twitter": {"username": "janedoe"},
                "linkedin": {"url": "li.com/jane"},
                "facebook": {"url": "fb.com/jane"},
            }
        )
        score_many = self.scorer.score_person(person_many, {}, {})

        person_one = _make_person(
            social_profiles={"github": {"username": "janedoe"}}
        )
        score_one = self.scorer.score_person(person_one, {}, {})

        assert score_many.overall_score >= score_one.overall_score

    def test_personal_info_exposure(self):
        person = _make_person(
            social_profiles={
                "github": {
                    "username": "janedoe",
                    "email": "jane@acme.com",
                    "location": "San Francisco",
                    "company": "Acme Corp",
                    "bio": "Engineer at Acme",
                    "blog": "janedoe.dev",
                }
            }
        )
        score = self.scorer.score_person(person, {}, {})
        info_findings = [
            f for f in score.findings
            if "Personal Information" in f.title
        ]
        assert len(info_findings) == 1
        assert len(info_findings[0].evidence) >= 3

    def test_high_github_visibility(self):
        person = _make_person(
            social_profiles={
                "github": {
                    "username": "janedoe",
                    "followers": 500,
                    "public_repos": 50,
                }
            }
        )
        score = self.scorer.score_person(person, {}, {})
        visibility = [
            f for f in score.findings if "GitHub Visibility" in f.title
        ]
        assert len(visibility) == 1


# ── Network Position Scoring ───────────────────────────────────

class TestNetworkPositionScoring:
    def setup_method(self):
        self.scorer = ExposureScorer()

    def test_no_metrics(self):
        person = _make_person()
        score = self.scorer.score_person(person, {}, {})
        network_findings = [
            f for f in score.findings
            if "Gatekeeper" in f.title or "Influence" in f.title
        ]
        assert len(network_findings) == 0

    def test_high_betweenness_gatekeeper(self):
        person = _make_person(name="Jane Doe")
        metrics = {
            "betweenness": {"person_0": 0.25},
            "pagerank": {"person_0": 0.05},
            "degree": {"person_0": 0.3},
        }
        # The scorer matches on person name in node_id. Since we use
        # "person_0" the match won't work by default. Let's test with
        # an id that contains the person name.
        # Actually: the current implementation tries to match person_name in node_id.
        # "jane doe" not in "person_0" - so we need to test the case where it does match.
        metrics2 = {
            "betweenness": {"jane doe": 0.25},
            "pagerank": {"jane doe": 0.05},
            "degree": {"jane doe": 0.3},
        }
        score = self.scorer.score_person(person, {}, metrics2)
        gatekeeper = [f for f in score.findings if "Gatekeeper" in f.title]
        assert len(gatekeeper) == 1

    def test_high_pagerank_influence(self):
        person = _make_person(name="Jane Doe")
        metrics = {
            "betweenness": {"jane doe": 0.05},
            "pagerank": {"jane doe": 0.2},
            "degree": {"jane doe": 0.3},
        }
        score = self.scorer.score_person(person, {}, metrics)
        influence = [f for f in score.findings if "Influence" in f.title]
        assert len(influence) == 1

    def test_hub_node(self):
        person = _make_person(name="Jane Doe")
        metrics = {
            "betweenness": {"jane doe": 0.05},
            "pagerank": {"jane doe": 0.05},
            "degree": {"jane doe": 0.7},
        }
        score = self.scorer.score_person(person, {}, metrics)
        hub = [f for f in score.findings if "Hub Node" in f.title]
        assert len(hub) == 1


# ── Infrastructure Scoring ─────────────────────────────────────

class TestInfrastructureScoring:
    def setup_method(self):
        self.scorer = ExposureScorer()

    def test_no_infra_data(self):
        org_score = self.scorer.score_organization([], {})
        assert len(org_score.infra_findings) == 0

    def test_cves_with_cvss_scored(self):
        infra = {
            "vulnerabilities": [
                {"cve": "CVE-2024-1234", "ip": "1.2.3.4", "port": 443, "cvss": 9.8},
                {"cve": "CVE-2024-5678", "ip": "1.2.3.4", "port": 80, "cvss": 5.0},
            ]
        }
        org_score = self.scorer.score_organization([], infra)
        cve_findings = [
            f for f in org_score.infra_findings if "CVE" in f.title
        ]
        assert len(cve_findings) == 1
        assert cve_findings[0].risk_level == RiskLevel.CRITICAL

    def test_cves_without_cvss_scored_by_volume(self):
        """Many CVEs without CVSS scores should still flag critical."""
        infra = {
            "vulnerabilities": [
                {"cve": f"CVE-2024-{i:04d}", "ip": "1.2.3.4", "port": 443, "cvss": None}
                for i in range(100)
            ]
        }
        org_score = self.scorer.score_organization([], infra)
        cve_findings = [
            f for f in org_score.infra_findings if "CVE" in f.title
        ]
        assert len(cve_findings) == 1
        assert cve_findings[0].risk_level == RiskLevel.CRITICAL
        assert cve_findings[0].score >= 9.0

    def test_high_risk_ports(self):
        infra = {
            "open_ports": [22, 80, 443, 3389, 27017],
        }
        org_score = self.scorer.score_organization([], infra)
        port_findings = [
            f for f in org_score.infra_findings if "Port" in f.title
        ]
        assert len(port_findings) == 1
        # RDP (3389) and MongoDB (27017) should make this critical
        assert port_findings[0].risk_level == RiskLevel.CRITICAL

    def test_emails_on_website(self):
        infra = {
            "emails_found": ["info@acme.com", "cto@acme.com", "hr@acme.com"],
        }
        org_score = self.scorer.score_organization([], infra)
        email_findings = [
            f for f in org_score.infra_findings if "Email" in f.title
        ]
        assert len(email_findings) == 1

    def test_web_technologies(self):
        infra = {
            "web_technologies": ["Server: nginx", "React", "WordPress"],
        }
        org_score = self.scorer.score_organization([], infra)
        tech_findings = [
            f for f in org_score.infra_findings if "Technology" in f.title
        ]
        assert len(tech_findings) == 1
        assert tech_findings[0].risk_level == RiskLevel.LOW


# ── Organization Scoring ───────────────────────────────────────

class TestOrganizationScoring:
    def setup_method(self):
        self.scorer = ExposureScorer()

    def test_empty_org_score(self):
        org_score = self.scorer.score_organization([], {})
        assert org_score.overall_score == 0.0
        assert org_score.risk_level == RiskLevel.LOW

    def test_org_score_from_people(self):
        person = _make_person(
            social_profiles={
                "github": {
                    "username": "janedoe",
                    "email": "jane@acme.com",
                    "followers": 200,
                    "public_repos": 50,
                }
            }
        )
        breach = {
            "breaches": [
                {"name": "BigBreach", "data_classes": ["Passwords"]}
            ],
            "pastes": [],
        }
        ps = self.scorer.score_person(person, breach, {})
        org_score = self.scorer.score_organization([ps], {})
        assert org_score.overall_score > 0
        assert org_score.summary != ""

    def test_org_score_people_only(self):
        """Org score with people only = 60% avg + 40% worst case."""
        ps_high = PersonScore(person_name="A", person_role="CTO")
        ps_high.overall_score = 8.0
        ps_high.risk_level = RiskLevel.CRITICAL

        ps_low = PersonScore(person_name="B", person_role="Intern")
        ps_low.overall_score = 2.0
        ps_low.risk_level = RiskLevel.LOW

        org_score = self.scorer.score_organization([ps_high, ps_low], {})
        # No infra findings → pure people score
        # avg = (8 + 2) / 2 = 5.0, max = 8.0
        # people_score = 5.0 * 0.6 + 8.0 * 0.4 = 6.2
        assert abs(org_score.overall_score - 6.2) < 0.01
        assert org_score.risk_level == RiskLevel.HIGH

    def test_org_score_blended(self):
        """Org score blends people (50%) + infra (50%) when both exist."""
        ps = PersonScore(person_name="A", person_role="CTO")
        ps.overall_score = 8.0
        ps.risk_level = RiskLevel.CRITICAL

        infra = {
            "open_ports": [22, 3389, 27017],
        }
        org_score = self.scorer.score_organization([ps], infra)
        # people_score = 8.0*0.6 + 8.0*0.4 = 8.0
        # infra has risky ports → creates a finding with score ~7.0
        # blended = 8.0*0.5 + infra_score*0.5
        assert org_score.overall_score > 4.0
        assert org_score.infra_findings  # infra findings exist

    def test_org_score_infra_only(self):
        """Org score with infra only uses infra score directly."""
        infra = {
            "open_ports": [22, 3389, 445, 27017],
        }
        org_score = self.scorer.score_organization([], infra)
        assert org_score.overall_score > 0.0
        assert org_score.infra_findings

    def test_org_breach_scoring(self):
        """Org-level breach data creates findings."""
        breach_data = {
            "user@example.com": {
                "breach_count": 3,
                "breaches": [
                    {"name": "B1", "data_classes": ["Emails", "Passwords"]},
                    {"name": "B2", "data_classes": ["Emails"]},
                    {"name": "B3", "data_classes": ["Phone numbers"]},
                ],
                "pastes": [],
            },
        }
        org_score = self.scorer.score_organization(
            [], {}, breach_data=breach_data
        )
        breach_findings = [
            f for f in org_score.infra_findings if f.category == "breach"
        ]
        assert len(breach_findings) == 1
        assert breach_findings[0].risk_level == RiskLevel.CRITICAL  # Passwords leaked

    def test_summary_includes_infra(self):
        infra = {
            "vulnerabilities": [
                {"cve": "CVE-2024-1234", "cvss": 9.8},
            ]
        }
        org_score = self.scorer.score_organization([], infra)
        assert "Infrastructure" in org_score.summary or "finding" in org_score.summary

    def test_empty_org_with_breach_data(self):
        """Org score reflects breach data even without people or infra."""
        breach_data = {
            "a@example.com": {
                "breach_count": 1,
                "breaches": [{"name": "B1", "data_classes": ["Emails"]}],
                "pastes": [],
            },
        }
        org_score = self.scorer.score_organization([], {}, breach_data=breach_data)
        assert org_score.overall_score > 0.0


# ── Enhanced Attack Path Tests ─────────────────────────────────

class TestAttackPaths:
    def _build_graph(self):
        from src.graph.network import (
            NetworkGraphBuilder, GraphNode, GraphEdge, RelationType
        )
        builder = NetworkGraphBuilder()
        for name in ["Alice", "Bob", "Charlie", "Dave"]:
            builder.add_node(GraphNode(
                id=name.lower(),
                label=name,
                node_type="person",
            ))
        builder.add_edge(GraphEdge(
            source_id="alice", target_id="bob",
            relation_type=RelationType.COLLEAGUE, weight=0.3,
        ))
        builder.add_edge(GraphEdge(
            source_id="bob", target_id="charlie",
            relation_type=RelationType.COLLABORATES, weight=0.8,
        ))
        builder.add_edge(GraphEdge(
            source_id="charlie", target_id="dave",
            relation_type=RelationType.FOLLOWS, weight=0.5,
        ))
        builder.add_edge(GraphEdge(
            source_id="alice", target_id="charlie",
            relation_type=RelationType.FOLLOWS, weight=0.5,
        ))
        builder.build_graph()
        return builder

    def test_paths_found(self):
        builder = self._build_graph()
        paths = builder.find_attack_paths("dave")
        assert len(paths) > 0

    def test_paths_have_risk_score(self):
        builder = self._build_graph()
        paths = builder.find_attack_paths("dave")
        for path in paths:
            assert "risk_score" in path
            assert "path_labels" in path
            assert "edge_types" in path
            assert "avg_edge_weight" in path

    def test_paths_sorted_by_risk(self):
        builder = self._build_graph()
        paths = builder.find_attack_paths("dave")
        for i in range(len(paths) - 1):
            assert paths[i]["risk_score"] >= paths[i + 1]["risk_score"]

    def test_max_paths_limit(self):
        builder = self._build_graph()
        paths = builder.find_attack_paths("dave", max_paths=2)
        assert len(paths) <= 2

    def test_path_labels(self):
        builder = self._build_graph()
        paths = builder.find_attack_paths("dave")
        for path in paths:
            assert path["entry_label"] in ["Alice", "Bob", "Charlie"]
            assert path["target_label"] == "Dave"
