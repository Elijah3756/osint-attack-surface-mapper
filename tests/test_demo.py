"""
Tests for the demo data generator and demo assessment pipeline.

Validates that synthetic data is realistic enough to exercise every
stage of the pipeline: discovery, graph building, scoring, and reporting.
"""

import asyncio
import pytest

from src.demo.generator import generate_demo_organization
from src.recon.discovery import Person, Organization
from src.graph.builder import OSINTGraphBuilder
from src.scoring.exposure import ExposureScorer, RiskLevel


# ── Demo Organization Tests ──────────────────────────────────────


class TestDemoOrganization:
    """Verify the synthetic Organization is well-formed."""

    def setup_method(self):
        self.org = generate_demo_organization()

    def test_returns_organization(self):
        assert isinstance(self.org, Organization)

    def test_has_name_and_domain(self):
        assert self.org.name == "NovaTech Solutions"
        assert self.org.domain == "novatech-solutions.com"

    def test_employee_count(self):
        assert self.org.employee_count >= 10
        assert all(isinstance(e, Person) for e in self.org.employees)

    def test_employees_have_names_and_roles(self):
        for emp in self.org.employees:
            assert emp.name, f"Employee missing name"
            assert emp.organization == "NovaTech Solutions"
            assert emp.role, f"{emp.name} missing role"

    def test_employees_have_emails(self):
        emails = [e.email for e in self.org.employees if e.email]
        assert len(emails) >= 10
        for email in emails:
            assert "@novatech-solutions.com" in email

    def test_employees_have_social_profiles(self):
        with_profiles = [e for e in self.org.employees if e.social_profiles]
        assert len(with_profiles) >= 10

    def test_github_profiles_have_required_fields(self):
        for emp in self.org.employees:
            gh = emp.social_profiles.get("github", {})
            if gh:
                assert "username" in gh
                assert "followers" in gh
                assert "public_repos" in gh

    def test_leadership_has_rich_profiles(self):
        """CTO and VP should have multi-platform presence."""
        cto = next(e for e in self.org.employees if "Chief Technology Officer" in (e.role or ""))
        assert len(cto.social_profiles) >= 3  # github, linkedin, twitter

    def test_employees_have_metadata(self):
        for emp in self.org.employees:
            assert "source" in emp.metadata or "sources" in emp.metadata


# ── Breach Data Tests ────────────────────────────────────────────


class TestDemoBreachData:
    """Verify breach data is realistic for scoring."""

    def setup_method(self):
        self.org = generate_demo_organization()

    def test_has_breach_data(self):
        assert len(self.org.breach_data) >= 3

    def test_breach_keys_are_emails(self):
        for email in self.org.breach_data:
            assert "@" in email

    def test_breaches_have_structure(self):
        for email, data in self.org.breach_data.items():
            assert "breaches" in data
            assert "breach_count" in data or len(data["breaches"]) > 0
            for breach in data["breaches"]:
                assert "name" in breach
                assert "data_classes" in breach

    def test_has_high_risk_data_classes(self):
        """At least one breach should have password data."""
        all_classes = set()
        for data in self.org.breach_data.values():
            for breach in data["breaches"]:
                all_classes.update(breach.get("data_classes", []))
        assert "Passwords" in all_classes

    def test_has_paste_exposure(self):
        """At least one person should have paste entries."""
        has_pastes = any(
            len(data.get("pastes", [])) > 0
            for data in self.org.breach_data.values()
        )
        assert has_pastes


# ── Infrastructure Tests ─────────────────────────────────────────


class TestDemoInfrastructure:
    """Verify infrastructure data is complete."""

    def setup_method(self):
        self.org = generate_demo_organization()
        self.infra = self.org.infrastructure

    def test_has_github_repos(self):
        repos = self.infra.get("github_repos", [])
        assert len(repos) >= 5
        for repo in repos:
            assert "name" in repo
            assert "url" in repo

    def test_has_hosts(self):
        hosts = self.infra.get("hosts", [])
        assert len(hosts) >= 3
        for host in hosts:
            assert "ip" in host
            assert "ports" in host

    def test_has_vulnerabilities(self):
        vulns = self.infra.get("vulnerabilities", [])
        assert len(vulns) >= 5
        for vuln in vulns:
            assert "cve" in vuln
            assert "cvss" in vuln
            assert vuln["cvss"] >= 0

    def test_has_high_cvss_vulns(self):
        vulns = self.infra.get("vulnerabilities", [])
        high = [v for v in vulns if v["cvss"] >= 9.0]
        assert len(high) >= 2

    def test_has_open_ports(self):
        ports = self.infra.get("open_ports", [])
        assert len(ports) >= 5
        assert 3389 in ports  # RDP should be there for attack path demo

    def test_has_subdomains(self):
        subs = self.infra.get("subdomains", [])
        assert len(subs) >= 8

    def test_has_email_pattern(self):
        assert self.infra.get("email_pattern")

    def test_has_security_headers(self):
        sec = self.infra.get("security_headers", {})
        assert "SPF" in sec
        assert "DMARC" in sec
        # DMARC should be missing for demo findings
        assert sec["DMARC"]["present"] is False

    def test_has_ssl_certs(self):
        certs = self.infra.get("ssl_certs", [])
        assert len(certs) >= 1

    def test_has_hunter_emails(self):
        assert len(self.infra.get("hunter_emails", [])) >= 5

    def test_has_commit_emails(self):
        assert len(self.infra.get("commit_emails", [])) >= 5


# ── Pipeline Integration Tests ───────────────────────────────────


class TestDemoPipeline:
    """Verify demo data works through the full pipeline."""

    def setup_method(self):
        self.org = generate_demo_organization()

    def test_graph_building(self):
        """Demo org should produce a valid graph."""
        builder = OSINTGraphBuilder()
        count = builder.add_people_from_discovery(self.org)
        assert count == self.org.employee_count

        builder.add_org_membership_edges(self.org)
        analysis = builder.build_and_analyze()

        assert analysis["status"] == "complete"
        assert analysis["stats"]["total_nodes"] == self.org.employee_count
        assert analysis["stats"]["total_edges"] > 0
        assert len(analysis["high_value_targets"]) > 0

    def test_graph_centrality_scores(self):
        """Centrality metrics should be non-trivial."""
        builder = OSINTGraphBuilder()
        builder.add_people_from_discovery(self.org)
        builder.add_org_membership_edges(self.org)
        analysis = builder.build_and_analyze()

        centrality = analysis["centrality"]
        assert "pagerank" in centrality
        assert "betweenness" in centrality
        assert "degree" in centrality

    def test_exposure_scoring(self):
        """Demo data should produce meaningful scores."""
        scorer = ExposureScorer()
        person_scores = []

        for person in self.org.employees:
            breach = {}
            if person.email and person.email.lower() in self.org.breach_data:
                breach = self.org.breach_data[person.email.lower()]
            score = scorer.score_person(person, breach, {})
            person_scores.append(score)

        assert len(person_scores) == self.org.employee_count

        # At least some people should have findings
        with_findings = [s for s in person_scores if s.findings]
        assert len(with_findings) >= 5

        # At least one should be critical or high risk
        high_risk = [
            s for s in person_scores
            if s.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
        ]
        assert len(high_risk) >= 1

    def test_org_scoring(self):
        """Organization should score as high/critical risk."""
        scorer = ExposureScorer()
        person_scores = []

        for person in self.org.employees:
            breach = {}
            if person.email and person.email.lower() in self.org.breach_data:
                breach = self.org.breach_data[person.email.lower()]
            score = scorer.score_person(person, breach, {})
            person_scores.append(score)

        org_score = scorer.score_organization(
            person_scores, self.org.infrastructure,
            breach_data=self.org.breach_data,
        )

        assert org_score.overall_score >= 6.0
        assert org_score.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
        assert len(org_score.infra_findings) >= 3
        assert org_score.summary

    def test_documents_present(self):
        assert len(self.org.documents) >= 3
        for doc in self.org.documents:
            assert "url" in doc
            assert "title" in doc
