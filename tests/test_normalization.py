"""Tests for the data normalization / deduplication layer in DiscoveryEngine."""

import pytest
from src.recon.discovery import (
    Person,
    Organization,
    DiscoveryEngine,
    _normalize_name,
    _dedup_key,
)


class TestNormalizeName:
    def test_basic(self):
        assert _normalize_name("Jane Doe") == "jane doe"

    def test_extra_whitespace(self):
        assert _normalize_name("  Jane   Doe  ") == "jane doe"

    def test_case_insensitive(self):
        assert _normalize_name("JANE DOE") == "jane doe"


class TestDedupKey:
    def test_dict_with_url(self):
        assert _dedup_key({"url": "https://a.com", "name": "X"}) == "https://a.com"

    def test_dict_with_email(self):
        assert _dedup_key({"email": "a@b.com"}) == "a@b.com"

    def test_dict_fallback_to_str(self):
        key = _dedup_key({"foo": "bar"})
        assert isinstance(key, str)

    def test_plain_string(self):
        assert _dedup_key("hello") == "hello"


class TestMergeResults:
    def _make_engine(self):
        engine = DiscoveryEngine(config={})
        engine.set_target("Acme", "acme.com")
        return engine

    def test_merge_new_employees(self):
        engine = self._make_engine()
        engine._merge_results({
            "employees": [
                {"name": "Jane Doe", "organization": "Acme", "email": "jane@acme.com"},
                {"name": "John Smith", "organization": "Acme"},
            ]
        })
        assert engine.org.employee_count == 2

    def test_dedup_by_email(self):
        engine = self._make_engine()
        engine._merge_results({
            "employees": [
                {"name": "Jane Doe", "organization": "Acme", "email": "jane@acme.com"},
            ]
        })
        # Second source finds the same person by email
        engine._merge_results({
            "employees": [
                {
                    "name": "Jane D.",
                    "organization": "Acme",
                    "email": "JANE@acme.com",
                    "role": "CTO",
                    "social_profiles": {"linkedin": {"url": "li.com/jane"}},
                    "metadata": {"source": "web_scraper"},
                },
            ]
        })
        assert engine.org.employee_count == 1
        jane = engine.org.employees[0]
        assert jane.role == "CTO"  # filled in from second source
        assert "linkedin" in jane.social_profiles

    def test_dedup_by_github_username(self):
        engine = self._make_engine()
        engine._merge_results({
            "employees": [
                {
                    "name": "Jane Doe",
                    "organization": "Acme",
                    "social_profiles": {"github": {"username": "janedoe"}},
                    "metadata": {"source": "github"},
                },
            ]
        })
        engine._merge_results({
            "employees": [
                {
                    "name": "Jane D",
                    "organization": "Acme",
                    "email": "jane@acme.com",
                    "social_profiles": {"github": {"username": "janedoe"}},
                    "metadata": {"source": "web_scraper"},
                },
            ]
        })
        assert engine.org.employee_count == 1
        assert engine.org.employees[0].email == "jane@acme.com"

    def test_dedup_by_name(self):
        engine = self._make_engine()
        engine._merge_results({
            "employees": [
                {"name": "Jane Doe", "organization": "Acme", "metadata": {"source": "github"}},
            ]
        })
        engine._merge_results({
            "employees": [
                {
                    "name": "jane doe",
                    "organization": "Acme",
                    "role": "Engineer",
                    "metadata": {"source": "web_scraper"},
                },
            ]
        })
        assert engine.org.employee_count == 1
        assert engine.org.employees[0].role == "Engineer"

    def test_different_people_not_merged(self):
        engine = self._make_engine()
        engine._merge_results({
            "employees": [
                {"name": "Jane Doe", "organization": "Acme", "email": "jane@acme.com"},
            ]
        })
        engine._merge_results({
            "employees": [
                {"name": "John Smith", "organization": "Acme", "email": "john@acme.com"},
            ]
        })
        assert engine.org.employee_count == 2

    def test_merge_infrastructure_lists(self):
        engine = self._make_engine()
        engine._merge_results({
            "infrastructure": {
                "github_repos": [{"url": "https://github.com/acme/repo1"}]
            }
        })
        engine._merge_results({
            "infrastructure": {
                "github_repos": [
                    {"url": "https://github.com/acme/repo1"},  # duplicate
                    {"url": "https://github.com/acme/repo2"},  # new
                ]
            }
        })
        repos = engine.org.infrastructure["github_repos"]
        assert len(repos) == 2

    def test_merge_documents_dedup(self):
        engine = self._make_engine()
        engine._merge_results({
            "documents": [{"url": "https://acme.com/report.pdf", "type": "pdf"}]
        })
        engine._merge_results({
            "documents": [
                {"url": "https://acme.com/report.pdf", "type": "pdf"},  # dup
                {"url": "https://acme.com/plan.docx", "type": "docx"},
            ]
        })
        assert len(engine.org.documents) == 2

    def test_merge_breach_data(self):
        engine = self._make_engine()
        engine._merge_results({
            "breach_data": {
                "jane@acme.com": {"breach_count": 2, "breaches": ["A", "B"]}
            }
        })
        assert "jane@acme.com" in engine.org.breach_data

    def test_merge_preserves_existing_fields(self):
        """Merging should not overwrite existing non-empty fields."""
        engine = self._make_engine()
        engine._merge_results({
            "employees": [
                {
                    "name": "Jane Doe",
                    "organization": "Acme",
                    "role": "CTO",
                    "email": "jane@acme.com",
                    "social_profiles": {"github": {"username": "janedoe"}},
                    "metadata": {"source": "github"},
                },
            ]
        })
        engine._merge_results({
            "employees": [
                {
                    "name": "Jane Doe",
                    "organization": "Acme",
                    "role": "Engineer",  # should NOT overwrite CTO
                    "email": "jane2@acme.com",  # should NOT overwrite
                    "social_profiles": {"linkedin": {"url": "li.com/jane"}},
                    "metadata": {"source": "web_scraper"},
                },
            ]
        })
        jane = engine.org.employees[0]
        assert jane.role == "CTO"  # original preserved
        assert jane.email == "jane@acme.com"  # original preserved
        assert "linkedin" in jane.social_profiles  # new platform added
        assert "github" in jane.social_profiles  # original preserved

    def test_sources_tracking(self):
        engine = self._make_engine()
        engine._merge_results({
            "employees": [
                {
                    "name": "Jane",
                    "organization": "Acme",
                    "metadata": {"source": "github"},
                },
            ]
        })
        engine._merge_results({
            "employees": [
                {
                    "name": "Jane",
                    "organization": "Acme",
                    "metadata": {"source": "web_scraper"},
                },
            ]
        })
        jane = engine.org.employees[0]
        assert "web_scraper" in jane.metadata.get("sources", [])
