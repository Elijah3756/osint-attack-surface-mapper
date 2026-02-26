"""Tests for Phase 3 collectors: Hunter.io and DNS/CT Logs."""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.recon.collectors import (
    HunterIOCollector,
    DNSCTCollector,
)
from src.recon.discovery import Organization, Person


# ── HunterIOCollector ─────────────────────────────────────────


class TestHunterIOCollector:
    def test_init_with_key(self):
        collector = HunterIOCollector(config={"hunter_api_key": "test_key"})
        assert collector.api_key == "test_key"
        assert collector.validate_config() is True

    def test_init_without_key(self):
        """Free tier works without a key."""
        collector = HunterIOCollector(config={})
        assert collector.api_key is None
        assert collector.validate_config() is True  # Still valid — free tier

    def test_default_rate_limit(self):
        collector = HunterIOCollector(config={})
        assert collector.rate_limit_delay == 2.0

    def test_custom_rate_limit(self):
        collector = HunterIOCollector(config={"rate_limit_delay": 5.0})
        assert collector.rate_limit_delay == 5.0

    @pytest.mark.asyncio
    async def test_collect_skips_without_domain(self):
        collector = HunterIOCollector(config={})
        org = Organization(name="Acme")  # no domain
        results = await collector.collect(org)
        assert results["infrastructure"]["email_pattern"] is None
        assert results["infrastructure"]["hunter_emails"] == []
        assert results["employees"] == []

    @pytest.mark.asyncio
    async def test_collect_handles_no_results(self):
        collector = HunterIOCollector(config={})
        org = Organization(name="Acme", domain="acme.com")

        with patch.object(
            collector, "_domain_search", return_value=None
        ), patch.object(collector, "_rate_limit", return_value=None):
            results = await collector.collect(org)

        assert results["infrastructure"]["email_pattern"] is None
        assert results["infrastructure"]["hunter_emails"] == []

    @pytest.mark.asyncio
    async def test_collect_with_mocked_api(self):
        """Full pipeline with realistic mocked Hunter.io response."""
        collector = HunterIOCollector(config={"hunter_api_key": "key"})
        org = Organization(name="Acme Corp", domain="acme.com")

        mock_domain_data = {
            "pattern": "{first}.{last}",
            "emails": [
                {
                    "value": "jane.doe@acme.com",
                    "confidence": 92,
                    "department": "engineering",
                    "first_name": "Jane",
                    "last_name": "Doe",
                    "position": "CTO",
                    "sources_count": 5,
                },
                {
                    "value": "bob.smith@acme.com",
                    "confidence": 87,
                    "department": "sales",
                    "first_name": "Bob",
                    "last_name": "Smith",
                    "position": "VP Sales",
                    "sources_count": 3,
                },
                {
                    "value": "info@acme.com",
                    "confidence": 60,
                    "department": None,
                    "first_name": None,
                    "last_name": None,
                    "position": None,
                    "sources_count": 10,
                },
            ],
        }

        with patch.object(
            collector, "_domain_search", return_value=mock_domain_data
        ), patch.object(collector, "_rate_limit", return_value=None):
            results = await collector.collect(org)

        infra = results["infrastructure"]
        assert infra["email_pattern"] == "{first}.{last}"
        assert len(infra["hunter_emails"]) == 3
        assert infra["departments"]["engineering"] == 1
        assert infra["departments"]["sales"] == 1

        # People with names should become employees
        assert len(results["employees"]) == 2
        names = {e["name"] for e in results["employees"]}
        assert "Jane Doe" in names
        assert "Bob Smith" in names
        # info@ has no name, should NOT be an employee
        assert not any(e["name"] == "" for e in results["employees"])

    @pytest.mark.asyncio
    async def test_collect_generates_emails_for_existing_employees(self):
        """When pattern is known, generate emails for discovered people."""
        collector = HunterIOCollector(config={})
        org = Organization(name="Acme", domain="acme.com")
        org.add_employee(Person(name="Alice Johnson", organization="Acme"))
        org.add_employee(Person(name="Charlie Brown", organization="Acme"))

        mock_domain_data = {
            "pattern": "{first}.{last}",
            "emails": [
                {
                    "value": "existing@acme.com",
                    "confidence": 90,
                    "department": "ops",
                    "first_name": "Ex",
                    "last_name": "Isting",
                    "position": "",
                    "sources_count": 1,
                },
            ],
        }

        with patch.object(
            collector, "_domain_search", return_value=mock_domain_data
        ), patch.object(collector, "_rate_limit", return_value=None):
            results = await collector.collect(org)

        all_emails = {e["email"] for e in results["infrastructure"]["hunter_emails"]}
        assert "existing@acme.com" in all_emails
        assert "alice.johnson@acme.com" in all_emails
        assert "charlie.brown@acme.com" in all_emails

    def test_generate_emails_first_dot_last(self):
        employees = [
            MagicMock(name="Jane Doe"),
            MagicMock(name="Bob Smith"),
        ]
        employees[0].name = "Jane Doe"
        employees[1].name = "Bob Smith"

        generated = HunterIOCollector._generate_emails_from_pattern(
            "{first}.{last}", "acme.com", employees
        )
        emails = {g["email"] for g in generated}
        assert "jane.doe@acme.com" in emails
        assert "bob.smith@acme.com" in emails
        assert all(g["confidence"] == 70 for g in generated)
        assert all(g["generated"] is True for g in generated)

    def test_generate_emails_f_last(self):
        employees = [MagicMock()]
        employees[0].name = "Jane Doe"

        generated = HunterIOCollector._generate_emails_from_pattern(
            "{f}{last}", "acme.com", employees
        )
        assert generated[0]["email"] == "jdoe@acme.com"

    def test_generate_emails_first_underscore_last(self):
        employees = [MagicMock()]
        employees[0].name = "Jane Doe"

        generated = HunterIOCollector._generate_emails_from_pattern(
            "{first}_{last}", "acme.com", employees
        )
        assert generated[0]["email"] == "jane_doe@acme.com"

    def test_generate_emails_f_dot_last(self):
        employees = [MagicMock()]
        employees[0].name = "Jane Doe"

        generated = HunterIOCollector._generate_emails_from_pattern(
            "{f}.{last}", "acme.com", employees
        )
        assert generated[0]["email"] == "j.doe@acme.com"

    def test_generate_emails_first_only(self):
        employees = [MagicMock()]
        employees[0].name = "Jane Doe"

        generated = HunterIOCollector._generate_emails_from_pattern(
            "{first}", "acme.com", employees
        )
        assert generated[0]["email"] == "jane@acme.com"

    def test_generate_emails_last_only(self):
        employees = [MagicMock()]
        employees[0].name = "Jane Doe"

        generated = HunterIOCollector._generate_emails_from_pattern(
            "{last}", "acme.com", employees
        )
        assert generated[0]["email"] == "doe@acme.com"

    def test_generate_emails_skips_single_name(self):
        employees = [MagicMock()]
        employees[0].name = "Madonna"

        generated = HunterIOCollector._generate_emails_from_pattern(
            "{first}.{last}", "acme.com", employees
        )
        assert len(generated) == 0

    def test_generate_emails_skips_empty_name(self):
        employees = [MagicMock()]
        employees[0].name = ""

        generated = HunterIOCollector._generate_emails_from_pattern(
            "{first}.{last}", "acme.com", employees
        )
        assert len(generated) == 0

    def test_generate_emails_handles_dict_input(self):
        """Should work with dict-style employee records too."""
        employees = [{"name": "Jane Doe"}]

        generated = HunterIOCollector._generate_emails_from_pattern(
            "{first}.{last}", "acme.com", employees
        )
        assert generated[0]["email"] == "jane.doe@acme.com"

    def test_generate_emails_unknown_pattern(self):
        employees = [MagicMock()]
        employees[0].name = "Jane Doe"

        generated = HunterIOCollector._generate_emails_from_pattern(
            "{weird_pattern}", "acme.com", employees
        )
        assert len(generated) == 0

    def test_progress_callback(self):
        collector = HunterIOCollector(config={})
        messages = []
        collector.set_progress_callback(lambda msg, status: messages.append(msg))
        collector._report("test hunter message", "info")
        assert "test hunter message" in messages


# ── DNSCTCollector ────────────────────────────────────────────


class TestDNSCTCollector:
    def test_init_defaults(self):
        collector = DNSCTCollector(config={})
        assert collector.max_subdomains == 500
        assert collector.resolve_dns is True
        assert collector.check_whois is True
        assert collector.rate_limit_delay == 0.5
        assert collector.validate_config() is True

    def test_init_custom_config(self):
        collector = DNSCTCollector(config={
            "max_subdomains": 100,
            "resolve_dns": False,
            "check_whois": False,
            "rate_limit_delay": 2.0,
        })
        assert collector.max_subdomains == 100
        assert collector.resolve_dns is False
        assert collector.check_whois is False
        assert collector.rate_limit_delay == 2.0

    @pytest.mark.asyncio
    async def test_collect_skips_without_domain(self):
        collector = DNSCTCollector(config={})
        org = Organization(name="Acme")  # no domain
        results = await collector.collect(org)
        assert results["infrastructure"]["subdomains"] == []
        assert results["infrastructure"]["dns_records"] == {}

    @pytest.mark.asyncio
    async def test_collect_with_mocked_pipeline(self):
        """Full pipeline: crt.sh → DNS → WHOIS → reverse DNS."""
        collector = DNSCTCollector(config={})
        org = Organization(name="Acme", domain="acme.com")

        mock_subdomains = {
            "dev.acme.com", "api.acme.com", "mail.acme.com", "acme.com"
        }
        mock_dns = {
            "A": ["1.2.3.4", "5.6.7.8"],
            "MX": ["10 mail.acme.com"],
            "TXT": [
                "v=spf1 include:_spf.google.com ~all",
                "v=DMARC1; p=reject; rua=mailto:dmarc@acme.com",
            ],
            "NS": ["ns1.example.com"],
        }
        mock_whois = {
            "domain": "acme.com",
            "registrar": "GoDaddy",
            "creation_date": "2010-01-15",
        }
        mock_sub_ips = {
            "dev.acme.com": ["10.0.0.1"],
            "api.acme.com": ["1.2.3.4"],
        }
        mock_reverse = [
            {"ip": "1.2.3.4", "ptr": "host-1.acme.com"},
            {"ip": "5.6.7.8", "ptr": None},
        ]

        with patch.object(collector, "_crtsh_search", return_value=mock_subdomains), \
             patch.object(collector, "_resolve_dns_records", return_value=mock_dns), \
             patch.object(collector, "_whois_lookup", return_value=mock_whois), \
             patch.object(collector, "_resolve_subdomain_ips", return_value=mock_sub_ips), \
             patch.object(collector, "_reverse_dns", return_value=mock_reverse), \
             patch.object(collector, "_rate_limit", return_value=None):

            results = await collector.collect(org)

        infra = results["infrastructure"]
        assert len(infra["subdomains"]) == 4
        assert "dev.acme.com" in infra["subdomains"]
        assert infra["dns_records"]["A"] == ["1.2.3.4", "5.6.7.8"]
        assert infra["mail_servers"] == ["10 mail.acme.com"]
        assert infra["whois"]["registrar"] == "GoDaddy"
        assert len(infra["reverse_dns"]) == 2

        # SPF and DMARC should be detected
        security = infra["security_headers"]
        assert security["SPF"]["present"] is True
        assert security["DMARC"]["present"] is True

        # IP consolidation: A records + subdomain IPs
        assert "1.2.3.4" in infra["ip_addresses"]
        assert "10.0.0.1" in infra["ip_addresses"]

    @pytest.mark.asyncio
    async def test_collect_without_dns_resolution(self):
        """Pipeline with resolve_dns=False skips DNS step."""
        collector = DNSCTCollector(config={"resolve_dns": False, "check_whois": False})
        org = Organization(name="Acme", domain="acme.com")

        mock_subdomains = {"sub1.acme.com", "sub2.acme.com"}

        with patch.object(collector, "_crtsh_search", return_value=mock_subdomains), \
             patch.object(collector, "_rate_limit", return_value=None):
            results = await collector.collect(org)

        infra = results["infrastructure"]
        assert len(infra["subdomains"]) == 2
        # DNS records not resolved
        assert infra["dns_records"] == {}
        assert infra["whois"] == {}

    # ── Subdomain Categorization ──────────────────────────────

    def test_categorize_subdomains_dev_staging(self):
        subs = {"dev.acme.com", "staging.acme.com", "qa.acme.com", "www.acme.com"}
        cats = DNSCTCollector._categorize_subdomains(subs)
        assert "Development/Staging" in cats
        assert "dev.acme.com" in cats["Development/Staging"]
        assert "staging.acme.com" in cats["Development/Staging"]
        assert "qa.acme.com" in cats["Development/Staging"]
        # www should not be categorized
        for category_subs in cats.values():
            assert "www.acme.com" not in category_subs

    def test_categorize_subdomains_admin(self):
        subs = {"admin.acme.com", "portal.acme.com", "dashboard.acme.com"}
        cats = DNSCTCollector._categorize_subdomains(subs)
        assert "Admin/Internal" in cats
        assert len(cats["Admin/Internal"]) == 3

    def test_categorize_subdomains_api(self):
        subs = {"api.acme.com", "graphql.acme.com", "rest.acme.com"}
        cats = DNSCTCollector._categorize_subdomains(subs)
        assert "API endpoints" in cats
        assert len(cats["API endpoints"]) == 3

    def test_categorize_subdomains_mail(self):
        subs = {"mail.acme.com", "smtp.acme.com", "webmail.acme.com"}
        cats = DNSCTCollector._categorize_subdomains(subs)
        assert "Mail" in cats
        assert len(cats["Mail"]) == 3

    def test_categorize_subdomains_vpn(self):
        subs = {"vpn.acme.com", "remote.acme.com", "bastion.acme.com"}
        cats = DNSCTCollector._categorize_subdomains(subs)
        assert "VPN/Remote" in cats
        assert len(cats["VPN/Remote"]) == 3

    def test_categorize_subdomains_empty(self):
        cats = DNSCTCollector._categorize_subdomains(set())
        assert cats == {}

    def test_categorize_subdomains_no_matches(self):
        subs = {"www.acme.com", "acme.com", "cdn.acme.com"}
        cats = DNSCTCollector._categorize_subdomains(subs)
        assert cats == {}

    # ── Email Security Analysis ───────────────────────────────

    def test_analyze_email_security_all_present(self):
        txt_records = [
            "v=spf1 include:_spf.google.com ~all",
            "v=DMARC1; p=reject; rua=mailto:dmarc@acme.com",
            "something_dkim_selector",
        ]
        security = DNSCTCollector._analyze_email_security(txt_records)
        assert security["SPF"]["present"] is True
        assert security["DMARC"]["present"] is True
        assert security["DKIM"]["present"] is True

    def test_analyze_email_security_none_present(self):
        txt_records = [
            "google-site-verification=abc123",
            "some-other-record",
        ]
        security = DNSCTCollector._analyze_email_security(txt_records)
        assert security["SPF"]["present"] is False
        assert security["DMARC"]["present"] is False
        assert security["DKIM"]["present"] is False

    def test_analyze_email_security_partial(self):
        txt_records = [
            "v=spf1 -all",
        ]
        security = DNSCTCollector._analyze_email_security(txt_records)
        assert security["SPF"]["present"] is True
        assert security["DMARC"]["present"] is False

    def test_analyze_email_security_empty(self):
        security = DNSCTCollector._analyze_email_security([])
        assert security["SPF"]["present"] is False
        assert security["DMARC"]["present"] is False
        assert security["DKIM"]["present"] is False

    def test_analyze_email_security_spf_detail_truncated(self):
        """SPF detail should be truncated to 120 chars."""
        long_spf = "v=spf1 " + "include:very-long-domain.example.com " * 10 + "~all"
        security = DNSCTCollector._analyze_email_security([long_spf])
        assert len(security["SPF"]["detail"]) <= 120

    # ── Progress Callback ─────────────────────────────────────

    def test_progress_callback(self):
        collector = DNSCTCollector(config={})
        messages = []
        collector.set_progress_callback(lambda msg, status: messages.append(msg))
        collector._report("test dns message", "info")
        assert "test dns message" in messages
