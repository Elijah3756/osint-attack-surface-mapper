"""Tests for Phase 2 collectors: Shodan, HIBP, and WebScraper."""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.recon.collectors import (
    BaseCollector,
    RateLimiter,
    ShodanCollector,
    HIBPCollector,
    WebScraperCollector,
)
from src.recon.discovery import Organization, Person


# ── RateLimiter ────────────────────────────────────────────────


class TestRateLimiter:
    def test_init(self):
        limiter = RateLimiter(calls_per_second=2.0)
        assert limiter._delay == 0.5

    @pytest.mark.asyncio
    async def test_acquire_enforces_delay(self):
        limiter = RateLimiter(calls_per_second=100.0)  # fast for tests
        await limiter.acquire()
        await limiter.acquire()
        # Should not raise; just verifying sequential acquire works

    def test_set_rate_limiter_on_collector(self):
        collector = ShodanCollector(config={"shodan_api_key": "test"})
        limiter = RateLimiter()
        collector.set_rate_limiter(limiter)
        assert collector._rate_limiter is limiter


# ── ShodanCollector ────────────────────────────────────────────


class TestShodanCollector:
    def test_init_with_key(self):
        collector = ShodanCollector(config={"shodan_api_key": "test_key"})
        assert collector.api_key == "test_key"
        assert collector.validate_config() is True

    def test_init_without_key(self):
        collector = ShodanCollector(config={})
        assert collector.api_key is None
        assert collector.validate_config() is False

    @pytest.mark.asyncio
    async def test_collect_skips_without_key(self):
        collector = ShodanCollector(config={})
        org = Organization(name="Acme", domain="acme.com")
        results = await collector.collect(org)
        assert results["infrastructure"]["hosts"] == []

    @pytest.mark.asyncio
    async def test_collect_skips_without_domain(self):
        collector = ShodanCollector(config={"shodan_api_key": "key"})
        org = Organization(name="Acme")  # no domain
        results = await collector.collect(org)
        assert results["infrastructure"]["hosts"] == []

    @pytest.mark.asyncio
    async def test_collect_with_mocked_api(self):
        """Verify the collection pipeline with mocked HTTP responses."""
        collector = ShodanCollector(config={"shodan_api_key": "key"})
        org = Organization(name="Acme", domain="acme.com")

        mock_dns = {"acme.com": "1.2.3.4"}
        mock_search = {
            "matches": [
                {"ip_str": "1.2.3.4"}
            ]
        }
        mock_host = {
            "ip_str": "1.2.3.4",
            "hostnames": ["acme.com"],
            "os": "Linux",
            "org": "Acme Corp",
            "isp": "AWS",
            "ports": [80, 443],
            "last_update": "2025-01-01",
            "data": [
                {
                    "port": 443,
                    "transport": "tcp",
                    "product": "nginx",
                    "version": "1.25",
                    "data": "HTTP/1.1 200 OK",
                    "ssl": {
                        "cert": {
                            "subject": {"CN": "acme.com"},
                            "issuer": {"O": "Let's Encrypt"},
                            "expires": "2025-12-01",
                            "fingerprint": {"sha256": "abc123"},
                        }
                    },
                    "vulns": {
                        "CVE-2024-1234": 7.5,
                    },
                }
            ],
        }

        with patch.object(collector, "_dns_resolve", return_value=mock_dns), \
             patch.object(collector, "_search_domain", return_value=mock_search["matches"]), \
             patch.object(collector, "_get_host", return_value=mock_host), \
             patch.object(collector, "_rate_limit", return_value=None):

            results = await collector.collect(org)

        infra = results["infrastructure"]
        assert len(infra["hosts"]) == 1
        assert infra["hosts"][0]["ip"] == "1.2.3.4"
        assert 80 in infra["open_ports"]
        assert 443 in infra["open_ports"]
        assert len(infra["vulnerabilities"]) == 1
        assert infra["vulnerabilities"][0]["cve"] == "CVE-2024-1234"
        assert len(infra["ssl_certs"]) == 1
        assert infra["ssl_certs"][0]["issued_to"] == "acme.com"

    def test_progress_callback(self):
        collector = ShodanCollector(config={"shodan_api_key": "key"})
        messages = []
        collector.set_progress_callback(lambda msg, status: messages.append(msg))
        collector._report("test message", "info")
        assert "test message" in messages


# ── HIBPCollector ──────────────────────────────────────────────


class TestHIBPCollector:
    def test_init_with_key(self):
        collector = HIBPCollector(config={"hibp_api_key": "test_key"})
        assert collector.api_key == "test_key"
        assert collector.validate_config() is True

    def test_init_without_key(self):
        collector = HIBPCollector(config={})
        assert collector.api_key is None
        assert collector.validate_config() is False

    def test_rate_limit_minimum(self):
        """HIBP enforces >= 1.5s between requests."""
        collector = HIBPCollector(config={"hibp_api_key": "k", "rate_limit_delay": 0.5})
        assert collector.rate_limit_delay >= 1.5

    # ── Tiered account tests ──────────────────────────────────

    def test_default_tier_is_pwned_1(self):
        """When no tier is specified, default to pwned_1."""
        collector = HIBPCollector(config={"hibp_api_key": "k"})
        assert collector.tier_key == "pwned_1"
        assert collector.tier_label == "Pwned 1 (Base)"
        assert collector.breached_per_domain == 25

    def test_tier_pwned_1_rate(self):
        """pwned_1 tier: 10 rpm → 6.0s delay."""
        collector = HIBPCollector(config={"hibp_api_key": "k", "account_tier": "pwned_1"})
        assert collector.rate_limit_delay == 6.0

    def test_tier_pwned_2(self):
        """pwned_2 tier: 50 rpm → 1.5s delay (HIBP floor), 50/domain."""
        collector = HIBPCollector(config={"hibp_api_key": "k", "account_tier": "pwned_2"})
        assert collector.tier_key == "pwned_2"
        assert collector.rate_limit_delay == 1.5  # max(1.5, 60/50=1.2) = 1.5
        assert collector.breached_per_domain == 50

    def test_tier_pwned_3(self):
        """pwned_3 tier: unlimited rpm & domain cap."""
        collector = HIBPCollector(config={"hibp_api_key": "k", "account_tier": "pwned_3"})
        assert collector.tier_key == "pwned_3"
        assert collector.rate_limit_delay == 1.5  # HIBP floor only
        assert collector.breached_per_domain == 0  # 0 = unlimited

    def test_tier_pwned_4(self):
        """pwned_4 tier: unlimited + domain search flag."""
        collector = HIBPCollector(config={"hibp_api_key": "k", "account_tier": "pwned_4"})
        assert collector.tier_key == "pwned_4"
        assert collector.tier["domain_search"] is True

    def test_unknown_tier_falls_back(self):
        """Unknown tier name falls back to pwned_1."""
        collector = HIBPCollector(config={"hibp_api_key": "k", "account_tier": "super_mega"})
        assert collector.tier_key == "pwned_1"
        assert collector.rate_limit_delay == 6.0

    def test_tier_name_normalization(self):
        """Tier names are case-insensitive and accept hyphens."""
        collector = HIBPCollector(config={"hibp_api_key": "k", "account_tier": "Pwned-2"})
        assert collector.tier_key == "pwned_2"

    def test_config_override_delay(self):
        """Config can increase delay but never below tier computed floor."""
        collector = HIBPCollector(
            config={"hibp_api_key": "k", "account_tier": "pwned_1", "rate_limit_delay": 10.0}
        )
        assert collector.rate_limit_delay == 10.0

    def test_config_override_delay_clamped(self):
        """Config delay below tier floor gets clamped up."""
        collector = HIBPCollector(
            config={"hibp_api_key": "k", "account_tier": "pwned_1", "rate_limit_delay": 2.0}
        )
        assert collector.rate_limit_delay == 6.0  # tier floor wins

    def test_config_override_domain_cap(self):
        """breached_per_domain in config overrides tier default."""
        collector = HIBPCollector(
            config={"hibp_api_key": "k", "account_tier": "pwned_1", "breached_per_domain": 10}
        )
        assert collector.breached_per_domain == 10

    def test_available_tiers_classmethod(self):
        """available_tiers() returns all tier definitions."""
        tiers = HIBPCollector.available_tiers()
        assert "pwned_1" in tiers
        assert "pwned_2" in tiers
        assert "pwned_3" in tiers
        assert "pwned_4" in tiers
        assert tiers["pwned_1"]["rpm"] == 10

    @pytest.mark.asyncio
    async def test_domain_cap_enforcement(self):
        """Emails are skipped once the per-domain breach cap is hit."""
        collector = HIBPCollector(
            config={"hibp_api_key": "key", "account_tier": "pwned_1"}
        )
        assert collector.breached_per_domain == 25

        org = Organization(name="Acme")
        # Add 30 employees at same domain — cap should kick in at 25
        for i in range(30):
            org.add_employee(
                Person(name=f"User{i}", organization="Acme", email=f"user{i}@acme.com")
            )

        call_count = 0

        async def mock_breaches(session, email):
            nonlocal call_count
            call_count += 1
            return [{"name": "Breach", "domain": "leak.com", "breach_date": "2024-01-01",
                     "pwn_count": 100, "data_classes": ["Emails"], "is_verified": True,
                     "is_sensitive": False}]

        with patch.object(collector, "_check_breaches", side_effect=mock_breaches), \
             patch.object(collector, "_check_pastes", return_value=[]), \
             patch.object(collector, "_rate_limit_hibp", return_value=None):

            results = await collector.collect(org)

        # Should have stopped checking at 25 breached for acme.com
        assert len(results["breach_data"]) == 25
        assert call_count == 25

    @pytest.mark.asyncio
    async def test_unlimited_tier_no_domain_cap(self):
        """pwned_3 tier has no domain cap — all emails are checked."""
        collector = HIBPCollector(
            config={"hibp_api_key": "key", "account_tier": "pwned_3"}
        )
        assert collector.breached_per_domain == 0  # unlimited

        org = Organization(name="Acme")
        for i in range(30):
            org.add_employee(
                Person(name=f"User{i}", organization="Acme", email=f"user{i}@acme.com")
            )

        async def mock_breaches(session, email):
            return [{"name": "Breach", "domain": "leak.com", "breach_date": "2024-01-01",
                     "pwn_count": 100, "data_classes": ["Emails"], "is_verified": True,
                     "is_sensitive": False}]

        with patch.object(collector, "_check_breaches", side_effect=mock_breaches), \
             patch.object(collector, "_check_pastes", return_value=[]), \
             patch.object(collector, "_rate_limit_hibp", return_value=None):

            results = await collector.collect(org)

        assert len(results["breach_data"]) == 30  # no cap

    @pytest.mark.asyncio
    async def test_domain_cap_per_domain(self):
        """Domain cap is enforced independently per email domain."""
        collector = HIBPCollector(
            config={"hibp_api_key": "key", "breached_per_domain": 2}
        )

        org = Organization(name="Acme")
        org.add_employee(Person(name="A", organization="Acme", email="a@foo.com"))
        org.add_employee(Person(name="B", organization="Acme", email="b@foo.com"))
        org.add_employee(Person(name="C", organization="Acme", email="c@foo.com"))
        org.add_employee(Person(name="D", organization="Acme", email="d@bar.com"))
        org.add_employee(Person(name="E", organization="Acme", email="e@bar.com"))
        org.add_employee(Person(name="F", organization="Acme", email="f@bar.com"))

        async def mock_breaches(session, email):
            return [{"name": "Breach", "domain": "leak.com", "breach_date": "2024-01-01",
                     "pwn_count": 100, "data_classes": ["Emails"], "is_verified": True,
                     "is_sensitive": False}]

        with patch.object(collector, "_check_breaches", side_effect=mock_breaches), \
             patch.object(collector, "_check_pastes", return_value=[]), \
             patch.object(collector, "_rate_limit_hibp", return_value=None):

            results = await collector.collect(org)

        # 2 from foo.com + 2 from bar.com = 4 total (1 skipped per domain)
        assert len(results["breach_data"]) == 4

    # ── Original tests ────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_collect_skips_without_key(self):
        collector = HIBPCollector(config={})
        org = Organization(name="Acme", domain="acme.com")
        results = await collector.collect(org)
        assert results["breach_data"] == {}

    @pytest.mark.asyncio
    async def test_collect_skips_without_emails(self):
        collector = HIBPCollector(config={"hibp_api_key": "key"})
        org = Organization(name="Acme", domain="acme.com")
        results = await collector.collect(org)
        assert results["breach_data"] == {}

    def test_gather_emails_from_profiles(self):
        org = Organization(name="Acme")
        org.add_employee(Person(name="Jane", organization="Acme", email="jane@acme.com"))
        org.add_employee(Person(name="John", organization="Acme", email="john@acme.com"))
        org.add_employee(Person(name="NoEmail", organization="Acme"))

        emails = HIBPCollector._gather_emails(org)
        assert "jane@acme.com" in emails
        assert "john@acme.com" in emails
        assert len(emails) == 2

    def test_gather_emails_from_commit_history(self):
        org = Organization(name="Acme")
        org.infrastructure["commit_emails"] = [
            {"email": "dev@acme.com", "name": "Dev"},
            {"email": "Jane@acme.com", "name": "Jane"},  # should dedup with profile email
        ]
        org.add_employee(Person(name="Jane", organization="Acme", email="jane@acme.com"))

        emails = HIBPCollector._gather_emails(org)
        assert "dev@acme.com" in emails
        assert "jane@acme.com" in emails
        assert len(emails) == 2  # deduped

    def test_gather_emails_deduplication(self):
        org = Organization(name="Acme")
        org.add_employee(
            Person(
                name="Jane",
                organization="Acme",
                email="JANE@acme.com",
                social_profiles={"github": {"email": "jane@acme.com"}},
            )
        )
        emails = HIBPCollector._gather_emails(org)
        assert len(emails) == 1

    @pytest.mark.asyncio
    async def test_collect_with_mocked_api(self):
        collector = HIBPCollector(config={"hibp_api_key": "key"})
        org = Organization(name="Acme")
        org.add_employee(Person(name="Jane", organization="Acme", email="jane@acme.com"))

        # _check_breaches returns already-formatted dicts (lowercase keys)
        mock_breaches = [
            {
                "name": "BigBreach",
                "domain": "bigbreach.com",
                "breach_date": "2023-06-01",
                "pwn_count": 1000000,
                "data_classes": ["Emails", "Passwords"],
                "is_verified": True,
                "is_sensitive": False,
            }
        ]

        with patch.object(collector, "_check_breaches", return_value=mock_breaches), \
             patch.object(collector, "_check_pastes", return_value=[]), \
             patch.object(collector, "_rate_limit_hibp", return_value=None):

            results = await collector.collect(org)

        assert "jane@acme.com" in results["breach_data"]
        data = results["breach_data"]["jane@acme.com"]
        assert data["breach_count"] == 1
        assert data["breaches"][0]["name"] == "BigBreach"


# ── WebScraperCollector ────────────────────────────────────────


class TestWebScraperCollector:
    def test_init_defaults(self):
        collector = WebScraperCollector(config={})
        assert collector.max_depth == 2
        assert collector.max_pages == 100
        assert collector.respect_robots is True
        assert collector.validate_config() is True

    def test_init_custom_config(self):
        collector = WebScraperCollector(config={
            "max_depth": 3,
            "max_pages": 50,
            "respect_robots_txt": False,
        })
        assert collector.max_depth == 3
        assert collector.max_pages == 50
        assert collector.respect_robots is False

    @pytest.mark.asyncio
    async def test_collect_skips_without_domain(self):
        collector = WebScraperCollector(config={})
        org = Organization(name="Acme")
        results = await collector.collect(org)
        assert results["employees"] == []

    def test_email_regex(self):
        test_html = "Contact us at info@acme.com or sales@acme.com"
        matches = WebScraperCollector.EMAIL_RE.findall(test_html)
        assert "info@acme.com" in matches
        assert "sales@acme.com" in matches

    def test_phone_regex(self):
        test_cases = [
            ("Call (555) 123-4567", True),
            ("Phone: 555.123.4567", True),
            ("Tel: +1-555-123-4567", True),
            ("Not a phone: 123", False),
        ]
        for text, should_match in test_cases:
            matches = WebScraperCollector.PHONE_RE.findall(text)
            assert bool(matches) == should_match, f"Failed for: {text}"

    def test_is_disallowed(self):
        disallowed = {"/admin", "/private/"}
        assert WebScraperCollector._is_disallowed(
            "https://acme.com/admin/panel", "https://acme.com", disallowed
        )
        assert not WebScraperCollector._is_disallowed(
            "https://acme.com/about", "https://acme.com", disallowed
        )

    def test_fingerprint_technologies(self):
        html = '<script src="react.js"></script><link href="bootstrap.css">'
        headers = {"Server": "nginx/1.25", "X-Powered-By": "Express"}

        techs = WebScraperCollector._fingerprint_technologies(html, headers)
        assert "Server: nginx/1.25" in techs
        assert "X-Powered-By: Express" in techs
        assert "React" in techs
        assert "Bootstrap" in techs

    def test_extract_people_schema_org(self):
        from bs4 import BeautifulSoup
        html = """
        <div itemscope itemtype="https://schema.org/Person">
            <span itemprop="name">Jane Doe</span>
            <span itemprop="jobTitle">CTO</span>
        </div>
        """
        soup = BeautifulSoup(html, "lxml")
        people = WebScraperCollector._extract_people(soup, "acme.com", "Acme")
        assert len(people) == 1
        assert people[0]["name"] == "Jane Doe"
        assert people[0]["role"] == "CTO"

    def test_extract_people_card_pattern(self):
        from bs4 import BeautifulSoup
        html = """
        <div class="team-member">
            <h3>Bob Smith</h3>
            <p>VP of Engineering</p>
        </div>
        <div class="team-member">
            <h3>Alice Jones</h3>
            <p>Head of Security</p>
        </div>
        """
        soup = BeautifulSoup(html, "lxml")
        people = WebScraperCollector._extract_people(soup, "acme.com", "Acme")
        assert len(people) == 2
        names = {p["name"] for p in people}
        assert "Bob Smith" in names
        assert "Alice Jones" in names

    def test_extract_people_no_duplicates(self):
        from bs4 import BeautifulSoup
        html = """
        <div itemscope itemtype="https://schema.org/Person">
            <span itemprop="name">Jane Doe</span>
        </div>
        <div class="team-member">
            <h3>Jane Doe</h3>
            <p>CTO</p>
        </div>
        """
        soup = BeautifulSoup(html, "lxml")
        people = WebScraperCollector._extract_people(soup, "acme.com", "Acme")
        assert len(people) == 1  # should deduplicate

    @pytest.mark.asyncio
    async def test_collect_with_mocked_pages(self):
        collector = WebScraperCollector(config={"max_depth": 1, "max_pages": 5})
        org = Organization(name="Acme", domain="acme.com")

        homepage_html = """
        <html>
            <head><title>Acme Corp</title></head>
            <body>
                <a href="/about">About Us</a>
                <a href="/docs/report.pdf">Annual Report</a>
                Contact: info@acme.com
            </body>
        </html>
        """
        about_html = """
        <html><body>
            <div class="team-member">
                <h3>Jane Doe</h3>
                <p>CEO</p>
            </div>
        </body></html>
        """

        call_count = 0

        async def mock_fetch(session, url):
            nonlocal call_count
            call_count += 1
            if "about" in url:
                return about_html, {"Server": "nginx"}
            return homepage_html, {"Server": "nginx", "X-Powered-By": "Express"}

        with patch.object(collector, "_fetch_page", side_effect=mock_fetch), \
             patch.object(collector, "_parse_robots", return_value=set()), \
             patch.object(collector, "_rate_limit", return_value=None):

            results = await collector.collect(org)

        assert len(results["employees"]) >= 1
        assert "info@acme.com" in results["infrastructure"]["emails_found"]
        assert any(d["type"] == "pdf" for d in results["documents"])
