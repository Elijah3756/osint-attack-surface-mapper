"""
Data Collectors - Modular collectors for various OSINT data sources.

Each collector implements the BaseCollector interface and targets
a specific public data source for ethical OSINT gathering.
"""

import asyncio
import logging
import re
import time
from abc import ABC, abstractmethod
from typing import Optional
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Async rate limiter using a token-bucket algorithm.

    Enforces a maximum number of requests per time window across
    all collectors sharing the same limiter instance.
    """

    def __init__(self, calls_per_second: float = 1.0):
        self._delay = 1.0 / calls_per_second
        self._semaphore = asyncio.Semaphore(1)
        self._last_call = 0.0

    async def acquire(self):
        """Wait until the next request is allowed."""
        async with self._semaphore:
            now = time.monotonic()
            elapsed = now - self._last_call
            if elapsed < self._delay:
                await asyncio.sleep(self._delay - elapsed)
            self._last_call = time.monotonic()


class BaseCollector(ABC):
    """Base class for all OSINT data collectors."""

    def __init__(self, config: dict):
        self.config = config
        self.rate_limit_delay = config.get("rate_limit_delay", 1.0)
        self._progress_callback = None
        self._rate_limiter: Optional[RateLimiter] = None

    def set_progress_callback(self, callback):
        """Set a callback for live progress updates: callback(message, status)."""
        self._progress_callback = callback

    def set_rate_limiter(self, limiter: RateLimiter):
        """Attach a shared rate limiter (for cross-collector throttling)."""
        self._rate_limiter = limiter

    def _report(self, message: str, status: str = "info"):
        """Report progress via callback if set, otherwise log."""
        if self._progress_callback:
            self._progress_callback(message, status)
        else:
            logger.info(message)

    @abstractmethod
    async def collect(self, organization) -> dict:
        """Collect data for the given organization. Must be implemented."""
        pass

    @abstractmethod
    def validate_config(self) -> bool:
        """Validate that required configuration/API keys are present."""
        pass

    async def _rate_limit(self):
        """Enforce rate limiting between API calls."""
        if self._rate_limiter:
            await self._rate_limiter.acquire()
        else:
            await asyncio.sleep(self.rate_limit_delay)


class GitHubCollector(BaseCollector):
    """
    Collects public data from GitHub.

    Discovers org members, repositories, commit authors,
    and publicly exposed information (emails in commits, etc.)

    Works in two modes:
    - Authenticated (with token): 5000 requests/hour, access to org members
    - Unauthenticated: 60 requests/hour, public data only
    """

    def __init__(self, config: dict):
        super().__init__(config)
        self.api_token = config.get("github_token")
        self.base_url = "https://api.github.com"
        self.max_repos = config.get("max_repos", 50)
        self.scan_commits = config.get("scan_commits", True)

    def validate_config(self) -> bool:
        # Works without token (just slower due to rate limits)
        return True

    def _get_headers(self) -> dict:
        """Build request headers, with auth if token available."""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "OSINT-Recon-Tool/0.1 (Educational Research)",
        }
        if self.api_token:
            headers["Authorization"] = f"token {self.api_token}"
        return headers

    async def collect(self, organization) -> dict:
        """
        Collect GitHub OSINT data for the target organization.

        Discovery pipeline:
        1. Search for the organization's GitHub account
        2. Enumerate public members
        3. List public repositories
        4. Scan commit history for emails and contributor info
        5. Extract profile metadata (bios, locations, links)
        """
        results = {
            "employees": [],
            "infrastructure": {"github_repos": []},
            "raw_profiles": [],
        }

        self._report(f"GitHub collection starting for: {organization.name}")

        async with aiohttp.ClientSession(headers=self._get_headers()) as session:
            # Step 1: Find the org account
            self._report("Searching for GitHub organization...", "info")
            org_login = await self._find_org(session, organization.name)

            if org_login:
                self._report(f"Found GitHub org: {org_login}", "ok")

                # Step 2: Get public members
                self._report("Enumerating public members...", "info")
                members = await self._get_org_members(session, org_login)
                self._report(f"Found {len(members)} public members", "ok")

                # Step 3: Get member profiles with details
                total_members = len(members)
                for i, member in enumerate(members):
                    await self._rate_limit()
                    self._report(
                        f"Fetching profile {i+1}/{total_members}: {member['login']}",
                        "info",
                    )
                    profile = await self._get_user_profile(
                        session, member["login"]
                    )
                    if profile:
                        person_data = self._profile_to_person(
                            profile, organization.name
                        )
                        results["employees"].append(person_data)
                        results["raw_profiles"].append(profile)

                self._report(
                    f"Collected {len(results['employees'])} member profiles", "ok"
                )

                # Step 4: Get public repos
                self._report("Listing public repositories...", "info")
                repos = await self._get_org_repos(session, org_login)
                results["infrastructure"]["github_repos"] = [
                    {
                        "name": r["name"],
                        "url": r["html_url"],
                        "language": r.get("language"),
                    }
                    for r in repos
                ]
                self._report(f"Found {len(repos)} public repos", "ok")

                # Step 5: Scan commits for additional emails
                if self.scan_commits and repos:
                    scan_repos = repos[:10]
                    self._report(
                        f"Scanning commit history across {len(scan_repos)} repos...",
                        "info",
                    )
                    commit_emails = await self._scan_commit_emails(
                        session, org_login, scan_repos
                    )
                    results["infrastructure"]["commit_emails"] = commit_emails
                    self._report(
                        f"Found {len(commit_emails)} unique emails in commits",
                        "ok",
                    )

            else:
                # Fallback: search for users who mention the org in their bio
                self._report(
                    "No org account found, searching user bios...", "warn"
                )
                users = await self._search_users_by_org(
                    session, organization.name
                )
                self._report(f"Bio search returned {len(users)} users", "info")
                for i, user in enumerate(users):
                    await self._rate_limit()
                    self._report(
                        f"Fetching profile {i+1}/{len(users)}: {user['login']}",
                        "info",
                    )
                    profile = await self._get_user_profile(
                        session, user["login"]
                    )
                    if profile:
                        person_data = self._profile_to_person(
                            profile, organization.name
                        )
                        results["employees"].append(person_data)

        self._report(
            f"GitHub collection complete: "
            f"{len(results['employees'])} people discovered",
            "ok",
        )
        return results

    async def _find_org(
        self, session: aiohttp.ClientSession, org_name: str
    ) -> Optional[str]:
        """Search for the organization's GitHub account."""

        # Check rate limit status first
        try:
            async with session.get(f"{self.base_url}/rate_limit") as resp:
                if resp.status == 200:
                    rl = await resp.json()
                    core = rl.get("resources", {}).get("core", {})
                    remaining = core.get("remaining", "?")
                    limit = core.get("limit", "?")
                    logger.info(f"GitHub API rate limit: {remaining}/{limit} remaining")
                    if remaining == 0:
                        logger.error(
                            "GitHub API rate limit exhausted! "
                            "Set a GITHUB_TOKEN for 5000 req/hr."
                        )
                        return None
        except Exception as e:
            logger.debug(f"Rate limit check failed: {e}")

        # Build unique slug variations to try
        seen = set()
        variations = []
        for v in [
            org_name,  # Exact case first (e.g., "Netflix")
            org_name.lower(),
            org_name.lower().replace(" ", "-"),
            org_name.lower().replace(" ", ""),
            org_name.lower().replace(" ", "").replace("-", "").replace(".", ""),
        ]:
            if v not in seen:
                seen.add(v)
                variations.append(v)

        for variation in variations:
            url = f"{self.base_url}/orgs/{variation}"
            logger.debug(f"Trying org lookup: {url}")
            try:
                async with session.get(url) as resp:
                    logger.debug(f"  Response: {resp.status}")
                    if resp.status == 200:
                        data = await resp.json()
                        return data["login"]
                    elif resp.status == 403:
                        body = await resp.json()
                        msg = body.get("message", "")
                        logger.warning(f"GitHub 403 for {variation}: {msg}")
                        if "rate limit" in msg.lower():
                            logger.error(
                                "Rate limited! Add a GitHub token to "
                                "config/settings.local.yaml or set "
                                "GITHUB_TOKEN env var."
                            )
                            return None
                    elif resp.status == 404:
                        logger.debug(f"  Org '{variation}' not found (404)")
                    else:
                        logger.debug(f"  Unexpected status {resp.status}")
            except Exception as e:
                logger.warning(f"Org lookup failed for {variation}: {e}")

        # Fallback: search API
        logger.info("Direct org lookup failed, trying search API...")
        url = f"{self.base_url}/search/users"
        params = {"q": f"{org_name} type:org", "per_page": 5}
        try:
            async with session.get(url, params=params) as resp:
                logger.debug(f"Search API response: {resp.status}")
                if resp.status == 200:
                    data = await resp.json()
                    items = data.get("items", [])
                    if items:
                        logger.info(
                            f"Search found org: {items[0].get('login')}"
                        )
                        return items[0]["login"]
                    else:
                        logger.warning("Search returned 0 org results")
                elif resp.status == 403:
                    body = await resp.json()
                    logger.error(f"Search API rate limited: {body.get('message')}")
                else:
                    logger.warning(f"Search API returned {resp.status}")
        except Exception as e:
            logger.error(f"Org search failed: {e}")

        return None

    async def _get_org_members(
        self, session: aiohttp.ClientSession, org_login: str
    ) -> list:
        """Get public members of an organization (paginated)."""
        members = []
        page = 1

        while True:
            url = f"{self.base_url}/orgs/{org_login}/members"
            params = {"per_page": 100, "page": page}

            try:
                async with session.get(url, params=params) as resp:
                    if resp.status != 200:
                        logger.warning(f"Members request failed: {resp.status}")
                        break
                    data = await resp.json()
                    if not data:
                        break
                    members.extend(data)
                    page += 1
                    await self._rate_limit()
            except Exception as e:
                logger.error(f"Error fetching members page {page}: {e}")
                break

        return members

    async def _get_user_profile(
        self, session: aiohttp.ClientSession, username: str
    ) -> Optional[dict]:
        """Get detailed profile for a single GitHub user."""
        url = f"{self.base_url}/users/{username}"

        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 403:
                    logger.warning("Rate limit hit, waiting 60s...")
                    await asyncio.sleep(60)
                    async with session.get(url) as retry_resp:
                        if retry_resp.status == 200:
                            return await retry_resp.json()
                else:
                    logger.warning(
                        f"Profile fetch failed for {username}: {resp.status}"
                    )
        except Exception as e:
            logger.error(f"Error fetching profile for {username}: {e}")

        return None

    async def _get_org_repos(
        self, session: aiohttp.ClientSession, org_login: str
    ) -> list:
        """Get public repositories for the organization (paginated)."""
        repos = []
        page = 1

        while len(repos) < self.max_repos:
            url = f"{self.base_url}/orgs/{org_login}/repos"
            params = {
                "type": "public",
                "sort": "updated",
                "per_page": min(100, self.max_repos - len(repos)),
                "page": page,
            }

            try:
                async with session.get(url, params=params) as resp:
                    if resp.status != 200:
                        break
                    data = await resp.json()
                    if not data:
                        break
                    repos.extend(data)
                    page += 1
                    await self._rate_limit()
            except Exception as e:
                logger.error(f"Error fetching repos page {page}: {e}")
                break

        return repos

    async def _scan_commit_emails(
        self,
        session: aiohttp.ClientSession,
        org_login: str,
        repos: list,
    ) -> list:
        """
        Scan recent commits for email addresses.

        Commit history often exposes employee emails even when
        profiles don't list them — a key OSINT technique.
        """
        emails = set()

        for repo in repos:
            repo_name = repo["name"]
            url = f"{self.base_url}/repos/{org_login}/{repo_name}/commits"
            params = {"per_page": 30}

            try:
                async with session.get(url, params=params) as resp:
                    if resp.status != 200:
                        continue
                    commits = await resp.json()

                    for commit in commits:
                        commit_data = commit.get("commit", {})
                        author = commit_data.get("author", {})
                        committer = commit_data.get("committer", {})

                        for person in [author, committer]:
                            email = person.get("email", "")
                            name = person.get("name", "")
                            if email and not self._is_noreply_email(email):
                                emails.add((email, name))

                await self._rate_limit()
            except Exception as e:
                logger.error(f"Error scanning commits for {repo_name}: {e}")

        return [{"email": e, "name": n} for e, n in emails]

    async def _search_users_by_org(
        self, session: aiohttp.ClientSession, org_name: str
    ) -> list:
        """Search for users who list the organization in their bio."""
        url = f"{self.base_url}/search/users"
        params = {"q": f'"{org_name}" in:bio', "per_page": 30}

        try:
            async with session.get(url, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("items", [])
        except Exception as e:
            logger.error(f"User search failed: {e}")

        return []

    @staticmethod
    def _is_noreply_email(email: str) -> bool:
        """Filter out GitHub noreply and bot emails."""
        noreply_patterns = [
            "noreply",
            "github.com",
            "users.noreply",
            "dependabot",
            "greenkeeper",
            "renovate",
        ]
        return any(pattern in email.lower() for pattern in noreply_patterns)

    @staticmethod
    def _profile_to_person(profile: dict, org_name: str) -> dict:
        """Convert a GitHub API profile to our Person data format."""
        return {
            "name": profile.get("name") or profile.get("login", "Unknown"),
            "organization": org_name,
            "role": profile.get("bio", ""),
            "email": profile.get("email"),
            "social_profiles": {
                "github": {
                    "username": profile.get("login"),
                    "url": profile.get("html_url"),
                    "bio": profile.get("bio"),
                    "location": profile.get("location"),
                    "company": profile.get("company"),
                    "blog": profile.get("blog"),
                    "twitter": profile.get("twitter_username"),
                    "public_repos": profile.get("public_repos", 0),
                    "followers": profile.get("followers", 0),
                    "following": profile.get("following", 0),
                    "created_at": profile.get("created_at"),
                }
            },
            "metadata": {
                "source": "github",
                "avatar_url": profile.get("avatar_url"),
                "hireable": profile.get("hireable"),
            },
        }


class ShodanCollector(BaseCollector):
    """
    Collects infrastructure data from Shodan.

    Maps an organization's internet-facing infrastructure:
    - Open ports and running services
    - SSL certificate details
    - Known vulnerabilities (CVEs)
    - Hostnames and IP ranges

    Requires a Shodan API key (free tier: 100 queries/month).
    """

    BASE_URL = "https://api.shodan.io"

    def __init__(self, config: dict):
        super().__init__(config)
        self.api_key = config.get("shodan_api_key")
        self.rate_limit_delay = config.get("rate_limit_delay", 1.0)

    def validate_config(self) -> bool:
        return self.api_key is not None

    async def collect(self, organization) -> dict:
        """
        Collect infrastructure data for the target organization.

        Pipeline:
        1. Resolve the org's domain to identify IP space
        2. Search Shodan for hosts associated with the domain
        3. Enumerate open ports, services, and vulnerabilities
        4. Extract SSL certificate metadata
        """
        results = {
            "infrastructure": {
                "hosts": [],
                "open_ports": [],
                "services": [],
                "vulnerabilities": [],
                "ssl_certs": [],
                "domains": [],
            }
        }

        if not self.validate_config():
            self._report("Shodan API key not configured — skipping", "warn")
            return results

        domain = organization.domain
        if not domain:
            self._report(
                "No domain set for organization — skipping Shodan", "warn"
            )
            return results

        self._report(f"Shodan collection starting for domain: {domain}")

        async with aiohttp.ClientSession() as session:
            # Step 1: DNS resolve
            self._report("Resolving domain DNS records...", "info")
            dns_data = await self._dns_resolve(session, domain)
            if dns_data:
                results["infrastructure"]["domains"].append(
                    {"domain": domain, "dns": dns_data}
                )
                self._report(
                    f"DNS resolved: {len(dns_data)} record types found", "ok"
                )

            # Step 2: Search Shodan for the domain
            self._report(f"Searching Shodan for hosts on {domain}...", "info")
            hosts = await self._search_domain(session, domain)
            self._report(f"Found {len(hosts)} hosts", "ok")

            # Step 3: Enumerate each host
            all_ports = set()
            all_vulns = []
            all_services = []

            for i, host_summary in enumerate(hosts):
                ip = host_summary.get("ip_str", "")
                await self._rate_limit()
                self._report(
                    f"Scanning host {i+1}/{len(hosts)}: {ip}", "info"
                )

                host_detail = await self._get_host(session, ip)
                if not host_detail:
                    continue

                host_record = {
                    "ip": ip,
                    "hostnames": host_detail.get("hostnames", []),
                    "os": host_detail.get("os"),
                    "org": host_detail.get("org"),
                    "isp": host_detail.get("isp"),
                    "ports": host_detail.get("ports", []),
                    "last_update": host_detail.get("last_update"),
                }
                results["infrastructure"]["hosts"].append(host_record)

                for port in host_detail.get("ports", []):
                    all_ports.add(port)

                # Extract service banners and vulns from each data entry
                for item in host_detail.get("data", []):
                    svc = {
                        "ip": ip,
                        "port": item.get("port"),
                        "transport": item.get("transport", "tcp"),
                        "product": item.get("product"),
                        "version": item.get("version"),
                        "banner_snippet": (item.get("data") or "")[:200],
                    }
                    all_services.append(svc)

                    # SSL certificate info
                    ssl_info = item.get("ssl", {})
                    if ssl_info:
                        cert = ssl_info.get("cert", {})
                        results["infrastructure"]["ssl_certs"].append(
                            {
                                "ip": ip,
                                "port": item.get("port"),
                                "issued_to": cert.get("subject", {}).get(
                                    "CN"
                                ),
                                "issuer": cert.get("issuer", {}).get("O"),
                                "expires": cert.get("expires"),
                                "fingerprint": ssl_info.get(
                                    "cert", {}
                                ).get("fingerprint", {}).get("sha256"),
                            }
                        )

                    # Vulnerabilities
                    vulns = item.get("vulns", {})
                    for cve_id, vuln_data in vulns.items():
                        all_vulns.append(
                            {
                                "cve": cve_id,
                                "ip": ip,
                                "port": item.get("port"),
                                "cvss": vuln_data
                                if isinstance(vuln_data, (int, float))
                                else None,
                            }
                        )

            results["infrastructure"]["open_ports"] = sorted(all_ports)
            results["infrastructure"]["services"] = all_services
            results["infrastructure"]["vulnerabilities"] = all_vulns

        self._report(
            f"Shodan collection complete: {len(hosts)} hosts, "
            f"{len(all_ports)} unique ports, {len(all_vulns)} CVEs",
            "ok",
        )
        return results

    async def _dns_resolve(
        self, session: aiohttp.ClientSession, domain: str
    ) -> Optional[dict]:
        """Resolve DNS records via Shodan."""
        url = f"{self.BASE_URL}/dns/resolve"
        params = {"hostnames": domain, "key": self.api_key}
        try:
            async with session.get(url, params=params) as resp:
                if resp.status == 200:
                    return await resp.json()
                logger.warning(f"Shodan DNS resolve failed: {resp.status}")
        except Exception as e:
            logger.error(f"Shodan DNS error: {e}")
        return None

    async def _search_domain(
        self, session: aiohttp.ClientSession, domain: str
    ) -> list:
        """Search Shodan for hosts associated with the domain."""
        url = f"{self.BASE_URL}/shodan/host/search"
        params = {
            "key": self.api_key,
            "query": f"hostname:{domain}",
            "page": 1,
        }
        try:
            async with session.get(url, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("matches", [])
                elif resp.status == 401:
                    self._report("Shodan API key invalid", "error")
                elif resp.status == 429:
                    self._report("Shodan rate limit exceeded", "warn")
                else:
                    logger.warning(f"Shodan search failed: {resp.status}")
        except Exception as e:
            logger.error(f"Shodan search error: {e}")
        return []

    async def _get_host(
        self, session: aiohttp.ClientSession, ip: str
    ) -> Optional[dict]:
        """Get detailed host information from Shodan."""
        url = f"{self.BASE_URL}/shodan/host/{ip}"
        params = {"key": self.api_key}
        try:
            async with session.get(url, params=params) as resp:
                if resp.status == 200:
                    return await resp.json()
                logger.warning(f"Shodan host lookup failed for {ip}: {resp.status}")
        except Exception as e:
            logger.error(f"Shodan host error for {ip}: {e}")
        return None


class HIBPCollector(BaseCollector):
    """
    Checks discovered emails against Have I Been Pwned.

    Looks up every email discovered by prior collectors (GitHub commit
    emails, profile emails) and returns per-email breach exposure data.

    Requires a HIBP API key (paid — hibp-key header).
    HIBP enforces a strict 1.5 s delay between requests.
    """

    BASE_URL = "https://haveibeenpwned.com/api/v3"

    def __init__(self, config: dict):
        super().__init__(config)
        self.api_key = config.get("hibp_api_key")
        # HIBP mandates >= 1500 ms between requests
        self.rate_limit_delay = max(
            config.get("rate_limit_delay", 1.5), 1.5
        )

    def validate_config(self) -> bool:
        return self.api_key is not None

    async def collect(self, organization) -> dict:
        """
        Check discovered emails against HIBP breach database.

        Pipeline:
        1. Gather all unique emails from the organization model
           (profile emails + commit-scraped emails)
        2. Query HIBP breachedaccount endpoint for each email
        3. Optionally query paste endpoint for paste exposure
        4. Return structured breach data keyed by email
        """
        results = {"breach_data": {}}

        if not self.validate_config():
            self._report("HIBP API key not configured — skipping", "warn")
            return results

        # Collect every email we know about
        emails = self._gather_emails(organization)
        if not emails:
            self._report("No emails discovered yet — skipping HIBP", "info")
            return results

        self._report(
            f"HIBP collection starting: checking {len(emails)} emails"
        )

        headers = {
            "hibp-api-key": self.api_key,
            "User-Agent": "OSINT-Recon-Tool/0.1 (Educational Research)",
        }

        async with aiohttp.ClientSession(headers=headers) as session:
            for i, email in enumerate(emails):
                await self._rate_limit()
                self._report(
                    f"Checking {i+1}/{len(emails)}: {email}", "info"
                )

                breaches = await self._check_breaches(session, email)
                pastes = await self._check_pastes(session, email)

                if breaches or pastes:
                    results["breach_data"][email] = {
                        "breaches": breaches,
                        "pastes": pastes,
                        "breach_count": len(breaches),
                        "paste_count": len(pastes),
                    }
                    self._report(
                        f"  {email}: {len(breaches)} breaches, "
                        f"{len(pastes)} pastes",
                        "warn",
                    )
                else:
                    self._report(f"  {email}: clean", "ok")

        total_breached = len(results["breach_data"])
        self._report(
            f"HIBP collection complete: {total_breached}/{len(emails)} "
            f"emails found in breaches",
            "ok",
        )
        return results

    @staticmethod
    def _gather_emails(organization) -> list[str]:
        """Extract unique emails from the organization model."""
        emails = set()

        # Emails from employee profiles
        for emp in organization.employees:
            if hasattr(emp, "email") and emp.email:
                emails.add(emp.email.lower())
            # Check social profile data for email fields
            profiles = (
                emp.social_profiles
                if hasattr(emp, "social_profiles")
                else {}
            )
            for platform, data in profiles.items():
                if isinstance(data, dict) and data.get("email"):
                    emails.add(data["email"].lower())

        # Emails scraped from commit history
        commit_emails = organization.infrastructure.get("commit_emails", [])
        for entry in commit_emails:
            if isinstance(entry, dict):
                email = entry.get("email", "")
            else:
                email = str(entry)
            if email:
                emails.add(email.lower())

        return sorted(emails)

    async def _check_breaches(
        self, session: aiohttp.ClientSession, email: str
    ) -> list:
        """Query HIBP for breaches affecting the given email."""
        url = f"{self.BASE_URL}/breachedaccount/{email}"
        params = {"truncateResponse": "false"}

        try:
            async with session.get(url, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return [
                        {
                            "name": b.get("Name"),
                            "domain": b.get("Domain"),
                            "breach_date": b.get("BreachDate"),
                            "pwn_count": b.get("PwnCount"),
                            "data_classes": b.get("DataClasses", []),
                            "is_verified": b.get("IsVerified"),
                            "is_sensitive": b.get("IsSensitive"),
                        }
                        for b in data
                    ]
                elif resp.status == 404:
                    return []  # Not breached
                elif resp.status == 401:
                    self._report("HIBP API key invalid", "error")
                elif resp.status == 429:
                    self._report("HIBP rate limit hit — backing off", "warn")
                    await asyncio.sleep(5)
                else:
                    logger.warning(
                        f"HIBP breach check failed for {email}: {resp.status}"
                    )
        except Exception as e:
            logger.error(f"HIBP breach error for {email}: {e}")
        return []

    async def _check_pastes(
        self, session: aiohttp.ClientSession, email: str
    ) -> list:
        """Query HIBP for paste exposure of the given email."""
        url = f"{self.BASE_URL}/pasteaccount/{email}"

        try:
            await self._rate_limit()
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return [
                        {
                            "source": p.get("Source"),
                            "title": p.get("Title"),
                            "date": p.get("Date"),
                            "email_count": p.get("EmailCount"),
                        }
                        for p in data
                    ]
                elif resp.status == 404:
                    return []
        except Exception as e:
            logger.error(f"HIBP paste error for {email}: {e}")
        return []


class WebScraperCollector(BaseCollector):
    """
    Scrapes public web pages for OSINT data.

    Targets:
    - Corporate "About Us" / "Team" / "Leadership" pages for employee names
    - Contact pages for email addresses and phone numbers
    - Publicly linked documents (PDF, DOCX) for metadata extraction
    - Technology stack fingerprinting from HTML headers and markup

    Respects robots.txt by default.
    """

    # Patterns for pages likely to contain employee information
    TEAM_PATH_PATTERNS = [
        "/about", "/about-us", "/team", "/our-team", "/leadership",
        "/people", "/staff", "/management", "/executives", "/company",
        "/who-we-are", "/contact", "/contact-us",
    ]

    EMAIL_RE = re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
    )

    PHONE_RE = re.compile(
        r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"
    )

    # Document extensions to flag (not download)
    DOC_EXTENSIONS = {
        ".pdf", ".docx", ".doc", ".xlsx", ".xls",
        ".pptx", ".ppt", ".csv", ".txt",
    }

    def __init__(self, config: dict):
        super().__init__(config)
        self.max_depth = config.get("max_depth", 2)
        self.max_pages = config.get("max_pages", 100)
        self.respect_robots = config.get("respect_robots_txt", True)
        self.user_agent = config.get(
            "user_agent",
            "OSINT-Research-Bot/1.0 (Educational Purpose)",
        )

    def validate_config(self) -> bool:
        return True

    async def collect(self, organization) -> dict:
        """
        Scrape the organization's public website for OSINT data.

        Pipeline:
        1. Check robots.txt for allowed paths
        2. Crawl team/about/contact pages for people and emails
        3. Catalog publicly linked documents
        4. Fingerprint web technologies from headers/HTML
        """
        results = {
            "employees": [],
            "documents": [],
            "infrastructure": {
                "web_technologies": [],
                "emails_found": [],
                "phones_found": [],
            },
        }

        domain = organization.domain
        if not domain:
            self._report(
                "No domain set for organization — skipping web scraper",
                "warn",
            )
            return results

        base_url = f"https://{domain}"
        self._report(f"Web scraper starting for: {base_url}")

        headers = {"User-Agent": self.user_agent}

        async with aiohttp.ClientSession(headers=headers) as session:
            # Step 1: Check robots.txt
            disallowed = set()
            if self.respect_robots:
                disallowed = await self._parse_robots(session, base_url)
                self._report(
                    f"robots.txt: {len(disallowed)} disallowed paths", "info"
                )

            # Step 2: Crawl team/about pages
            self._report("Scanning for team and contact pages...", "info")
            visited = set()
            all_emails = set()
            all_phones = set()
            all_documents = []
            discovered_people = []

            pages_to_visit = [
                urljoin(base_url, path)
                for path in self.TEAM_PATH_PATTERNS
            ]
            # Also try the homepage
            pages_to_visit.insert(0, base_url)

            for url in pages_to_visit:
                if len(visited) >= self.max_pages:
                    break
                if url in visited:
                    continue
                if self._is_disallowed(url, base_url, disallowed):
                    logger.debug(f"Skipping disallowed: {url}")
                    continue

                visited.add(url)
                await self._rate_limit()
                self._report(f"Fetching: {url}", "info")

                page_data = await self._fetch_page(session, url)
                if not page_data:
                    continue

                html, resp_headers = page_data

                # Extract technology fingerprints from homepage
                if url == base_url:
                    techs = self._fingerprint_technologies(
                        html, resp_headers
                    )
                    results["infrastructure"]["web_technologies"] = techs
                    if techs:
                        self._report(
                            f"Technologies detected: {', '.join(techs)}", "ok"
                        )

                # Parse for people, emails, documents
                soup = BeautifulSoup(html, "lxml")

                # Emails
                emails_on_page = set(self.EMAIL_RE.findall(html))
                # Filter out common false positives
                emails_on_page = {
                    e for e in emails_on_page
                    if not any(
                        x in e.lower()
                        for x in ["example.com", "sentry.io", "wixpress"]
                    )
                }
                all_emails.update(emails_on_page)

                # Phone numbers
                phones_on_page = set(self.PHONE_RE.findall(html))
                all_phones.update(phones_on_page)

                # Document links
                for link in soup.find_all("a", href=True):
                    href = link["href"]
                    full_url = urljoin(url, href)
                    parsed = urlparse(full_url)
                    ext = "." + parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path else ""
                    if ext in self.DOC_EXTENSIONS:
                        all_documents.append(
                            {
                                "url": full_url,
                                "type": ext.lstrip("."),
                                "link_text": link.get_text(strip=True)[:100],
                                "found_on": url,
                            }
                        )

                # People extraction from team-style pages
                people = self._extract_people(soup, domain, organization.name)
                discovered_people.extend(people)

                # Follow internal links one level deep (if depth allows)
                if self.max_depth > 1 and len(visited) < self.max_pages:
                    for link in soup.find_all("a", href=True):
                        next_url = urljoin(url, link["href"])
                        parsed_next = urlparse(next_url)
                        # Stay on the same domain
                        if (
                            parsed_next.netloc == urlparse(base_url).netloc
                            and next_url not in visited
                            and not self._is_disallowed(
                                next_url, base_url, disallowed
                            )
                        ):
                            # Prioritize pages with team-related keywords
                            link_text = link.get_text(strip=True).lower()
                            path_lower = parsed_next.path.lower()
                            if any(
                                kw in link_text or kw in path_lower
                                for kw in [
                                    "team", "about", "people", "staff",
                                    "leader", "contact", "who",
                                ]
                            ):
                                pages_to_visit.append(next_url)

            results["employees"] = discovered_people
            results["documents"] = all_documents
            results["infrastructure"]["emails_found"] = sorted(all_emails)
            results["infrastructure"]["phones_found"] = sorted(all_phones)

        self._report(
            f"Web scraper complete: {len(discovered_people)} people, "
            f"{len(all_emails)} emails, {len(all_documents)} documents",
            "ok",
        )
        return results

    async def _parse_robots(
        self, session: aiohttp.ClientSession, base_url: str
    ) -> set:
        """Parse robots.txt and return disallowed paths."""
        disallowed = set()
        url = f"{base_url}/robots.txt"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    for line in text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path:
                                disallowed.add(path)
        except Exception as e:
            logger.debug(f"robots.txt fetch failed: {e}")
        return disallowed

    @staticmethod
    def _is_disallowed(url: str, base_url: str, disallowed: set) -> bool:
        """Check if a URL is blocked by robots.txt rules."""
        parsed = urlparse(url)
        path = parsed.path
        for rule in disallowed:
            if path.startswith(rule):
                return True
        return False

    async def _fetch_page(
        self, session: aiohttp.ClientSession, url: str
    ) -> Optional[tuple]:
        """Fetch a page, returning (html, headers) or None."""
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=15),
                allow_redirects=True,
            ) as resp:
                if resp.status != 200:
                    return None
                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type:
                    return None
                html = await resp.text()
                return html, dict(resp.headers)
        except Exception as e:
            logger.debug(f"Page fetch failed for {url}: {e}")
        return None

    @staticmethod
    def _fingerprint_technologies(html: str, headers: dict) -> list:
        """Identify web technologies from response headers and HTML."""
        techs = []

        # Server header
        server = headers.get("Server", "")
        if server:
            techs.append(f"Server: {server}")

        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            techs.append(f"X-Powered-By: {powered_by}")

        # Common framework fingerprints in HTML
        fingerprints = {
            "wp-content": "WordPress",
            "drupal": "Drupal",
            "joomla": "Joomla",
            "shopify": "Shopify",
            "squarespace": "Squarespace",
            "wix.com": "Wix",
            "hubspot": "HubSpot",
            "react": "React",
            "angular": "Angular",
            "vue.js": "Vue.js",
            "next.js": "Next.js",
            "gatsby": "Gatsby",
            "bootstrap": "Bootstrap",
            "tailwind": "Tailwind CSS",
            "jquery": "jQuery",
            "cloudflare": "Cloudflare",
            "google-analytics": "Google Analytics",
            "gtag": "Google Tag Manager",
        }
        html_lower = html.lower()
        for pattern, name in fingerprints.items():
            if pattern in html_lower:
                techs.append(name)

        return techs

    @staticmethod
    def _extract_people(
        soup: BeautifulSoup, domain: str, org_name: str
    ) -> list:
        """
        Extract people from team/about page structures.

        Looks for common HTML patterns:
        - Cards with headings + role/title text
        - Schema.org Person markup
        - Structured list items with name + title patterns
        """
        people = []
        seen_names = set()

        # Strategy 1: Schema.org Person markup
        for el in soup.find_all(attrs={"itemtype": re.compile(r"schema\.org/Person")}):
            name_el = el.find(attrs={"itemprop": "name"})
            title_el = el.find(attrs={"itemprop": "jobTitle"})
            if name_el:
                name = name_el.get_text(strip=True)
                if name and name not in seen_names:
                    seen_names.add(name)
                    people.append(
                        {
                            "name": name,
                            "organization": org_name,
                            "role": title_el.get_text(strip=True) if title_el else None,
                            "email": None,
                            "social_profiles": {},
                            "metadata": {"source": "web_scraper"},
                        }
                    )

        # Strategy 2: Common card patterns (div/article with h2/h3 name + p title)
        for container in soup.find_all(["div", "article", "li"], class_=re.compile(
            r"team|member|person|staff|card|profile|bio", re.IGNORECASE
        )):
            heading = container.find(["h2", "h3", "h4", "strong"])
            if not heading:
                continue
            name = heading.get_text(strip=True)
            if not name or len(name) > 60 or len(name) < 3:
                continue
            if name in seen_names:
                continue

            # Look for a role/title in a sibling or child <p>, <span>, <small>
            role = None
            for tag in container.find_all(["p", "span", "small", "div"]):
                text = tag.get_text(strip=True)
                if text and text != name and len(text) < 80:
                    role = text
                    break

            seen_names.add(name)
            people.append(
                {
                    "name": name,
                    "organization": org_name,
                    "role": role,
                    "email": None,
                    "social_profiles": {},
                    "metadata": {"source": "web_scraper"},
                }
            )

        return people


class HunterIOCollector(BaseCollector):
    """
    Discovers email addresses and naming patterns via Hunter.io.

    Free tier (no key required for domain search):
    - Domain search: find emails associated with a domain
    - Email pattern detection: infer the org's email format
    - Department breakdown and confidence scores

    With API key:
    - Higher rate limits
    - Email verification endpoint
    - More results per domain search

    This collector is especially powerful when combined with names
    discovered by other collectors — once the email pattern is known
    (e.g. first.last@company.com), probable emails can be generated
    for every discovered person and checked against HIBP.
    """

    BASE_URL = "https://api.hunter.io/v2"

    def __init__(self, config: dict):
        super().__init__(config)
        self.api_key = config.get("hunter_api_key")
        self.rate_limit_delay = config.get("rate_limit_delay", 2.0)

    def validate_config(self) -> bool:
        # Works without a key (limited to 25 searches/month via free web)
        return True

    async def collect(self, organization) -> dict:
        """
        Discover emails and naming patterns for the target domain.

        Pipeline:
        1. Domain search — enumerate known emails for the domain
        2. Pattern detection — infer email format (first.last, f.last, etc.)
        3. Email generation — create probable emails for discovered people
        4. Department mapping — group emails by department
        """
        results = {
            "employees": [],
            "infrastructure": {
                "email_pattern": None,
                "hunter_emails": [],
                "departments": {},
            },
        }

        domain = organization.domain
        if not domain:
            self._report(
                "No domain set — skipping Hunter.io", "warn"
            )
            return results

        self._report(f"Hunter.io collection starting for: {domain}")

        async with aiohttp.ClientSession() as session:
            # Step 1: Domain search
            self._report("Searching Hunter.io for domain emails...", "info")
            domain_data = await self._domain_search(session, domain)

            if not domain_data:
                self._report("No Hunter.io results (check domain or quota)", "warn")
                return results

            # Extract pattern
            pattern = domain_data.get("pattern")
            if pattern:
                results["infrastructure"]["email_pattern"] = pattern
                self._report(
                    f"Email pattern detected: {pattern}@{domain}", "ok"
                )

            # Extract emails
            emails_data = domain_data.get("emails", [])
            self._report(f"Found {len(emails_data)} emails via Hunter.io", "ok")

            departments = {}
            for entry in emails_data:
                email = entry.get("value", "")
                if not email:
                    continue

                confidence = entry.get("confidence", 0)
                dept = entry.get("department") or "unknown"
                first_name = entry.get("first_name") or ""
                last_name = entry.get("last_name") or ""
                position = entry.get("position") or ""

                results["infrastructure"]["hunter_emails"].append({
                    "email": email,
                    "confidence": confidence,
                    "department": dept,
                    "first_name": first_name,
                    "last_name": last_name,
                    "position": position,
                    "sources_count": entry.get("sources_count", 0),
                })

                # Track departments
                departments.setdefault(dept, 0)
                departments[dept] += 1

                # Build person record if we have a name
                name = f"{first_name} {last_name}".strip()
                if name and len(name) > 1:
                    results["employees"].append({
                        "name": name,
                        "organization": organization.name,
                        "role": position or None,
                        "email": email,
                        "social_profiles": {},
                        "metadata": {
                            "source": "hunter_io",
                            "confidence": confidence,
                            "department": dept,
                        },
                    })

            results["infrastructure"]["departments"] = departments
            if departments:
                top_depts = sorted(
                    departments.items(), key=lambda x: x[1], reverse=True
                )[:5]
                dept_str = ", ".join(f"{d} ({c})" for d, c in top_depts)
                self._report(f"Departments: {dept_str}", "ok")

            # Step 2: Generate probable emails for existing employees
            if pattern and organization.employees:
                self._report(
                    "Generating probable emails from pattern...", "info"
                )
                generated = self._generate_emails_from_pattern(
                    pattern, domain, organization.employees
                )
                existing_emails = {
                    e["email"].lower()
                    for e in results["infrastructure"]["hunter_emails"]
                }
                new_emails = [
                    g for g in generated
                    if g["email"].lower() not in existing_emails
                ]
                results["infrastructure"]["hunter_emails"].extend(new_emails)
                self._report(
                    f"Generated {len(new_emails)} probable emails from pattern",
                    "ok",
                )

        self._report(
            f"Hunter.io complete: {len(results['employees'])} people, "
            f"{len(results['infrastructure']['hunter_emails'])} total emails, "
            f"pattern: {pattern or 'unknown'}",
            "ok",
        )
        return results

    async def _domain_search(
        self, session: aiohttp.ClientSession, domain: str
    ) -> Optional[dict]:
        """Search Hunter.io for emails associated with a domain."""
        url = f"{self.BASE_URL}/domain-search"
        params = {"domain": domain, "limit": 100}
        if self.api_key:
            params["api_key"] = self.api_key

        try:
            async with session.get(
                url,
                params=params,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status == 200:
                    body = await resp.json()
                    return body.get("data", {})
                elif resp.status == 401:
                    self._report("Hunter.io API key invalid", "fail")
                elif resp.status == 429:
                    self._report(
                        "Hunter.io rate limit / quota exhausted", "warn"
                    )
                else:
                    logger.warning(f"Hunter.io domain search failed: {resp.status}")
        except Exception as e:
            logger.error(f"Hunter.io error: {e}")
        return None

    @staticmethod
    def _generate_emails_from_pattern(
        pattern: str, domain: str, employees: list
    ) -> list:
        """
        Generate probable email addresses from the discovered pattern.

        Supported patterns:
        - {first}.{last}   → john.doe@domain.com
        - {first}{last}    → johndoe@domain.com
        - {f}{last}        → jdoe@domain.com
        - {first}          → john@domain.com
        - {first}_{last}   → john_doe@domain.com
        - {f}.{last}       → j.doe@domain.com
        - {last}           → doe@domain.com
        """
        generated = []

        for emp in employees:
            name = emp.name if hasattr(emp, "name") else emp.get("name", "")
            if not name:
                continue

            parts = name.strip().split()
            if len(parts) < 2:
                continue

            first = parts[0].lower()
            last = parts[-1].lower()
            f = first[0] if first else ""

            # Remove non-alpha chars
            first = re.sub(r"[^a-z]", "", first)
            last = re.sub(r"[^a-z]", "", last)
            f = re.sub(r"[^a-z]", "", f)

            if not first or not last:
                continue

            pattern_map = {
                "{first}.{last}": f"{first}.{last}",
                "{first}{last}": f"{first}{last}",
                "{f}{last}": f"{f}{last}",
                "{first}": first,
                "{first}_{last}": f"{first}_{last}",
                "{f}.{last}": f"{f}.{last}",
                "{last}": last,
                "{last}.{first}": f"{last}.{first}",
                "{last}{f}": f"{last}{f}",
            }

            local_part = pattern_map.get(pattern)
            if local_part:
                email = f"{local_part}@{domain}"
                generated.append({
                    "email": email,
                    "confidence": 70,  # Pattern-inferred
                    "department": "unknown",
                    "first_name": parts[0],
                    "last_name": parts[-1],
                    "position": "",
                    "sources_count": 0,
                    "generated": True,
                })

        return generated


class DNSCTCollector(BaseCollector):
    """
    Discovers subdomains, DNS records, and registration data.

    Data sources (all free, no API key needed):
    - crt.sh: Certificate Transparency log search for subdomains
    - DNS resolution: A, AAAA, MX, TXT, NS, CNAME, SOA records
    - WHOIS: Domain registration and registrant information
    - Reverse DNS: PTR records for discovered IPs

    This collector reveals the org's infrastructure footprint:
    which services they run, where they're hosted, mail providers,
    TXT records (SPF, DMARC, verification tokens), and hidden
    subdomains exposed through SSL certificates.
    """

    # crt.sh is a free CT log aggregator
    CRTSH_URL = "https://crt.sh"

    def __init__(self, config: dict):
        super().__init__(config)
        self.max_subdomains = config.get("max_subdomains", 500)
        self.resolve_dns = config.get("resolve_dns", True)
        self.check_whois = config.get("check_whois", True)
        self.rate_limit_delay = config.get("rate_limit_delay", 0.5)

    def validate_config(self) -> bool:
        return True  # All sources are free

    async def collect(self, organization) -> dict:
        """
        Full DNS/CT reconnaissance for the target domain.

        Pipeline:
        1. crt.sh — enumerate subdomains from Certificate Transparency logs
        2. DNS records — resolve A, MX, TXT, NS, CNAME, SOA for each
        3. WHOIS — domain registration info and registrant data
        4. Reverse DNS — PTR lookups on discovered IPs
        5. Security analysis — check SPF, DMARC, DNSSEC
        """
        results = {
            "infrastructure": {
                "subdomains": [],
                "dns_records": {},
                "whois": {},
                "reverse_dns": [],
                "security_headers": {},
                "ip_addresses": [],
                "mail_servers": [],
            }
        }

        domain = organization.domain
        if not domain:
            self._report("No domain set — skipping DNS/CT recon", "warn")
            return results

        self._report(f"DNS/CT collection starting for: {domain}")

        async with aiohttp.ClientSession() as session:
            # Step 1: Certificate Transparency log search
            self._report(
                "Querying Certificate Transparency logs (crt.sh)...", "info"
            )
            subdomains = await self._crtsh_search(session, domain)
            results["infrastructure"]["subdomains"] = sorted(subdomains)
            self._report(
                f"Discovered {len(subdomains)} unique subdomains", "ok"
            )

            # Categorize interesting subdomains
            interesting = self._categorize_subdomains(subdomains)
            if interesting:
                for category, subs in interesting.items():
                    self._report(
                        f"  {category}: {', '.join(subs[:5])}"
                        + (f" (+{len(subs)-5} more)" if len(subs) > 5 else ""),
                        "info",
                    )

            # Step 2: DNS record resolution
            if self.resolve_dns:
                self._report("Resolving DNS records...", "info")
                dns_data = await self._resolve_dns_records(session, domain)
                results["infrastructure"]["dns_records"] = dns_data

                # Extract IPs
                a_records = dns_data.get("A", [])
                results["infrastructure"]["ip_addresses"] = a_records
                if a_records:
                    self._report(
                        f"A records: {', '.join(a_records[:5])}", "ok"
                    )

                # Extract mail servers
                mx_records = dns_data.get("MX", [])
                results["infrastructure"]["mail_servers"] = mx_records
                if mx_records:
                    self._report(
                        f"Mail servers: {', '.join(str(m) for m in mx_records[:3])}",
                        "ok",
                    )

                # Check email security
                txt_records = dns_data.get("TXT", [])
                security = self._analyze_email_security(txt_records)
                results["infrastructure"]["security_headers"] = security
                for check, status in security.items():
                    icon = "ok" if status["present"] else "warn"
                    self._report(f"  {check}: {status['detail']}", icon)

                # Resolve subdomains (sample up to 20 for IPs)
                if subdomains:
                    sample = list(subdomains)[:20]
                    self._report(
                        f"Resolving IPs for {len(sample)} subdomains...",
                        "info",
                    )
                    sub_ips = await self._resolve_subdomain_ips(
                        session, sample
                    )
                    all_ips = set(a_records)
                    for ip_list in sub_ips.values():
                        all_ips.update(ip_list)
                    results["infrastructure"]["ip_addresses"] = sorted(all_ips)
                    self._report(
                        f"Total unique IPs discovered: {len(all_ips)}", "ok"
                    )

            # Step 3: WHOIS lookup
            if self.check_whois:
                self._report("Looking up WHOIS registration data...", "info")
                whois_data = await self._whois_lookup(session, domain)
                results["infrastructure"]["whois"] = whois_data
                if whois_data:
                    registrar = whois_data.get("registrar", "Unknown")
                    created = whois_data.get("creation_date", "Unknown")
                    self._report(
                        f"Registrar: {registrar}, Created: {created}", "ok"
                    )
                else:
                    self._report("WHOIS data not available", "info")

            # Step 4: Reverse DNS on discovered IPs
            all_ips = results["infrastructure"]["ip_addresses"]
            if all_ips:
                sample_ips = list(all_ips)[:10]
                self._report(
                    f"Running reverse DNS on {len(sample_ips)} IPs...", "info"
                )
                reverse = await self._reverse_dns(session, sample_ips)
                results["infrastructure"]["reverse_dns"] = reverse
                ptr_count = sum(1 for r in reverse if r.get("ptr"))
                self._report(
                    f"Reverse DNS: {ptr_count}/{len(sample_ips)} have PTR records",
                    "ok",
                )

        total_subs = len(results["infrastructure"]["subdomains"])
        total_ips = len(results["infrastructure"]["ip_addresses"])
        self._report(
            f"DNS/CT complete: {total_subs} subdomains, "
            f"{total_ips} IPs, "
            f"{len(results['infrastructure'].get('mail_servers', []))} mail servers",
            "ok",
        )
        return results

    async def _crtsh_search(
        self, session: aiohttp.ClientSession, domain: str
    ) -> set:
        """Query crt.sh Certificate Transparency logs for subdomains."""
        subdomains = set()
        url = f"{self.CRTSH_URL}/"
        params = {"q": f"%.{domain}", "output": "json"}

        try:
            async with session.get(
                url,
                params=params,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        # crt.sh can return multiple names per cert
                        for name in name_value.split("\n"):
                            name = name.strip().lower()
                            # Remove wildcard prefix
                            if name.startswith("*."):
                                name = name[2:]
                            # Must be a subdomain of our target
                            if name.endswith(f".{domain}") or name == domain:
                                subdomains.add(name)

                            if len(subdomains) >= self.max_subdomains:
                                break
                elif resp.status == 429:
                    self._report("crt.sh rate limited — try again later", "warn")
                else:
                    logger.warning(f"crt.sh returned status {resp.status}")
        except asyncio.TimeoutError:
            self._report("crt.sh request timed out", "warn")
        except Exception as e:
            logger.error(f"crt.sh error: {e}")

        return subdomains

    @staticmethod
    def _categorize_subdomains(subdomains: set) -> dict:
        """Group subdomains into categories for analysis."""
        categories = {
            "Development/Staging": [],
            "Admin/Internal": [],
            "API endpoints": [],
            "Mail": [],
            "VPN/Remote": [],
        }

        patterns = {
            "Development/Staging": [
                "dev", "staging", "stage", "test", "qa", "uat",
                "sandbox", "demo", "beta", "preview", "canary",
            ],
            "Admin/Internal": [
                "admin", "internal", "intranet", "portal",
                "dashboard", "console", "manage", "cms", "backoffice",
            ],
            "API endpoints": [
                "api", "graphql", "rest", "webhook", "ws",
                "gateway", "rpc",
            ],
            "Mail": [
                "mail", "smtp", "imap", "pop", "exchange",
                "webmail", "mx", "email",
            ],
            "VPN/Remote": [
                "vpn", "remote", "rdp", "ssh", "bastion",
                "jump", "gateway", "tunnel",
            ],
        }

        for sub in subdomains:
            prefix = sub.split(".")[0].lower()
            for category, keywords in patterns.items():
                if any(kw in prefix for kw in keywords):
                    categories[category].append(sub)
                    break

        return {k: v for k, v in categories.items() if v}

    async def _resolve_dns_records(
        self, session: aiohttp.ClientSession, domain: str
    ) -> dict:
        """Resolve standard DNS record types using public DNS-over-HTTPS."""
        records = {}
        # Use Google's public DNS-over-HTTPS API
        dns_url = "https://dns.google/resolve"
        record_types = {
            "A": 1,
            "AAAA": 28,
            "MX": 15,
            "TXT": 16,
            "NS": 2,
            "CNAME": 5,
            "SOA": 6,
        }

        for rtype, rcode in record_types.items():
            await self._rate_limit()
            try:
                params = {"name": domain, "type": rcode}
                async with session.get(
                    dns_url,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        answers = data.get("Answer", [])
                        values = []
                        for ans in answers:
                            val = ans.get("data", "").strip().rstrip(".")
                            if val:
                                values.append(val)
                        if values:
                            records[rtype] = values
            except Exception as e:
                logger.debug(f"DNS {rtype} lookup failed for {domain}: {e}")

        return records

    @staticmethod
    def _analyze_email_security(txt_records: list) -> dict:
        """Analyze TXT records for email security configuration."""
        security = {
            "SPF": {"present": False, "detail": "Not configured"},
            "DMARC": {"present": False, "detail": "Not configured"},
            "DKIM": {"present": False, "detail": "Cannot verify via TXT alone"},
        }

        for txt in txt_records:
            txt_lower = txt.lower()
            if txt_lower.startswith("v=spf1"):
                security["SPF"] = {
                    "present": True,
                    "detail": txt[:120],
                }
            if txt_lower.startswith("v=dmarc"):
                security["DMARC"] = {
                    "present": True,
                    "detail": txt[:120],
                }
            if "dkim" in txt_lower:
                security["DKIM"] = {
                    "present": True,
                    "detail": "DKIM selector found in TXT",
                }

        return security

    async def _resolve_subdomain_ips(
        self, session: aiohttp.ClientSession, subdomains: list
    ) -> dict:
        """Resolve A records for a list of subdomains."""
        results = {}
        dns_url = "https://dns.google/resolve"

        for sub in subdomains:
            await self._rate_limit()
            try:
                params = {"name": sub, "type": 1}
                async with session.get(
                    dns_url,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        ips = [
                            a["data"]
                            for a in data.get("Answer", [])
                            if a.get("type") == 1
                        ]
                        if ips:
                            results[sub] = ips
            except Exception:
                pass

        return results

    async def _whois_lookup(
        self, session: aiohttp.ClientSession, domain: str
    ) -> dict:
        """
        WHOIS lookup using a free JSON API.

        Falls back gracefully if the service is unavailable.
        """
        # Use a free WHOIS JSON API
        url = f"https://rdap.org/domain/{domain}"
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=15)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()

                    # Parse RDAP response
                    result = {
                        "domain": domain,
                        "handle": data.get("handle"),
                        "status": data.get("status", []),
                    }

                    # Extract events (creation, expiration, etc.)
                    for event in data.get("events", []):
                        action = event.get("eventAction", "")
                        date = event.get("eventDate", "")
                        if action == "registration":
                            result["creation_date"] = date[:10]
                        elif action == "expiration":
                            result["expiration_date"] = date[:10]
                        elif action == "last changed":
                            result["updated_date"] = date[:10]

                    # Extract nameservers
                    ns_list = data.get("nameservers", [])
                    result["nameservers"] = [
                        ns.get("ldhName", "") for ns in ns_list
                    ]

                    # Extract registrar from entities
                    for entity in data.get("entities", []):
                        roles = entity.get("roles", [])
                        if "registrar" in roles:
                            vcard = entity.get("vcardArray", [None, []])
                            if len(vcard) > 1:
                                for field in vcard[1]:
                                    if field[0] == "fn":
                                        result["registrar"] = field[3]
                                        break
                            if "registrar" not in result:
                                result["registrar"] = entity.get(
                                    "handle", "Unknown"
                                )

                    return result
                else:
                    logger.debug(f"RDAP lookup failed: {resp.status}")
        except Exception as e:
            logger.debug(f"WHOIS/RDAP error for {domain}: {e}")

        return {}

    async def _reverse_dns(
        self, session: aiohttp.ClientSession, ips: list
    ) -> list:
        """Perform reverse DNS (PTR) lookups on IP addresses."""
        results = []
        dns_url = "https://dns.google/resolve"

        for ip in ips:
            await self._rate_limit()
            # Build reverse DNS name
            octets = ip.split(".")
            if len(octets) != 4:
                continue
            ptr_name = ".".join(reversed(octets)) + ".in-addr.arpa"

            try:
                params = {"name": ptr_name, "type": 12}  # PTR
                async with session.get(
                    dns_url,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        answers = data.get("Answer", [])
                        ptrs = [
                            a["data"].rstrip(".")
                            for a in answers
                            if a.get("type") == 12
                        ]
                        results.append({
                            "ip": ip,
                            "ptr": ptrs[0] if ptrs else None,
                        })
            except Exception:
                results.append({"ip": ip, "ptr": None})

        return results
