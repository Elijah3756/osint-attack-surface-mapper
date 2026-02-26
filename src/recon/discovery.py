"""
Discovery Module - Core reconnaissance engine for OSINT data collection.

Discovers employees, social media accounts, and public-facing data
for a target organization using ethical OSINT techniques.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class Person:
    """Represents a discovered individual associated with the target org."""
    name: str
    organization: str
    role: Optional[str] = None
    email: Optional[str] = None
    social_profiles: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @property
    def profile_count(self) -> int:
        return len(self.social_profiles)


@dataclass
class Organization:
    """Represents the target organization being assessed."""
    name: str
    domain: Optional[str] = None
    industry: Optional[str] = None
    employees: list = field(default_factory=list)
    infrastructure: dict = field(default_factory=dict)
    documents: list = field(default_factory=list)
    breach_data: dict = field(default_factory=dict)
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @property
    def employee_count(self) -> int:
        return len(self.employees)

    def add_employee(self, person: Person):
        self.employees.append(person)
        logger.info(f"Added employee: {person.name} ({person.role})")


class DiscoveryEngine:
    """
    Orchestrates OSINT discovery across multiple data sources.

    Coordinates the various collector modules to build a comprehensive
    picture of an organization's public attack surface.
    """

    def __init__(self, config: dict):
        self.config = config
        self.collectors = []
        self.org = None
        logger.info("DiscoveryEngine initialized")

    def set_target(self, org_name: str, domain: Optional[str] = None):
        """Set the target organization for reconnaissance."""
        self.org = Organization(name=org_name, domain=domain)
        logger.info(f"Target set: {org_name} (domain: {domain})")
        return self.org

    def register_collector(self, collector):
        """Register a data collection module."""
        self.collectors.append(collector)
        logger.info(f"Registered collector: {collector.__class__.__name__}")

    async def run_discovery(self) -> Organization:
        """
        Execute all registered collectors against the target.

        Returns the Organization object populated with discovered data.
        """
        if not self.org:
            raise ValueError("No target set. Call set_target() first.")

        logger.info(f"Starting discovery for {self.org.name}")

        for collector in self.collectors:
            try:
                logger.info(f"Running collector: {collector.__class__.__name__}")
                results = await collector.collect(self.org)
                self._merge_results(results)
            except Exception as e:
                logger.error(f"Collector {collector.__class__.__name__} failed: {e}")
                continue

        logger.info(
            f"Discovery complete: {self.org.employee_count} employees found"
        )
        return self.org

    def _merge_results(self, results: dict):
        """
        Merge collector results into the organization model with deduplication.

        People are matched across sources by:
        1. Email address (exact, case-insensitive)
        2. GitHub username (exact)
        3. Name similarity (exact, case-insensitive)

        When a match is found, profiles and metadata are merged rather than
        creating a duplicate entry.
        """
        if "employees" in results:
            for person_data in results["employees"]:
                person = Person(**person_data)
                existing = self._find_existing_person(person)
                if existing:
                    self._merge_person(existing, person)
                    logger.info(f"Merged data for: {person.name}")
                else:
                    self.org.add_employee(person)

        if "infrastructure" in results:
            # Deep-merge infrastructure dicts: extend lists, update dicts
            for key, value in results["infrastructure"].items():
                if key in self.org.infrastructure:
                    existing = self.org.infrastructure[key]
                    if isinstance(existing, list) and isinstance(value, list):
                        # Extend and deduplicate if items are dicts with 'url' or 'email'
                        existing_set = {
                            _dedup_key(item) for item in existing
                        }
                        for item in value:
                            if _dedup_key(item) not in existing_set:
                                existing.append(item)
                                existing_set.add(_dedup_key(item))
                    elif isinstance(existing, dict) and isinstance(value, dict):
                        existing.update(value)
                    else:
                        self.org.infrastructure[key] = value
                else:
                    self.org.infrastructure[key] = value

        if "documents" in results:
            existing_urls = {
                d.get("url") for d in self.org.documents if isinstance(d, dict)
            }
            for doc in results["documents"]:
                url = doc.get("url") if isinstance(doc, dict) else None
                if url not in existing_urls:
                    self.org.documents.append(doc)
                    existing_urls.add(url)

        if "breach_data" in results:
            self.org.breach_data.update(results["breach_data"])

    def _find_existing_person(self, person: Person) -> Optional[Person]:
        """Find an existing person in the org that matches the new person."""
        for existing in self.org.employees:
            # Match by email (strongest signal)
            if (
                person.email
                and existing.email
                and person.email.lower() == existing.email.lower()
            ):
                return existing

            # Match by GitHub username
            new_gh = person.social_profiles.get("github", {}).get("username")
            ext_gh = existing.social_profiles.get("github", {}).get("username")
            if new_gh and ext_gh and new_gh.lower() == ext_gh.lower():
                return existing

            # Match by name (case-insensitive exact match)
            if (
                person.name
                and existing.name
                and _normalize_name(person.name) == _normalize_name(existing.name)
            ):
                return existing

        return None

    @staticmethod
    def _merge_person(existing: Person, new: Person):
        """Merge new person data into an existing Person record."""
        # Fill in missing fields
        if not existing.email and new.email:
            existing.email = new.email
        if not existing.role and new.role:
            existing.role = new.role

        # Merge social profiles (add new platforms, don't overwrite existing)
        for platform, data in new.social_profiles.items():
            if platform not in existing.social_profiles:
                existing.social_profiles[platform] = data

        # Merge metadata
        for key, value in new.metadata.items():
            if key not in existing.metadata:
                existing.metadata[key] = value

        # Track all sources
        existing_sources = existing.metadata.get("sources", [])
        new_source = new.metadata.get("source", "unknown")
        if new_source not in existing_sources:
            existing_sources.append(new_source)
        existing.metadata["sources"] = existing_sources


def _normalize_name(name: str) -> str:
    """Normalize a name for comparison: lowercase, strip, collapse whitespace."""
    return " ".join(name.lower().strip().split())


def _dedup_key(item) -> str:
    """Generate a deduplication key for a list item."""
    if isinstance(item, dict):
        # Use url, email, or name as dedup key
        return (
            item.get("url")
            or item.get("email")
            or item.get("name")
            or str(item)
        )
    return str(item)
