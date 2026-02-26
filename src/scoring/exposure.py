"""
Exposure Scoring Module - Quantifies organizational attack surface risk.

Scores individuals and the organization based on discovered OSINT data,
breach exposure, social media footprint, and infrastructure findings.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ExposureFinding:
    """A single exposure finding for an individual or organization."""
    category: str  # breach, social_media, infrastructure, metadata
    title: str
    description: str
    risk_level: RiskLevel
    score: float  # 0.0 - 10.0
    evidence: list = field(default_factory=list)
    remediation: str = ""


@dataclass
class PersonScore:
    """Aggregate exposure score for an individual."""
    person_name: str
    person_role: str
    findings: list = field(default_factory=list)
    overall_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.INFO

    def compute_score(self):
        """Calculate overall score from individual findings."""
        if not self.findings:
            self.overall_score = 0.0
            self.risk_level = RiskLevel.INFO
            return

        self.overall_score = min(
            10.0,
            sum(f.score for f in self.findings) / len(self.findings) * 1.5,
        )

        if self.overall_score >= 8.0:
            self.risk_level = RiskLevel.CRITICAL
        elif self.overall_score >= 6.0:
            self.risk_level = RiskLevel.HIGH
        elif self.overall_score >= 4.0:
            self.risk_level = RiskLevel.MEDIUM
        elif self.overall_score >= 2.0:
            self.risk_level = RiskLevel.LOW
        else:
            self.risk_level = RiskLevel.INFO


@dataclass
class OrganizationScore:
    """Aggregate exposure score for the entire organization."""
    org_name: str
    person_scores: list = field(default_factory=list)
    infra_findings: list = field(default_factory=list)
    overall_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.INFO
    summary: str = ""


class ExposureScorer:
    """
    Calculates exposure scores based on OSINT findings.

    Scoring weights:
    - Breach exposure: 30% (known compromised credentials)
    - Social media footprint: 25% (oversharing, connections)
    - Infrastructure exposure: 25% (open ports, CVEs)
    - Metadata leakage: 20% (documents, email patterns)
    """

    CATEGORY_WEIGHTS = {
        "breach": 0.30,
        "social_media": 0.25,
        "infrastructure": 0.25,
        "metadata": 0.20,
    }

    def __init__(self, config: dict = None):
        self.config = config or {}

    def score_person(self, person, breach_data: dict, graph_metrics: dict) -> PersonScore:
        """
        Score an individual's exposure.

        Args:
            person: Person dataclass from discovery
            breach_data: HIBP results for this person
            graph_metrics: Centrality scores from the network graph
        """
        person_score = PersonScore(
            person_name=person.name,
            person_role=person.role or "Unknown",
        )

        # Score breach exposure
        self._score_breaches(person_score, breach_data)

        # Score social media exposure
        self._score_social_media(person_score, person)

        # Score based on network position (high centrality = higher value target)
        self._score_network_position(person_score, graph_metrics)

        person_score.compute_score()
        logger.info(
            f"Scored {person.name}: {person_score.overall_score:.1f} "
            f"({person_score.risk_level.value})"
        )
        return person_score

    def score_organization(
        self, person_scores: list, infra_data: dict,
        breach_data: dict = None,
    ) -> OrganizationScore:
        """
        Compute aggregate organizational exposure score.
        """
        org_score = OrganizationScore(
            org_name="Target Organization",
            person_scores=person_scores,
        )

        # Score infrastructure findings
        self._score_infrastructure(org_score, infra_data)

        # Org-level breach summary (aggregate of all breached emails)
        self._score_org_breaches(org_score, breach_data or {})

        # ── People component ────────────────────────────────
        people_score = 0.0
        if person_scores:
            avg_person = sum(p.overall_score for p in person_scores) / len(
                person_scores
            )
            max_person = max(p.overall_score for p in person_scores)
            # Weighted: 60% average exposure + 40% worst case
            people_score = avg_person * 0.6 + max_person * 0.4

        # ── Infrastructure component ────────────────────────
        infra_score = 0.0
        if org_score.infra_findings:
            infra_score = min(
                10.0,
                max(f.score for f in org_score.infra_findings),
            )

        # ── Blended org score ───────────────────────────────
        # If we only have infra data (no people), infra drives the score.
        # If we have both, blend 50/50 people vs infrastructure.
        if person_scores and org_score.infra_findings:
            org_score.overall_score = people_score * 0.5 + infra_score * 0.5
        elif org_score.infra_findings:
            org_score.overall_score = infra_score
        else:
            org_score.overall_score = people_score

        if org_score.overall_score >= 8.0:
            org_score.risk_level = RiskLevel.CRITICAL
        elif org_score.overall_score >= 6.0:
            org_score.risk_level = RiskLevel.HIGH
        elif org_score.overall_score >= 4.0:
            org_score.risk_level = RiskLevel.MEDIUM
        else:
            org_score.risk_level = RiskLevel.LOW

        org_score.summary = self._generate_summary(org_score)
        return org_score

    # ── Breach Scoring ──────────────────────────────────────────

    def _score_breaches(self, person_score: PersonScore, breach_data: dict):
        """
        Score based on presence in known data breaches.

        Factors:
        - Number of breaches (more breaches = more exposure)
        - Recency of breaches (recent breaches are more dangerous)
        - Types of data exposed (passwords >> emails)
        - Paste exposure (leaked credential dumps)
        """
        if not breach_data:
            return

        breaches = breach_data.get("breaches", [])
        pastes = breach_data.get("pastes", [])

        if not breaches and not pastes:
            return

        # ── Factor 1: Breach count ───────────────────────────
        breach_count = len(breaches)
        if breach_count >= 5:
            count_score = 9.0
        elif breach_count >= 3:
            count_score = 7.0
        elif breach_count >= 1:
            count_score = 5.0
        else:
            count_score = 0.0

        if breach_count > 0:
            person_score.findings.append(ExposureFinding(
                category="breach",
                title="Presence in Data Breaches",
                description=(
                    f"Email found in {breach_count} known data breach(es)."
                ),
                risk_level=(
                    RiskLevel.CRITICAL if breach_count >= 5
                    else RiskLevel.HIGH if breach_count >= 3
                    else RiskLevel.MEDIUM
                ),
                score=count_score,
                evidence=[
                    b.get("name", "Unknown breach") for b in breaches
                ],
                remediation=(
                    "Rotate all credentials associated with the breached email. "
                    "Enable MFA on every account."
                ),
            ))

        # ── Factor 2: Sensitive data classes ─────────────────
        HIGH_RISK_CLASSES = {
            "Passwords", "Password hints", "Security questions and answers",
            "Credit cards", "Bank account numbers", "Auth tokens",
            "IP addresses", "Phone numbers",
        }
        all_classes = set()
        for b in breaches:
            all_classes.update(b.get("data_classes", []))

        high_risk_leaked = all_classes & HIGH_RISK_CLASSES
        if high_risk_leaked:
            person_score.findings.append(ExposureFinding(
                category="breach",
                title="High-Risk Data Exposed",
                description=(
                    f"Sensitive data types leaked: "
                    f"{', '.join(sorted(high_risk_leaked))}."
                ),
                risk_level=RiskLevel.CRITICAL,
                score=9.0,
                evidence=sorted(high_risk_leaked),
                remediation=(
                    "Immediately change passwords on all services. "
                    "Monitor financial accounts for fraud."
                ),
            ))

        # ── Factor 3: Paste exposure ─────────────────────────
        paste_count = len(pastes)
        if paste_count > 0:
            person_score.findings.append(ExposureFinding(
                category="breach",
                title="Credentials Found in Pastes",
                description=(
                    f"Email appeared in {paste_count} paste(s), "
                    f"indicating credential dump exposure."
                ),
                risk_level=RiskLevel.HIGH,
                score=7.0,
                evidence=[
                    p.get("source", "Unknown") for p in pastes
                ],
                remediation=(
                    "Assume credentials are compromised. "
                    "Reset passwords and check for unauthorized access."
                ),
            ))

    # ── Social Media Scoring ──────────────────────────────────

    def _score_social_media(self, person_score: PersonScore, person):
        """
        Score based on social media exposure.

        Factors:
        - Number of platforms with public profiles
        - Personal info publicly shared (email, location, company)
        - GitHub activity level (repos, followers = visibility)
        - Cross-platform linkage (correlatable identities)
        """
        profiles = getattr(person, "social_profiles", {})
        if not profiles:
            return

        # ── Factor 1: Platform count ─────────────────────────
        platform_count = len(profiles)
        if platform_count >= 4:
            platform_score = 7.0
            level = RiskLevel.HIGH
        elif platform_count >= 2:
            platform_score = 5.0
            level = RiskLevel.MEDIUM
        elif platform_count >= 1:
            platform_score = 3.0
            level = RiskLevel.LOW
        else:
            return

        person_score.findings.append(ExposureFinding(
            category="social_media",
            title="Public Social Media Profiles",
            description=(
                f"Found {platform_count} public social media profile(s): "
                f"{', '.join(profiles.keys())}."
            ),
            risk_level=level,
            score=platform_score,
            evidence=list(profiles.keys()),
            remediation=(
                "Review privacy settings on all profiles. "
                "Limit publicly visible personal information."
            ),
        ))

        # ── Factor 2: Personal information exposure ──────────
        exposed_fields = []
        for platform, data in profiles.items():
            if not isinstance(data, dict):
                continue
            if data.get("email"):
                exposed_fields.append(f"{platform}: email")
            if data.get("location"):
                exposed_fields.append(f"{platform}: location")
            if data.get("company"):
                exposed_fields.append(f"{platform}: company")
            if data.get("bio"):
                exposed_fields.append(f"{platform}: bio")
            if data.get("blog"):
                exposed_fields.append(f"{platform}: personal website")
            if data.get("twitter"):
                exposed_fields.append(f"{platform}: linked Twitter")

        if exposed_fields:
            info_score = min(8.0, 2.0 + len(exposed_fields) * 0.8)
            person_score.findings.append(ExposureFinding(
                category="social_media",
                title="Personal Information Publicly Exposed",
                description=(
                    f"{len(exposed_fields)} personal data field(s) visible "
                    f"across public profiles."
                ),
                risk_level=(
                    RiskLevel.HIGH if len(exposed_fields) >= 5
                    else RiskLevel.MEDIUM
                ),
                score=info_score,
                evidence=exposed_fields,
                remediation=(
                    "Remove or restrict visibility of personal details "
                    "(location, personal email, phone) from public profiles."
                ),
            ))

        # ── Factor 3: GitHub visibility / activity ───────────
        gh = profiles.get("github", {})
        if isinstance(gh, dict):
            followers = gh.get("followers", 0) or 0
            public_repos = gh.get("public_repos", 0) or 0

            if followers >= 100 or public_repos >= 30:
                person_score.findings.append(ExposureFinding(
                    category="social_media",
                    title="High GitHub Visibility",
                    description=(
                        f"GitHub account has {followers} followers and "
                        f"{public_repos} public repos — high-profile target."
                    ),
                    risk_level=RiskLevel.MEDIUM,
                    score=5.0,
                    evidence=[
                        f"Followers: {followers}",
                        f"Public repos: {public_repos}",
                    ],
                    remediation=(
                        "Review repository contents for sensitive data "
                        "(API keys, internal docs, config files)."
                    ),
                ))

    # ── Network Position Scoring ──────────────────────────────

    def _score_network_position(self, person_score: PersonScore, metrics: dict):
        """
        Score based on network graph centrality position.

        Factors:
        - High betweenness = gatekeeper (bridges between groups)
        - High PageRank = influential (important connections)
        - High degree = hub node (many connections = broad access)
        """
        if not metrics:
            return

        # Look up this person's centrality scores
        # metrics is {metric_name: {node_id: score}} from compute_centrality
        betweenness_scores = metrics.get("betweenness", {})
        pagerank_scores = metrics.get("pagerank", {})
        degree_scores = metrics.get("degree", {})

        # Find the node matching this person (by label/name)
        person_name = person_score.person_name.lower()
        person_betweenness = 0.0
        person_pagerank = 0.0
        person_degree = 0.0

        for node_id in betweenness_scores:
            if person_name in node_id.lower():
                person_betweenness = betweenness_scores.get(node_id, 0.0)
                person_pagerank = pagerank_scores.get(node_id, 0.0)
                person_degree = degree_scores.get(node_id, 0.0)
                break

        # ── Factor 1: Gatekeeper position ────────────────────
        if person_betweenness > 0.1:
            person_score.findings.append(ExposureFinding(
                category="metadata",
                title="Network Gatekeeper",
                description=(
                    f"High betweenness centrality ({person_betweenness:.3f}) "
                    f"indicates this person bridges key groups — "
                    f"compromising them grants lateral access."
                ),
                risk_level=RiskLevel.HIGH,
                score=7.5,
                evidence=[f"Betweenness centrality: {person_betweenness:.4f}"],
                remediation=(
                    "Ensure this person has strong MFA and "
                    "security awareness training."
                ),
            ))

        # ── Factor 2: Influence (PageRank) ───────────────────
        if person_pagerank > 0.1:
            person_score.findings.append(ExposureFinding(
                category="metadata",
                title="High-Influence Network Position",
                description=(
                    f"High PageRank ({person_pagerank:.3f}) indicates "
                    f"this person is a key influencer — impersonation "
                    f"of them would be highly effective."
                ),
                risk_level=RiskLevel.HIGH,
                score=7.0,
                evidence=[f"PageRank: {person_pagerank:.4f}"],
                remediation=(
                    "Implement impersonation detection and "
                    "strengthen email authentication (DMARC/DKIM)."
                ),
            ))

        # ── Factor 3: Hub node (high degree) ─────────────────
        if person_degree > 0.5:
            person_score.findings.append(ExposureFinding(
                category="metadata",
                title="Hub Node — Extensive Connections",
                description=(
                    f"Degree centrality of {person_degree:.3f} means this "
                    f"person is connected to over half the network."
                ),
                risk_level=RiskLevel.MEDIUM,
                score=5.5,
                evidence=[f"Degree centrality: {person_degree:.4f}"],
                remediation=(
                    "Limit access scope using least-privilege principles."
                ),
            ))

    # ── Infrastructure Scoring ────────────────────────────────

    def _score_infrastructure(self, org_score: OrganizationScore, infra: dict):
        """
        Score infrastructure exposure from Shodan and web scraper data.

        Factors:
        - Known CVEs on internet-facing services
        - Open high-risk ports (RDP, SMB, Telnet, FTP, DB ports)
        - SSL certificate issues
        - Exposed documents / technology fingerprints
        - Email addresses found on public web pages
        """
        if not infra:
            return

        HIGH_RISK_PORTS = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            445: "SMB",
            1433: "MSSQL",
            1521: "Oracle",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            9200: "Elasticsearch",
            27017: "MongoDB",
        }

        # ── Factor 1: Known CVEs ─────────────────────────────
        vulns = infra.get("vulnerabilities", [])
        if vulns:
            high_cvss = [v for v in vulns if (v.get("cvss") or 0) >= 7.0]
            # CVEs without CVSS scores are still a risk — use volume
            unknown_cvss = [v for v in vulns if v.get("cvss") is None]
            unique_cves = set(v.get("cve", "") for v in vulns if v.get("cve"))

            # Score from both CVSS severity and sheer volume
            if high_cvss:
                score = min(10.0, 5.0 + len(high_cvss) * 1.5)
            elif len(unique_cves) >= 100:
                score = 9.0   # massive CVE surface even without CVSS
            elif len(unique_cves) >= 20:
                score = 7.5
            elif len(unique_cves) >= 5:
                score = 6.0
            else:
                score = 5.0

            # Determine risk level
            if high_cvss or len(unique_cves) >= 50:
                level = RiskLevel.CRITICAL
            elif len(unique_cves) >= 10:
                level = RiskLevel.HIGH
            else:
                level = RiskLevel.MEDIUM

            desc_parts = [
                f"{len(vulns)} CVE occurrence(s) across exposed services "
                f"({len(unique_cves)} unique)."
            ]
            if high_cvss:
                desc_parts.append(
                    f"{len(high_cvss)} rated high/critical (CVSS ≥ 7.0)."
                )
            if unknown_cvss:
                desc_parts.append(
                    f"{len(unknown_cvss)} without CVSS scores "
                    f"(severity unconfirmed)."
                )

            org_score.infra_findings.append(ExposureFinding(
                category="infrastructure",
                title="Known CVEs on Internet-Facing Services",
                description=" ".join(desc_parts),
                risk_level=level,
                score=score,
                evidence=[v.get("cve", "Unknown") for v in vulns[:15]],
                remediation=(
                    "Patch all systems with known CVEs immediately. "
                    "Run CVSS lookups on unscored CVEs to prioritize. "
                    "Consider vulnerability scanning for full coverage."
                ),
            ))

        # ── Factor 2: High-risk open ports ───────────────────
        open_ports = infra.get("open_ports", [])
        risky_open = {
            p: HIGH_RISK_PORTS[p]
            for p in open_ports
            if p in HIGH_RISK_PORTS
        }
        if risky_open:
            score = min(9.0, 4.0 + len(risky_open) * 1.0)
            org_score.infra_findings.append(ExposureFinding(
                category="infrastructure",
                title="High-Risk Ports Exposed to Internet",
                description=(
                    f"{len(risky_open)} high-risk port(s) open: "
                    f"{', '.join(f'{p} ({svc})' for p, svc in risky_open.items())}."
                ),
                risk_level=(
                    RiskLevel.CRITICAL if any(
                        p in risky_open for p in [3389, 445, 23, 27017, 6379]
                    ) else RiskLevel.HIGH
                ),
                score=score,
                evidence=[f"Port {p}: {svc}" for p, svc in risky_open.items()],
                remediation=(
                    "Close unnecessary ports. Move management interfaces "
                    "(RDP, SSH, DB) behind VPN. Implement firewall rules."
                ),
            ))

        # ── Factor 3: SSL certificate issues ─────────────────
        ssl_certs = infra.get("ssl_certs", [])
        if ssl_certs:
            # Flag expired or soon-to-expire certs
            from datetime import datetime
            expired = []
            for cert in ssl_certs:
                expires = cert.get("expires")
                if expires:
                    try:
                        exp_date = datetime.fromisoformat(
                            expires.replace("Z", "+00:00")
                        )
                        if exp_date < datetime.now(exp_date.tzinfo):
                            expired.append(cert)
                    except (ValueError, TypeError):
                        pass

            if expired:
                org_score.infra_findings.append(ExposureFinding(
                    category="infrastructure",
                    title="Expired SSL Certificates",
                    description=(
                        f"{len(expired)} SSL certificate(s) have expired, "
                        f"indicating poor certificate management."
                    ),
                    risk_level=RiskLevel.MEDIUM,
                    score=5.0,
                    evidence=[
                        f"{c.get('issued_to', '?')} expired {c.get('expires', '?')}"
                        for c in expired
                    ],
                    remediation="Renew expired certificates and implement auto-renewal.",
                ))

        # ── Factor 4: Exposed documents ──────────────────────
        # Documents come from the organization model, but emails_found
        # and web_technologies are in infra
        emails_found = infra.get("emails_found", [])
        if emails_found:
            org_score.infra_findings.append(ExposureFinding(
                category="metadata",
                title="Email Addresses on Public Website",
                description=(
                    f"{len(emails_found)} email address(es) found on public web pages. "
                    f"These can be used for phishing and credential stuffing."
                ),
                risk_level=(
                    RiskLevel.HIGH if len(emails_found) >= 10
                    else RiskLevel.MEDIUM
                ),
                score=min(7.0, 3.0 + len(emails_found) * 0.3),
                evidence=emails_found[:10],
                remediation=(
                    "Replace public email addresses with contact forms. "
                    "Use role-based aliases (info@, sales@) instead of personal emails."
                ),
            ))

        web_techs = infra.get("web_technologies", [])
        if web_techs:
            org_score.infra_findings.append(ExposureFinding(
                category="infrastructure",
                title="Technology Stack Fingerprinted",
                description=(
                    f"{len(web_techs)} technolog(ies) identified on the "
                    f"public website, enabling targeted exploit selection."
                ),
                risk_level=RiskLevel.LOW,
                score=2.5,
                evidence=web_techs[:10],
                remediation=(
                    "Remove version numbers from HTTP headers. "
                    "Suppress unnecessary server banners."
                ),
            ))

    # ── Org-Level Breach Scoring ────────────────────────────────

    def _score_org_breaches(self, org_score: OrganizationScore, breach_data: dict):
        """
        Score the organization based on aggregate breach exposure.

        Even if individual person-breach matching fails (e.g. web-scraped
        people without email addresses), this captures the org-wide breach
        picture from HIBP.
        """
        if not breach_data:
            return

        total_emails = len(breach_data)
        total_breaches = sum(
            d.get("breach_count", len(d.get("breaches", [])))
            for d in breach_data.values()
        )

        # Collect all unique breach names
        all_breach_names = set()
        all_data_classes = set()
        for email, data in breach_data.items():
            for b in data.get("breaches", []):
                all_breach_names.add(b.get("name", "Unknown"))
                all_data_classes.update(b.get("data_classes", []))

        if total_emails == 0:
            return

        # Score based on breadth and severity
        if total_emails >= 10:
            score = 9.0
            level = RiskLevel.CRITICAL
        elif total_emails >= 5:
            score = 7.5
            level = RiskLevel.HIGH
        elif total_emails >= 1:
            score = 6.0
            level = RiskLevel.HIGH
        else:
            return

        HIGH_RISK_CLASSES = {
            "Passwords", "Password hints", "Credit cards",
            "Bank account numbers", "Auth tokens",
        }
        leaked_sensitive = all_data_classes & HIGH_RISK_CLASSES
        if leaked_sensitive:
            score = min(10.0, score + 1.5)
            level = RiskLevel.CRITICAL

        org_score.infra_findings.append(ExposureFinding(
            category="breach",
            title="Employee Emails Found in Data Breaches",
            description=(
                f"{total_emails} employee email(s) appeared in "
                f"{len(all_breach_names)} unique breach(es) "
                f"({total_breaches} total occurrences). "
                f"Data types leaked: {', '.join(sorted(all_data_classes)[:8])}."
            ),
            risk_level=level,
            score=score,
            evidence=[
                f"{email}: {d.get('breach_count', '?')} breaches"
                for email, d in list(breach_data.items())[:10]
            ],
            remediation=(
                "Force credential rotation for all breached accounts. "
                "Enable MFA organization-wide. "
                "Monitor for credential stuffing attacks."
            ),
        ))

    # ── Executive Summary ─────────────────────────────────────

    def _generate_summary(self, org_score: OrganizationScore) -> str:
        """Generate executive summary of organizational exposure."""
        total = len(org_score.person_scores)
        critical = sum(
            1 for p in org_score.person_scores
            if p.risk_level == RiskLevel.CRITICAL
        )
        high = sum(
            1 for p in org_score.person_scores
            if p.risk_level == RiskLevel.HIGH
        )
        medium = sum(
            1 for p in org_score.person_scores
            if p.risk_level == RiskLevel.MEDIUM
        )

        infra_critical = sum(
            1 for f in org_score.infra_findings
            if f.risk_level == RiskLevel.CRITICAL
        )
        infra_high = sum(
            1 for f in org_score.infra_findings
            if f.risk_level == RiskLevel.HIGH
        )

        lines = [
            f"Assessment of {total} discovered employee(s): "
            f"{critical} critical, {high} high, {medium} medium risk.",
        ]

        if org_score.infra_findings:
            lines.append(
                f"Infrastructure: {len(org_score.infra_findings)} finding(s) "
                f"({infra_critical} critical, {infra_high} high)."
            )

        lines.append(
            f"Overall organizational exposure: "
            f"{org_score.overall_score:.1f}/10.0 ({org_score.risk_level.value})."
        )

        # Top recommendation
        if critical > 0 or infra_critical > 0:
            lines.append(
                "PRIORITY: Address critical-risk personnel and patch "
                "CVEs on internet-facing systems immediately."
            )
        elif high > 0 or infra_high > 0:
            lines.append(
                "RECOMMENDATION: Reduce social media exposure for "
                "high-risk individuals and close unnecessary open ports."
            )

        return " ".join(lines)
