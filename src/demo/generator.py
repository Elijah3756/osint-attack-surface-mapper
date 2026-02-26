"""
Demo Data Generator - Creates realistic synthetic OSINT data for portfolio demos.

Generates a complete Organization object with fake employees, breach data,
infrastructure findings, and documents — enough to exercise every stage of
the pipeline without requiring live API keys.

Usage:
    python main.py --demo
"""

from src.recon.discovery import Person, Organization


def generate_demo_organization() -> Organization:
    """
    Build a realistic fake target organization for demo mode.

    Returns a fully-populated Organization with:
    - 12 employees across engineering, security, and leadership
    - GitHub profiles with varying activity levels
    - Breach data for several employees
    - Infrastructure findings (hosts, CVEs, open ports, SSL, subdomains)
    - Public documents and email pattern exposure
    """
    org = Organization(
        name="NovaTech Solutions",
        domain="novatech-solutions.com",
        industry="Enterprise SaaS",
    )

    # ── Employees ──────────────────────────────────────────────
    employees = [
        Person(
            name="Marcus Chen",
            organization="NovaTech Solutions",
            role="Chief Technology Officer",
            email="m.chen@novatech-solutions.com",
            social_profiles={
                "github": {
                    "username": "marcuschen",
                    "followers": 342,
                    "following": 89,
                    "public_repos": 47,
                    "bio": "CTO @NovaTech | Distributed systems | ex-AWS",
                    "location": "San Francisco, CA",
                    "company": "NovaTech Solutions",
                    "blog": "https://marcuschen.dev",
                    "twitter": "marcuschendev",
                    "email": "m.chen@novatech-solutions.com",
                },
                "linkedin": {
                    "url": "https://linkedin.com/in/marcuschen",
                    "location": "San Francisco Bay Area",
                    "company": "NovaTech Solutions",
                },
                "twitter": {
                    "username": "marcuschendev",
                    "followers": 1820,
                },
            },
            metadata={"source": "github", "sources": ["github", "hunter", "linkedin"]},
        ),
        Person(
            name="Sarah Okafor",
            organization="NovaTech Solutions",
            role="VP of Engineering",
            email="s.okafor@novatech-solutions.com",
            social_profiles={
                "github": {
                    "username": "sokafor",
                    "followers": 215,
                    "following": 67,
                    "public_repos": 31,
                    "bio": "VP Eng @NovaTech | Python & Go",
                    "location": "Austin, TX",
                    "company": "NovaTech Solutions",
                },
                "linkedin": {
                    "url": "https://linkedin.com/in/sarahokafor",
                    "company": "NovaTech Solutions",
                },
            },
            metadata={"source": "github", "sources": ["github", "hunter"]},
        ),
        Person(
            name="James Whitfield",
            organization="NovaTech Solutions",
            role="Lead Security Engineer",
            email="j.whitfield@novatech-solutions.com",
            social_profiles={
                "github": {
                    "username": "jwhitfield-sec",
                    "followers": 178,
                    "following": 122,
                    "public_repos": 22,
                    "bio": "AppSec lead @NovaTech | OSCP | Bug bounty hunter",
                    "location": "Denver, CO",
                    "company": "NovaTech Solutions",
                    "blog": "https://whitfieldsec.io",
                },
            },
            metadata={"source": "github", "sources": ["github", "web_scraper"]},
        ),
        Person(
            name="Priya Sharma",
            organization="NovaTech Solutions",
            role="Senior Backend Developer",
            email="p.sharma@novatech-solutions.com",
            social_profiles={
                "github": {
                    "username": "priyasharma-dev",
                    "followers": 94,
                    "following": 53,
                    "public_repos": 19,
                    "bio": "Backend eng @NovaTech | Rust & Python",
                    "location": "Seattle, WA",
                    "company": "NovaTech Solutions",
                },
            },
            metadata={"source": "github", "sources": ["github"]},
        ),
        Person(
            name="David Kim",
            organization="NovaTech Solutions",
            role="DevOps / SRE Lead",
            email="d.kim@novatech-solutions.com",
            social_profiles={
                "github": {
                    "username": "dkim-ops",
                    "followers": 67,
                    "following": 45,
                    "public_repos": 14,
                    "bio": "SRE @NovaTech | Kubernetes | Terraform",
                    "location": "Portland, OR",
                    "company": "NovaTech Solutions",
                },
                "twitter": {
                    "username": "dkim_ops",
                    "followers": 430,
                },
            },
            metadata={"source": "github", "sources": ["github", "dns_ct"]},
        ),
        Person(
            name="Elena Rodriguez",
            organization="NovaTech Solutions",
            role="Frontend Tech Lead",
            email="e.rodriguez@novatech-solutions.com",
            social_profiles={
                "github": {
                    "username": "erodriguez",
                    "followers": 112,
                    "following": 78,
                    "public_repos": 26,
                    "bio": "Frontend lead @NovaTech | React + TypeScript",
                    "location": "New York, NY",
                    "company": "NovaTech Solutions",
                    "blog": "https://elenarodriguez.dev",
                },
            },
            metadata={"source": "github", "sources": ["github", "hunter"]},
        ),
        Person(
            name="Alex Nguyen",
            organization="NovaTech Solutions",
            role="Junior Developer",
            email="a.nguyen@novatech-solutions.com",
            social_profiles={
                "github": {
                    "username": "alexnguyen-nt",
                    "followers": 12,
                    "following": 34,
                    "public_repos": 8,
                    "location": "Chicago, IL",
                    "company": "NovaTech Solutions",
                },
            },
            metadata={"source": "github", "sources": ["github"]},
        ),
        Person(
            name="Rachel Adebayo",
            organization="NovaTech Solutions",
            role="Cloud Architect",
            email="r.adebayo@novatech-solutions.com",
            social_profiles={
                "github": {
                    "username": "radebayo",
                    "followers": 156,
                    "following": 62,
                    "public_repos": 18,
                    "bio": "Cloud architect @NovaTech | AWS + GCP",
                    "location": "Atlanta, GA",
                    "company": "NovaTech Solutions",
                },
                "linkedin": {
                    "url": "https://linkedin.com/in/racheladebayo",
                    "company": "NovaTech Solutions",
                    "location": "Atlanta, GA",
                },
            },
            metadata={"source": "github", "sources": ["github", "hunter", "linkedin"]},
        ),
        Person(
            name="Tom Bradley",
            organization="NovaTech Solutions",
            role="QA Engineer",
            email="t.bradley@novatech-solutions.com",
            social_profiles={
                "github": {
                    "username": "tbradley-qa",
                    "followers": 23,
                    "following": 41,
                    "public_repos": 5,
                    "company": "NovaTech Solutions",
                },
            },
            metadata={"source": "github", "sources": ["github"]},
        ),
        Person(
            name="Linda Zhao",
            organization="NovaTech Solutions",
            role="Data Engineer",
            email="l.zhao@novatech-solutions.com",
            social_profiles={
                "github": {
                    "username": "lindazhao",
                    "followers": 88,
                    "following": 55,
                    "public_repos": 15,
                    "bio": "Data eng @NovaTech | Spark + Airflow",
                    "location": "San Jose, CA",
                    "company": "NovaTech Solutions",
                },
            },
            metadata={"source": "github", "sources": ["github", "hunter"]},
        ),
        Person(
            name="Chris Patel",
            organization="NovaTech Solutions",
            role="Mobile Developer",
            email="c.patel@novatech-solutions.com",
            social_profiles={
                "github": {
                    "username": "chrispatel",
                    "followers": 45,
                    "following": 38,
                    "public_repos": 11,
                    "location": "Boston, MA",
                    "company": "NovaTech Solutions",
                },
            },
            metadata={"source": "github", "sources": ["github"]},
        ),
        Person(
            name="Jordan Hayes",
            organization="NovaTech Solutions",
            role="Product Manager",
            email="j.hayes@novatech-solutions.com",
            social_profiles={
                "linkedin": {
                    "url": "https://linkedin.com/in/jordanhayes",
                    "location": "San Francisco, CA",
                    "company": "NovaTech Solutions",
                },
            },
            metadata={"source": "web_scraper", "sources": ["web_scraper", "hunter"]},
        ),
    ]

    for emp in employees:
        org.add_employee(emp)

    # ── Breach Data ────────────────────────────────────────────
    org.breach_data = {
        "m.chen@novatech-solutions.com": {
            "breach_count": 3,
            "breaches": [
                {
                    "name": "LinkedIn 2021",
                    "date": "2021-06-22",
                    "data_classes": [
                        "Email addresses", "Passwords", "Phone numbers",
                        "Geolocation", "Professional info",
                    ],
                },
                {
                    "name": "Dropbox 2012",
                    "date": "2012-07-01",
                    "data_classes": [
                        "Email addresses", "Passwords",
                    ],
                },
                {
                    "name": "Adobe 2013",
                    "date": "2013-10-04",
                    "data_classes": [
                        "Email addresses", "Password hints",
                        "Usernames",
                    ],
                },
            ],
            "pastes": [
                {"source": "Pastebin", "date": "2022-01-15"},
            ],
        },
        "s.okafor@novatech-solutions.com": {
            "breach_count": 2,
            "breaches": [
                {
                    "name": "LinkedIn 2021",
                    "date": "2021-06-22",
                    "data_classes": [
                        "Email addresses", "Passwords",
                        "Professional info",
                    ],
                },
                {
                    "name": "Canva 2019",
                    "date": "2019-05-24",
                    "data_classes": [
                        "Email addresses", "Usernames",
                        "Geolocation",
                    ],
                },
            ],
            "pastes": [],
        },
        "j.whitfield@novatech-solutions.com": {
            "breach_count": 1,
            "breaches": [
                {
                    "name": "Exactis 2018",
                    "date": "2018-06-01",
                    "data_classes": [
                        "Email addresses", "Phone numbers",
                        "IP addresses", "Physical addresses",
                    ],
                },
            ],
            "pastes": [],
        },
        "d.kim@novatech-solutions.com": {
            "breach_count": 2,
            "breaches": [
                {
                    "name": "LastPass 2022",
                    "date": "2022-12-22",
                    "data_classes": [
                        "Email addresses", "Passwords",
                        "Auth tokens", "IP addresses",
                    ],
                },
                {
                    "name": "Gravatar 2020",
                    "date": "2020-10-01",
                    "data_classes": [
                        "Email addresses", "Usernames",
                    ],
                },
            ],
            "pastes": [
                {"source": "Ghostbin", "date": "2023-03-10"},
                {"source": "Pastebin", "date": "2023-05-02"},
            ],
        },
        "e.rodriguez@novatech-solutions.com": {
            "breach_count": 1,
            "breaches": [
                {
                    "name": "Dubsmash 2018",
                    "date": "2018-12-01",
                    "data_classes": [
                        "Email addresses", "Passwords",
                        "Usernames",
                    ],
                },
            ],
            "pastes": [],
        },
    }

    # ── Infrastructure ─────────────────────────────────────────
    org.infrastructure = {
        "github_repos": [
            {"name": "novatech-api", "url": "https://github.com/novatech-solutions/novatech-api", "stars": 12, "language": "Python"},
            {"name": "novatech-frontend", "url": "https://github.com/novatech-solutions/novatech-frontend", "stars": 8, "language": "TypeScript"},
            {"name": "infrastructure", "url": "https://github.com/novatech-solutions/infrastructure", "stars": 3, "language": "HCL"},
            {"name": "data-pipeline", "url": "https://github.com/novatech-solutions/data-pipeline", "stars": 5, "language": "Python"},
            {"name": "mobile-app", "url": "https://github.com/novatech-solutions/mobile-app", "stars": 2, "language": "Kotlin"},
            {"name": "docs", "url": "https://github.com/novatech-solutions/docs", "stars": 1, "language": "Markdown"},
            {"name": "auth-service", "url": "https://github.com/novatech-solutions/auth-service", "stars": 4, "language": "Go"},
            {"name": "ml-models", "url": "https://github.com/novatech-solutions/ml-models", "stars": 7, "language": "Python"},
        ],
        "commit_emails": [
            "m.chen@novatech-solutions.com",
            "s.okafor@novatech-solutions.com",
            "j.whitfield@novatech-solutions.com",
            "p.sharma@novatech-solutions.com",
            "d.kim@novatech-solutions.com",
            "e.rodriguez@novatech-solutions.com",
            "a.nguyen@novatech-solutions.com",
            "l.zhao@novatech-solutions.com",
            "c.patel@novatech-solutions.com",
        ],
        "hosts": [
            {
                "ip": "203.0.113.10",
                "hostnames": ["api.novatech-solutions.com"],
                "ports": [80, 443, 8080],
                "os": "Ubuntu 22.04",
            },
            {
                "ip": "203.0.113.11",
                "hostnames": ["staging.novatech-solutions.com"],
                "ports": [22, 80, 443, 3389, 8443],
                "os": "Windows Server 2019",
            },
            {
                "ip": "203.0.113.12",
                "hostnames": ["db.novatech-solutions.com"],
                "ports": [22, 5432, 6379],
                "os": "Ubuntu 20.04",
            },
            {
                "ip": "203.0.113.13",
                "hostnames": ["mail.novatech-solutions.com"],
                "ports": [25, 80, 443, 993],
                "os": "Ubuntu 22.04",
            },
        ],
        "open_ports": [22, 25, 80, 443, 3389, 5432, 6379, 8080, 8443],
        "vulnerabilities": [
            {"cve": "CVE-2024-3094", "cvss": 10.0, "host": "203.0.113.10", "service": "xz-utils", "description": "XZ Utils backdoor"},
            {"cve": "CVE-2023-44487", "cvss": 7.5, "host": "203.0.113.10", "service": "nginx", "description": "HTTP/2 Rapid Reset DDoS"},
            {"cve": "CVE-2023-38545", "cvss": 9.8, "host": "203.0.113.11", "service": "curl", "description": "curl SOCKS5 heap overflow"},
            {"cve": "CVE-2023-4911", "cvss": 7.8, "host": "203.0.113.12", "service": "glibc", "description": "Looney Tunables privilege escalation"},
            {"cve": "CVE-2022-47966", "cvss": 9.8, "host": "203.0.113.11", "service": "ManageEngine", "description": "Unauthenticated RCE"},
            {"cve": "CVE-2023-22515", "cvss": 10.0, "host": "203.0.113.10", "service": "Confluence", "description": "Privilege escalation to admin"},
            {"cve": "CVE-2024-21887", "cvss": 9.1, "host": "203.0.113.13", "service": "Ivanti", "description": "Authentication bypass"},
        ],
        "ssl_certs": [
            {
                "issued_to": "*.novatech-solutions.com",
                "issuer": "Let's Encrypt",
                "expires": "2025-08-15T00:00:00Z",
            },
            {
                "issued_to": "staging.novatech-solutions.com",
                "issuer": "Self-signed",
                "expires": "2024-01-01T00:00:00Z",  # Expired
            },
        ],
        "emails_found": [
            "info@novatech-solutions.com",
            "careers@novatech-solutions.com",
            "m.chen@novatech-solutions.com",
            "support@novatech-solutions.com",
            "j.hayes@novatech-solutions.com",
            "sales@novatech-solutions.com",
        ],
        "web_technologies": [
            "React 18.2", "Next.js 14", "nginx 1.24",
            "PostgreSQL", "Redis", "Python 3.11",
            "Docker", "Kubernetes", "AWS CloudFront",
        ],
        "hunter_emails": [
            "m.chen@novatech-solutions.com",
            "s.okafor@novatech-solutions.com",
            "j.whitfield@novatech-solutions.com",
            "p.sharma@novatech-solutions.com",
            "d.kim@novatech-solutions.com",
            "e.rodriguez@novatech-solutions.com",
            "r.adebayo@novatech-solutions.com",
            "j.hayes@novatech-solutions.com",
        ],
        "email_pattern": "{first_initial}.{last}",
        "subdomains": [
            "api.novatech-solutions.com",
            "staging.novatech-solutions.com",
            "db.novatech-solutions.com",
            "mail.novatech-solutions.com",
            "cdn.novatech-solutions.com",
            "grafana.novatech-solutions.com",
            "jenkins.novatech-solutions.com",
            "vpn.novatech-solutions.com",
            "jira.novatech-solutions.com",
            "wiki.novatech-solutions.com",
            "dev.novatech-solutions.com",
        ],
        "ip_addresses": [
            "203.0.113.10", "203.0.113.11",
            "203.0.113.12", "203.0.113.13",
            "203.0.113.20", "203.0.113.21",
        ],
        "mail_servers": [
            "mail.novatech-solutions.com",
            "mx-backup.novatech-solutions.com",
        ],
        "security_headers": {
            "SPF": {"present": True, "record": "v=spf1 include:_spf.google.com ~all"},
            "DMARC": {"present": False},
            "DKIM": {"present": True},
        },
    }

    # ── Documents ──────────────────────────────────────────────
    org.documents = [
        {
            "url": "https://novatech-solutions.com/about",
            "title": "About NovaTech Solutions",
            "type": "webpage",
        },
        {
            "url": "https://novatech-solutions.com/team",
            "title": "Our Team - NovaTech Solutions",
            "type": "webpage",
        },
        {
            "url": "https://novatech-solutions.com/careers",
            "title": "Careers at NovaTech Solutions",
            "type": "webpage",
        },
        {
            "url": "https://novatech-solutions.com/blog/our-tech-stack",
            "title": "Our Tech Stack - Engineering Blog",
            "type": "blog_post",
        },
    ]

    return org
