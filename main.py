#!/usr/bin/env python3
"""
OSINT Recon & Social Network Attack Surface Mapper

A red team OSINT tool that maps an organization's social network
attack surface through ethical open-source intelligence gathering.

Usage:
    python main.py --target "Example Corp" --domain example.com
    python main.py --config config/settings.yaml
    python main.py --target "Example Corp" --github-only

Author: Elijah Bellamy
Version: 0.1.0
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path

import yaml

from src.recon.discovery import DiscoveryEngine
from src.recon.collectors import (
    GitHubCollector,
    ShodanCollector,
    HIBPCollector,
    WebScraperCollector,
    HunterIOCollector,
    DNSCTCollector,
    RateLimiter,
)
from src.graph.builder import OSINTGraphBuilder
from src.scoring.exposure import ExposureScorer
from src.reporting.generator import ReportGenerator
from src.demo.generator import generate_demo_organization
from src.utils.display import (
    console,
    print_banner,
    print_target_info,
    print_api_status,
    print_stage,
    print_substep,
    print_discovery_results,
    print_graph_results,
    print_scoring_results,
    print_final_summary,
    status_spinner,
)


def load_config(config_path: str = "config/settings.yaml") -> dict:
    """Load configuration from YAML file, with env var fallbacks."""
    local_path = Path(config_path.replace(".yaml", ".local.yaml"))
    path = local_path if local_path.exists() else Path(config_path)

    if not path.exists():
        config = {}
    else:
        with open(path) as f:
            config = yaml.safe_load(f) or {}

    # Override API keys with environment variables (highest priority)
    api_keys = config.setdefault("api_keys", {})
    env_mappings = {
        "github_token": "GITHUB_TOKEN",
        "shodan_api_key": "SHODAN_API_KEY",
        "hibp_api_key": "HIBP_API_KEY",
        "hunter_api_key": "HUNTER_API_KEY",
    }
    for config_key, env_var in env_mappings.items():
        env_val = os.environ.get(env_var)
        if env_val and not env_val.startswith("$"):
            api_keys[config_key] = env_val

    return config


def setup_logging(config: dict, verbose: bool = False):
    """Configure logging — file only in normal mode, file+console in verbose."""
    log_config = config.get("logging", {})
    log_file = log_config.get("file", "data/osint_recon.log")
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)

    level = logging.DEBUG if verbose else logging.INFO
    handlers = [logging.FileHandler(log_file, mode="a")]

    # Only add console handler in verbose mode (Rich handles display otherwise)
    if verbose:
        handlers.append(logging.StreamHandler(sys.stdout))

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers,
    )


async def run_assessment(config: dict, target_name: str, target_domain: str = None):
    """Execute the full OSINT assessment pipeline with Rich progress display."""
    logger = logging.getLogger(__name__)
    start_time = time.time()

    # Ensure output directories exist
    Path("data/exports").mkdir(parents=True, exist_ok=True)
    Path("data/raw").mkdir(parents=True, exist_ok=True)

    api_keys = config.get("api_keys", {})
    collectors_config = config.get("collectors", {})
    github_enabled = collectors_config.get("github", {}).get("enabled", True)

    # ── Banner & Config ─────────────────────────────────────
    print_banner()

    active_collectors = []
    if github_enabled:
        active_collectors.append("GitHub")
    if collectors_config.get("shodan", {}).get("enabled"):
        active_collectors.append("Shodan")
    if collectors_config.get("hibp", {}).get("enabled"):
        active_collectors.append("HIBP")
    if collectors_config.get("web_scraper", {}).get("enabled"):
        active_collectors.append("WebScraper")
    if collectors_config.get("hunter_io", {}).get("enabled"):
        active_collectors.append("Hunter.io")
    if collectors_config.get("dns_ct", {}).get("enabled"):
        active_collectors.append("DNS/CT")

    print_target_info(target_name, target_domain, active_collectors)

    has_token = bool(api_keys.get("github_token"))
    print_api_status(has_token)

    # ── Stage 1: Discovery ──────────────────────────────────
    print_stage(1, "Reconnaissance", "Collecting OSINT data from public sources")

    engine = DiscoveryEngine(config)
    engine.set_target(target_name, target_domain)

    # Shared rate limiter across all collectors (1 req/sec default)
    shared_limiter = RateLimiter(calls_per_second=1.0)

    if github_enabled:
        github_config = {**api_keys, **collectors_config.get("github", {})}
        github_collector = GitHubCollector(github_config)
        github_collector.set_progress_callback(print_substep)
        github_collector.set_rate_limiter(shared_limiter)
        engine.register_collector(github_collector)
        print_substep("GitHub collector registered", "ok")

    if collectors_config.get("shodan", {}).get("enabled"):
        shodan_config = {**api_keys, **collectors_config.get("shodan", {})}
        shodan_collector = ShodanCollector(shodan_config)
        shodan_collector.set_progress_callback(print_substep)
        shodan_collector.set_rate_limiter(shared_limiter)
        engine.register_collector(shodan_collector)
        print_substep("Shodan collector registered", "ok")
    if collectors_config.get("hibp", {}).get("enabled"):
        hibp_config = {**api_keys, **collectors_config.get("hibp", {})}
        hibp_collector = HIBPCollector(hibp_config)
        hibp_collector.set_progress_callback(print_substep)
        hibp_collector.set_rate_limiter(shared_limiter)
        engine.register_collector(hibp_collector)
        print_substep("HIBP collector registered", "ok")
    if collectors_config.get("web_scraper", {}).get("enabled"):
        ws_config = {**api_keys, **collectors_config.get("web_scraper", {})}
        ws_collector = WebScraperCollector(ws_config)
        ws_collector.set_progress_callback(print_substep)
        ws_collector.set_rate_limiter(shared_limiter)
        engine.register_collector(ws_collector)
        print_substep("Web scraper collector registered", "ok")

    if collectors_config.get("hunter_io", {}).get("enabled"):
        hunter_config = {**api_keys, **collectors_config.get("hunter_io", {})}
        hunter_collector = HunterIOCollector(hunter_config)
        hunter_collector.set_progress_callback(print_substep)
        hunter_collector.set_rate_limiter(shared_limiter)
        engine.register_collector(hunter_collector)
        print_substep("Hunter.io collector registered", "ok")

    if collectors_config.get("dns_ct", {}).get("enabled"):
        dns_config = {**api_keys, **collectors_config.get("dns_ct", {})}
        dns_collector = DNSCTCollector(dns_config)
        dns_collector.set_progress_callback(print_substep)
        dns_collector.set_rate_limiter(shared_limiter)
        engine.register_collector(dns_collector)
        print_substep("DNS/CT recon collector registered", "ok")

    console.print()
    org = await engine.run_discovery()

    if org.employee_count > 0:
        print_substep(f"Found {org.employee_count} people", "ok")
    else:
        print_substep("No people discovered", "warn")
        if not has_token:
            print_substep(
                "Try setting GITHUB_TOKEN for better API access", "info"
            )

    repo_count = len(org.infrastructure.get("github_repos", []))
    email_count = len(org.infrastructure.get("commit_emails", []))
    print_substep(f"Found {repo_count} public repositories", "ok" if repo_count else "info")
    print_substep(f"Found {email_count} emails in commit history", "ok" if email_count else "info")

    # Shodan results
    host_count = len(org.infrastructure.get("hosts", []))
    vuln_count = len(org.infrastructure.get("vulnerabilities", []))
    if host_count or vuln_count:
        print_substep(f"Found {host_count} internet-facing hosts", "ok" if host_count else "info")
        print_substep(f"Found {vuln_count} known CVEs", "warn" if vuln_count else "info")

    # HIBP results
    breach_count = len(org.breach_data)
    if breach_count:
        print_substep(f"{breach_count} emails found in data breaches", "warn")

    # Web scraper results
    doc_count = len(org.documents)
    web_emails = len(org.infrastructure.get("emails_found", []))
    if doc_count or web_emails:
        print_substep(f"Found {doc_count} public documents", "ok" if doc_count else "info")
        print_substep(f"Found {web_emails} emails on website", "ok" if web_emails else "info")

    # Hunter.io results
    hunter_emails = len(org.infrastructure.get("hunter_emails", []))
    email_pattern = org.infrastructure.get("email_pattern")
    if hunter_emails or email_pattern:
        print_substep(f"Hunter.io: {hunter_emails} emails discovered", "ok" if hunter_emails else "info")
        if email_pattern:
            domain_str = target_domain or "domain.com"
            print_substep(f"Email pattern: {email_pattern}@{domain_str}", "ok")

    # DNS/CT results
    subdomain_count = len(org.infrastructure.get("subdomains", []))
    ip_count = len(org.infrastructure.get("ip_addresses", []))
    mail_count = len(org.infrastructure.get("mail_servers", []))
    if subdomain_count or ip_count:
        print_substep(f"CT logs: {subdomain_count} subdomains discovered", "ok" if subdomain_count else "info")
        print_substep(f"DNS: {ip_count} unique IPs, {mail_count} mail servers", "ok" if ip_count else "info")
        security = org.infrastructure.get("security_headers", {})
        if security:
            spf = security.get("SPF", {}).get("present", False)
            dmarc = security.get("DMARC", {}).get("present", False)
            if not spf or not dmarc:
                missing = []
                if not spf:
                    missing.append("SPF")
                if not dmarc:
                    missing.append("DMARC")
                print_substep(f"Missing email security: {', '.join(missing)}", "warn")

    # Save raw data
    raw_data = {
        "target": target_name,
        "domain": target_domain,
        "employee_count": org.employee_count,
        "employees": [
            {
                "name": p.name,
                "role": p.role,
                "email": p.email,
                "profiles": p.social_profiles,
                "metadata": p.metadata,
            }
            for p in org.employees
        ],
        "infrastructure": org.infrastructure,
        "documents": org.documents,
        "breach_data": org.breach_data,
    }
    with open("data/raw/discovery_results.json", "w") as f:
        json.dump(raw_data, f, indent=2, default=str)
    print_substep("Raw data saved to data/raw/discovery_results.json", "ok")

    console.print()
    print_discovery_results(org.employee_count, repo_count, email_count)

    # ── Stage 2: Graph Building ─────────────────────────────
    print_stage(2, "Network Graph Analysis", "Mapping relationships and identifying key targets")

    graph_builder = OSINTGraphBuilder(config)
    node_count = graph_builder.add_people_from_discovery(org)
    print_substep(f"Added {node_count} nodes to graph", "ok" if node_count else "info")

    stats = {}
    high_value = []
    centrality = {}
    pyvis_path = None

    if node_count > 1:
        graph_builder.add_org_membership_edges(org)
        print_substep("Added organization membership edges", "ok")

        if github_enabled:
            with status_spinner("Analyzing repository collaborations..."):
                await graph_builder.add_github_collaboration_edges(org, api_keys)
            print_substep("Added repository collaboration edges", "ok")

            with status_spinner("Analyzing follower relationships..."):
                await graph_builder.add_github_follower_edges(org, api_keys)
            print_substep("Added follower relationship edges", "ok")

        with status_spinner("Computing centrality metrics..."):
            analysis = graph_builder.build_and_analyze()

        if analysis["status"] == "complete":
            stats = analysis["stats"]
            high_value = analysis["high_value_targets"]
            centrality = analysis["centrality"]

            print_substep(
                f"Graph built: {stats['total_nodes']} nodes, "
                f"{stats['total_edges']} edges",
                "ok",
            )
            print_substep(f"Identified {len(high_value)} high-value targets", "ok")

            # Export graph files
            graph_builder.export("data/exports/network_graph.gexf")
            print_substep("Exported GEXF for Gephi", "ok")

            pyvis_path = "data/exports/network_graph.html"
            graph_builder.generate_pyvis_html(pyvis_path, org=org)
            print_substep("Generated interactive HTML graph with tags", "ok")

            console.print()
            print_graph_results(stats, high_value)
    else:
        print_substep("Not enough nodes for graph analysis (need 2+)", "warn")

    # ── Stage 3: Exposure Scoring ───────────────────────────
    print_stage(3, "Exposure Scoring", "Calculating risk scores for individuals and organization")

    scorer = ExposureScorer(config.get("scoring", {}))
    person_scores = []

    with status_spinner("Scoring individual exposure..."):
        for person in org.employees:
            # Look up breach data for this person by email
            person_breach = {}
            if person.email and person.email.lower() in org.breach_data:
                person_breach = org.breach_data[person.email.lower()]
            graph_metrics = centrality
            score = scorer.score_person(person, person_breach, graph_metrics)
            person_scores.append(score)

    if person_scores:
        print_substep(f"Scored {len(person_scores)} individuals", "ok")
    else:
        print_substep("No individuals to score", "info")

    org_score = scorer.score_organization(
        person_scores, org.infrastructure, breach_data=org.breach_data
    )
    print_substep(
        f"Organization score: {org_score.overall_score:.1f}/10.0 "
        f"({org_score.risk_level.value.upper()})",
        "ok",
    )

    console.print()
    print_scoring_results(org_score, person_scores)

    # ── Stage 4: Report Generation ──────────────────────────
    print_stage(4, "Report Generation", "Creating assessment deliverables")

    reporter = ReportGenerator(
        output_dir=config.get("reporting", {}).get("output_dir", "data/exports")
    )

    attack_paths = []
    if high_value and graph_builder.graph._graph:
        for target in high_value[:3]:
            paths = graph_builder.graph.find_attack_paths(target.id)
            attack_paths.extend(paths)
        if attack_paths:
            print_substep(f"Mapped {len(attack_paths)} attack paths", "ok")

    # JSON export
    json_path = reporter.generate_json_export(org_score, person_scores)
    print_substep("JSON findings exported", "ok")

    # PDF report
    try:
        pdf_path = reporter.generate_pdf_report(
            org_score=org_score,
            person_scores=person_scores,
            graph_stats=stats or {},
            high_value_targets=high_value,
            attack_paths=attack_paths,
            org_name=target_name,
            domain=target_domain or "",
        )
        print_substep("PDF assessment report generated", "ok")
    except Exception as e:
        pdf_path = None
        print_substep(f"PDF generation failed: {e}", "fail")

    # Interactive HTML dashboard
    try:
        # Build graph data dict for HTML report
        graph_data = {}
        if graph_builder.graph._graph:
            graph_nodes = {}
            for node_id, node in graph_builder.graph.nodes.items():
                graph_nodes[node_id] = {
                    "label": node.label,
                    "node_type": node.node_type,
                    **node.attributes,
                }
            graph_edges = []
            for edge in graph_builder.graph.edges:
                graph_edges.append({
                    "source": edge.source_id,
                    "target": edge.target_id,
                    "relation": edge.relation_type.value,
                    "weight": edge.weight,
                })
            graph_data = {"nodes": graph_nodes, "edges": graph_edges}

        html_path = reporter.generate_html_report(
            org_score=org_score,
            person_scores=person_scores,
            graph_data=graph_data,
            graph_stats=stats or {},
            high_value_targets=high_value,
            attack_paths=attack_paths,
            org_name=target_name,
            domain=target_domain or "",
            pyvis_html_path=pyvis_path,
        )
        print_substep("Interactive HTML dashboard generated", "ok")
    except Exception as e:
        html_path = None
        print_substep(f"HTML dashboard failed: {e}", "fail")

    # ── Final Summary ───────────────────────────────────────
    elapsed = time.time() - start_time

    exports = {
        "PDF Report": pdf_path,
        "HTML Dashboard": html_path,
        "JSON Findings": json_path,
        "Network Graph (HTML)": "data/exports/network_graph.html" if stats else None,
        "Network Graph (GEXF)": "data/exports/network_graph.gexf" if stats else None,
        "Raw Discovery Data": "data/raw/discovery_results.json",
    }

    print_final_summary(
        target_name=target_name,
        employee_count=org.employee_count,
        stats=stats,
        high_value_count=len(high_value),
        org_score_value=org_score.overall_score,
        risk_level=org_score.risk_level.value,
        elapsed_seconds=elapsed,
        exports={k: v for k, v in exports.items() if v},
    )

    return org_score


async def run_demo_assessment(config: dict):
    """
    Run a full assessment pipeline with synthetic demo data.

    Skips all API collectors and uses pre-built fake data so the tool
    can be showcased without any API keys.  Every downstream stage
    (graph building, scoring, reporting) runs identically to a real
    assessment.
    """
    logger = logging.getLogger(__name__)
    start_time = time.time()

    Path("data/exports").mkdir(parents=True, exist_ok=True)
    Path("data/raw").mkdir(parents=True, exist_ok=True)

    # ── Banner ─────────────────────────────────────────────────
    print_banner()

    org = generate_demo_organization()
    target_name = org.name
    domain = org.domain

    demo_collectors = [
        "GitHub", "Shodan", "HIBP", "Hunter.io", "DNS/CT", "WebScraper",
    ]
    print_target_info(target_name, domain, demo_collectors)
    console.print("[bold yellow]  ⚡ DEMO MODE — using synthetic data (no API keys needed)[/bold yellow]\n")

    # ── Stage 1: Discovery (pre-built) ─────────────────────────
    print_stage(1, "Reconnaissance", "Loading synthetic OSINT data")

    repo_count = len(org.infrastructure.get("github_repos", []))
    email_count = len(org.infrastructure.get("commit_emails", []))
    host_count = len(org.infrastructure.get("hosts", []))
    vuln_count = len(org.infrastructure.get("vulnerabilities", []))
    breach_count = len(org.breach_data)
    hunter_emails = len(org.infrastructure.get("hunter_emails", []))
    subdomain_count = len(org.infrastructure.get("subdomains", []))
    ip_count = len(org.infrastructure.get("ip_addresses", []))
    mail_count = len(org.infrastructure.get("mail_servers", []))

    print_substep(f"Found {org.employee_count} people", "ok")
    print_substep(f"Found {repo_count} public repositories", "ok")
    print_substep(f"Found {email_count} emails in commit history", "ok")
    print_substep(f"Found {host_count} internet-facing hosts", "ok")
    print_substep(f"Found {vuln_count} known CVEs", "warn")
    print_substep(f"{breach_count} emails found in data breaches", "warn")
    print_substep(f"Hunter.io: {hunter_emails} emails discovered", "ok")
    email_pattern = org.infrastructure.get("email_pattern")
    if email_pattern:
        print_substep(f"Email pattern: {email_pattern}@{domain}", "ok")
    print_substep(f"CT logs: {subdomain_count} subdomains discovered", "ok")
    print_substep(f"DNS: {ip_count} unique IPs, {mail_count} mail servers", "ok")

    security = org.infrastructure.get("security_headers", {})
    if security:
        spf = security.get("SPF", {}).get("present", False)
        dmarc = security.get("DMARC", {}).get("present", False)
        if not spf or not dmarc:
            missing = []
            if not spf:
                missing.append("SPF")
            if not dmarc:
                missing.append("DMARC")
            print_substep(f"Missing email security: {', '.join(missing)}", "warn")

    # Save raw data
    raw_data = {
        "target": target_name,
        "domain": domain,
        "demo_mode": True,
        "employee_count": org.employee_count,
        "employees": [
            {
                "name": p.name,
                "role": p.role,
                "email": p.email,
                "profiles": p.social_profiles,
                "metadata": p.metadata,
            }
            for p in org.employees
        ],
        "infrastructure": org.infrastructure,
        "documents": org.documents,
        "breach_data": org.breach_data,
    }
    with open("data/raw/discovery_results.json", "w") as f:
        json.dump(raw_data, f, indent=2, default=str)
    print_substep("Raw data saved to data/raw/discovery_results.json", "ok")

    console.print()
    print_discovery_results(org.employee_count, repo_count, email_count)

    # ── Stage 2: Graph Building ────────────────────────────────
    print_stage(2, "Network Graph Analysis", "Mapping relationships and identifying key targets")

    graph_builder = OSINTGraphBuilder(config)
    node_count = graph_builder.add_people_from_discovery(org)
    print_substep(f"Added {node_count} nodes to graph", "ok")

    stats = {}
    high_value = []
    centrality = {}
    pyvis_path = None

    if node_count > 1:
        graph_builder.add_org_membership_edges(org)
        print_substep("Added organization membership edges", "ok")

        # In demo mode we skip live GitHub API calls for collab/follower edges.
        # The org membership edges alone give us a connected graph for analysis.

        with status_spinner("Computing centrality metrics..."):
            analysis = graph_builder.build_and_analyze()

        if analysis["status"] == "complete":
            stats = analysis["stats"]
            high_value = analysis["high_value_targets"]
            centrality = analysis["centrality"]

            print_substep(
                f"Graph built: {stats['total_nodes']} nodes, "
                f"{stats['total_edges']} edges",
                "ok",
            )
            print_substep(f"Identified {len(high_value)} high-value targets", "ok")

            graph_builder.export("data/exports/network_graph.gexf")
            print_substep("Exported GEXF for Gephi", "ok")

            pyvis_path = "data/exports/network_graph.html"
            graph_builder.generate_pyvis_html(pyvis_path, org=org)
            print_substep("Generated interactive HTML graph", "ok")

            console.print()
            print_graph_results(stats, high_value)

    # ── Stage 3: Exposure Scoring ──────────────────────────────
    print_stage(3, "Exposure Scoring", "Calculating risk scores for individuals and organization")

    scorer = ExposureScorer(config.get("scoring", {}))
    person_scores = []

    with status_spinner("Scoring individual exposure..."):
        for person in org.employees:
            person_breach = {}
            if person.email and person.email.lower() in org.breach_data:
                person_breach = org.breach_data[person.email.lower()]
            graph_metrics = centrality
            score = scorer.score_person(person, person_breach, graph_metrics)
            person_scores.append(score)

    if person_scores:
        print_substep(f"Scored {len(person_scores)} individuals", "ok")

    org_score = scorer.score_organization(
        person_scores, org.infrastructure, breach_data=org.breach_data
    )
    print_substep(
        f"Organization score: {org_score.overall_score:.1f}/10.0 "
        f"({org_score.risk_level.value.upper()})",
        "ok",
    )

    console.print()
    print_scoring_results(org_score, person_scores)

    # ── Stage 4: Report Generation ─────────────────────────────
    print_stage(4, "Report Generation", "Creating assessment deliverables")

    reporter = ReportGenerator(
        output_dir=config.get("reporting", {}).get("output_dir", "data/exports")
    )

    attack_paths = []
    if high_value and graph_builder.graph._graph:
        for target in high_value[:3]:
            paths = graph_builder.graph.find_attack_paths(target.id)
            attack_paths.extend(paths)
        if attack_paths:
            print_substep(f"Mapped {len(attack_paths)} attack paths", "ok")

    # JSON
    json_path = reporter.generate_json_export(org_score, person_scores)
    print_substep("JSON findings exported", "ok")

    # PDF
    try:
        pdf_path = reporter.generate_pdf_report(
            org_score=org_score,
            person_scores=person_scores,
            graph_stats=stats or {},
            high_value_targets=high_value,
            attack_paths=attack_paths,
            org_name=target_name,
            domain=domain or "",
        )
        print_substep("PDF assessment report generated", "ok")
    except Exception as e:
        pdf_path = None
        print_substep(f"PDF generation failed: {e}", "fail")

    # HTML
    try:
        graph_data = {}
        if graph_builder.graph._graph:
            graph_nodes = {}
            for node_id, node in graph_builder.graph.nodes.items():
                graph_nodes[node_id] = {
                    "label": node.label,
                    "node_type": node.node_type,
                    **node.attributes,
                }
            graph_edges = []
            for edge in graph_builder.graph.edges:
                graph_edges.append({
                    "source": edge.source_id,
                    "target": edge.target_id,
                    "relation": edge.relation_type.value,
                    "weight": edge.weight,
                })
            graph_data = {"nodes": graph_nodes, "edges": graph_edges}

        html_path = reporter.generate_html_report(
            org_score=org_score,
            person_scores=person_scores,
            graph_data=graph_data,
            graph_stats=stats or {},
            high_value_targets=high_value,
            attack_paths=attack_paths,
            org_name=target_name,
            domain=domain or "",
            pyvis_html_path=pyvis_path,
        )
        print_substep("Interactive HTML dashboard generated", "ok")
    except Exception as e:
        html_path = None
        print_substep(f"HTML dashboard failed: {e}", "fail")

    # ── Final Summary ──────────────────────────────────────────
    elapsed = time.time() - start_time

    exports = {
        "PDF Report": pdf_path,
        "HTML Dashboard": html_path,
        "JSON Findings": json_path,
        "Network Graph (HTML)": "data/exports/network_graph.html" if stats else None,
        "Network Graph (GEXF)": "data/exports/network_graph.gexf" if stats else None,
        "Raw Discovery Data": "data/raw/discovery_results.json",
    }

    print_final_summary(
        target_name=target_name,
        employee_count=org.employee_count,
        stats=stats,
        high_value_count=len(high_value),
        org_score_value=org_score.overall_score,
        risk_level=org_score.risk_level.value,
        elapsed_seconds=elapsed,
        exports={k: v for k, v in exports.items() if v},
    )

    return org_score


def parse_args():
    parser = argparse.ArgumentParser(
        description="OSINT Recon & Social Network Attack Surface Mapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --demo                              # Run with synthetic data
  python main.py --target "Netflix" --domain netflix.com
  python main.py --target "Anthropic" --github-only
  python main.py --config config/settings.yaml --target "Acme Corp"
        """,
    )
    parser.add_argument(
        "--target", "-t", help="Target organization name (not needed with --demo)"
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="Run with synthetic demo data (no API keys needed)",
    )
    parser.add_argument(
        "--domain", "-d", help="Target organization domain"
    )
    parser.add_argument(
        "--config", "-c", default="config/settings.yaml",
        help="Path to configuration file",
    )
    parser.add_argument(
        "--github-only", action="store_true",
        help="Only run the GitHub collector",
    )
    parser.add_argument(
        "--output-dir", "-o", default="data/exports",
        help="Output directory for reports",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.demo and not args.target:
        print("Error: --target is required unless using --demo mode.")
        print("Usage: python main.py --target 'Org Name' --domain example.com")
        print("       python main.py --demo")
        sys.exit(1)

    config = load_config(args.config)

    if args.github_only:
        config.setdefault("collectors", {})
        for collector in ["shodan", "hibp", "web_scraper"]:
            config["collectors"].setdefault(collector, {})["enabled"] = False
        config["collectors"].setdefault("github", {})["enabled"] = True

    setup_logging(config, verbose=args.verbose)

    if args.output_dir:
        config.setdefault("reporting", {})["output_dir"] = args.output_dir

    if args.demo:
        asyncio.run(run_demo_assessment(config))
    else:
        target = args.target
        domain = args.domain

        # Auto-detect: if --target looks like a domain, use it as both
        # Must contain a dot, no spaces (avoid matching "Dr. Smith"), and have
        # a TLD-length suffix after the last dot (2-6 chars like .com, .edu)
        if not domain and "." in target and " " not in target:
            last_part = target.rsplit(".", 1)[-1]
            if 2 <= len(last_part) <= 6:
                domain = target

        asyncio.run(run_assessment(config, target, domain))


if __name__ == "__main__":
    main()
