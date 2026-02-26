"""
Display Module - Rich console output for real-time progress tracking.

Provides a professional terminal UI with live progress updates,
status panels, and a final assessment summary dashboard.
"""

import time
from contextlib import contextmanager

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule

console = Console()

# ── Banner ──────────────────────────────────────────────────

BANNER = r"""
[bold red]  ___  ____ ___ _   _ _____  [/] [bold green] ____                      [/]
[bold red] / _ \/ ___|_ _| \ | |_   _|[/] [bold green]|  _ \ ___  ___ ___  _ __  [/]
[bold red]| | | \___ \| ||  \| | | |  [/] [bold green]| |_) / _ \/ __/ _ \| '_ \ [/]
[bold red]| |_| |___) | || |\  | | |  [/] [bold green]|  _ <  __/ (_| (_) | | | |[/]
[bold red] \___/|____/___|_| \_| |_|  [/] [bold green]|_| \_\___|\___\___/|_| |_|[/]
[dim]       Social Network Attack Surface Mapper v0.1.0[/]
[dim]       Author: Elijah Bellamy[/]
"""


def print_banner():
    """Display the tool banner."""
    console.print(BANNER)


def print_target_info(target_name: str, domain: str = None, collectors: list = None):
    """Display target configuration panel."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold red", width=16)
    table.add_column("Value", style="white")

    table.add_row("Target", target_name)
    table.add_row("Domain", domain or "Not specified")
    table.add_row("Collectors", ", ".join(collectors or ["GitHub"]))

    panel = Panel(table, title="[bold green]Target Configuration[/]", border_style="red")
    console.print(panel)
    console.print()


def print_api_status(has_github_token: bool, rate_remaining: int = None, rate_limit: int = None):
    """Display API authentication status."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold", width=16)
    table.add_column("Value")

    if has_github_token:
        table.add_row("GitHub Token", "[green]Configured[/]")
    else:
        table.add_row("GitHub Token", "[yellow]Not set (60 req/hr limit)[/]")

    if rate_remaining is not None:
        color = "green" if rate_remaining > 100 else "yellow" if rate_remaining > 10 else "red"
        table.add_row("Rate Limit", f"[{color}]{rate_remaining}/{rate_limit} remaining[/]")

    panel = Panel(table, title="[bold]API Status[/]", border_style="dim")
    console.print(panel)
    console.print()


# ── Stage Headers ───────────────────────────────────────────

def print_stage(number: int, title: str, description: str = ""):
    """Display a stage header."""
    console.print()
    console.print(Rule(f"[bold green]Stage {number}: {title}[/]", style="red"))
    if description:
        console.print(f"  [dim]{description}[/]")
    console.print()


# ── Progress Tracking ───────────────────────────────────────

def create_progress() -> Progress:
    """Create a Rich progress bar for tracking multi-step operations."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold green]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    )


@contextmanager
def status_spinner(message: str):
    """Context manager for a simple spinner with status message."""
    with console.status(f"[bold red]{message}[/]", spinner="dots"):
        yield


def print_substep(message: str, status: str = "ok"):
    """Print a substep result."""
    icons = {
        "ok": "[green]\u2713[/]",
        "warn": "[yellow]![/]",
        "fail": "[red]\u2717[/]",
        "info": "[blue]\u2022[/]",
        "skip": "[dim]-[/]",
    }
    icon = icons.get(status, icons["info"])
    console.print(f"  {icon} {message}")


# ── Discovery Results ───────────────────────────────────────

def print_discovery_results(employee_count: int, repo_count: int, email_count: int):
    """Display discovery stage results."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Metric", style="bold", width=24)
    table.add_column("Count", justify="right", style="green")

    table.add_row("People Discovered", str(employee_count))
    table.add_row("Public Repositories", str(repo_count))
    table.add_row("Emails from Commits", str(email_count))

    panel = Panel(table, title="[bold red]Discovery Results[/]", border_style="green")
    console.print(panel)


# ── Graph Results ───────────────────────────────────────────

def print_graph_results(stats: dict, high_value_targets: list):
    """Display graph analysis results."""
    # Graph stats
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Metric", style="bold", width=24)
    table.add_column("Value", justify="right", style="green")

    table.add_row("Nodes (People)", str(stats.get("total_nodes", 0)))
    table.add_row("Edges (Connections)", str(stats.get("total_edges", 0)))
    table.add_row("Graph Density", f"{stats.get('density', 0):.4f}")
    table.add_row("Clusters", str(stats.get("connected_components", 0)))
    table.add_row("Avg Clustering", f"{stats.get('avg_clustering', 0):.4f}")

    panel = Panel(table, title="[bold green]Network Graph Stats[/]", border_style="red")
    console.print(panel)
    console.print()

    # High-value targets
    if high_value_targets:
        hvt_table = Table(
            title="High-Value Targets",
            show_lines=False,
            header_style="bold white on red",
        )
        hvt_table.add_column("#", justify="center", width=4)
        hvt_table.add_column("Name", style="bold", min_width=20)
        hvt_table.add_column("PageRank", justify="right", style="green")
        hvt_table.add_column("Betweenness", justify="right", style="red")
        hvt_table.add_column("Degree", justify="right")
        hvt_table.add_column("Risk", justify="center")

        for i, target in enumerate(high_value_targets[:10]):
            pr = target.centrality_scores.get("pagerank", 0)
            bt = target.centrality_scores.get("betweenness", 0)
            dg = target.centrality_scores.get("degree", 0)

            # Risk color based on composite score
            composite = pr * 0.3 + bt * 0.3 + dg * 0.2
            if composite > 0.15:
                risk = "[bold red]CRITICAL[/]"
            elif composite > 0.08:
                risk = "[bold yellow]HIGH[/]"
            elif composite > 0.04:
                risk = "[yellow]MEDIUM[/]"
            else:
                risk = "[green]LOW[/]"

            hvt_table.add_row(
                str(i + 1),
                target.label,
                f"{pr:.4f}",
                f"{bt:.4f}",
                f"{dg:.4f}",
                risk,
            )

        console.print(hvt_table)


# ── Scoring Results ─────────────────────────────────────────

def print_scoring_results(org_score, person_scores: list):
    """Display exposure scoring results."""
    # Risk level color
    risk_colors = {
        "critical": "bold red",
        "high": "bold yellow",
        "medium": "yellow",
        "low": "green",
        "info": "dim",
    }
    risk_style = risk_colors.get(org_score.risk_level.value, "white")

    score_text = Text()
    score_text.append(f"  {org_score.overall_score:.1f}", style="bold white")
    score_text.append(" / 10.0  ", style="dim")
    score_text.append(f"[{org_score.risk_level.value.upper()}]", style=risk_style)

    panel = Panel(
        score_text,
        title="[bold]Organization Risk Score[/]",
        border_style=risk_style.replace("bold ", ""),
        width=50,
    )
    console.print(panel)

    # Breakdown by risk level
    if person_scores:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for ps in person_scores:
            counts[ps.risk_level.value] = counts.get(ps.risk_level.value, 0) + 1

        breakdown = Table(show_header=False, box=None, padding=(0, 2))
        breakdown.add_column("Level", width=12)
        breakdown.add_column("Count", justify="right", width=6)
        breakdown.add_column("Bar", width=30)

        total = len(person_scores) or 1
        for level, count in counts.items():
            if count > 0:
                bar_len = int((count / total) * 30)
                color = risk_colors.get(level, "white").replace("bold ", "")
                bar = f"[{color}]{'█' * bar_len}{'░' * (30 - bar_len)}[/]"
                breakdown.add_row(
                    f"[{risk_colors[level]}]{level.upper()}[/]",
                    str(count),
                    bar,
                )

        console.print(breakdown)


# ── Final Summary ───────────────────────────────────────────

def print_final_summary(
    target_name: str,
    employee_count: int,
    stats: dict,
    high_value_count: int,
    org_score_value: float,
    risk_level: str,
    exports: dict,
    elapsed_seconds: float,
):
    """Display the final assessment summary dashboard."""
    console.print()
    console.print(Rule("[bold red]Assessment Complete[/]", style="green"))
    console.print()

    # Main metrics row
    metrics_table = Table(show_header=False, box=None, padding=(0, 3))
    metrics_table.add_column("Metric", style="bold red", width=22)
    metrics_table.add_column("Value", style="green", justify="right")

    metrics_table.add_row("Target", target_name)
    metrics_table.add_row("People Discovered", str(employee_count))
    metrics_table.add_row("Graph Nodes", str(stats.get("total_nodes", 0)))
    metrics_table.add_row("Graph Edges", str(stats.get("total_edges", 0)))
    metrics_table.add_row("High-Value Targets", str(high_value_count))

    risk_colors = {
        "critical": "bold red",
        "high": "bold yellow",
        "medium": "yellow",
        "low": "green",
        "info": "dim",
    }
    risk_style = risk_colors.get(risk_level, "white")
    metrics_table.add_row(
        "Risk Score",
        Text(f"{org_score_value:.1f}/10.0 [{risk_level.upper()}]", style=risk_style),
    )
    metrics_table.add_row("Duration", f"{elapsed_seconds:.1f}s")

    panel = Panel(metrics_table, title="[bold green]Summary[/]", border_style="red")
    console.print(panel)

    # Exports
    if exports:
        console.print()
        console.print("[bold]Exports:[/]")
        for label, path in exports.items():
            if path:
                console.print(f"  [green]\u2713[/] {label}: [underline]{path}[/]")

    console.print()
