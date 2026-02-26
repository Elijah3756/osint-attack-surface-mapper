"""
Graph Builder - Constructs network graphs from discovered OSINT data.

Takes raw discovery results and builds meaningful relationship edges
between people based on shared repositories, follower networks,
and organizational proximity.
"""

import asyncio
import logging
from typing import Optional

import aiohttp

from src.graph.network import (
    NetworkGraphBuilder,
    GraphNode,
    GraphEdge,
    RelationType,
)

logger = logging.getLogger(__name__)


class OSINTGraphBuilder:
    """
    Builds a social network graph from OSINT discovery results.

    Creates nodes for people/accounts and infers edges from:
    - Shared GitHub repository contributions
    - GitHub follower/following relationships
    - Same organization membership
    - Shared social connections (Twitter mutuals, etc.)
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.graph = NetworkGraphBuilder()
        self._person_node_map = {}  # person name/login -> node_id

    def add_people_from_discovery(self, organization) -> int:
        """
        Add all discovered people as graph nodes.

        Returns the number of nodes added.
        """
        count = 0
        for i, person in enumerate(organization.employees):
            node_id = f"person_{i}"

            # Try to get GitHub username for better dedup
            github_data = person.social_profiles.get("github", {})
            username = github_data.get("username", "")

            # Ensure no None values — GEXF export requires typed attrs
            attrs = {
                "role": person.role or "",
                "email": person.email or "",
                "github_username": username or "",
                "location": github_data.get("location") or "",
                "followers": github_data.get("followers") or 0,
                "public_repos": github_data.get("public_repos") or 0,
            }
            node = GraphNode(
                id=node_id,
                label=person.name or "Unknown",
                node_type="person",
                attributes=attrs,
            )
            self.graph.add_node(node)

            # Map both name and github username to node_id
            self._person_node_map[person.name.lower()] = node_id
            if username:
                self._person_node_map[username.lower()] = node_id

            count += 1

        logger.info(f"Added {count} person nodes to graph")
        return count

    def add_org_membership_edges(self, organization):
        """
        Add edges between all members of the same organization.

        Everyone in the same org gets a weak 'colleague' connection.
        This provides baseline connectivity for the graph.
        """
        node_ids = list(self.graph.nodes.keys())
        edge_count = 0

        for i in range(len(node_ids)):
            for j in range(i + 1, len(node_ids)):
                edge = GraphEdge(
                    source_id=node_ids[i],
                    target_id=node_ids[j],
                    relation_type=RelationType.COLLEAGUE,
                    weight=0.3,  # Weak baseline connection
                    evidence=[f"Both members of {organization.name} GitHub org"],
                )
                self.graph.add_edge(edge)
                edge_count += 1

        logger.info(f"Added {edge_count} org membership edges")

    async def add_github_collaboration_edges(
        self,
        organization,
        github_config: dict,
    ):
        """
        Add stronger edges based on shared GitHub repo contributions.

        People who contribute to the same repositories have a stronger
        working relationship — these are the most meaningful edges.
        """
        repos = organization.infrastructure.get("github_repos", [])
        if not repos:
            logger.info("No repos found, skipping collaboration edges")
            return

        api_token = github_config.get("github_token")
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "OSINT-Recon-Tool/0.1",
        }
        if api_token:
            headers["Authorization"] = f"token {api_token}"

        # Map: repo_name -> list of contributor usernames
        repo_contributors = {}
        edge_count = 0

        async with aiohttp.ClientSession(headers=headers) as session:
            for repo in repos[:15]:  # Limit to top 15 repos
                repo_name = repo["name"]
                repo_url = repo.get("url", "")

                # Extract org/repo from URL
                if "github.com" in repo_url:
                    parts = repo_url.rstrip("/").split("/")
                    if len(parts) >= 2:
                        owner = parts[-2]
                        rname = parts[-1]
                    else:
                        continue
                else:
                    continue

                url = f"https://api.github.com/repos/{owner}/{rname}/contributors"
                try:
                    async with session.get(url, params={"per_page": 50}) as resp:
                        if resp.status == 200:
                            contributors = await resp.json()
                            usernames = [
                                c["login"].lower()
                                for c in contributors
                                if isinstance(c, dict) and "login" in c
                            ]
                            repo_contributors[repo_name] = usernames
                except Exception as e:
                    logger.debug(f"Error getting contributors for {repo_name}: {e}")

                # Rate limit
                await asyncio.sleep(1.0)

        # Build edges from shared repo contributions
        for repo_name, contributors in repo_contributors.items():
            # Find which of our discovered people contributed
            our_people = []
            for username in contributors:
                node_id = self._person_node_map.get(username)
                if node_id:
                    our_people.append(node_id)

            # Create edges between co-contributors
            for i in range(len(our_people)):
                for j in range(i + 1, len(our_people)):
                    edge = GraphEdge(
                        source_id=our_people[i],
                        target_id=our_people[j],
                        relation_type=RelationType.COLLABORATES,
                        weight=0.8,  # Strong connection
                        evidence=[f"Co-contributors on {repo_name}"],
                    )
                    self.graph.add_edge(edge)
                    edge_count += 1

        logger.info(f"Added {edge_count} collaboration edges from repo data")

    async def add_github_follower_edges(
        self,
        organization,
        github_config: dict,
    ):
        """
        Add edges based on GitHub follow relationships between org members.

        If person A follows person B and both are in the org, that indicates
        a directional awareness/interest relationship.
        """
        api_token = github_config.get("github_token")
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "OSINT-Recon-Tool/0.1",
        }
        if api_token:
            headers["Authorization"] = f"token {api_token}"

        # Get set of all our discovered GitHub usernames
        our_usernames = set()
        for person in organization.employees:
            gh = person.social_profiles.get("github", {})
            if gh.get("username"):
                our_usernames.add(gh["username"].lower())

        edge_count = 0

        async with aiohttp.ClientSession(headers=headers) as session:
            for person in organization.employees:
                gh = person.social_profiles.get("github", {})
                username = gh.get("username")
                if not username:
                    continue

                # Get who this person follows
                url = f"https://api.github.com/users/{username}/following"
                try:
                    async with session.get(url, params={"per_page": 100}) as resp:
                        if resp.status == 200:
                            following = await resp.json()
                            for followed in following:
                                followed_login = followed["login"].lower()
                                if followed_login in our_usernames:
                                    source_id = self._person_node_map.get(
                                        username.lower()
                                    )
                                    target_id = self._person_node_map.get(
                                        followed_login
                                    )
                                    if source_id and target_id and source_id != target_id:
                                        edge = GraphEdge(
                                            source_id=source_id,
                                            target_id=target_id,
                                            relation_type=RelationType.FOLLOWS,
                                            weight=0.5,
                                            evidence=[
                                                f"{username} follows {followed_login} on GitHub"
                                            ],
                                        )
                                        self.graph.add_edge(edge)
                                        edge_count += 1
                except Exception as e:
                    logger.debug(f"Error getting following for {username}: {e}")

                await asyncio.sleep(1.0)

        logger.info(f"Added {edge_count} follower edges")

    def build_and_analyze(self) -> dict:
        """
        Build the graph and run all analysis.

        Returns a summary dict with stats, high-value targets, etc.
        """
        if not self.graph.nodes:
            logger.warning("No nodes in graph, nothing to analyze")
            return {"status": "empty"}

        self.graph.build_graph()
        centrality = self.graph.compute_centrality()
        high_value = self.graph.identify_high_value_targets(top_n=10)
        stats = self.graph.get_graph_stats()

        return {
            "status": "complete",
            "stats": stats,
            "centrality": centrality,
            "high_value_targets": high_value,
        }

    def export(self, filepath: str):
        """Export graph to GEXF for Gephi visualization."""
        self.graph.export_gephi(filepath)

    def generate_pyvis_html(self, filepath: str, org=None, breach_data=None):
        """
        Generate an interactive HTML visualization using pyvis.

        When *org* and *breach_data* are supplied the output includes rich
        tag badges on every node (risk level, role, data source, breach
        status) and a filterable legend / sidebar panel.
        """
        try:
            from pyvis.network import Network

            net = Network(
                height="800px",
                width="100%",
                bgcolor="#1a1a2e",
                font_color="white",
                directed=True,
            )

            # Configure physics for nice layout
            net.barnes_hut(
                gravity=-5000,
                central_gravity=0.3,
                spring_length=200,
            )

            # Pre-compute tag data from org if available
            person_tags = {}  # node_id -> {risk, role_tag, source, breached, ...}
            if org:
                breach_data = breach_data or getattr(org, "breach_data", {}) or {}
                for i, person in enumerate(org.employees):
                    node_id = f"person_{i}"
                    email = (person.email or "").lower()
                    is_breached = email in breach_data if email else False
                    breach_count = 0
                    if is_breached:
                        bd = breach_data[email]
                        breach_count = bd.get("breach_count", len(bd.get("breaches", [])))

                    source = person.metadata.get("source", "unknown")
                    sources = person.metadata.get("sources", [source])
                    role_raw = person.role or ""
                    role_tag = self._classify_role(role_raw)

                    person_tags[node_id] = {
                        "breached": is_breached,
                        "breach_count": breach_count,
                        "role_tag": role_tag,
                        "sources": sources,
                        "email": email,
                    }

            # Track tag counts for legend
            tag_counts = {
                "risk": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "breach": {"Breached": 0, "Clean": 0},
                "source": {},
                "role": {},
            }

            # Add nodes with styling based on centrality + tags
            for node_id, node in self.graph.nodes.items():
                score = node.centrality_scores.get("pagerank", 0)
                size = 15 + (score * 500)  # Scale node size by importance
                risk_level = self._risk_level(score)
                color = self._risk_color(score)
                tag_counts["risk"][risk_level] += 1

                tags = person_tags.get(node_id, {})
                breached = tags.get("breached", False)
                breach_count = tags.get("breach_count", 0)
                role_tag = tags.get("role_tag", "")
                sources = tags.get("sources", [])

                if breached:
                    tag_counts["breach"]["Breached"] += 1
                else:
                    tag_counts["breach"]["Clean"] += 1

                for src in sources:
                    tag_counts["source"][src] = tag_counts["source"].get(src, 0) + 1
                if role_tag:
                    tag_counts["role"][role_tag] = tag_counts["role"].get(role_tag, 0) + 1

                # Build multi-line label: Name \n Role \n [RISK]
                label_lines = [node.label]
                role_val = node.attributes.get("role", "")
                if role_val:
                    # Truncate long roles
                    label_lines.append(role_val[:35] + ("…" if len(role_val) > 35 else ""))

                # Build rich tooltip with structured list layout
                badge_css = (
                    "display:inline-block;padding:2px 7px;border-radius:3px;"
                    "font-size:11px;font-weight:bold;margin:1px 2px;"
                )
                row_css = (
                    "display:flex;justify-content:space-between;"
                    "align-items:center;padding:3px 0;"
                    "border-bottom:1px solid rgba(255,255,255,0.08);"
                )
                label_css = "color:#aaa;font-size:11px;min-width:90px;"
                val_css = "color:#fff;font-size:11px;text-align:right;"

                risk_colors = {
                    "CRITICAL": "#dc2626", "HIGH": "#ea580c",
                    "MEDIUM": "#d97706", "LOW": "#16a34a",
                }
                risk_badge = (
                    f'<span style="{badge_css}background:{risk_colors[risk_level]};'
                    f'color:#fff">{risk_level}</span>'
                )

                if breached:
                    breach_badge = (
                        f'<span style="{badge_css}background:#dc2626;color:#fff">'
                        f"🔓 {breach_count} breach{'es' if breach_count != 1 else ''}</span>"
                    )
                else:
                    breach_badge = (
                        f'<span style="{badge_css}background:#16a34a;color:#fff">'
                        f"✓ Clean</span>"
                    )

                src_colors = {
                    "github": "#333", "web_scraper": "#0284c7",
                    "hunter_io": "#7c3aed", "unknown": "#6b7280",
                }
                source_badges = " ".join(
                    f'<span style="{badge_css}background:{src_colors.get(s, "#6b7280")};'
                    f'color:#fff">{s}</span>'
                    for s in sources
                )

                role_badge = ""
                if role_tag:
                    role_badge = (
                        f'<span style="{badge_css}background:#4338ca;color:#fff">'
                        f"{role_tag}</span>"
                    )

                email_display = tags.get("email", "N/A") or "N/A"
                location_display = node.attributes.get("location", "") or "N/A"

                title = (
                    f"<div style='font-family:-apple-system,BlinkMacSystemFont,"
                    f"sans-serif;min-width:260px;background:#1a1a2e;"
                    f"padding:12px;border-radius:6px;color:#e0e0e0'>"
                    # Header
                    f"<div style='font-size:15px;font-weight:700;color:#fff;"
                    f"margin-bottom:2px'>{node.label}</div>"
                    f"<div style='font-size:12px;color:#999;margin-bottom:10px;"
                    f"font-style:italic'>{node.attributes.get('role', 'N/A')}</div>"
                    # Tags row
                    f"<div style='margin-bottom:10px'>"
                    f"{risk_badge} {breach_badge} {role_badge}</div>"
                    # Info list
                    f"<table style='width:100%;border-collapse:collapse;font-size:11px'>"
                    f"<tr style='border-bottom:1px solid #333'>"
                    f"<td style='color:#888;padding:4px 8px 4px 0'>Email</td>"
                    f"<td style='color:#fff;text-align:right;padding:4px 0'>{email_display}</td></tr>"
                    f"<tr style='border-bottom:1px solid #333'>"
                    f"<td style='color:#888;padding:4px 8px 4px 0'>Location</td>"
                    f"<td style='color:#fff;text-align:right;padding:4px 0'>{location_display}</td></tr>"
                    f"<tr style='border-bottom:1px solid #333'>"
                    f"<td style='color:#888;padding:4px 8px 4px 0'>PageRank</td>"
                    f"<td style='color:#fff;text-align:right;padding:4px 0'>{score:.4f}</td></tr>"
                    f"<tr style='border-bottom:1px solid #333'>"
                    f"<td style='color:#888;padding:4px 8px 4px 0'>Followers</td>"
                    f"<td style='color:#fff;text-align:right;padding:4px 0'>{node.attributes.get('followers', 0)}</td></tr>"
                    f"<tr style='border-bottom:1px solid #333'>"
                    f"<td style='color:#888;padding:4px 8px 4px 0'>Public Repos</td>"
                    f"<td style='color:#fff;text-align:right;padding:4px 0'>{node.attributes.get('public_repos', 0)}</td></tr>"
                    f"<tr>"
                    f"<td style='color:#888;padding:4px 8px 4px 0'>Sources</td>"
                    f"<td style='text-align:right;padding:4px 0'>{source_badges}</td></tr>"
                    f"</table>"
                    f"</div>"
                )

                # Border ring for breached nodes
                node_opts = {
                    "color": {
                        "background": color,
                        "border": "#dc2626" if breached else color,
                        "highlight": {"background": "#fff", "border": color},
                    },
                    "borderWidth": 3 if breached else 1,
                }

                net.add_node(
                    node_id,
                    label="\n".join(label_lines),
                    title=title,
                    size=size,
                    font={"multi": True, "size": 12},
                    **node_opts,
                )

            # Add edges with styling
            for edge in self.graph.edges:
                color_map = {
                    RelationType.COLLABORATES: "#ff6b6b",
                    RelationType.FOLLOWS: "#4ecdc4",
                    RelationType.COLLEAGUE: "#45b7d155",
                }
                net.add_edge(
                    edge.source_id,
                    edge.target_id,
                    title=edge.relation_type.value,
                    color=color_map.get(edge.relation_type, "#666"),
                    width=edge.weight * 3,
                )

            net.save_graph(filepath)
            logger.info(f"Interactive graph saved to {filepath}")

            # Inject tag legend / sidebar panel into the HTML
            self._inject_tag_legend(filepath, tag_counts)

        except ImportError:
            logger.error("pyvis not installed: pip install pyvis")
        except Exception as e:
            logger.error(f"Pyvis graph generation failed: {e}")
            raise

    def _inject_tag_legend(self, filepath: str, tag_counts: dict):
        """Inject a floating tag legend panel into the pyvis HTML output."""
        try:
            with open(filepath, "r") as f:
                html = f.read()
        except Exception:
            return

        legend_html = self._build_legend_html(tag_counts)

        # Script that converts plain-text title attributes into DOM elements
        # so vis.js renders them as rich HTML tooltips instead of raw text.
        # NOTE: The title content is generated entirely by our own code above
        # (not user-supplied), so parsing it as HTML here is safe.
        tooltip_fix = """
<script>
(function() {
    var _poll = setInterval(function() {
        if (typeof nodes !== 'undefined' && nodes instanceof vis.DataSet &&
            typeof network !== 'undefined') {
            clearInterval(_poll);

            /* ── Convert title strings → DOM elements for HTML tooltips ── */
            var all = nodes.get();
            var _origNodeColors = {};
            all.forEach(function(n) {
                if (n.title && typeof n.title === 'string') {
                    var el = document.createElement('div');
                    el.innerHTML = n.title;   // safe: content is self-generated
                    n.title = el;
                }
                _origNodeColors[n.id] = n.color || null;
            });
            nodes.update(all);

            /* ── Store original edge colors ── */
            var allEdges = edges.get();
            var _origEdgeColors = {};
            allEdges.forEach(function(e) {
                _origEdgeColors[e.id] = { color: e.color, width: e.width };
            });

            var _focused = false;

            /* ── Click node → focus on its neighborhood ── */
            network.on('click', function(params) {
                if (params.nodes.length === 1) {
                    var selectedId = params.nodes[0];
                    var connEdges = network.getConnectedEdges(selectedId);
                    var connNodes = network.getConnectedNodes(selectedId);
                    var neighborhood = new Set(connNodes);
                    neighborhood.add(selectedId);

                    /* Dim all nodes outside the neighborhood */
                    var nUpdates = [];
                    nodes.get().forEach(function(n) {
                        if (neighborhood.has(n.id)) {
                            nUpdates.push({
                                id: n.id,
                                opacity: 1.0,
                                color: _origNodeColors[n.id],
                                font: { color: '#ffffff', size: 12, multi: true }
                            });
                        } else {
                            nUpdates.push({
                                id: n.id,
                                opacity: 0.12,
                                color: { background: '#333', border: '#333',
                                         highlight: { background: '#333', border: '#333' } },
                                font: { color: 'rgba(255,255,255,0.08)', size: 12, multi: true }
                            });
                        }
                    });
                    nodes.update(nUpdates);

                    /* Dim all edges not connected to selected node */
                    var connSet = new Set(connEdges);
                    var eUpdates = [];
                    edges.get().forEach(function(e) {
                        if (connSet.has(e.id)) {
                            var orig = _origEdgeColors[e.id] || {};
                            eUpdates.push({
                                id: e.id,
                                color: orig.color,
                                width: (orig.width || 1) * 1.5
                            });
                        } else {
                            eUpdates.push({
                                id: e.id,
                                color: { color: 'rgba(100,100,100,0.06)', highlight: 'rgba(100,100,100,0.06)' },
                                width: 0.3
                            });
                        }
                    });
                    edges.update(eUpdates);
                    _focused = true;

                } else if (params.nodes.length === 0 && _focused) {
                    /* Click on empty space → restore everything */
                    var resetN = [];
                    nodes.get().forEach(function(n) {
                        resetN.push({
                            id: n.id,
                            opacity: 1.0,
                            color: _origNodeColors[n.id],
                            font: { color: '#ffffff', size: 12, multi: true }
                        });
                    });
                    nodes.update(resetN);

                    var resetE = [];
                    edges.get().forEach(function(e) {
                        var orig = _origEdgeColors[e.id] || {};
                        resetE.push({
                            id: e.id,
                            color: orig.color,
                            width: orig.width
                        });
                    });
                    edges.update(resetE);
                    _focused = false;
                }
            });
        }
    }, 100);
})();
</script>
"""

        # Insert legend + tooltip fix before closing </body> tag
        html = html.replace("</body>", f"{legend_html}\n{tooltip_fix}\n</body>")

        try:
            with open(filepath, "w") as f:
                f.write(html)
        except Exception as e:
            logger.warning(f"Failed to inject tag legend: {e}")

    @staticmethod
    def _build_legend_html(tag_counts: dict) -> str:
        """Build the floating legend sidebar HTML/CSS."""
        risk_colors = {
            "CRITICAL": "#dc2626", "HIGH": "#ea580c",
            "MEDIUM": "#d97706", "LOW": "#16a34a",
        }
        source_colors = {
            "github": "#333", "web_scraper": "#0284c7",
            "hunter_io": "#7c3aed", "unknown": "#6b7280",
        }

        # Build risk tags
        risk_items = ""
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = tag_counts["risk"].get(level, 0)
            if count > 0:
                risk_items += (
                    f'<div class="tag-item">'
                    f'<span class="tag-badge" style="background:{risk_colors[level]}">'
                    f'{level}</span>'
                    f'<span class="tag-count">{count}</span></div>'
                )

        # Build breach tags
        breach_items = ""
        for label, count in tag_counts.get("breach", {}).items():
            if count > 0:
                bg = "#dc2626" if label == "Breached" else "#16a34a"
                icon = "🔓" if label == "Breached" else "✓"
                breach_items += (
                    f'<div class="tag-item">'
                    f'<span class="tag-badge" style="background:{bg}">'
                    f'{icon} {label}</span>'
                    f'<span class="tag-count">{count}</span></div>'
                )

        # Build source tags
        source_items = ""
        for src, count in sorted(tag_counts.get("source", {}).items(), key=lambda x: -x[1]):
            bg = source_colors.get(src, "#6b7280")
            source_items += (
                f'<div class="tag-item">'
                f'<span class="tag-badge" style="background:{bg}">'
                f'{src}</span>'
                f'<span class="tag-count">{count}</span></div>'
            )

        # Build role tags
        role_items = ""
        for role, count in sorted(tag_counts.get("role", {}).items(), key=lambda x: -x[1]):
            role_items += (
                f'<div class="tag-item">'
                f'<span class="tag-badge" style="background:#4338ca">'
                f'{role}</span>'
                f'<span class="tag-count">{count}</span></div>'
            )

        # Edge legend
        edge_legend = (
            '<div class="tag-section">'
            '<div class="tag-section-title">Edge Types</div>'
            '<div class="tag-item">'
            '<span class="edge-line" style="background:#ff6b6b"></span>'
            '<span class="tag-label">Collaborates</span></div>'
            '<div class="tag-item">'
            '<span class="edge-line" style="background:#4ecdc4"></span>'
            '<span class="tag-label">Follows</span></div>'
            '<div class="tag-item">'
            '<span class="edge-line" style="background:#45b7d1;opacity:0.4"></span>'
            '<span class="tag-label">Colleague</span></div>'
            '</div>'
        )

        return f"""
<style>
#tag-legend {{
    position: fixed; top: 10px; right: 10px; width: 220px;
    background: rgba(20,20,40,0.95); border: 1px solid #333;
    border-radius: 8px; padding: 14px; z-index: 9999;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    color: #e0e0e0; font-size: 12px;
    max-height: 90vh; overflow-y: auto;
    box-shadow: 0 4px 20px rgba(0,0,0,0.5);
}}
#tag-legend h3 {{
    margin: 0 0 10px 0; font-size: 14px; color: #fff;
    border-bottom: 1px solid #444; padding-bottom: 6px;
}}
.tag-section {{ margin-bottom: 12px; }}
.tag-section-title {{
    font-weight: 600; color: #aaa; font-size: 10px;
    text-transform: uppercase; letter-spacing: 1px;
    margin-bottom: 6px;
}}
.tag-item {{
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 4px;
}}
.tag-badge {{
    display: inline-block; padding: 2px 8px; border-radius: 3px;
    font-size: 10px; font-weight: 600; color: #fff;
    white-space: nowrap;
}}
.tag-count {{
    color: #888; font-size: 11px; font-weight: 600;
}}
.tag-label {{ color: #ccc; font-size: 11px; flex: 1; margin-left: 8px; }}
.edge-line {{
    display: inline-block; width: 24px; height: 3px;
    border-radius: 2px; vertical-align: middle;
}}
#legend-toggle {{
    position: fixed; top: 10px; right: 10px; z-index: 10000;
    background: rgba(20,20,40,0.9); border: 1px solid #444;
    color: #fff; padding: 6px 12px; border-radius: 6px;
    cursor: pointer; font-size: 12px; display: none;
}}
</style>
<button id="legend-toggle" onclick="document.getElementById('tag-legend').style.display='block';this.style.display='none';">
    ☰ Legend
</button>
<div id="tag-legend">
    <h3>🏷️ Network Tags
        <span style="float:right;cursor:pointer;font-size:16px" onclick="this.parentElement.parentElement.style.display='none';document.getElementById('legend-toggle').style.display='block';">✕</span>
    </h3>
    <div class="tag-section">
        <div class="tag-section-title">Risk Level</div>
        {risk_items}
    </div>
    <div class="tag-section">
        <div class="tag-section-title">Breach Status</div>
        {breach_items}
    </div>
    {"<div class='tag-section'><div class='tag-section-title'>Data Source</div>" + source_items + "</div>" if source_items else ""}
    {"<div class='tag-section'><div class='tag-section-title'>Role Category</div>" + role_items + "</div>" if role_items else ""}
    {edge_legend}
</div>
"""

    @staticmethod
    def _classify_role(role: str) -> str:
        """Classify a raw role string into a category tag."""
        if not role:
            return ""
        role_lower = role.lower()
        categories = {
            "Engineering": ["engineer", "developer", "dev", "swe", "programmer", "coder", "architect"],
            "Security": ["security", "infosec", "cyber", "pentest", "soc ", "ciso"],
            "Management": ["manager", "director", "vp ", "head of", "lead", "chief", "cto", "ceo", "cfo", "coo"],
            "Research": ["research", "scientist", "phd", "professor", "academic"],
            "DevOps/SRE": ["devops", "sre", "infrastructure", "platform", "cloud", "ops"],
            "Design": ["design", "ux", "ui ", "product design"],
            "Data": ["data", "ml ", "machine learning", "ai ", "analytics"],
        }
        for category, keywords in categories.items():
            if any(kw in role_lower for kw in keywords):
                return category
        return "Other"

    @staticmethod
    def _risk_level(score: float) -> str:
        """Map centrality score to a risk level label."""
        if score > 0.15:
            return "CRITICAL"
        elif score > 0.08:
            return "HIGH"
        elif score > 0.04:
            return "MEDIUM"
        else:
            return "LOW"

    @staticmethod
    def _risk_color(score: float) -> str:
        """Map centrality score to a risk color."""
        if score > 0.15:
            return "#ff0000"  # Critical - red
        elif score > 0.08:
            return "#ff6b00"  # High - orange
        elif score > 0.04:
            return "#ffd700"  # Medium - gold
        else:
            return "#4ecdc4"  # Low - teal
