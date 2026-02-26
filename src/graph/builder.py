"""
Graph Builder - Constructs network graphs from discovered OSINT data.

Takes raw discovery results and builds meaningful relationship edges
between people based on shared repositories, follower networks,
and organizational proximity.
"""

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
                import asyncio
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

                import asyncio
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

    def generate_pyvis_html(self, filepath: str):
        """Generate an interactive HTML visualization using pyvis."""
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

            # Add nodes with styling based on centrality
            for node_id, node in self.graph.nodes.items():
                score = node.centrality_scores.get("pagerank", 0)
                size = 15 + (score * 500)  # Scale node size by importance
                color = self._risk_color(score)

                title = (
                    f"<b>{node.label}</b><br>"
                    f"Role: {node.attributes.get('role', 'N/A')}<br>"
                    f"Location: {node.attributes.get('location', 'N/A')}<br>"
                    f"PageRank: {score:.4f}<br>"
                    f"Followers: {node.attributes.get('followers', 0)}"
                )

                net.add_node(
                    node_id,
                    label=node.label,
                    title=title,
                    size=size,
                    color=color,
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

        except ImportError:
            logger.error("pyvis not installed: pip install pyvis")

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
