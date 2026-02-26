"""
Network Graph Module - Builds and analyzes social network graphs.

Creates relationship maps between discovered entities using graph theory
to identify high-value targets, influence paths, and organizational structure.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

logger = logging.getLogger(__name__)


class RelationType(Enum):
    """Types of relationships between entities in the graph."""
    COLLEAGUE = "colleague"
    MANAGES = "manages"
    REPORTS_TO = "reports_to"
    FOLLOWS = "follows"
    CONNECTED = "connected"
    COLLABORATES = "collaborates"
    MENTIONS = "mentions"


@dataclass
class GraphNode:
    """Represents an entity (person, account, org) in the network graph."""
    id: str
    label: str
    node_type: str  # person, account, organization, domain
    attributes: dict = field(default_factory=dict)
    centrality_scores: dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Represents a relationship between two nodes."""
    source_id: str
    target_id: str
    relation_type: RelationType
    weight: float = 1.0
    evidence: list = field(default_factory=list)


class NetworkGraphBuilder:
    """
    Builds and analyzes the social network graph.

    Uses NetworkX under the hood to construct the graph and compute
    centrality metrics that identify high-value targets.
    """

    def __init__(self):
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self._graph = None  # NetworkX graph instance

    def add_node(self, node: GraphNode):
        """Add an entity to the graph."""
        self.nodes[node.id] = node
        logger.debug(f"Added node: {node.label} ({node.node_type})")

    def add_edge(self, edge: GraphEdge):
        """Add a relationship to the graph."""
        self.edges.append(edge)
        logger.debug(
            f"Added edge: {edge.source_id} -> {edge.target_id} "
            f"({edge.relation_type.value})"
        )

    def build_graph(self):
        """
        Construct the NetworkX graph from nodes and edges.

        Call this after all nodes and edges have been added.
        """
        try:
            import networkx as nx
        except ImportError:
            raise ImportError("NetworkX is required: pip install networkx")

        self._graph = nx.DiGraph()

        for node_id, node in self.nodes.items():
            self._graph.add_node(
                node_id,
                label=node.label,
                node_type=node.node_type,
                **node.attributes,
            )

        for edge in self.edges:
            self._graph.add_edge(
                edge.source_id,
                edge.target_id,
                relation=edge.relation_type.value,
                weight=edge.weight,
            )

        logger.info(
            f"Graph built: {self._graph.number_of_nodes()} nodes, "
            f"{self._graph.number_of_edges()} edges"
        )

    def compute_centrality(self) -> dict:
        """
        Compute centrality metrics to identify high-value targets.

        Returns a dict of node_id -> centrality scores including:
        - degree: number of connections (most connected people)
        - betweenness: bridge nodes between groups (gatekeepers)
        - closeness: shortest path to all others (influence spread)
        - pagerank: recursive importance (key influencers)
        """
        import networkx as nx

        if not self._graph:
            raise ValueError("Graph not built. Call build_graph() first.")

        undirected = self._graph.to_undirected()

        metrics = {
            "degree": nx.degree_centrality(undirected),
            "betweenness": nx.betweenness_centrality(undirected),
            "closeness": nx.closeness_centrality(undirected),
            "pagerank": nx.pagerank(self._graph),
        }

        # Store scores on each node
        for node_id in self.nodes:
            self.nodes[node_id].centrality_scores = {
                metric: scores.get(node_id, 0.0)
                for metric, scores in metrics.items()
            }

        logger.info("Centrality metrics computed for all nodes")
        return metrics

    def identify_high_value_targets(self, top_n: int = 10) -> list[GraphNode]:
        """
        Rank nodes by composite centrality score to find top targets.

        Uses a weighted combination of centrality metrics to produce
        an overall "target value" score.
        """
        if not any(n.centrality_scores for n in self.nodes.values()):
            self.compute_centrality()

        weights = {
            "degree": 0.2,
            "betweenness": 0.3,
            "closeness": 0.2,
            "pagerank": 0.3,
        }

        scored = []
        for node_id, node in self.nodes.items():
            if node.node_type == "person":
                composite = sum(
                    node.centrality_scores.get(metric, 0) * weight
                    for metric, weight in weights.items()
                )
                scored.append((composite, node))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [node for _, node in scored[:top_n]]

    def find_attack_paths(
        self, target_id: str, max_paths: int = 10
    ) -> list:
        """
        Find the most efficient social engineering paths to a target.

        Identifies chains of relationships that could be leveraged
        in a social engineering campaign.  Paths are ranked by a
        composite risk score that favours:
        - Fewer hops (shorter chains are more practical)
        - Higher edge weight (stronger relationships are easier to exploit)
        - Higher entry-point degree centrality (more approachable people)
        """
        import networkx as nx

        if not self._graph:
            raise ValueError("Graph not built. Call build_graph() first.")

        paths = []
        entry_points = [
            n for n, d in self._graph.nodes(data=True)
            if d.get("node_type") == "person"
            and n != target_id
        ]

        degree_cent = nx.degree_centrality(self._graph.to_undirected())

        for entry in entry_points:
            try:
                path = nx.shortest_path(
                    self._graph, source=entry, target=target_id
                )
                if len(path) <= 1:
                    continue

                # Compute average edge weight along the path
                edge_weights = []
                edge_labels = []
                for i in range(len(path) - 1):
                    edata = self._graph.get_edge_data(path[i], path[i + 1]) or {}
                    edge_weights.append(edata.get("weight", 0.5))
                    edge_labels.append(edata.get("relation", "connected"))

                avg_weight = sum(edge_weights) / len(edge_weights)
                entry_degree = degree_cent.get(entry, 0)
                hops = len(path) - 1

                # Composite risk: prefer short paths with strong edges
                # from highly-connected entry points
                risk_score = (
                    (1.0 / hops) * 0.4
                    + avg_weight * 0.35
                    + entry_degree * 0.25
                )

                # Build human-readable labels
                path_labels = []
                for node_id in path:
                    node_data = self._graph.nodes.get(node_id, {})
                    path_labels.append(
                        node_data.get("label", node_id)
                    )

                paths.append({
                    "entry_point": entry,
                    "entry_label": self._graph.nodes.get(
                        entry, {}
                    ).get("label", entry),
                    "target_label": self._graph.nodes.get(
                        target_id, {}
                    ).get("label", target_id),
                    "path": path,
                    "path_labels": path_labels,
                    "edge_types": edge_labels,
                    "hops": hops,
                    "avg_edge_weight": round(avg_weight, 3),
                    "risk_score": round(risk_score, 4),
                })
            except nx.NetworkXNoPath:
                continue

        # Sort by risk score (highest first = most exploitable)
        paths.sort(key=lambda x: x["risk_score"], reverse=True)
        return paths[:max_paths]

    def export_gephi(self, filepath: str):
        """Export graph in GEXF format for Gephi visualization."""
        import networkx as nx

        if not self._graph:
            raise ValueError("Graph not built. Call build_graph() first.")

        # GEXF does not allow NoneType attribute values.
        # Sanitize every node and edge attribute before writing.
        clean = self._graph.copy()
        for _, data in clean.nodes(data=True):
            for key, val in list(data.items()):
                if val is None:
                    data[key] = ""
                elif isinstance(val, list):
                    data[key] = str(val)
        for _, _, data in clean.edges(data=True):
            for key, val in list(data.items()):
                if val is None:
                    data[key] = ""
                elif isinstance(val, list):
                    data[key] = str(val)

        nx.write_gexf(clean, filepath)
        logger.info(f"Graph exported to {filepath}")

    def get_graph_stats(self) -> dict:
        """Return summary statistics about the network graph."""
        import networkx as nx

        if not self._graph:
            return {"status": "not built"}

        undirected = self._graph.to_undirected()
        return {
            "total_nodes": self._graph.number_of_nodes(),
            "total_edges": self._graph.number_of_edges(),
            "density": nx.density(self._graph),
            "connected_components": nx.number_connected_components(undirected),
            "avg_clustering": nx.average_clustering(undirected),
        }
