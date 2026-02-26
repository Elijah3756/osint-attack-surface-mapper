"""Tests for the Network Graph Builder and OSINT Graph Builder."""

import pytest
from src.graph.network import (
    NetworkGraphBuilder,
    GraphNode,
    GraphEdge,
    RelationType,
)
from src.graph.builder import OSINTGraphBuilder
from src.recon.discovery import Person, Organization


class TestNetworkGraphBuilder:
    def setup_method(self):
        self.builder = NetworkGraphBuilder()

    def test_add_node(self):
        node = GraphNode(id="p1", label="Alice", node_type="person")
        self.builder.add_node(node)
        assert "p1" in self.builder.nodes

    def test_add_edge(self):
        edge = GraphEdge(
            source_id="p1",
            target_id="p2",
            relation_type=RelationType.COLLEAGUE,
        )
        self.builder.add_edge(edge)
        assert len(self.builder.edges) == 1

    def test_build_graph(self):
        self.builder.add_node(
            GraphNode(id="p1", label="Alice", node_type="person")
        )
        self.builder.add_node(
            GraphNode(id="p2", label="Bob", node_type="person")
        )
        self.builder.add_edge(
            GraphEdge(
                source_id="p1",
                target_id="p2",
                relation_type=RelationType.COLLEAGUE,
            )
        )
        self.builder.build_graph()
        stats = self.builder.get_graph_stats()
        assert stats["total_nodes"] == 2
        assert stats["total_edges"] == 1

    def test_identify_high_value_targets(self):
        # Build a star network with p0 as the hub
        for i in range(5):
            self.builder.add_node(
                GraphNode(id=f"p{i}", label=f"Person {i}", node_type="person")
            )

        for i in range(1, 5):
            self.builder.add_edge(
                GraphEdge(
                    source_id="p0",
                    target_id=f"p{i}",
                    relation_type=RelationType.COLLEAGUE,
                )
            )

        self.builder.build_graph()
        targets = self.builder.identify_high_value_targets(top_n=3)
        assert targets[0].id == "p0"
        assert len(targets) == 3

    def test_graph_stats(self):
        for i in range(3):
            self.builder.add_node(
                GraphNode(id=f"p{i}", label=f"Person {i}", node_type="person")
            )
        self.builder.add_edge(
            GraphEdge(source_id="p0", target_id="p1", relation_type=RelationType.FOLLOWS)
        )
        self.builder.add_edge(
            GraphEdge(source_id="p1", target_id="p2", relation_type=RelationType.COLLABORATES)
        )
        self.builder.build_graph()
        stats = self.builder.get_graph_stats()
        assert stats["total_nodes"] == 3
        assert stats["total_edges"] == 2
        assert 0 <= stats["density"] <= 1

    def test_find_attack_paths(self):
        for i in range(4):
            self.builder.add_node(
                GraphNode(id=f"p{i}", label=f"Person {i}", node_type="person")
            )
        # Chain: p0 -> p1 -> p2 -> p3
        self.builder.add_edge(
            GraphEdge(source_id="p0", target_id="p1", relation_type=RelationType.FOLLOWS)
        )
        self.builder.add_edge(
            GraphEdge(source_id="p1", target_id="p2", relation_type=RelationType.COLLEAGUE)
        )
        self.builder.add_edge(
            GraphEdge(source_id="p2", target_id="p3", relation_type=RelationType.MANAGES)
        )
        self.builder.build_graph()
        paths = self.builder.find_attack_paths("p3")
        assert len(paths) > 0
        # p2 -> p3 should be the shortest (1 hop)
        shortest = min(paths, key=lambda p: p["hops"])
        assert shortest["hops"] == 1

    def test_empty_graph_stats(self):
        stats = self.builder.get_graph_stats()
        assert stats == {"status": "not built"}


class TestOSINTGraphBuilder:
    def _make_org_with_people(self, count: int) -> Organization:
        """Helper: create an org with N mock employees."""
        org = Organization(name="TestCorp", domain="testcorp.com")
        for i in range(count):
            person = Person(
                name=f"Person {i}",
                organization="TestCorp",
                role=f"Role {i}",
                email=f"person{i}@testcorp.com",
                social_profiles={
                    "github": {
                        "username": f"person{i}",
                        "url": f"https://github.com/person{i}",
                        "followers": i * 10,
                        "public_repos": i * 5,
                        "location": "San Francisco",
                    }
                },
            )
            org.add_employee(person)
        return org

    def test_add_people_from_discovery(self):
        org = self._make_org_with_people(5)
        builder = OSINTGraphBuilder()
        count = builder.add_people_from_discovery(org)
        assert count == 5
        assert len(builder.graph.nodes) == 5

    def test_add_org_membership_edges(self):
        org = self._make_org_with_people(4)
        builder = OSINTGraphBuilder()
        builder.add_people_from_discovery(org)
        builder.add_org_membership_edges(org)
        # 4 people = C(4,2) = 6 edges
        assert len(builder.graph.edges) == 6

    def test_build_and_analyze(self):
        org = self._make_org_with_people(5)
        builder = OSINTGraphBuilder()
        builder.add_people_from_discovery(org)
        builder.add_org_membership_edges(org)
        result = builder.build_and_analyze()
        assert result["status"] == "complete"
        assert result["stats"]["total_nodes"] == 5
        assert len(result["high_value_targets"]) > 0

    def test_empty_graph_analyze(self):
        builder = OSINTGraphBuilder()
        result = builder.build_and_analyze()
        assert result["status"] == "empty"

    def test_person_node_mapping(self):
        org = self._make_org_with_people(3)
        builder = OSINTGraphBuilder()
        builder.add_people_from_discovery(org)
        # Should map both name and github username
        assert "person 0" in builder._person_node_map
        assert "person0" in builder._person_node_map
