"""Tests for the Discovery Engine."""

import pytest
from src.recon.discovery import Person, Organization, DiscoveryEngine


class TestPerson:
    def test_create_person(self):
        person = Person(name="Jane Doe", organization="Acme Corp", role="Engineer")
        assert person.name == "Jane Doe"
        assert person.role == "Engineer"
        assert person.profile_count == 0

    def test_person_with_profiles(self):
        person = Person(
            name="Jane Doe",
            organization="Acme Corp",
            social_profiles={"github": "janedoe", "twitter": "@janedoe"},
        )
        assert person.profile_count == 2


class TestOrganization:
    def test_create_organization(self):
        org = Organization(name="Acme Corp", domain="acme.com")
        assert org.name == "Acme Corp"
        assert org.employee_count == 0

    def test_add_employee(self):
        org = Organization(name="Acme Corp")
        person = Person(name="Jane Doe", organization="Acme Corp")
        org.add_employee(person)
        assert org.employee_count == 1


class TestDiscoveryEngine:
    def test_set_target(self):
        engine = DiscoveryEngine(config={})
        org = engine.set_target("Acme Corp", "acme.com")
        assert org.name == "Acme Corp"
        assert org.domain == "acme.com"

    def test_register_collector(self):
        engine = DiscoveryEngine(config={})
        assert len(engine.collectors) == 0
