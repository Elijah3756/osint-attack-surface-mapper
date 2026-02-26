"""Tests for the GitHub Collector."""

import pytest
from src.recon.collectors import GitHubCollector


class TestGitHubCollector:
    def test_init_without_token(self):
        collector = GitHubCollector(config={})
        assert collector.api_token is None
        assert collector.validate_config() is True  # Should work without token

    def test_init_with_token(self):
        collector = GitHubCollector(config={"github_token": "test_token"})
        assert collector.api_token == "test_token"

    def test_headers_without_token(self):
        collector = GitHubCollector(config={})
        headers = collector._get_headers()
        assert "Authorization" not in headers
        assert "User-Agent" in headers

    def test_headers_with_token(self):
        collector = GitHubCollector(config={"github_token": "test_token"})
        headers = collector._get_headers()
        assert headers["Authorization"] == "token test_token"

    def test_is_noreply_email(self):
        assert GitHubCollector._is_noreply_email("user@users.noreply.github.com")
        assert GitHubCollector._is_noreply_email("dependabot[bot]@github.com")
        assert GitHubCollector._is_noreply_email("noreply@example.com")
        assert not GitHubCollector._is_noreply_email("jane@acme.com")
        assert not GitHubCollector._is_noreply_email("john.doe@company.org")

    def test_profile_to_person(self):
        profile = {
            "name": "Jane Doe",
            "login": "janedoe",
            "html_url": "https://github.com/janedoe",
            "bio": "Software Engineer at Acme",
            "email": "jane@acme.com",
            "location": "San Francisco",
            "company": "Acme Corp",
            "blog": "https://janedoe.dev",
            "twitter_username": "janedoe",
            "public_repos": 42,
            "followers": 100,
            "following": 50,
            "created_at": "2020-01-01T00:00:00Z",
            "avatar_url": "https://avatars.githubusercontent.com/janedoe",
            "hireable": True,
        }

        person = GitHubCollector._profile_to_person(profile, "Acme Corp")

        assert person["name"] == "Jane Doe"
        assert person["organization"] == "Acme Corp"
        assert person["email"] == "jane@acme.com"
        assert person["social_profiles"]["github"]["username"] == "janedoe"
        assert person["social_profiles"]["github"]["followers"] == 100
        assert person["metadata"]["source"] == "github"

    def test_profile_to_person_no_name(self):
        """Falls back to login when name is None."""
        profile = {"name": None, "login": "janedoe"}
        person = GitHubCollector._profile_to_person(profile, "Acme")
        assert person["name"] == "janedoe"

    def test_rate_limit_config(self):
        collector = GitHubCollector(config={"rate_limit_delay": 2.0})
        assert collector.rate_limit_delay == 2.0

    def test_max_repos_config(self):
        collector = GitHubCollector(config={"max_repos": 25})
        assert collector.max_repos == 25

    def test_scan_commits_default(self):
        collector = GitHubCollector(config={})
        assert collector.scan_commits is True

    def test_scan_commits_disabled(self):
        collector = GitHubCollector(config={"scan_commits": False})
        assert collector.scan_commits is False
