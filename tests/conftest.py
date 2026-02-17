"""
Pytest configuration and fixtures for SCIM integration tests.
"""

import os
import pytest
import requests


class SCIMClient:
    """HTTP client for SCIM API requests with resource tracking for cleanup."""

    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.headers = {
            "Authorization": token,
            "Content-Type": "application/scim+json",
        }
        self.created_users = []
        self.created_groups = []
        self.created_datasets = []

    def request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make a SCIM API request."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        kwargs.setdefault("headers", {})
        kwargs["headers"].update(self.headers)
        return requests.request(method, url, **kwargs)

    def cleanup(self):
        """Delete all created resources."""
        for user_id in self.created_users:
            try:
                self.request("DELETE", f"/Users/{user_id}")
            except Exception:
                pass
        for group_id in self.created_groups:
            try:
                self.request("DELETE", f"/Groups/{group_id}")
            except Exception:
                pass
        for dataset_id in self.created_datasets:
            try:
                self.request("DELETE", f"/Datasets/{dataset_id}")
            except Exception:
                pass


@pytest.fixture(scope="module")
def scim_base_url():
    """SCIM API base URL from environment."""
    return os.environ.get("SCIM_BASE_URL", "http://localhost:5000/v2")


@pytest.fixture(scope="module")
def scim_token():
    """SCIM test token from environment. Skips tests if not set."""
    token = os.environ.get("SCIM_TEST_TOKEN", "")
    if not token:
        pytest.skip("SCIM_TEST_TOKEN environment variable not set")
    return token


@pytest.fixture(scope="module")
def scim_client(scim_base_url, scim_token):
    """SCIM API client with automatic cleanup after all tests."""
    client = SCIMClient(scim_base_url, scim_token)
    yield client
    client.cleanup()
