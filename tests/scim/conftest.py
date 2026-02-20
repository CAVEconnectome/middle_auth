"""
Pytest configuration and fixtures for SCIM integration tests.
"""

import os

import pytest
import requests
from tests.test_utils import get_token_for_user


class SCIMClient:
    """HTTP client for SCIM API requests with resource tracking for cleanup."""

    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.token = token
        auth_value = token.strip() if token else ""
        if auth_value and not auth_value.lower().startswith("bearer "):
            auth_value = f"Bearer {auth_value}"
        self.headers = {
            "Authorization": auth_value,
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
    raw = os.environ.get("SCIM_BASE_URL", "http://localhost:5000/auth").rstrip("/")
    # Allow either:
    # - SCIM_BASE_URL=https://host/auth  -> append /scim/v2
    # - SCIM_BASE_URL=https://host/auth/scim/v2 -> use as-is
    if raw.endswith("/scim/v2"):
        return raw
    return raw + "/scim/v2"


@pytest.fixture(scope="module")
def scim_token():
    """SCIM test token from environment. Skips tests if not set."""
    token = (os.environ.get("SCIM_TEST_TOKEN") or "").strip()

    # If a real token is provided, use it.
    if token and token.lower() not in {"not_needed", "none", "false"}:
        return token

    # Otherwise, use the shared default admin token source.
    return get_token_for_user("default@admin.local")


@pytest.fixture(scope="module")
def scim_client(scim_base_url, scim_token):
    """SCIM API client with automatic cleanup after all tests."""
    client = SCIMClient(scim_base_url, scim_token)
    yield client
    client.cleanup()
