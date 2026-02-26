import os
import uuid

import pytest
import requests
from tests.test_utils import get_token_for_user


@pytest.fixture()
def create_user(request, api_client, default_admin):
    params = getattr(request, "param", {}) or {}

    default_name = f"test-{uuid.uuid4().hex[:8]}"
    email = params.get("email", f"{default_name}@test.account")
    name = params.get("name", default_name)

    response = api_client.request(
        "POST",
        "/api/v1/user",
        token=default_admin,
        json={"name": name, "email": email},
    )
    assert response.status_code == 200

    token = get_token_for_user(email)
    return token


@pytest.fixture(scope="session")
def default_admin():
    return get_token_for_user("default@admin.local")


# @pytest.fixture()
# def dataset_admin(api_client, request):
#     admin_token_value = default_admin
#     user_token_value = create_user(request)

#     user_response = api_client.request("GET", "/api/v1/user/cache", token=user_token_value)

#     user_response.raise_for_status()
#     user_id = user_response.json()["id"]

#     dataset_name = f"test-dataset-{uuid.uuid4().hex[:8]}"
#     dataset_response = api_client.request(
#         "POST",
#         "/api/v1/dataset",
#         token=admin_token_value,
#         json={"name": dataset_name, "tos_id": None},
#     )
#     dataset_response.raise_for_status()
#     dataset_id = dataset_response.json()["id"]

#     add_admin_response = api_client.request(
#         "POST",
#         f"/api/v1/dataset/{dataset_id}/admin",
#         token=admin_token_value,
#         json={"user_id": user_id},
#     )
#     add_admin_response.raise_for_status()

#     return user_token_value


class APIClient:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.created_users = []

    def request(self, method, endpoint, token=None, **kwargs):
        headers = kwargs.pop("headers", {})
        if token:
            headers.update(
                {
                    "Authorization": "Bearer " + token,
                    "Content-Type": "application/json",
                }
            )

        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        response = requests.request(method, url, headers=headers, **kwargs)

        if (
            method.upper() == "POST"
            and endpoint == "/api/v1/user"
            and response.ok
        ):
            user_data = response.json()
            if isinstance(user_data, dict) and "id" in user_data:
                self.created_users.append(user_data["id"])

        return response

    def cleanup(self, token=None):
        for user_id in self.created_users:
            try:
                self.request("DELETE", f"/api/v1/user/{user_id}", token=token)
            except Exception:
                pass


@pytest.fixture(scope="session")
def base_url():
    return os.environ.get("MIDDLE_AUTH_BASE_URL", "http://localhost:5000/auth")


@pytest.fixture(scope="module")
def api_client(base_url):
    client = APIClient(base_url)
    yield client
    client.cleanup()


@pytest.fixture(autouse=True)
def cleanup_created_users(api_client, default_admin):
    yield
    api_client.cleanup(token=default_admin)
