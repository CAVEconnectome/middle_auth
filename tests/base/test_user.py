import os
import uuid
from urllib.parse import quote


def test_user_create(api_client, default_admin):
    token = default_admin
    payload = {
        "name": "Test User",
        "email": f"test.user.{uuid.uuid4().hex[:8]}@example.com",
    }

    response = api_client.request("POST", "/api/v1/user", token=token, json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["email"] == payload["email"]
    assert data["name"] == payload["name"]
    api_client.created_users.append(data["id"])

    get_response = api_client.request(
        "GET", f"/api/v1/user/{data['id']}", token=token
    )

    assert get_response.status_code == 200
    assert get_response.json()["email"] == payload["email"]
    assert get_response.json()["name"] == payload["name"]


def test_user_update(api_client, default_admin):
    token = default_admin
    payload = {
        "name": "Original Name",
        "email": f"update.user.{uuid.uuid4().hex[:8]}@example.com",
    }
    create_response = api_client.request(
        "POST", "/api/v1/user", token=token, json=payload
    )

    assert create_response.status_code == 200
    user_id = create_response.json()["id"]
    api_client.created_users.append(user_id)

    response = api_client.request(
        "PUT", f"/api/v1/user/{user_id}", token=token, json={"name": "Updated Name"}
    )

    assert response.status_code == 200
    assert response.json() == "success"

    get_response = api_client.request("GET", f"/api/v1/user/{user_id}", token=token)

    assert get_response.status_code == 200
    assert get_response.json()["name"] == "Updated Name"


def test_user_delete(api_client, default_admin):
    token = default_admin
    payload = {
        "name": "Delete Me",
        "email": f"delete.user.{uuid.uuid4().hex[:8]}@example.com",
    }
    create_response = api_client.request(
        "POST", "/api/v1/user", token=token, json=payload
    )

    assert create_response.status_code == 200
    user_id = create_response.json()["id"]

    response = api_client.request(
        "DELETE", f"/api/v1/user/{user_id}", token=token
    )

    assert response.status_code == 200
    assert response.json() == "success"

    get_response = api_client.request("GET", f"/api/v1/user/{user_id}", token=token)
    assert get_response.status_code == 404


def test_user_cache(api_client, create_user):
    token = create_user

    response = api_client.request("GET", "/api/v1/user/cache", token=token)

    assert response.status_code == 200
    data = response.json()
    assert data["email"]


def test_get_user_admin_response(api_client, default_admin):
    token = default_admin
    payload = {
        "name": "Admin View",
        "email": f"admin.view.{uuid.uuid4().hex[:8]}@example.com",
    }

    create_response = api_client.request(
        "POST", "/api/v1/user", token=token, json=payload
    )

    assert create_response.status_code == 200
    user_id = create_response.json()["id"]

    get_response = api_client.request("GET", f"/api/v1/user/{user_id}", token=token)

    assert get_response.status_code == 200
    data = get_response.json()
    assert data["email"] == payload["email"]
    assert data["admin"] is False


def test_get_user_limited_response(api_client, default_admin, create_user):
    admin = default_admin
    limited = create_user
    payload = {
        "name": "Limited View",
        "email": f"limited.view.{uuid.uuid4().hex[:8]}@example.com",
    }

    create_response = api_client.request(
        "POST", "/api/v1/user", token=admin, json=payload
    )

    assert create_response.status_code == 200
    user_id = create_response.json()["id"]

    get_response = api_client.request(
        "GET", f"/api/v1/user/{user_id}", token=limited
    )

    assert get_response.status_code == 200
    data = get_response.json()
    assert data["name"] == payload["name"]
    assert "email" not in data
    assert "admin" not in data


def test_user_token_endpoints(api_client, create_user):
    token = create_user

    create_response = api_client.request("POST", "/api/v1/user/token", token=token)

    assert create_response.status_code == 200
    created_token = create_response.json()
    assert created_token

    list_response = api_client.request("GET", "/api/v1/user/token", token=token)

    assert list_response.status_code == 200
    tokens = list_response.json()
    assert any(entry["token"] == created_token for entry in tokens)

    token_entry = next(entry for entry in tokens if entry["token"] == created_token)
    token_id = token_entry["id"]

    delete_response = api_client.request(
        "DELETE", f"/api/v1/user/token/{token_id}", token=token
    )

    assert delete_response.status_code == 200
    assert delete_response.json() == "success"

    list_response = api_client.request("GET", "/api/v1/user/token", token=token)
    assert list_response.status_code == 200
    tokens = list_response.json()
    assert not any(entry["id"] == token_id for entry in tokens)


def test_logout(api_client, create_user):
    token = create_user

    response = api_client.request("GET", "/api/v1/logout", token=token)

    assert response.status_code == 200
    assert response.json() == "success"

    cache_response = api_client.request("GET", "/api/v1/user/cache", token=token)
    assert cache_response.status_code == 401


def test_logout_all(api_client, create_user):
    token = create_user

    response = api_client.request("GET", "/api/v1/logout_all", token=token)

    assert response.status_code == 200
    assert response.json() == "success"

    cache_response = api_client.request("GET", "/api/v1/user/cache", token=token)
    assert cache_response.status_code == 401

def test_no_token(api_client):
    cache_response = api_client.request("GET", "/api/v1/user/cache", allow_redirects=False)
    location = cache_response.headers.get("Location")
    assert location

    print("location:", location)

    print("base_url:", os.environ.get("MIDDLE_AUTH_BASE_URL"))

    # sticky_auth_url = os.environ.get(
    #     "STICKY_AUTH_URL",
    #     os.environ.get("AUTH_URL", os.environ.get("AUTH_URI", "localhost:5000/auth")),
    # )
    # authorize_uri = f"https://{sticky_auth_url}/api/v1/authorize"
    base_url = os.environ.get("MIDDLE_AUTH_BASE_URL")
    expected_redirect = f"{base_url}/api/v1/user/cache"
    expected_location = f"{base_url}/api/v1/authorize?redirect={quote(expected_redirect)}"
    assert location == expected_location

def test_invalid_token(api_client):
    cache_response = api_client.request("GET", "/api/v1/user/cache", token="invalidtoken")
    assert cache_response.status_code == 401
