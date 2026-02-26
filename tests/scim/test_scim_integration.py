"""
SCIM 2.0 Integration Test Suite

Run with:
    export SCIM_BASE_URL="http://localhost:5000/v2"
    export SCIM_TEST_TOKEN="your_service_account_token"
    pytest tests/test_scim_integration.py -v

Or via Docker:
    docker compose -f docker-compose.test.yml up
"""

import pytest


# =============================================================================
# Discovery Endpoints
# =============================================================================


@pytest.mark.order(1)
def test_service_provider_config(scim_client):
    """Test ServiceProviderConfig discovery endpoint."""
    response = scim_client.request("GET", "/ServiceProviderConfig")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    assert "schemas" in data


@pytest.mark.order(2)
def test_resource_types(scim_client):
    """Test ResourceTypes discovery endpoint."""
    response = scim_client.request("GET", "/ResourceTypes")
    assert response.status_code == 200
    data = response.json()
    assert "Resources" in data
    types = [r["id"] for r in data["Resources"]]
    assert "User" in types
    assert "Group" in types
    assert "Dataset" in types


@pytest.mark.order(3)
def test_schemas(scim_client):
    """Test Schemas discovery endpoint."""
    response = scim_client.request("GET", "/Schemas")
    assert response.status_code == 200


# =============================================================================
# User CRUD
# =============================================================================


@pytest.mark.order(10)
def test_user_create(scim_client):
    """Test user creation and retrieval."""
    user_data = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "scimtest@example.com",
        "name": {"givenName": "SCIM", "familyName": "Test"},
        "displayName": "SCIM Test User",
        "emails": [{"value": "scimtest@example.com", "type": "work", "primary": True}],
        "externalId": "test-ext-user-001",
    }
    response = scim_client.request("POST", "/Users", json=user_data)
    assert response.status_code in [200, 201], f"Expected 200/201, got {response.status_code}: {response.text}"
    user = response.json()
    user_id = user["id"]
    scim_client.created_users.append(user_id)

    response = scim_client.request("GET", f"/Users/{user_id}")
    assert response.status_code == 200
    assert response.json()["id"] == user_id


@pytest.mark.order(11)
def test_user_search(scim_client):
    """Test user search with filter."""
    response = scim_client.request(
        "GET", "/Users", params={"filter": 'userName eq "scimtest@example.com"'}
    )
    assert response.status_code == 200
    data = response.json()
    assert "Resources" in data
    assert len(data["Resources"]) > 0


@pytest.mark.order(12)
def test_user_patch(scim_client):
    """Test user PATCH update."""
    assert len(scim_client.created_users) > 0
    user_id = scim_client.created_users[0]

    patch_data = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {"op": "replace", "path": "displayName", "value": "Updated SCIM Test User"}
        ],
    }
    response = scim_client.request("PATCH", f"/Users/{user_id}", json=patch_data)
    assert response.status_code == 200
    assert response.json()["displayName"] == "Updated SCIM Test User"


# =============================================================================
# Group CRUD
# =============================================================================


@pytest.mark.order(20)
def test_group_create(scim_client):
    """Test group creation and retrieval."""
    group_data = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "SCIM Test Group",
        "members": [],
        "externalId": "test-ext-group-001",
    }
    response = scim_client.request("POST", "/Groups", json=group_data)
    assert response.status_code in [200, 201]
    group = response.json()
    group_id = group["id"]
    scim_client.created_groups.append(group_id)

    response = scim_client.request("GET", f"/Groups/{group_id}")
    assert response.status_code == 200


# =============================================================================
# Group Membership
# =============================================================================


@pytest.mark.order(30)
def test_group_add_member(scim_client):
    """Test adding user to group."""
    assert len(scim_client.created_users) > 0 and len(scim_client.created_groups) > 0
    user_id = scim_client.created_users[0]
    group_id = scim_client.created_groups[0]

    patch_data = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "add",
                "path": "members",
                "value": [{"value": user_id, "display": "SCIM Test User"}],
            }
        ],
    }
    response = scim_client.request("PATCH", f"/Groups/{group_id}", json=patch_data)
    assert response.status_code == 200
    data = response.json()
    assert len(data["members"]) > 0


@pytest.mark.order(31)
def test_group_remove_member(scim_client):
    """Test removing user from group."""
    assert len(scim_client.created_users) > 0 and len(scim_client.created_groups) > 0
    user_id = scim_client.created_users[0]
    group_id = scim_client.created_groups[0]

    patch_data = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "remove",
                "path": "members",
                "value": [{"value": user_id}],
            }
        ],
    }
    response = scim_client.request("PATCH", f"/Groups/{group_id}", json=patch_data)
    assert response.status_code == 200


# =============================================================================
# Dataset CRUD
# =============================================================================


@pytest.mark.order(40)
def test_dataset_create(scim_client):
    """Test dataset creation and retrieval."""
    dataset_data = {
        "schemas": ["urn:ietf:params:scim:schemas:neuroglancer:2.0:Dataset"],
        "name": "scim-test-dataset",
        "serviceTables": [{"serviceName": "test-service", "tableName": "test-table"}],
        "externalId": "test-ext-dataset-001",
    }
    response = scim_client.request("POST", "/Datasets", json=dataset_data)
    assert response.status_code in [200, 201]
    dataset = response.json()
    dataset_id = dataset["id"]
    scim_client.created_datasets.append(dataset_id)

    response = scim_client.request("GET", f"/Datasets/{dataset_id}")
    assert response.status_code == 200


# =============================================================================
# Duplicate Creation (409 Conflict)
# =============================================================================


@pytest.mark.order(50)
def test_duplicate_user_returns_409(scim_client):
    """Test duplicate creation returns 409 Conflict per SCIM RFC 7644."""
    user_data = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "idempotent@example.com",
        "displayName": "Idempotent Test User",
        "externalId": "idempotent-test-001",
    }

    response1 = scim_client.request("POST", "/Users", json=user_data)
    assert response1.status_code in [200, 201], (
        f"Expected 200/201, got {response1.status_code}: {response1.text}"
    )
    user1 = response1.json()
    scim_client.created_users.append(user1["id"])

    response2 = scim_client.request("POST", "/Users", json=user_data)
    assert response2.status_code == 409, (
        f"Expected 409 Conflict for duplicate, got {response2.status_code}: {response2.text}"
    )
    data = response2.json()
    assert "detail" in data or "scimType" in data
