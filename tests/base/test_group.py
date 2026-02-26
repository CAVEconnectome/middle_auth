import uuid

def test_list_groups_default(api_client, default_admin):
    token = default_admin
    response = api_client.request("GET", "/api/v1/group", token=token)
    assert response.status_code == 200
    # Verify that the default group is present
    groups = response.json()
    assert any(group["name"] == "default" for group in groups)


def test_group_create_and_get(default_admin, api_client):
    token = default_admin
    name = f"test-group-{uuid.uuid4().hex[:8]}"
    payload = {"name": name}

    response = api_client.request("POST", "/api/v1/group", token=token, json=payload)

    assert response.status_code == 200
    assert response.json() == "success"

    list_response = api_client.request(
        "GET", "/api/v1/group", token=token, params={"name": name}
    )

    assert list_response.status_code == 200
    groups = [group for group in list_response.json() if group["name"] == name]
    assert groups

    group_id = groups[0]["id"]
    get_response = api_client.request("GET", f"/api/v1/group/{group_id}", token=token)

    assert get_response.status_code == 200
    assert get_response.json()["name"] == name


def test_group_add_user_membership(default_admin, api_client):
    admin_token = default_admin
    group_name = f"test-group-{uuid.uuid4().hex[:8]}"
    user_email = f"group.user.{uuid.uuid4().hex[:8]}@example.com"

    group_response = api_client.request(
        "POST", "/api/v1/group", token=admin_token, json={"name": group_name}
    )

    assert group_response.status_code == 200
    assert group_response.json() == "success"

    list_response = api_client.request(
        "GET", "/api/v1/group", token=admin_token, params={"name": group_name}
    )

    assert list_response.status_code == 200
    groups = [group for group in list_response.json() if group["name"] == group_name]
    assert groups
    group_id = groups[0]["id"]

    user_response = api_client.request(
        "POST",
        "/api/v1/user",
        token=admin_token,
        json={"name": "Group User", "email": user_email},
    )

    assert user_response.status_code == 200
    user_id = user_response.json()["id"]

    tos_name = f"test-tos-{uuid.uuid4().hex[:8]}"
    tos_response = api_client.request(
        "POST",
        "/api/v1/tos",
        token=admin_token,
        json={"name": tos_name, "text": "Test TOS"},
    )

    assert tos_response.status_code == 200
    tos_id = tos_response.json()["id"]

    dataset_name = f"test-dataset-{uuid.uuid4().hex[:8]}"
    dataset_response = api_client.request(
        "POST",
        "/api/v1/dataset",
        token=admin_token,
        json={"name": dataset_name, "tos_id": tos_id},
    )

    assert dataset_response.status_code == 200
    dataset_id = dataset_response.json()["id"]

    permissions_response = api_client.request(
        "GET", "/api/v1/permission", token=admin_token
    )

    assert permissions_response.status_code == 200
    permissions = permissions_response.json()
    view_permission = next(
        permission for permission in permissions if permission["name"] == "view"
    )
    view_permission_id = view_permission["id"]

    add_response = api_client.request(
        "POST",
        f"/api/v1/group/{group_id}/user",
        token=admin_token,
        json={"user_id": user_id},
    )

    assert add_response.status_code == 200
    assert add_response.json() == "success"

    members_response = api_client.request(
        "GET", f"/api/v1/group/{group_id}/user", token=admin_token
    )

    assert members_response.status_code == 200
    members = members_response.json()
    assert any(member["id"] == user_id for member in members)

    dataset_group_response = api_client.request(
        "POST",
        f"/api/v1/dataset/{dataset_id}/group",
        token=admin_token,
        json={"group_id": group_id, "permission_ids": [view_permission_id]},
    )

    assert dataset_group_response.status_code == 200
    assert dataset_group_response.json() == "success"

    user_permissions_response = api_client.request(
        "GET", f"/api/v1/user/{user_id}/permissions", token=admin_token
    )

    assert user_permissions_response.status_code == 200
    permissions_data = user_permissions_response.json()
    assert "permissions_v2_ignore_tos" in permissions_data
    assert dataset_name in permissions_data["permissions_v2_ignore_tos"]
    assert ["view"] == permissions_data["permissions_v2_ignore_tos"][dataset_name]
    assert "missing_tos" in permissions_data
    assert len(permissions_data["missing_tos"]) == 1
    assert permissions_data["missing_tos"][0].get("dataset_name") == dataset_name

