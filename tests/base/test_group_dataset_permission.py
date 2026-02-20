import uuid


def _get_group_id(api_client, token, name):
    response = api_client.request(
        "GET", "/api/v1/group", token=token, params={"name": name}
    )
    assert response.status_code == 200
    groups = [group for group in response.json() if group["name"] == name]
    assert groups, f"Group '{name}' not found"
    return groups[0]["id"]


def _get_permission_id(api_client, token, name):
    response = api_client.request("GET", "/api/v1/permission", token=token)
    assert response.status_code == 200
    permissions = [perm for perm in response.json() if perm["name"] == name]
    assert permissions, f"Permission '{name}' not found"
    return permissions[0]["id"]


def test_group_dataset_permission_add_remove(api_client, default_admin):
    token = default_admin
    group_id = _get_group_id(api_client, token, "default")
    permission_id = _get_permission_id(api_client, token, "view")

    tos_name = f"test-tos-{uuid.uuid4().hex[:8]}"
    dataset_name = f"test-dataset-{uuid.uuid4().hex[:8]}"

    tos_response = api_client.request(
        "POST",
        "/api/v1/tos",
        token=token,
        json={"name": tos_name, "text": "Test TOS"},
    )
    assert tos_response.status_code == 200
    tos_id = tos_response.json()["id"]

    dataset_response = api_client.request(
        "POST",
        "/api/v1/dataset",
        token=token,
        json={"name": dataset_name, "tos_id": tos_id},
    )
    assert dataset_response.status_code == 200
    dataset_id = dataset_response.json()["id"]

    add_response = api_client.request(
        "POST",
        f"/api/v1/dataset/{dataset_id}/group",
        token=token,
        json={"group_id": group_id, "permission_ids": [permission_id]},
    )
    assert add_response.status_code == 200
    assert add_response.json() == "success"

    dataset_groups_response = api_client.request(
        "GET", f"/api/v1/dataset/{dataset_id}/group", token=token
    )
    assert dataset_groups_response.status_code == 200
    dataset_permissions = dataset_groups_response.json()
    assert any(
        entry["id"] == group_id and entry["permission_id"] == permission_id
        for entry in dataset_permissions
    )

    group_datasets_response = api_client.request(
        "GET", f"/api/v1/group/{group_id}/dataset", token=token
    )
    assert group_datasets_response.status_code == 200
    group_permissions = group_datasets_response.json()
    assert any(
        entry["id"] == dataset_id and entry["permission_id"] == permission_id
        for entry in group_permissions
    )

    delete_response = api_client.request(
        "DELETE",
        f"/api/v1/dataset/{dataset_id}/group/{group_id}/permission/{permission_id}",
        token=token,
    )
    assert delete_response.status_code == 200
    assert delete_response.json() == "success"

    dataset_groups_response = api_client.request(
        "GET", f"/api/v1/dataset/{dataset_id}/group", token=token
    )
    assert dataset_groups_response.status_code == 200
    dataset_permissions = dataset_groups_response.json()
    assert not any(
        entry["id"] == group_id and entry["permission_id"] == permission_id
        for entry in dataset_permissions
    )
