import uuid


def _create_service_account(api_client, token, name=None):
    sa_name = name or f"test-sa-{uuid.uuid4().hex[:8]}"
    response = api_client.request(
        "POST", "/api/v1/service_account", token=token, json={"name": sa_name}
    )
    assert response.status_code == 200
    sa = response.json()
    assert sa["name"] == sa_name
    assert sa["service_account"] is True
    return sa


def test_service_account_lifecycle(api_client, default_admin):
    admin_token = default_admin
    admin_user_response = api_client.request(
        "GET", "/api/v1/user/cache", token=admin_token
    )
    assert admin_user_response.status_code == 200
    admin_user = admin_user_response.json()

    sa = _create_service_account(api_client, admin_token)
    sa_id = sa["id"]

    list_response = api_client.request(
        "GET", "/api/v1/service_account", token=admin_token, params={"id": sa_id}
    )
    assert list_response.status_code == 200
    assert any(entry["id"] == sa_id for entry in list_response.json())

    get_response = api_client.request(
        "GET", f"/api/v1/service_account/{sa_id}", token=admin_token
    )
    assert get_response.status_code == 200
    sa_details = get_response.json()
    assert sa_details["id"] == sa_id
    assert sa_details["name"] == sa["name"]
    assert sa_details["parent_id"] == admin_user["id"]

    update_response = api_client.request(
        "PUT",
        f"/api/v1/service_account/{sa_id}",
        token=admin_token,
        json={"name": f"updated-{uuid.uuid4().hex[:6]}"},
    )
    assert update_response.status_code == 200
    assert update_response.json() == "success"

    token_response = api_client.request(
        "GET", f"/api/v1/service_account/{sa_id}/token", token=admin_token
    )
    assert token_response.status_code == 200
    assert token_response.json()

    permissions_response = api_client.request(
        "GET", f"/api/v1/service_account/{sa_id}/permissions", token=admin_token
    )
    assert permissions_response.status_code == 200
    permissions = permissions_response.json()
    assert permissions["id"] == sa_id
    assert "permissions_v2" in permissions
    assert "groups" in permissions

    delete_response = api_client.request(
        "DELETE", f"/api/v1/service_account/{sa_id}", token=admin_token
    )
    assert delete_response.status_code == 200
    assert delete_response.json() == "success"

    get_after_delete = api_client.request(
        "GET", f"/api/v1/service_account/{sa_id}", token=admin_token
    )
    assert get_after_delete.status_code == 404


def test_service_account_group_membership(api_client, default_admin):
    admin_token = default_admin
    group_name = f"test-sa-group-{uuid.uuid4().hex[:8]}"

    group_response = api_client.request(
        "POST", "/api/v1/group", token=admin_token, json={"name": group_name}
    )
    assert group_response.status_code == 200
    assert group_response.json() == "success"

    group_list = api_client.request(
        "GET", "/api/v1/group", token=admin_token, params={"name": group_name}
    )
    assert group_list.status_code == 200
    groups = [group for group in group_list.json() if group["name"] == group_name]
    assert groups
    group_id = groups[0]["id"]

    sa = _create_service_account(api_client, admin_token)
    sa_id = sa["id"]

    add_response = api_client.request(
        "POST",
        f"/api/v1/group/{group_id}/service_account",
        token=admin_token,
        json={"sa_id": sa_id},
    )
    assert add_response.status_code == 200
    assert add_response.json() == "success"

    group_sas = api_client.request(
        "GET", f"/api/v1/group/{group_id}/service_account", token=admin_token
    )
    assert group_sas.status_code == 200
    assert any(entry["id"] == sa_id for entry in group_sas.json())

    sa_groups = api_client.request(
        "GET", f"/api/v1/service_account/{sa_id}/group", token=admin_token
    )
    assert sa_groups.status_code == 200
    assert any(entry["id"] == group_id for entry in sa_groups.json())

    remove_response = api_client.request(
        "DELETE",
        f"/api/v1/group/{group_id}/service_account/{sa_id}",
        token=admin_token,
    )
    assert remove_response.status_code == 200
    assert remove_response.json() == "success"

    group_sas = api_client.request(
        "GET", f"/api/v1/group/{group_id}/service_account", token=admin_token
    )
    assert group_sas.status_code == 200
    assert not any(entry["id"] == sa_id for entry in group_sas.json())

    delete_response = api_client.request(
        "DELETE", f"/api/v1/service_account/{sa_id}", token=admin_token
    )
    assert delete_response.status_code == 200
    assert delete_response.json() == "success"
