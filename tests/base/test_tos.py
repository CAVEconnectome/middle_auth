import uuid


def test_tos_create_get_update(api_client, default_admin):
    token = default_admin
    tos_name = f"test-tos-{uuid.uuid4().hex[:8]}"

    create_response = api_client.request(
        "POST",
        "/api/v1/tos",
        token=token,
        json={"name": tos_name, "text": "Test TOS"},
    )

    assert create_response.status_code == 200
    tos = create_response.json()
    tos_id = tos["id"]
    assert tos["name"] == tos_name  

    get_response = api_client.request("GET", f"/api/v1/tos/{tos_id}", token=token)

    assert get_response.status_code == 200
    assert get_response.json()["name"] == tos_name

    update_response = api_client.request(
        "PUT",
        f"/api/v1/tos/{tos_id}",
        token=token,
        json={"text": "Updated TOS"},
    )

    assert update_response.status_code == 200
    assert update_response.json() == "success"

    verify_response = api_client.request("GET", f"/api/v1/tos/{tos_id}", token=token)

    assert verify_response.status_code == 200
    assert verify_response.json()["text"] == "Updated TOS"
