import uuid


def test_dataset_create_and_update(api_client, default_admin):
    token = default_admin
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

    create_response = api_client.request(
        "POST",
        "/api/v1/dataset",
        token=token,
        json={"name": dataset_name, "tos_id": tos_id},
    )

    assert create_response.status_code == 200
    dataset = create_response.json()
    dataset_id = dataset["id"]
    assert dataset["name"] == dataset_name
    assert dataset["tos_id"] == tos_id

    get_response = api_client.request(
        "GET", f"/api/v1/dataset/{dataset_id}", token=token
    )

    assert get_response.status_code == 200
    assert get_response.json()["name"] == dataset_name

    updated_name = f"{dataset_name}-updated"
    update_response = api_client.request(
        "PUT",
        f"/api/v1/dataset/{dataset_id}",
        token=token,
        json={"name": updated_name},
    )

    assert update_response.status_code == 200
    assert update_response.json() == "success"

    verify_response = api_client.request(
        "GET", f"/api/v1/dataset/{dataset_id}", token=token
    )

    assert verify_response.status_code == 200
    assert verify_response.json()["name"] == updated_name
