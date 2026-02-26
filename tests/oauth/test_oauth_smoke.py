import os
import re
import pytest
from urllib.parse import parse_qs, quote, urlparse, urlunparse
from uuid import uuid4

from tests.oauth import WrappedSession, combined_ca_bundle_path, token_from_set_cookie
from tests.test_utils import delete_login_email_file, set_login_email

base_url = os.environ.get("MIDDLE_AUTH_BASE_URL", "http://localhost:5001/auth").rstrip("/")


@pytest.fixture()
def login_email(request):
    email = getattr(request, "param", "controlled.user.foo1@example.com")
    set_login_email(email)
    try:
        yield email
    finally:
        delete_login_email_file()


@pytest.mark.parametrize(
    "login_email",
    ["controlled.user.foo1@example.com"],
    indirect=True,
)
def test_oauth_flow_uses_mock_userinfo(login_email):
    authorize_url = f"{base_url}/api/v1/authorize"

    session = WrappedSession()
    verify_bundle = combined_ca_bundle_path()
    session.verify = verify_bundle

    authorize_response = session.get(
        authorize_url, allow_redirects=False#, verify=verify_bundle
    )
    assert authorize_response.status_code == 302

    oauth_location = authorize_response.headers.get("Location")
    assert oauth_location
    assert oauth_location.startswith("https://accounts.google.com/o/oauth2/auth")

    oauth_url = urlparse(oauth_location)
    oauth_location = urlunparse(oauth_url)

    oauth_response = session.get(oauth_location, allow_redirects=False)
    assert oauth_response.status_code == 302

    callback_location = oauth_response.headers.get("Location")
    assert callback_location

    callback_response = session.get(callback_location, allow_redirects=False)#, verify=verify_bundle)

    token_name = os.environ.get("TOKEN_NAME", "middle_auth_token")
    token = None

    if callback_response.status_code == 302:
        post_auth_location = callback_response.headers.get("Location")
        assert post_auth_location
        assert post_auth_location.startswith("/auth/settings/username")
        query = parse_qs(urlparse(post_auth_location).query)
        assert query.get("new_account", [""])[0] == "true"

        token = token_from_set_cookie(callback_response.headers.get("Set-Cookie"), token_name)
        assert token
    else:
        assert callback_response.status_code == 200
        match = re.search(r'"token"\s*:\s*"([^"]+)"', callback_response.text)
        assert match
        token = match.group(1)

    me_response = session.get(
        f"{base_url}/api/v1/user/me",
        headers={"Authorization": f"Bearer {token}"},
        verify=verify_bundle,
    )
    assert me_response.status_code == 200
    me_data = me_response.json()
    assert me_data["email"] == login_email

@pytest.mark.parametrize(
    "login_email",
    [f"controlled.user.{uuid4().hex[:8]}@example.com"],
    indirect=True,
)
def test_oauth_flow_new_user(browser, login_email):
    with browser.new_context(
        ignore_https_errors=True,
    ) as context:
        page = context.new_page()

        resp = page.goto(f"{base_url}/api/v1/user/me")
        assert resp is not None
        assert resp.status == 200

        assert "/auth/settings/username" in page.url

        page.locator("#submit").click()
        page.wait_for_load_state("networkidle")
        resp = page.goto(f"{base_url}/api/v1/user/me")
        assert resp is not None
        assert resp.status == 200

        data = page.evaluate("() => JSON.parse(document.body.innerText)")
        print("data", data)
        assert data["email"] == login_email
        assert data["admin"] is False

@pytest.mark.parametrize(
    "login_email",
    ["default@admin.local"],
    indirect=True,
)
def test_oauth_flow_default_admin(browser, login_email):
    token_name = os.environ.get("TOKEN_NAME", "middle_auth_token")

    with browser.new_context(
        ignore_https_errors=True,
    ) as context:
        page = context.new_page()
        resp = page.goto(f"{base_url}/api/v1/user/me")
        assert resp is not None
        assert resp.status == 200

        data = page.evaluate("() => JSON.parse(document.body.innerText)")
        assert data["email"] == login_email
        assert data["admin"] is True
        assert data["name"] == "Default Admin"

        cookies = context.cookies([base_url])
        token_cookie = next((cookie for cookie in cookies if cookie["name"] == token_name), None)
        assert token_cookie is not None
        assert token_cookie.get("value")